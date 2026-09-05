//! ICMP Address Mask Request and Reply (RFC 950 appendix I, ICMP types 17 and 18).
//!
//! An interface that answers this states the mask of the network it is attached to. That
//! makes it one of the few prefix-bearing sources reachable without credentials: a router
//! interface discovered by reachability alone is an address and nothing more, and this is
//! how it can become a network.
//!
//! What a reply establishes is bounded on both sides. It is the device's own claim, so the
//! resulting prefix is graded advertised, never observed. And a mask that is not contiguous
//! is not a prefix at all -- choosing which bits were meant would be inventing the network
//! rather than reading it -- so it is refused outright.
//!
//! Many hosts and most modern routers do not implement this at all, which is unremarkable:
//! no reply means the interface's prefix stays unresolved, and an unresolved interface is
//! reported as exactly that.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use ipnet::Ipv4Net;

use crate::net::socket::SocketBinding;
use crate::probes::attempt::AttemptOutcome;
use crate::probes::path::{icmp_message, internet_checksum};

/// ICMP types for the exchange.
const ADDRESS_MASK_REQUEST: u8 = 17;
const ADDRESS_MASK_REPLY: u8 = 18;

/// Request and reply are both twelve bytes: type, code, checksum, identifier, sequence and
/// the mask.
const MESSAGE_LEN: usize = 12;

/// What was asked, kept so a reply can be checked against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskQuery {
    pub identifier: u16,
    pub sequence: u16,
    pub target: Ipv4Addr,
}

/// A mask an interface stated for itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskReply {
    /// The interface that answered, which must be the address that was asked.
    pub address: Ipv4Addr,
    pub mask: Ipv4Addr,
    /// The network the address and mask describe together.
    pub prefix: Ipv4Net,
    /// The bytes the fact came from.
    pub raw: Vec<u8>,
}

/// The outcome of one address-mask exchange.
pub type MaskOutcome = AttemptOutcome<MaskReply>;

/// Builds an address mask request.
pub fn request(query: MaskQuery) -> Vec<u8> {
    let mut message = vec![ADDRESS_MASK_REQUEST, 0, 0, 0];
    message.extend_from_slice(&query.identifier.to_be_bytes());
    message.extend_from_slice(&query.sequence.to_be_bytes());
    // The mask field is zero in a request; the answer fills it in.
    message.extend_from_slice(&[0, 0, 0, 0]);
    let checksum = internet_checksum(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

/// Whether a mask is a prefix: a run of ones followed by a run of zeros.
///
/// A discontiguous mask is not a network. Reading one as a prefix length would mean
/// choosing which bits the device meant, which is the difference between reading a network
/// and inventing one.
pub fn prefix_length(mask: Ipv4Addr) -> Option<u8> {
    crate::net::interface::contiguous_prefix_len(mask)
}

/// Validates a datagram as the reply to `query` and reads the mask it carried.
///
/// Correlated on every field the exchange provides: the message type, the identifier and
/// sequence we chose, and the address it came from. Without the source check a reply from
/// any interface would be attributed to the one that was asked -- which on a path with
/// several routers is not a remote possibility.
pub fn parse_reply(datagram: &[u8], query: MaskQuery, from: IpAddr) -> Option<MaskReply> {
    let IpAddr::V4(from) = from else {
        return None;
    };
    if from != query.target {
        return None;
    }

    let icmp = icmp_message(datagram)?;
    if icmp.len() < MESSAGE_LEN {
        return None;
    }
    if icmp[0] != ADDRESS_MASK_REPLY || icmp[1] != 0 {
        return None;
    }
    if u16::from_be_bytes([icmp[4], icmp[5]]) != query.identifier {
        return None;
    }
    if u16::from_be_bytes([icmp[6], icmp[7]]) != query.sequence {
        return None;
    }
    // The reply carries its own checksum over the twelve bytes.
    if internet_checksum(&icmp[..MESSAGE_LEN]) != 0 {
        return None;
    }

    let mask = Ipv4Addr::new(icmp[8], icmp[9], icmp[10], icmp[11]);
    let length = prefix_length(mask)?;
    // A /0 or /32 answer describes no network an operator can act on: the first claims the
    // whole address space, the second claims only the interface itself.
    if length == 0 || length == 32 {
        return None;
    }
    let prefix = Ipv4Net::new(query.target, length).ok()?.trunc();

    Some(MaskReply {
        address: query.target,
        mask,
        prefix,
        raw: icmp[..MESSAGE_LEN].to_vec(),
    })
}

/// Asks one interface for the mask of the network it is attached to.
#[cfg(unix)]
pub async fn ask(
    target: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    binding: &SocketBinding,
    budget: Duration,
) -> MaskOutcome {
    let query = MaskQuery {
        identifier,
        sequence,
        target,
    };
    let sent = format!("ICMP address mask request to {target}");

    let Some(socket) = crate::probes::path::icmp_socket() else {
        return AttemptOutcome::unavailable(
            "an ICMP socket could not be opened: address mask requests need root".to_string(),
        );
    };
    let destination = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(target, 0));
    if binding.bind_icmp(&socket).is_err() {
        return AttemptOutcome::not_sent(
            "the ICMP socket could not be bound to the selected interface".to_string(),
        );
    }
    if socket.send_to(&request(query), destination).await.is_err() {
        return AttemptOutcome::not_sent(format!("the request to {target} could not be sent"));
    }

    let deadline = tokio::time::Instant::now() + budget;
    let mut buffer = [0u8; 1500];
    let mut rejected = 0usize;

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Ok(Ok((length, from))) =
            tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await
        else {
            continue;
        };
        match parse_reply(&buffer[..length], query, from.ip()) {
            Some(reply) => {
                return AttemptOutcome::Answered {
                    sent,
                    result: reply,
                };
            }
            // Other ICMP arrives on this socket constantly; only a reply from the address
            // we asked, carrying our identifier, counts as a failed answer.
            None => {
                if from.ip() == IpAddr::V4(target) {
                    rejected += 1;
                }
            }
        }
    }

    if rejected > 0 {
        return AttemptOutcome::InvalidResponse { sent, rejected };
    }
    AttemptOutcome::NoResponse { sent }
}

/// Where raw ICMP cannot be opened, the request is unavailable rather than unanswered.
#[cfg(not(unix))]
pub async fn ask(
    target: Ipv4Addr,
    _identifier: u16,
    _sequence: u16,
    _binding: &SocketBinding,
    _budget: Duration,
) -> MaskOutcome {
    let _ = target;
    AttemptOutcome::unavailable(
        "raw ICMP is not available on this platform, so no address mask can be requested"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: Ipv4Addr = Ipv4Addr::new(192, 168, 51, 1);

    fn query() -> MaskQuery {
        MaskQuery {
            identifier: 0x2b1d,
            sequence: 4,
            target: TARGET,
        }
    }

    fn reply(identifier: u16, sequence: u16, mask: [u8; 4]) -> Vec<u8> {
        let mut message = vec![ADDRESS_MASK_REPLY, 0, 0, 0];
        message.extend_from_slice(&identifier.to_be_bytes());
        message.extend_from_slice(&sequence.to_be_bytes());
        message.extend_from_slice(&mask);
        let checksum = internet_checksum(&message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());
        message
    }

    #[test]
    fn the_request_carries_our_identity_and_an_empty_mask() {
        let message = request(query());
        assert_eq!(message.len(), MESSAGE_LEN);
        assert_eq!(message[0], ADDRESS_MASK_REQUEST);
        assert_eq!(message[1], 0);
        assert_eq!(&message[4..6], &0x2b1du16.to_be_bytes());
        assert_eq!(&message[6..8], &4u16.to_be_bytes());
        assert_eq!(&message[8..12], &[0, 0, 0, 0], "the answer fills this in");
        assert_eq!(internet_checksum(&message), 0, "the checksum verifies");
    }

    #[test]
    fn a_correlated_reply_establishes_the_interfaces_network() {
        // The acceptance case: a router interface found by reachability is an address and
        // nothing more until it states its own mask.
        let message = reply(0x2b1d, 4, [255, 255, 255, 0]);
        let parsed =
            parse_reply(&message, query(), IpAddr::V4(TARGET)).expect("a correlated reply");

        assert_eq!(parsed.address, TARGET);
        assert_eq!(parsed.mask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(parsed.prefix, "192.168.51.0/24".parse::<Ipv4Net>().unwrap());
        assert_eq!(parsed.raw.len(), MESSAGE_LEN);
    }

    #[test]
    fn a_reply_from_another_interface_is_not_this_interfaces_mask() {
        // On a path with several routers this is the ordinary case, not an exotic one:
        // attributing another interface's mask to the one we asked would name a network
        // that does not exist there.
        let message = reply(0x2b1d, 4, [255, 255, 255, 0]);
        let elsewhere = IpAddr::V4(Ipv4Addr::new(192, 168, 70, 1));
        assert!(parse_reply(&message, query(), elsewhere).is_none());
    }

    #[test]
    fn a_reply_to_another_exchange_is_refused() {
        let from = IpAddr::V4(TARGET);
        // Another program's identifier.
        assert!(parse_reply(&reply(0x1111, 4, [255, 255, 255, 0]), query(), from).is_none());
        // An earlier sequence of our own.
        assert!(parse_reply(&reply(0x2b1d, 1, [255, 255, 255, 0]), query(), from).is_none());
        // A request looped back is not a reply.
        let mut request_type = reply(0x2b1d, 4, [255, 255, 255, 0]);
        request_type[0] = ADDRESS_MASK_REQUEST;
        assert!(parse_reply(&request_type, query(), from).is_none());
        // A corrupted checksum.
        let mut corrupt = reply(0x2b1d, 4, [255, 255, 255, 0]);
        corrupt[9] ^= 0xff;
        assert!(parse_reply(&corrupt, query(), from).is_none());
    }

    #[test]
    fn a_mask_that_is_not_a_prefix_establishes_nothing() {
        let from = IpAddr::V4(TARGET);
        // Discontiguous: choosing which bits were meant would invent the network.
        assert!(parse_reply(&reply(0x2b1d, 4, [255, 0, 255, 0]), query(), from).is_none());
        assert_eq!(prefix_length(Ipv4Addr::new(255, 0, 255, 0)), None);

        // /0 claims the whole address space and /32 claims only the interface; neither
        // describes a network an operator can act on.
        assert!(parse_reply(&reply(0x2b1d, 4, [0, 0, 0, 0]), query(), from).is_none());
        assert!(parse_reply(&reply(0x2b1d, 4, [255, 255, 255, 255]), query(), from).is_none());

        assert_eq!(prefix_length(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(prefix_length(Ipv4Addr::new(255, 255, 240, 0)), Some(20));
    }

    #[test]
    fn truncated_datagrams_are_refused_rather_than_read_past() {
        let message = reply(0x2b1d, 4, [255, 255, 255, 0]);
        for length in 0..message.len() {
            assert!(parse_reply(&message[..length], query(), IpAddr::V4(TARGET)).is_none());
        }
    }
}
