//! Finding peers on the local link.
//!
//! Discovery answers "is there an idNX here, and what is its identity" — nothing more.
//! Being discovered is not being trusted: a peer found this way is offered to the operator
//! and its evidence is refused until they pair with it. Anything else would let whoever can
//! reach the link inject topology, which is worse than not discovering peers at all.
//!
//! `_idnx._tcp.local` over mDNS, on the selected interface only, because a peer found
//! through another interface is on a link this vantage never claimed to see.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::time::timeout;

use super::identity::PeerId;
use super::limits::{MAX_TEXT_BYTES, sanitize};
use crate::net::socket::SocketBinding;

/// The service peers advertise and look for.
pub const SERVICE: &str = "_idnx._tcp.local";

/// mDNS multicast group and port.
const MDNS_V4: (IpAddr, u16) = (IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 251)), 5353);

/// A peer seen on the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// Where it can be reached.
    pub address: SocketAddr,
    /// The identity it advertised. Unverified: anything can claim any identity here, and
    /// the claim is only settled by the handshake.
    pub claimed_identity: Option<PeerId>,
    /// The name it published, sanitized for display.
    pub name: String,
    /// Whether this machine has paired with it.
    pub paired: bool,
}

impl DiscoveredPeer {
    /// One line for the operator.
    pub fn describe(&self) -> String {
        let identity = match &self.claimed_identity {
            Some(id) => id.short(),
            None => "unidentified".to_string(),
        };
        let trust = if self.paired {
            "paired"
        } else {
            "not paired — its evidence is refused until you pair with it"
        };
        format!("{} at {} [{identity}] ({trust})", self.name, self.address)
    }
}

/// Builds the mDNS query for the service.
pub fn service_query() -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    // Header: id 0, standard query, one question.
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    encode_name(&mut packet, SERVICE);
    // QTYPE PTR, QCLASS IN with the unicast-response bit clear.
    packet.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]);
    packet
}

/// The TXT record a peer publishes about itself.
///
/// Identity only, plus the port. Deliberately nothing about the network being mapped:
/// mDNS is broadcast to the whole link, so anything here is public to every device on it.
pub fn advertisement(identity: &PeerId, port: u16) -> String {
    format!("id={} port={port}", identity.to_hex())
}

/// Parses a peer's advertisement.
///
/// Bounded and sanitized: this is unauthenticated text from the link, and it ends up on a
/// terminal.
pub fn parse_advertisement(text: &str) -> Option<(PeerId, u16)> {
    if text.len() > MAX_TEXT_BYTES {
        return None;
    }

    let mut identity = None;
    let mut port = None;
    for field in text.split_whitespace() {
        if let Some(value) = field.strip_prefix("id=") {
            identity = PeerId::from_hex(value).ok();
        } else if let Some(value) = field.strip_prefix("port=") {
            port = value.parse::<u16>().ok();
        }
    }
    Some((identity?, port?))
}

/// Writes a DNS name into a packet.
fn encode_name(packet: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        packet.push(label.len().min(63) as u8);
        packet.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    packet.push(0);
}

/// Extracts advertisements from an mDNS response.
///
/// Deliberately tolerant of the record structure and strict about the contents: appliance
/// mDNS implementations are frequently non-conformant, and losing one malformed record
/// matters less than refusing every peer on a link because one device is wrong.
pub fn advertisements_in(packet: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    // TXT strings are length-prefixed, and the ones this looks for begin with "id=".
    let mut index = 0usize;
    while index < packet.len() {
        let length = packet[index] as usize;
        index += 1;
        if length == 0 || index + length > packet.len() {
            continue;
        }
        if let Ok(text) = std::str::from_utf8(&packet[index..index + length])
            && text.starts_with("id=")
        {
            out.push(sanitize(text));
        }
        index += length;
    }
    out
}

/// Asks the link who is running idNX.
///
/// Sends on the selected interface only and collects whatever answers within the window.
/// Returning an empty list means nothing answered, which is not an error: most links have
/// no other idNX on them.
pub async fn discover(
    binding: &SocketBinding,
    listen: Duration,
) -> Result<Vec<String>, std::io::Error> {
    let socket = binding.udp_multicast_v4(0).await?;
    let destination = SocketAddr::new(MDNS_V4.0, MDNS_V4.1);
    socket.send_to(&service_query(), destination).await?;

    let mut found = Vec::new();
    let deadline = tokio::time::Instant::now() + listen;
    let mut buffer = vec![0u8; 4096];

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let Ok(Ok((length, _from))) = timeout(remaining, socket.recv_from(&mut buffer)).await
        else {
            break;
        };
        found.extend(advertisements_in(&buffer[..length]));
    }

    found.sort();
    found.dedup();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::identity::PeerKey;

    #[test]
    fn an_advertisement_round_trips() {
        let id = PeerKey::generate().id();
        let (parsed, port) = parse_advertisement(&advertisement(&id, 7373)).expect("parses");
        assert_eq!(parsed, id);
        assert_eq!(port, 7373);
    }

    #[test]
    fn an_advertisement_carries_identity_and_nothing_about_the_network() {
        // mDNS reaches every device on the link, so anything published here is public.
        let id = PeerKey::generate().id();
        let text = advertisement(&id, 7373);
        assert!(text.contains(&id.to_hex()));
        assert!(!text.contains("192.168"));
        assert!(text.split_whitespace().count() == 2, "{text}");
    }

    #[test]
    fn hostile_advertisement_text_is_refused_rather_than_trusted() {
        assert!(parse_advertisement("").is_none());
        assert!(parse_advertisement("id=🔑 port=1").is_none());
        assert!(parse_advertisement("id=notahexkey port=1").is_none());
        assert!(parse_advertisement(&format!("id={} port=x", "ab".repeat(32))).is_none());
        // Oversized input is dropped before it is examined.
        assert!(parse_advertisement(&"a".repeat(MAX_TEXT_BYTES + 1)).is_none());
    }

    #[test]
    fn terminal_escapes_in_an_advertisement_cannot_reach_the_display() {
        // Anything on the link can send these, and they are printed.
        let mut packet = Vec::new();
        let hostile = "id=\u{1b}[2Jforged";
        packet.push(hostile.len() as u8);
        packet.extend_from_slice(hostile.as_bytes());

        let found = advertisements_in(&packet);
        assert_eq!(found.len(), 1);
        assert!(!found[0].contains('\u{1b}'));
    }

    #[test]
    fn a_discovered_peer_is_not_a_trusted_one() {
        // The distinction this whole module rests on: anything can claim any identity, and
        // being seen on the link grants nothing.
        let id = PeerKey::generate().id();
        let peer = DiscoveredPeer {
            address: "192.168.1.9:7373".parse().unwrap(),
            claimed_identity: Some(id),
            name: "idnx".to_string(),
            paired: false,
        };
        assert!(peer.describe().contains("not paired"));
        assert!(peer.describe().contains("refused"));

        let paired = DiscoveredPeer {
            paired: true,
            ..peer
        };
        assert!(paired.describe().contains("(paired)"));
    }

    #[test]
    fn the_service_query_asks_for_the_right_name() {
        let query = service_query();
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1, "one question");
        assert!(
            query.windows(6).any(|w| w == b"\x05_idnx"),
            "the service label is present"
        );
        assert_eq!(
            &query[query.len() - 4..],
            &[0x00, 0x0c, 0x00, 0x01],
            "PTR IN"
        );
    }

    #[test]
    fn a_truncated_packet_does_not_panic() {
        // Appliance mDNS is frequently malformed; losing a record is acceptable, reading
        // out of bounds is not.
        assert!(advertisements_in(&[]).is_empty());
        assert!(advertisements_in(&[200]).is_empty());
        assert!(advertisements_in(&[3, b'i']).is_empty());
    }
}
