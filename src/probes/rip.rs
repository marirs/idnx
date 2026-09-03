//! RIP: the one routing protocol a router will describe its tables to, unauthenticated.
//!
//! A RIPv2 response carries real prefixes with real netmasks and real next hops. That is
//! prefix-bearing evidence in the strict sense: the network exists because a router said so
//! in a protocol field, not because anything was inferred from an address.
//!
//! Two ways in, with different scopes and different meanings.
//!
//! * **Passively**, on the link. RIPv2 multicasts its updates to 224.0.0.9 and RIPng to
//!   ff02::9, both link-scoped. Anything heard there was advertised to this link, and the
//!   advertising router is the one that sent the frame.
//! * **By unicast request** to a specific router. RFC 2453 section 3.9.1 defines a request
//!   for the whole table, and a router that answers has disclosed its routes to us
//!   directly. Read-only: a request cannot alter anything, and no authentication is
//!   attempted.
//!
//! RIPng is IPv6 and link-scoped; it is never sent to an IPv4 address discovered on a
//! traceroute, which would be addressing a protocol to something that cannot speak it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net};

use crate::net::socket::SocketBinding;

/// The port both directions of RIP use.
pub const RIP_PORT: u16 = 520;

/// RIP commands.
const RIP_REQUEST: u8 = 1;
const RIP_RESPONSE: u8 = 2;

/// Address family identifiers that appear in a RIP entry.
const AFI_INET: u16 = 2;
/// A request for the whole table uses this family with a metric of 16.
const AFI_UNSPECIFIED: u16 = 0;

/// One route a router advertised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RipRoute {
    pub prefix: IpNet,
    /// Where the advertising router says to send traffic. Zero means "via me".
    pub next_hop: Option<IpAddr>,
    /// RIP metric. 16 is unreachable and is an advertisement of withdrawal.
    pub metric: u32,
    /// Route tag, carried through because it identifies redistributed routes.
    pub tag: u16,
    /// The exact 20 bytes of the entry that produced this route.
    ///
    /// Kept so a network can be traced back to the protocol field that established it. A
    /// prefix with no recoverable origin is indistinguishable from one that was invented.
    pub raw_entry: Vec<u8>,
}

impl RipRoute {
    /// Whether this entry advertises reachability rather than withdrawal.
    pub fn is_reachable(&self) -> bool {
        self.metric < 16
    }

    /// The entry bytes as hex, for the evidence trail.
    pub fn evidence(&self) -> String {
        let hex: String = self
            .raw_entry
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        format!(
            "RIPv2 entry (AFI 2, tag {}, metric {}): {hex}",
            self.tag, self.metric
        )
    }
}

/// Builds a request for a router's entire table.
///
/// RFC 2453 section 3.9.1: one entry, address family zero, metric sixteen. Read-only by
/// construction -- a request carries no routes and cannot change anything.
pub fn table_request() -> Vec<u8> {
    let mut packet = vec![RIP_REQUEST, 2, 0, 0];
    packet.extend_from_slice(&AFI_UNSPECIFIED.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes()); // route tag
    packet.extend_from_slice(&[0, 0, 0, 0]); // address
    packet.extend_from_slice(&[0, 0, 0, 0]); // netmask
    packet.extend_from_slice(&[0, 0, 0, 0]); // next hop
    packet.extend_from_slice(&16u32.to_be_bytes()); // metric: infinity
    packet
}

/// Parses a RIPv2 response into the routes it advertises.
///
/// Strict about the header and tolerant about individual entries: a router that includes an
/// address family this parser does not know should lose that entry, not the whole message.
/// Anything that is not a version 2 response is refused outright, because a RIPv1 message
/// carries no netmask and a prefix cannot be derived from it without guessing.
pub fn parse_response(datagram: &[u8]) -> Option<Vec<RipRoute>> {
    if datagram.len() < 4 {
        return None;
    }
    if datagram[0] != RIP_RESPONSE {
        return None;
    }
    // Version 2 only. A version 1 entry has no netmask field, and inventing one from the
    // address class would be assuming a prefix nobody advertised.
    if datagram[1] != 2 {
        return None;
    }

    let mut routes = Vec::new();
    let mut offset = 4usize;
    while offset + 20 <= datagram.len() {
        let entry = &datagram[offset..offset + 20];
        offset += 20;

        let family = u16::from_be_bytes([entry[0], entry[1]]);
        if family != AFI_INET {
            // Authentication entries use family 0xffff, and other families are simply not
            // IPv4 routes. Skipped, not fatal.
            continue;
        }

        let address = Ipv4Addr::new(entry[4], entry[5], entry[6], entry[7]);
        let netmask = Ipv4Addr::new(entry[8], entry[9], entry[10], entry[11]);
        let next_hop = Ipv4Addr::new(entry[12], entry[13], entry[14], entry[15]);
        let metric = u32::from_be_bytes([entry[16], entry[17], entry[18], entry[19]]);

        let Some(prefix_length) = contiguous_prefix_length(netmask) else {
            // A non-contiguous mask is not a prefix. Refused rather than rounded.
            continue;
        };
        let Ok(network) = Ipv4Net::new(address, prefix_length) else {
            continue;
        };

        routes.push(RipRoute {
            prefix: IpNet::V4(network.trunc()),
            next_hop: (!next_hop.is_unspecified()).then_some(IpAddr::V4(next_hop)),
            metric,
            tag: u16::from_be_bytes([entry[2], entry[3]]),
            raw_entry: entry.to_vec(),
        });
    }

    Some(routes)
}

/// Converts a netmask to a prefix length, rejecting anything not contiguous.
fn contiguous_prefix_length(netmask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from_be_bytes(netmask.octets());
    let leading = bits.leading_ones();
    // Everything after the leading ones must be zero, or this is not a prefix at all.
    if leading == 32 {
        return Some(32);
    }
    if bits << leading == 0 {
        Some(leading as u8)
    } else {
        None
    }
}

/// Asks one router for its routing table.
///
/// `None` means it did not answer, which says nothing about whether it routes. A router
/// that answers has disclosed its table directly, and every prefix carries the entry bytes
/// that established it.
pub async fn request_table(
    target: Ipv4Addr,
    binding: &SocketBinding,
    timeout: Duration,
) -> Option<Vec<RipRoute>> {
    let destination = SocketAddr::V4(SocketAddrV4::new(target, RIP_PORT));
    let socket = binding.udp_socket(&destination).await.ok()?;
    socket.send_to(&table_request(), destination).await.ok()?;

    let mut buffer = [0u8; 4096];
    let (length, from) = tokio::time::timeout(timeout, socket.recv_from(&mut buffer))
        .await
        .ok()?
        .ok()?;

    // Only an answer from the router that was asked. A response from elsewhere would
    // otherwise be attributed to it.
    if from.ip() != IpAddr::V4(target) {
        return None;
    }
    parse_response(&buffer[..length])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a RIPv2 entry.
    fn entry(
        afi: u16,
        tag: u16,
        address: [u8; 4],
        mask: [u8; 4],
        hop: [u8; 4],
        metric: u32,
    ) -> Vec<u8> {
        let mut out = afi.to_be_bytes().to_vec();
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&address);
        out.extend_from_slice(&mask);
        out.extend_from_slice(&hop);
        out.extend_from_slice(&metric.to_be_bytes());
        out
    }

    fn response(entries: Vec<Vec<u8>>) -> Vec<u8> {
        let mut packet = vec![RIP_RESPONSE, 2, 0, 0];
        for e in entries {
            packet.extend_from_slice(&e);
        }
        packet
    }

    #[test]
    fn a_request_asks_for_the_whole_table_and_carries_no_routes() {
        // RFC 2453 3.9.1. Read-only by construction: there is nothing in it to install.
        let request = table_request();
        assert_eq!(request.len(), 24);
        assert_eq!(request[0], RIP_REQUEST);
        assert_eq!(request[1], 2, "version 2");
        assert_eq!(
            u16::from_be_bytes([request[4], request[5]]),
            AFI_UNSPECIFIED
        );
        assert_eq!(
            u32::from_be_bytes([request[20], request[21], request[22], request[23]]),
            16
        );
    }

    #[test]
    fn a_response_yields_prefixes_with_the_bytes_that_established_them() {
        let packet = response(vec![
            entry(
                AFI_INET,
                0,
                [192, 168, 51, 0],
                [255, 255, 255, 0],
                [0, 0, 0, 0],
                1,
            ),
            entry(
                AFI_INET,
                7,
                [10, 9, 0, 0],
                [255, 255, 0, 0],
                [192, 168, 70, 2],
                2,
            ),
        ]);

        let routes = parse_response(&packet).expect("a response");
        assert_eq!(routes.len(), 2);

        assert_eq!(routes[0].prefix.to_string(), "192.168.51.0/24");
        assert!(routes[0].next_hop.is_none(), "zero means via the sender");
        assert!(routes[0].is_reachable());

        assert_eq!(routes[1].prefix.to_string(), "10.9.0.0/16");
        assert_eq!(
            routes[1].next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 70, 2)))
        );
        assert_eq!(routes[1].tag, 7);

        // The exact entry is recoverable, so a network can be traced to the protocol field
        // that produced it rather than taken on trust.
        assert_eq!(routes[0].raw_entry.len(), 20);
        assert!(routes[0].evidence().contains("metric 1"));
        assert!(
            routes[0].evidence().contains("c0a83300"),
            "{}",
            routes[0].evidence()
        );
    }

    #[test]
    fn an_unreachable_metric_is_a_withdrawal_not_a_network() {
        // Metric 16 is RIP's way of saying a route is gone. Recording it as a discovered
        // network would add a network the router just told us it cannot reach.
        let packet = response(vec![entry(
            AFI_INET,
            0,
            [172, 16, 0, 0],
            [255, 255, 0, 0],
            [0, 0, 0, 0],
            16,
        )]);
        let routes = parse_response(&packet).expect("a response");
        assert_eq!(routes.len(), 1);
        assert!(!routes[0].is_reachable());
    }

    #[test]
    fn a_version_one_message_is_refused() {
        // RIPv1 carries no netmask. Deriving one from the address class would be assuming a
        // prefix the router never advertised.
        let mut packet = response(vec![entry(
            AFI_INET,
            0,
            [192, 168, 51, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            1,
        )]);
        packet[1] = 1;
        assert!(parse_response(&packet).is_none());
    }

    #[test]
    fn a_non_contiguous_mask_is_not_a_prefix() {
        // 255.0.255.0 describes no CIDR block. Rounding it to something nearby would
        // invent a network.
        let packet = response(vec![entry(
            AFI_INET,
            0,
            [10, 0, 0, 0],
            [255, 0, 255, 0],
            [0, 0, 0, 0],
            1,
        )]);
        assert!(parse_response(&packet).expect("a response").is_empty());
    }

    #[test]
    fn an_authentication_entry_loses_itself_and_not_the_message() {
        // RIPv2 authentication occupies the first entry with family 0xffff. A router using
        // it still advertises usable routes after it.
        let packet = response(vec![
            entry(0xffff, 2, [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], 0),
            entry(
                AFI_INET,
                0,
                [192, 168, 51, 0],
                [255, 255, 255, 0],
                [0, 0, 0, 0],
                1,
            ),
        ]);
        let routes = parse_response(&packet).expect("a response");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix.to_string(), "192.168.51.0/24");
    }

    #[test]
    fn a_request_is_not_mistaken_for_a_response() {
        assert!(parse_response(&table_request()).is_none());
    }

    #[test]
    fn a_truncated_or_malformed_message_does_not_panic() {
        let full = response(vec![entry(
            AFI_INET,
            0,
            [192, 168, 51, 0],
            [255, 255, 255, 0],
            [0, 0, 0, 0],
            1,
        )]);
        for length in 0..full.len() {
            let _ = parse_response(&full[..length]);
        }
        assert!(parse_response(&[]).is_none());
        assert!(parse_response(&[2]).is_none());
        // A trailing partial entry is ignored rather than read past.
        let mut ragged = full.clone();
        ragged.extend_from_slice(&[0, 2, 0]);
        assert_eq!(parse_response(&ragged).expect("a response").len(), 1);
    }

    #[test]
    fn prefix_lengths_are_derived_only_from_contiguous_masks() {
        assert_eq!(
            contiguous_prefix_length(Ipv4Addr::new(255, 255, 255, 0)),
            Some(24)
        );
        assert_eq!(
            contiguous_prefix_length(Ipv4Addr::new(255, 255, 255, 255)),
            Some(32)
        );
        assert_eq!(contiguous_prefix_length(Ipv4Addr::new(0, 0, 0, 0)), Some(0));
        assert_eq!(
            contiguous_prefix_length(Ipv4Addr::new(255, 0, 255, 0)),
            None
        );
        assert_eq!(
            contiguous_prefix_length(Ipv4Addr::new(255, 255, 0, 1)),
            None
        );
    }
}
