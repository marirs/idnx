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

/// Entries one RIPv2 datagram may carry.
///
/// RFC 2453: a response is a four-byte header and at most twenty-five twenty-byte entries,
/// which is what keeps it inside a 512-byte UDP payload. A longer message is not a RIP
/// response, and parsing one would take prefixes out of whatever the extra bytes are.
pub const MAX_ENTRIES_PER_DATAGRAM: usize = 25;
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
/// Strict about the message and selective about entries. A message that is not a
/// well-formed version 2 response is refused whole: a RIPv1 message carries no netmask and
/// a prefix cannot be derived from it without guessing, a length that is not a header plus
/// whole entries means the datagram was truncated or is not RIP at all, and a non-zero
/// reserved field means it is not the message this parser thinks it is. Entries that are
/// individually unusable -- an unknown address family, a mask that is not a prefix -- are
/// dropped without discarding the ones that are fine.
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
    // RFC 2453: the two bytes after the version are reserved and must be zero. A non-zero
    // value means this is not the message being parsed, and reading entries out of it
    // would produce prefixes from arbitrary bytes.
    if datagram[2] != 0 || datagram[3] != 0 {
        return None;
    }
    // A response is a header and whole entries. Silently keeping the entries before a
    // ragged tail would accept a truncated datagram as a complete table.
    if !(datagram.len() - 4).is_multiple_of(20) {
        return None;
    }
    // And no more entries than the protocol permits. Documenting the limit while accepting
    // longer messages meant prefixes could be read out of whatever followed a real table.
    if (datagram.len() - 4) / 20 > MAX_ENTRIES_PER_DATAGRAM {
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
        // RFC 2453 limits a metric to 1..=16. Zero is not a valid distance, and treating it
        // as reachable accepted a prefix from a field the protocol says cannot hold that
        // value; anything above 16 is out of range entirely.
        if !(1..=16).contains(&metric) {
            continue;
        }

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

/// A router's answer to a table request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RipTable {
    /// Every distinct route advertised, across all response datagrams.
    pub routes: Vec<RipRoute>,
    /// How many valid response datagrams arrived. A table larger than one datagram is
    /// split across several, and reporting the count keeps a partial read distinguishable
    /// from a complete one.
    pub datagrams: usize,
}

impl RipTable {
    /// Whether the router advertised any usable route.
    ///
    /// A router may answer with an empty table, or with nothing but withdrawals. It has
    /// then confirmed that it speaks RIP and disclosed no routes, and saying it advertised
    /// routes would describe something that did not happen.
    pub fn advertised_routes(&self) -> bool {
        self.routes.iter().any(RipRoute::is_reachable)
    }
}

/// Asks one router for its routing table.
///
/// `None` means it did not answer, which says nothing about whether it routes.
///
/// A RIP table does not fit in one datagram: an entry is twenty bytes and a response holds
/// at most twenty-five of them, so a router with more routes than that sends several.
/// Reading one and stopping took the first twenty-five routes and called it the table.
/// Datagrams are collected until the router goes quiet, deduplicated, and counted.
pub async fn request_table(
    target: Ipv4Addr,
    binding: &SocketBinding,
    timeout: Duration,
) -> Option<RipTable> {
    /// How long to keep listening after the last datagram before deciding the table ended.
    const QUIET_PERIOD: Duration = Duration::from_millis(400);
    /// A ceiling on how long one router may be listened to, so a chatty or hostile
    /// responder cannot hold the run open.
    ///
    /// A fixed deadline, not a function of the caller's per-datagram timeout: combining
    /// them with `max` produced a limit that grew with the timeout and imposed no ceiling
    /// at all.
    const OVERALL_LIMIT: Duration = Duration::from_secs(5);

    let destination = SocketAddr::V4(SocketAddrV4::new(target, RIP_PORT));
    let socket = binding.udp_socket(&destination).await.ok()?;
    socket.send_to(&table_request(), destination).await.ok()?;

    let overall_deadline = tokio::time::Instant::now() + OVERALL_LIMIT;
    let mut buffer = [0u8; 4096];
    let mut routes: Vec<RipRoute> = Vec::new();
    let mut datagrams = 0usize;

    loop {
        // The first datagram gets the caller's timeout; later ones only the quiet period,
        // so a complete table is not paid for at full price per packet.
        let window = if datagrams == 0 {
            timeout
        } else {
            QUIET_PERIOD
        };
        let remaining = match overall_deadline.checked_duration_since(tokio::time::Instant::now()) {
            Some(remaining) => remaining.min(window),
            None => break,
        };

        let Ok(Ok((length, from))) =
            tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await
        else {
            break;
        };

        // Only answers from the router that was asked. A response from elsewhere would
        // otherwise be attributed to it.
        if from.ip() != IpAddr::V4(target) {
            continue;
        }
        let Some(parsed) = parse_response(&buffer[..length]) else {
            continue;
        };

        datagrams += 1;
        for route in parsed {
            // Split tables repeat entries across datagrams, and a router may simply
            // re-advertise. Identity is the whole route: two equal-cost paths to one
            // prefix through different next hops are two routes, and so are the same
            // prefix carrying different route tags -- collapsing on prefix and metric
            // alone discarded them.
            if !routes.iter().any(|existing| {
                existing.prefix == route.prefix
                    && existing.next_hop == route.next_hop
                    && existing.metric == route.metric
                    && existing.tag == route.tag
            }) {
                routes.push(route);
            }
        }
    }

    (datagrams > 0).then_some(RipTable { routes, datagrams })
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
    }

    #[test]
    fn a_metric_outside_the_protocols_range_is_refused() {
        // RFC 2453 allows 1..=16. Zero is not a distance, and accepting it produced a
        // reachable prefix from a field that cannot legally hold that value.
        for metric in [0u32, 17, 255, u32::MAX] {
            let packet = response(vec![entry(
                AFI_INET,
                0,
                [192, 168, 51, 0],
                [255, 255, 255, 0],
                [0, 0, 0, 0],
                metric,
            )]);
            assert!(
                parse_response(&packet).expect("a response").is_empty(),
                "metric {metric} was accepted"
            );
        }

        // The boundaries themselves are valid: 1 is reachable, 16 is a withdrawal.
        for metric in [1u32, 16] {
            let packet = response(vec![entry(
                AFI_INET,
                0,
                [192, 168, 51, 0],
                [255, 255, 255, 0],
                [0, 0, 0, 0],
                metric,
            )]);
            assert_eq!(parse_response(&packet).expect("a response").len(), 1);
        }
    }

    #[test]
    fn a_datagram_that_is_not_a_header_and_whole_entries_is_refused() {
        // Keeping the entries before a ragged tail accepted a truncated datagram as a
        // complete table.
        let mut ragged = response(vec![entry(
            AFI_INET,
            0,
            [192, 168, 51, 0],
            [255, 255, 255, 0],
            [0, 0, 0, 0],
            1,
        )]);
        ragged.extend_from_slice(&[0, 2, 0]);
        assert!(parse_response(&ragged).is_none());

        // And a header with no entries at all is still well formed.
        assert_eq!(
            parse_response(&response(vec![])).expect("a response").len(),
            0
        );
    }

    #[test]
    fn a_nonzero_reserved_field_is_refused() {
        // It means this is not the message being parsed, and reading entries out of it
        // would produce prefixes from arbitrary bytes.
        let mut packet = response(vec![entry(
            AFI_INET,
            0,
            [192, 168, 51, 0],
            [255, 255, 255, 0],
            [0, 0, 0, 0],
            1,
        )]);
        packet[2] = 0x01;
        assert!(parse_response(&packet).is_none());

        packet[2] = 0;
        packet[3] = 0x01;
        assert!(parse_response(&packet).is_none());
    }

    #[test]
    fn a_datagram_with_more_entries_than_the_protocol_allows_is_refused() {
        // RFC 2453 caps a response at twenty-five entries. Accepting more meant prefixes
        // could be read out of whatever followed a genuine table.
        let usable = vec![
            entry(
                AFI_INET,
                0,
                [192, 168, 51, 0],
                [255, 255, 255, 0],
                [0, 0, 0, 0],
                1
            );
            MAX_ENTRIES_PER_DATAGRAM
        ];
        assert_eq!(
            parse_response(&response(usable.clone()))
                .expect("a response")
                .len(),
            MAX_ENTRIES_PER_DATAGRAM
        );

        let mut oversized = usable;
        oversized.push(entry(
            AFI_INET,
            0,
            [10, 0, 0, 0],
            [255, 0, 0, 0],
            [0, 0, 0, 0],
            1,
        ));
        assert!(parse_response(&response(oversized)).is_none());
    }

    #[test]
    fn equal_cost_routes_are_distinct_when_their_next_hop_or_tag_differs() {
        // Two paths to one prefix through different routers are two routes, and the same
        // prefix under different tags describes different redistributions. Collapsing on
        // prefix and metric discarded both distinctions.
        let packet = response(vec![
            entry(
                AFI_INET,
                0,
                [10, 9, 0, 0],
                [255, 255, 0, 0],
                [192, 168, 70, 2],
                2,
            ),
            entry(
                AFI_INET,
                0,
                [10, 9, 0, 0],
                [255, 255, 0, 0],
                [192, 168, 70, 3],
                2,
            ),
            entry(
                AFI_INET,
                5,
                [10, 9, 0, 0],
                [255, 255, 0, 0],
                [192, 168, 70, 2],
                2,
            ),
        ]);
        let routes = parse_response(&packet).expect("a response");
        assert_eq!(routes.len(), 3);

        // Every one is a distinct identity under the rule the collector uses.
        let mut identities: Vec<(String, Option<IpAddr>, u32, u16)> = routes
            .iter()
            .map(|r| (r.prefix.to_string(), r.next_hop, r.metric, r.tag))
            .collect();
        identities.sort_by_key(|i| format!("{i:?}"));
        identities.dedup();
        assert_eq!(identities.len(), 3);
    }

    #[test]
    fn an_answer_carrying_no_usable_route_is_not_an_advertisement() {
        // A router that answers with an empty table, or with nothing but withdrawals, has
        // confirmed it speaks RIP and disclosed no routes.
        let empty = RipTable {
            routes: Vec::new(),
            datagrams: 1,
        };
        assert!(!empty.advertised_routes());

        let withdrawal = parse_response(&response(vec![entry(
            AFI_INET,
            0,
            [172, 16, 0, 0],
            [255, 255, 0, 0],
            [0, 0, 0, 0],
            16,
        )]))
        .expect("a response");
        assert!(
            !RipTable {
                routes: withdrawal,
                datagrams: 1
            }
            .advertised_routes()
        );

        let advertised = parse_response(&response(vec![entry(
            AFI_INET,
            0,
            [192, 168, 51, 0],
            [255, 255, 255, 0],
            [0, 0, 0, 0],
            1,
        )]))
        .expect("a response");
        assert!(
            RipTable {
                routes: advertised,
                datagrams: 1
            }
            .advertised_routes()
        );
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
