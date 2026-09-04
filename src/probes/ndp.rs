//! Active IPv6 neighbour liveness confirmation (RFC 4861 §7).
//!
//! The IPv6 counterpart to the ARP probe, and it establishes exactly as much: at the moment
//! we asked, a station on this link answered for the address we asked about and disclosed
//! its link-layer address. The neighbour cache cannot say that — it records what was
//! learned at some point and keeps nothing to check.
//!
//! Three checks are what make an advertisement trustworthy, and all three are enforced
//! here: the hop limit must be 255, which is how RFC 4861 §11.2 keeps off-link stations
//! from forging neighbour discovery (a router would have decremented it); the ICMPv6
//! checksum must verify over the real pseudo-header, so the source and destination
//! addresses are covered rather than assumed; and the target address in the advertisement
//! must be the address that was solicited.
//!
//! Silence means "not confirmed", never "offline".

use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use ipnet::Ipv6Net;

use crate::net::icmpv6::{IcmpV6Socket, REQUIRED_HOP_LIMIT};
use crate::net::linklayer::interface_mac;
use crate::probes::attempt::AttemptOutcome;

/// ICMPv6 types used by neighbour discovery.
const NEIGHBOR_SOLICITATION: u8 = 135;
const NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// Neighbour discovery options carrying a link-layer address.
const OPTION_SOURCE_LINK_LAYER: u8 = 1;
const OPTION_TARGET_LINK_LAYER: u8 = 2;

/// What was asked, kept so an advertisement can be checked against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpQuery {
    /// This interface's hardware address, sent as the source link-layer option so the
    /// neighbour can answer without soliciting us in turn.
    pub sender_mac: [u8; 6],
    /// The address whose owner we are asking for.
    pub target: Ipv6Addr,
}

impl NdpQuery {
    /// Builds the neighbour solicitation, checksum field left zero.
    ///
    /// The kernel fills the checksum for an `IPPROTO_ICMPV6` raw socket, and it is the only
    /// party that knows which source address the packet will finally carry.
    pub fn solicitation(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(32);
        message.push(NEIGHBOR_SOLICITATION);
        message.push(0); // code
        message.extend_from_slice(&[0, 0]); // checksum, computed by the kernel
        message.extend_from_slice(&[0, 0, 0, 0]); // reserved
        message.extend_from_slice(&self.target.octets());
        message.push(OPTION_SOURCE_LINK_LAYER);
        message.push(1); // option length in units of 8 bytes
        message.extend_from_slice(&self.sender_mac);
        message
    }

    pub fn describe(&self) -> String {
        format!(
            "ICMPv6 neighbour solicitation for {} to {}",
            self.target,
            solicited_node_multicast(self.target)
        )
    }
}

/// The solicited-node multicast address for a target (RFC 4291 §2.7.1).
///
/// Addressed here rather than to `ff02::1`: an all-nodes solicitation wakes every station
/// on the link to answer a question about one of them.
pub fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let octets = target.octets();
    let mut solicited = [0u8; 16];
    solicited[0] = 0xff;
    solicited[1] = 0x02;
    solicited[11] = 0x01;
    solicited[12] = 0xff;
    solicited[13..16].copy_from_slice(&octets[13..16]);
    Ipv6Addr::from(solicited)
}

/// An advertisement that survived validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpAdvertisement {
    /// The target address, which is always the address that was solicited.
    pub address: Ipv6Addr,
    /// The address the advertisement was sent from, which need not equal the target.
    pub from: Ipv6Addr,
    /// The link-layer address, when the advertisement carried the option. Absent is
    /// normal for a reply from the target's own address and is not an error.
    pub mac: Option<[u8; 6]>,
    /// The R flag: the sender says it is a router. A claim, recorded as such.
    pub router: bool,
    /// The bytes supporting every fact above.
    pub raw: Vec<u8>,
}

impl NdpAdvertisement {
    pub fn mac_text(&self) -> Option<String> {
        self.mac.map(|mac| {
            mac.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        })
    }
}

/// The outcome of one neighbour discovery attempt.
pub type NdpOutcome = AttemptOutcome<NdpAdvertisement>;

/// The internet checksum over an ICMPv6 message and its IPv6 pseudo-header (RFC 4443 §2.3).
///
/// Computed rather than trusted: the pseudo-header is what binds a message to the addresses
/// it was actually sent between, and without it a payload lifted from elsewhere would
/// verify.
pub fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        let mut index = 0;
        while index + 1 < bytes.len() {
            sum += u16::from_be_bytes([bytes[index], bytes[index + 1]]) as u32;
            index += 2;
        }
        if index < bytes.len() {
            sum += (bytes[index] as u32) << 8;
        }
    };

    add(&source.octets());
    add(&destination.octets());
    add(&(message.len() as u32).to_be_bytes());
    add(&[0, 0, 0, 58]); // three zero bytes then the next-header value for ICMPv6
    add(message);

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Whether a message is even a candidate answer to one of `solicited`.
///
/// A raw ICMPv6 socket receives everything the protocol carries: router advertisements,
/// echo replies, other stations' neighbour solicitations, redirects. None of those are
/// failed answers to this question, and counting them as such would report dozens of
/// "replies that failed validation" on a link where nothing answered at all.
///
/// The arrival interface is part of the test. Neighbour discovery describes one link, and a
/// message that reached a different interface describes a different one.
pub fn is_candidate_advertisement(
    message: &[u8],
    arrived_on: u32,
    selected_interface: u32,
    solicited: &[Ipv6Addr],
) -> bool {
    if arrived_on != selected_interface {
        return false;
    }
    if message.len() < 24 || message[0] != NEIGHBOR_ADVERTISEMENT || message[1] != 0 {
        return false;
    }
    let Ok(octets) = <[u8; 16]>::try_from(&message[8..24]) else {
        return false;
    };
    let target = Ipv6Addr::from(octets);
    solicited.contains(&target)
}

/// Validates an advertisement as the answer to `query`.
///
/// `hop_limit` and `destination` come from the receiving socket's ancillary data, not from
/// the payload: an attacker controls every byte of the message but not the header the
/// kernel reports.
pub fn parse_advertisement(
    message: &[u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    hop_limit: u8,
    query: &NdpQuery,
) -> Option<NdpAdvertisement> {
    if hop_limit != REQUIRED_HOP_LIMIT {
        return None;
    }
    if message.len() < 24 {
        return None;
    }
    if message[0] != NEIGHBOR_ADVERTISEMENT || message[1] != 0 {
        return None;
    }
    // A verifying checksum is zero over the message with its checksum field in place.
    if icmpv6_checksum(source, destination, message) != 0 {
        return None;
    }

    let target = Ipv6Addr::from(<[u8; 16]>::try_from(&message[8..24]).ok()?);
    if target != query.target {
        return None;
    }

    let router = message[4] & 0x80 != 0;
    // The S flag. An unsolicited advertisement is a valid announcement, but it is not an
    // answer to this question and must not confirm what we asked.
    if message[4] & 0x40 == 0 {
        return None;
    }

    let mut mac = None;
    let mut cursor = 24;
    while cursor + 2 <= message.len() {
        let kind = message[cursor];
        let units = message[cursor + 1] as usize;
        if units == 0 {
            // A zero-length option would loop forever; RFC 4861 §4.6 forbids it.
            return None;
        }
        let end = cursor + units * 8;
        if end > message.len() {
            return None;
        }
        if kind == OPTION_TARGET_LINK_LAYER && units == 1 {
            let address: [u8; 6] = message[cursor + 2..cursor + 8].try_into().ok()?;
            // A group address is not a station's own hardware address.
            if address[0] & 0x01 == 0 && address != [0u8; 6] {
                mac = Some(address);
            }
        }
        cursor = end;
    }

    Some(NdpAdvertisement {
        address: target,
        from: source,
        mac,
        router,
        raw: message.to_vec(),
    })
}

/// Asks one on-link IPv6 address to identify itself, and waits for a validated
/// advertisement.
///
/// `on_link` is the prefix this interface is attached to, or `None` when the target is
/// link-local and therefore on-link by definition. Neighbour discovery is link-scoped;
/// soliciting an address beyond the link records whatever a router answered as that
/// address's own identity.
pub async fn confirm_liveness(
    interface: &str,
    scope_index: u32,
    on_link: Option<Ipv6Net>,
    target: Ipv6Addr,
    budget: Duration,
) -> NdpOutcome {
    let link_local = (target.segments()[0] & 0xffc0) == 0xfe80;
    // Not applicable, not unavailable: the probe works here, this address is not one it
    // can answer for.
    if !link_local && !on_link.is_some_and(|net| net.contains(&target)) {
        return AttemptOutcome::not_applicable(format!(
            "{target} is not on this link; neighbour discovery resolves nothing beyond it"
        ));
    }

    let interface = interface.to_string();
    tokio::task::spawn_blocking(move || {
        let sender_mac = match interface_mac(&interface) {
            Some(mac) => mac,
            None => {
                return AttemptOutcome::not_sent(format!(
                    "{interface} has no hardware address to send from"
                ));
            }
        };
        let query = NdpQuery { sender_mac, target };
        let socket = match IcmpV6Socket::open(scope_index) {
            Ok(socket) => socket,
            Err(reason) => return AttemptOutcome::unavailable(reason),
        };

        let destination = solicited_node_multicast(target);
        if let Err(reason) = socket.send_to(&query.solicitation(), destination, scope_index) {
            return AttemptOutcome::not_sent(reason);
        }

        let deadline = Instant::now() + budget;
        let solicited = [target];
        let mut rejected = 0usize;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let received = match socket.recv(remaining) {
                Some(received) => received,
                None => continue,
            };
            // Unrelated ICMPv6 is ignored, not counted as a failed answer.
            if !is_candidate_advertisement(
                &received.message,
                received.interface_index,
                scope_index,
                &solicited,
            ) {
                continue;
            }
            if let Some(advertisement) = parse_advertisement(
                &received.message,
                received.source,
                received.destination,
                received.hop_limit,
                &query,
            ) {
                return AttemptOutcome::Answered {
                    sent: query.describe(),
                    result: advertisement,
                };
            }
            rejected += 1;
        }

        if rejected > 0 {
            AttemptOutcome::InvalidResponse {
                sent: query.describe(),
                rejected,
            }
        } else {
            AttemptOutcome::NoResponse {
                sent: query.describe(),
            }
        }
    })
    .await
    .unwrap_or_else(|error| {
        AttemptOutcome::not_sent(format!(
            "the neighbour discovery task did not complete: {error}"
        ))
    })
}

/// What one neighbour sweep asked and what answered.
#[derive(Debug, Clone, Default)]
pub struct NdpSweep {
    pub asked: Vec<Ipv6Addr>,
    pub advertisements: Vec<NdpAdvertisement>,
}

impl NdpSweep {
    /// Addresses that were solicited and did not answer within the budget.
    pub fn unconfirmed(&self) -> Vec<Ipv6Addr> {
        self.asked
            .iter()
            .filter(|address| {
                !self
                    .advertisements
                    .iter()
                    .any(|found| found.address == **address)
            })
            .copied()
            .collect()
    }

    /// Addresses that more than one station advertised for, with every link-layer address
    /// that did. Kept rather than resolved, for the same reason as the ARP case.
    pub fn contested(&self) -> Vec<(Ipv6Addr, Vec<Option<[u8; 6]>>)> {
        let mut grouped: Vec<(Ipv6Addr, Vec<Option<[u8; 6]>>)> = Vec::new();
        for found in &self.advertisements {
            match grouped.iter_mut().find(|(addr, _)| *addr == found.address) {
                Some((_, macs)) => macs.push(found.mac),
                None => grouped.push((found.address, vec![found.mac])),
            }
        }
        grouped.retain(|(_, macs)| macs.len() > 1);
        grouped
    }
}

/// The outcome of one neighbour sweep.
pub type NdpSweepOutcome = AttemptOutcome<NdpSweep>;

/// Solicits every named on-link address over one socket.
///
/// Addresses come from the caller -- there is no IPv6 host sweep, and inventing one would
/// mean enumerating a space that cannot be enumerated. In practice these are the addresses
/// something already reported, re-asked so the answer is current rather than remembered.
pub async fn sweep_liveness(
    interface: &str,
    scope_index: u32,
    on_link: Option<Ipv6Net>,
    targets: Vec<Ipv6Addr>,
    budget: Duration,
) -> NdpSweepOutcome {
    let reachable: Vec<Ipv6Addr> = targets
        .into_iter()
        .filter(|address| {
            let link_local = (address.segments()[0] & 0xffc0) == 0xfe80;
            link_local || on_link.is_some_and(|net| net.contains(address))
        })
        .collect();
    if reachable.is_empty() {
        // Not applicable rather than unavailable: neighbour discovery works here, there was
        // simply nothing on this link to ask about.
        return AttemptOutcome::not_applicable(
            "no on-link address to solicit; neighbour discovery resolves nothing beyond the link"
                .to_string(),
        );
    }

    let interface = interface.to_string();
    tokio::task::spawn_blocking(move || {
        let sender_mac = match interface_mac(&interface) {
            Some(mac) => mac,
            None => {
                return AttemptOutcome::not_sent(format!(
                    "{interface} has no hardware address to send from"
                ));
            }
        };
        let socket = match IcmpV6Socket::open(scope_index) {
            Ok(socket) => socket,
            Err(reason) => return AttemptOutcome::unavailable(reason),
        };

        // Only solicitations that actually left may correlate an advertisement. Validating
        // against every query built would let an unsolicited announcement confirm an
        // address this run never asked about.
        let mut sent_queries: Vec<NdpQuery> = Vec::with_capacity(reachable.len());
        let mut refused = None;
        for target in &reachable {
            let query = NdpQuery {
                sender_mac,
                target: *target,
            };
            let destination = solicited_node_multicast(query.target);
            match socket.send_to(&query.solicitation(), destination, scope_index) {
                Ok(()) => sent_queries.push(query),
                Err(reason) => {
                    refused = Some(reason);
                    break;
                }
            }
        }
        if sent_queries.is_empty() {
            return AttemptOutcome::not_sent(
                refused.unwrap_or_else(|| "no solicitation could be transmitted".to_string()),
            );
        }
        let asked: Vec<Ipv6Addr> = sent_queries.iter().map(|q| q.target).collect();

        let sent = format!(
            "ICMPv6 neighbour solicitation for {} address(es)",
            asked.len()
        );
        let deadline = Instant::now() + budget;
        let mut advertisements: Vec<NdpAdvertisement> = Vec::new();
        let mut rejected = 0usize;

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Some(received) = socket.recv(remaining) else {
                continue;
            };
            // Router advertisements, echo replies and other stations' solicitations all
            // arrive on this socket and none of them are failed answers to this question.
            if !is_candidate_advertisement(
                &received.message,
                received.interface_index,
                scope_index,
                &asked,
            ) {
                continue;
            }

            let matched = sent_queries.iter().find_map(|query| {
                parse_advertisement(
                    &received.message,
                    received.source,
                    received.destination,
                    received.hop_limit,
                    query,
                )
            });
            match matched {
                Some(found) => {
                    // Deduplicated by (address, link-layer address). Collapsing on the
                    // address alone discarded a second station advertising for it, which is
                    // the conflict worth reporting rather than resolving.
                    if !advertisements
                        .iter()
                        .any(|seen| seen.address == found.address && seen.mac == found.mac)
                    {
                        advertisements.push(found);
                    }
                }
                None => rejected += 1,
            }
        }

        if !advertisements.is_empty() {
            return AttemptOutcome::Answered {
                sent,
                result: NdpSweep {
                    asked,
                    advertisements,
                },
            };
        }
        if rejected > 0 {
            return AttemptOutcome::InvalidResponse { sent, rejected };
        }
        AttemptOutcome::NoResponse { sent }
    })
    .await
    .unwrap_or_else(|error| {
        AttemptOutcome::not_sent(format!(
            "the neighbour sweep task did not complete: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0212, 0x34ff, 0xfe56, 0x7890);
    const US: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0299, 0x88ff, 0xfe77, 0x6655);

    fn query() -> NdpQuery {
        NdpQuery {
            sender_mac: [0x02, 0x99, 0x88, 0x77, 0x66, 0x55],
            target: TARGET,
        }
    }

    /// Builds an advertisement and fills in a checksum that actually verifies.
    fn advertisement(target: Ipv6Addr, flags: u8, option: Option<[u8; 6]>) -> Vec<u8> {
        let mut message = vec![NEIGHBOR_ADVERTISEMENT, 0, 0, 0, flags, 0, 0, 0];
        message.extend_from_slice(&target.octets());
        if let Some(mac) = option {
            message.push(OPTION_TARGET_LINK_LAYER);
            message.push(1);
            message.extend_from_slice(&mac);
        }
        let checksum = icmpv6_checksum(TARGET, US, &message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());
        message
    }

    #[test]
    fn the_solicitation_is_addressed_to_the_targets_solicited_node_group() {
        // Not ff02::1: an all-nodes solicitation wakes every station on the link to answer
        // a question about one of them.
        assert_eq!(
            solicited_node_multicast(TARGET),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff56, 0x7890)
        );

        let message = query().solicitation();
        assert_eq!(message[0], NEIGHBOR_SOLICITATION);
        assert_eq!(message[1], 0);
        assert_eq!(&message[2..4], &[0, 0], "the kernel computes the checksum");
        assert_eq!(&message[8..24], &TARGET.octets());
        assert_eq!(message[24], OPTION_SOURCE_LINK_LAYER);
        assert_eq!(message[25], 1);
        assert_eq!(&message[26..32], &query().sender_mac);
    }

    #[test]
    fn a_solicited_advertisement_yields_the_link_layer_address() {
        let mac = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
        let message = advertisement(TARGET, 0x60, Some(mac)); // solicited + override
        let parsed =
            parse_advertisement(&message, TARGET, US, 255, &query()).expect("a valid answer");
        assert_eq!(parsed.address, TARGET);
        assert_eq!(parsed.mac, Some(mac));
        assert_eq!(parsed.mac_text().as_deref(), Some("00:1a:2b:3c:4d:5e"));
        assert!(!parsed.router);
        assert_eq!(parsed.raw, message);
    }

    #[test]
    fn a_hop_limit_below_255_is_refused() {
        // RFC 4861 §11.2: anything less has crossed a router, so it cannot describe this
        // link and may have been injected from anywhere.
        let message = advertisement(TARGET, 0x60, None);
        for hop_limit in [0u8, 1, 64, 128, 254] {
            assert!(parse_advertisement(&message, TARGET, US, hop_limit, &query()).is_none());
        }
        assert!(parse_advertisement(&message, TARGET, US, 255, &query()).is_some());
    }

    #[test]
    fn a_checksum_that_does_not_verify_is_refused() {
        let mut message = advertisement(TARGET, 0x60, None);
        message[5] ^= 0x01; // a byte covered by the checksum
        assert!(parse_advertisement(&message, TARGET, US, 255, &query()).is_none());

        // The pseudo-header is covered too: the same bytes arriving between other addresses
        // must not verify.
        let untouched = advertisement(TARGET, 0x60, None);
        let elsewhere = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1234);
        assert!(parse_advertisement(&untouched, elsewhere, US, 255, &query()).is_none());
    }

    #[test]
    fn an_advertisement_for_a_different_address_is_not_our_answer() {
        let other = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x9999);
        // Checksummed correctly for its own contents, so only the target check can reject
        // it: an advertisement about another address is a valid message, just not a reply
        // to this question.
        let message = advertisement(other, 0x60, None);
        assert!(parse_advertisement(&message, TARGET, US, 255, &query()).is_none());
    }

    #[test]
    fn an_unsolicited_announcement_does_not_answer_a_solicitation() {
        // Valid on its own terms, but it is not a reply, and treating it as one would let
        // any station confirm any address on its own schedule.
        let message = advertisement(TARGET, 0x00, None);
        assert!(parse_advertisement(&message, TARGET, US, 255, &query()).is_none());
    }

    #[test]
    fn the_router_flag_is_recorded_as_a_claim() {
        let message = advertisement(TARGET, 0xe0, None); // router + solicited + override
        let parsed = parse_advertisement(&message, TARGET, US, 255, &query()).expect("valid");
        assert!(parsed.router);
    }

    #[test]
    fn malformed_options_do_not_loop_or_read_past_the_message() {
        let mut message = advertisement(TARGET, 0x60, Some([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]));
        message[25] = 0; // a zero-length option would never advance
        let fixed = {
            message[2..4].copy_from_slice(&[0, 0]);
            icmpv6_checksum(TARGET, US, &message)
        };
        message[2..4].copy_from_slice(&fixed.to_be_bytes());
        assert!(parse_advertisement(&message, TARGET, US, 255, &query()).is_none());

        // An option claiming more bytes than the message holds.
        let mut overrun = advertisement(TARGET, 0x60, Some([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]));
        overrun[25] = 4;
        overrun[2..4].copy_from_slice(&[0, 0]);
        let fixed = icmpv6_checksum(TARGET, US, &overrun);
        overrun[2..4].copy_from_slice(&fixed.to_be_bytes());
        assert!(parse_advertisement(&overrun, TARGET, US, 255, &query()).is_none());
    }

    #[test]
    fn truncated_messages_are_refused_rather_than_read_past() {
        let message = advertisement(TARGET, 0x60, None);
        for length in 0..message.len() {
            assert!(parse_advertisement(&message[..length], TARGET, US, 255, &query()).is_none());
        }
    }

    #[test]
    fn a_sweep_separates_what_was_solicited_from_what_answered() {
        let sweep = NdpSweep {
            asked: vec![TARGET, US],
            advertisements: vec![NdpAdvertisement {
                address: US,
                from: US,
                mac: None,
                router: false,
                raw: Vec::new(),
            }],
        };
        assert_eq!(sweep.unconfirmed(), vec![TARGET]);
    }

    /// Live check of the whole privileged path: socket options, solicitation, and an
    /// advertisement that passes hop-limit, checksum, target and solicited-flag validation.
    /// Ignored by default because it needs root and a real neighbour.
    #[tokio::test]
    #[ignore = "needs root and a live on-link IPv6 neighbour"]
    // Resolving the interface index goes through libc, which is unix-only here; the probe
    // itself refuses on other platforms anyway.
    #[cfg(unix)]
    async fn ndp_probe_live() {
        let interface = std::env::var("IDNX_NDP_INTERFACE").expect("IDNX_NDP_INTERFACE");
        let target: Ipv6Addr = std::env::var("IDNX_NDP_TARGET")
            .expect("IDNX_NDP_TARGET")
            .parse()
            .expect("an IPv6 address");
        let scope = std::ffi::CString::new(interface.clone()).expect("an interface name");
        let index = unsafe { libc::if_nametoindex(scope.as_ptr()) };
        assert_ne!(index, 0, "{interface} has no kernel index");

        let outcome =
            confirm_liveness(&interface, index, None, target, Duration::from_millis(2000)).await;
        println!("{}", outcome.describe("ndp"));
        match outcome {
            AttemptOutcome::Answered { result, .. } => {
                assert_eq!(result.address, target);
                println!(
                    "{} is at {} (router={})",
                    result.address,
                    result.mac_text().unwrap_or_else(|| "unstated".to_string()),
                    result.router
                );
            }
            other => panic!("no validated advertisement: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_sweep_with_nothing_on_the_link_to_solicit_sends_nothing() {
        let outcome = sweep_liveness(
            "en0",
            1,
            Some("2001:db8::/64".parse().unwrap()),
            vec!["2001:db8:1::5".parse().unwrap()],
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(outcome, AttemptOutcome::NotApplicable { .. }));
        assert!(!outcome.transmitted());
    }

    #[tokio::test]
    async fn an_address_off_the_link_is_refused_instead_of_solicited() {
        let outcome = confirm_liveness(
            "en0",
            1,
            Some("2001:db8::/64".parse().unwrap()),
            "2001:db8:1::1".parse().unwrap(),
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(outcome, AttemptOutcome::NotApplicable { .. }));
        assert!(!outcome.transmitted());
    }
}
