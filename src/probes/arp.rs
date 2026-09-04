//! Active ARP liveness confirmation (RFC 826).
//!
//! What this establishes and only this: at the moment we asked, a station on this link
//! claimed the address we asked about, and named its hardware address. That is a fact about
//! now, which is what separates it from the neighbour cache — a cache entry records that a
//! MAC was learned at some point, keeps no reply to check, and stays put long after the
//! host is gone.
//!
//! Silence means "not confirmed", never "offline". A host may be quiet because it is
//! filtering, because the request never reached it, or because we could not send one.
//! Those four states are reported separately by [`AttemptOutcome`] rather than collapsed
//! into an absence.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use ipnet::Ipv4Net;

use crate::net::linklayer::{LinkChannel, interface_mac};
use crate::probes::attempt::AttemptOutcome;

/// Ethernet type for ARP, and for the VLAN tag that may precede it.
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: u16 = 0x8100;

/// ARP over Ethernet carrying IPv4: the only combination this probe speaks.
const HARDWARE_ETHERNET: u16 = 1;
const PROTOCOL_IPV4: u16 = 0x0800;
const OPERATION_REQUEST: u16 = 1;
const OPERATION_REPLY: u16 = 2;

/// Ethernet header plus a full ARP payload.
const ARP_FRAME_LEN: usize = 14 + 28;

/// What was asked, kept so the reply can be checked against it.
///
/// Correlation is the whole point. Without the original question, any ARP reply on a busy
/// link — and replies for other addresses are constant — would confirm whatever host we
/// happened to be probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpQuery {
    /// This interface's hardware address, read from the kernel. A request carrying an
    /// address this interface does not own is answered somewhere else.
    pub sender_mac: [u8; 6],
    /// This interface's IPv4 address, which the reply must be addressed back to.
    pub sender_ip: Ipv4Addr,
    /// The address whose owner we are asking for.
    pub target_ip: Ipv4Addr,
}

impl ArpQuery {
    /// Builds the broadcast request frame.
    pub fn request_frame(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(ARP_FRAME_LEN);
        frame.extend_from_slice(&[0xff; 6]); // ARP requests are broadcast by definition.
        frame.extend_from_slice(&self.sender_mac);
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());

        frame.extend_from_slice(&HARDWARE_ETHERNET.to_be_bytes());
        frame.extend_from_slice(&PROTOCOL_IPV4.to_be_bytes());
        frame.push(6); // hardware address length
        frame.push(4); // protocol address length
        frame.extend_from_slice(&OPERATION_REQUEST.to_be_bytes());
        frame.extend_from_slice(&self.sender_mac);
        frame.extend_from_slice(&self.sender_ip.octets());
        // Target hardware address is unknown; that is what is being asked.
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&self.target_ip.octets());
        frame
    }

    /// One line describing what went out, for the outcome report.
    pub fn describe(&self) -> String {
        format!("ARP who-has {} tell {}", self.target_ip, self.sender_ip)
    }
}

/// A reply that survived validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpReply {
    /// The address claimed, which is always the address that was asked about: a reply
    /// naming any other address is rejected rather than recorded.
    pub address: Ipv4Addr,
    pub mac: [u8; 6],
    /// VLAN tag the reply carried, when the link is trunked. Recorded, never assumed.
    pub vlan: Option<u16>,
    /// The frame as it arrived, so every derived fact keeps its supporting bytes.
    pub raw: Vec<u8>,
}

impl ArpReply {
    pub fn mac_text(&self) -> String {
        self.mac
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// The outcome of one ARP attempt.
pub type ArpOutcome = AttemptOutcome<ArpReply>;

/// Whether a frame is even a candidate answer: an ARP reply addressed to this station.
///
/// Separated from validation so the two are counted apart. Every link carries traffic that
/// was never an answer to anything we asked, and counting all of it as "failed validation"
/// would report a thousand rejections on an idle network. A frame that reaches this bar and
/// then fails [`parse_arp_reply`] is the interesting case: something answered us about the
/// wrong address.
///
/// Takes the hardware address rather than a query, because every condition it tests is the
/// same for all of them. Testing it per query counted one frame once for each address in
/// the sweep, so a single stray reply on a /24 was reported as 254 failed validations.
pub fn is_candidate_reply(frame: &[u8], sender_mac: &[u8; 6]) -> bool {
    if frame.len() < 22 || frame[0..6] != *sender_mac {
        return false;
    }
    let mut offset = 12;
    let mut ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    if ethertype == ETHERTYPE_VLAN {
        if frame.len() < offset + 12 {
            return false;
        }
        offset += 4;
        ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    }
    if ethertype != ETHERTYPE_ARP {
        return false;
    }
    frame
        .get(offset + 8..offset + 10)
        .is_some_and(|op| u16::from_be_bytes([op[0], op[1]]) == OPERATION_REPLY)
}

/// Validates a frame as the answer to `query`.
///
/// Every field is checked against what was asked: the sender must be the address we asked
/// about, the reply must be addressed to our own address and hardware address, and the
/// hardware address it discloses must be a real unicast station address. A frame failing
/// any of these is not a weaker answer, it is an answer to a different question.
pub fn parse_arp_reply(frame: &[u8], query: &ArpQuery) -> Option<ArpReply> {
    if frame.len() < 14 {
        return None;
    }

    // The reply is addressed to us at the link layer as well; a broadcast ARP request from
    // another station must not be read as our answer.
    let destination = &frame[0..6];
    if destination != query.sender_mac {
        return None;
    }

    let mut offset = 12;
    let mut vlan = None;
    let mut ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    if ethertype == ETHERTYPE_VLAN {
        if frame.len() < offset + 8 {
            return None;
        }
        vlan = Some(u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]) & 0x0fff);
        offset += 4;
        ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    }
    if ethertype != ETHERTYPE_ARP {
        return None;
    }

    let arp = frame.get(offset + 2..)?;
    if arp.len() < 28 {
        return None;
    }
    if u16::from_be_bytes([arp[0], arp[1]]) != HARDWARE_ETHERNET {
        return None;
    }
    if u16::from_be_bytes([arp[2], arp[3]]) != PROTOCOL_IPV4 {
        return None;
    }
    if arp[4] != 6 || arp[5] != 4 {
        return None;
    }
    if u16::from_be_bytes([arp[6], arp[7]]) != OPERATION_REPLY {
        return None;
    }

    let sender_mac: [u8; 6] = arp[8..14].try_into().ok()?;
    let sender_ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    let target_mac: [u8; 6] = arp[18..24].try_into().ok()?;
    let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);

    if sender_ip != query.target_ip {
        return None;
    }
    if target_ip != query.sender_ip {
        return None;
    }
    if target_mac != query.sender_mac {
        return None;
    }
    // A group address cannot be a station's own hardware address; accepting one would
    // record a device identity that belongs to nothing.
    if sender_mac[0] & 0x01 != 0 || sender_mac == [0u8; 6] {
        return None;
    }

    Some(ArpReply {
        address: sender_ip,
        mac: sender_mac,
        vlan,
        raw: frame.to_vec(),
    })
}

/// Asks one on-link IPv4 address to identify itself, and waits for a validated reply.
///
/// `network` is the prefix the selected interface is attached to. ARP is link-scoped, so an
/// address outside it cannot be resolved here and is refused rather than broadcast: the
/// answer would come from whichever router happened to proxy, and would be recorded as the
/// address's own hardware identity.
pub async fn confirm_liveness(
    interface: &str,
    network: Ipv4Net,
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    budget: Duration,
) -> ArpOutcome {
    // Not applicable, not unavailable: ARP works here, this address is simply not
    // something it can answer for.
    if !network.contains(&target_ip) {
        return AttemptOutcome::not_applicable(format!(
            "{target_ip} is not on {network}; ARP is link-scoped and resolves nothing beyond it"
        ));
    }
    if target_ip == sender_ip {
        return AttemptOutcome::not_applicable(
            "the target is this interface's own address; a station does not ARP for itself"
                .to_string(),
        );
    }

    let interface = interface.to_string();
    // Blocking file descriptor work, kept off the async runtime.
    let joined = tokio::task::spawn_blocking(move || {
        let sender_mac = match interface_mac(&interface) {
            Some(mac) => mac,
            None => {
                return AttemptOutcome::not_sent(format!(
                    "{interface} has no hardware address to send from"
                ));
            }
        };
        let query = ArpQuery {
            sender_mac,
            sender_ip,
            target_ip,
        };

        let channel = match LinkChannel::open(&interface) {
            Ok(channel) => channel,
            // Open failures include the ordinary unprivileged case, which is the reason
            // this is Unavailable rather than NotSent: no request was formed or attempted.
            Err(reason) => return AttemptOutcome::unavailable(reason),
        };

        if let Err(reason) = channel.send(&query.request_frame()) {
            return AttemptOutcome::not_sent(reason);
        }

        let deadline = Instant::now() + budget;
        let mut candidates = 0usize;
        let read = channel.read_until(deadline, |frame| {
            if is_candidate_reply(frame, &query.sender_mac) {
                candidates += 1;
            }
            parse_arp_reply(frame, &query)
        });

        match read.found {
            Some(reply) => AttemptOutcome::Answered {
                sent: query.describe(),
                result: reply,
            },
            // Something replied to us about an address we did not ask about. Reported apart
            // from silence: it says the channel works and the answer did not correlate.
            None if candidates > 0 => AttemptOutcome::InvalidResponse {
                sent: query.describe(),
                rejected: candidates,
            },
            None => AttemptOutcome::NoResponse {
                sent: query.describe(),
            },
        }
    })
    .await;

    joined.unwrap_or_else(|error| {
        AttemptOutcome::not_sent(format!("the ARP probe task did not complete: {error}"))
    })
}

/// What one sweep asked and what answered.
///
/// The asked list is kept because it is the only thing that makes an absence meaningful: an
/// address that was never asked about and one that was asked and stayed quiet are different
/// facts, and neither of them says the host is offline.
#[derive(Debug, Clone, Default)]
pub struct ArpSweep {
    pub asked: Vec<Ipv4Addr>,
    pub replies: Vec<ArpReply>,
}

impl ArpSweep {
    /// Addresses that were asked and did not answer within the budget.
    pub fn unconfirmed(&self) -> Vec<Ipv4Addr> {
        self.asked
            .iter()
            .filter(|address| !self.replies.iter().any(|reply| reply.address == **address))
            .copied()
            .collect()
    }

    /// Addresses that more than one station answered for, with every hardware address that
    /// did.
    ///
    /// Kept rather than resolved. Two validated replies for one address is a real finding --
    /// a duplicate assignment, a failover pair mid-transition, or someone spoofing -- and
    /// picking whichever arrived first would report a device identity that is at best half
    /// the truth.
    pub fn contested(&self) -> Vec<(Ipv4Addr, Vec<[u8; 6]>)> {
        let mut grouped: Vec<(Ipv4Addr, Vec<[u8; 6]>)> = Vec::new();
        for reply in &self.replies {
            match grouped.iter_mut().find(|(addr, _)| *addr == reply.address) {
                Some((_, macs)) => macs.push(reply.mac),
                None => grouped.push((reply.address, vec![reply.mac])),
            }
        }
        grouped.retain(|(_, macs)| macs.len() > 1);
        grouped
    }
}

/// The outcome of one sweep.
pub type ArpSweepOutcome = AttemptOutcome<ArpSweep>;

/// Asks every named on-link address to identify itself, over one channel.
///
/// One channel rather than one per address: opening a BPF device per target would spend
/// the entire budget on setup, and the replies all arrive on the same link anyway. Requests
/// go out first and the read follows, so a fast neighbour is not missed while later
/// requests are still being written.
pub async fn sweep_liveness(
    interface: &str,
    network: Ipv4Net,
    sender_ip: Ipv4Addr,
    targets: Vec<Ipv4Addr>,
    budget: Duration,
) -> ArpSweepOutcome {
    let on_link: Vec<Ipv4Addr> = targets
        .into_iter()
        .filter(|address| network.contains(address) && *address != sender_ip)
        .collect();
    if on_link.is_empty() {
        return AttemptOutcome::not_applicable(format!(
            "no address to ask on {network}; ARP is link-scoped and resolves nothing beyond it"
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
        let channel = match LinkChannel::open(&interface) {
            Ok(channel) => channel,
            Err(reason) => return AttemptOutcome::unavailable(reason),
        };

        // Only queries whose request actually reached the wire may correlate a reply.
        //
        // Building every query and validating against all of them would accept an
        // unsolicited announcement for an address whose request was never sent -- and
        // record it as a confirmation obtained by asking.
        let mut sent_queries: Vec<ArpQuery> = Vec::with_capacity(on_link.len());
        let mut refused = None;
        for target_ip in &on_link {
            let query = ArpQuery {
                sender_mac,
                sender_ip,
                target_ip: *target_ip,
            };
            match channel.send(&query.request_frame()) {
                Ok(()) => sent_queries.push(query),
                // Keep the first reason and stop: a channel that has started refusing
                // writes will refuse the rest, and reporting 254 identical failures buries
                // the one fact that matters.
                Err(reason) => {
                    refused = Some(reason);
                    break;
                }
            }
        }
        if sent_queries.is_empty() {
            return AttemptOutcome::not_sent(
                refused.unwrap_or_else(|| "no request could be transmitted".to_string()),
            );
        }
        let asked: Vec<Ipv4Addr> = sent_queries.iter().map(|q| q.target_ip).collect();

        let sent = format!("ARP who-has {} address(es) on {network}", asked.len());
        let deadline = Instant::now() + budget;
        let mut replies: Vec<ArpReply> = Vec::new();
        let mut candidates = 0usize;

        // Never returns Some, so the read runs to the deadline and collects every answer.
        channel.read_until(deadline, |frame| -> Option<()> {
            // Counted once per frame, before any correlation: whether a frame is an ARP
            // reply addressed to this station does not depend on which address we asked
            // about, and testing it inside the query loop counted one stray reply once per
            // target in the sweep.
            if is_candidate_reply(frame, &sender_mac) {
                candidates += 1;
            }

            for query in &sent_queries {
                // Deduplicated by (address, hardware address), not by address alone.
                // Collapsing on the address discarded the second station answering for it,
                // which is exactly the conflict worth reporting.
                if let Some(reply) = parse_arp_reply(frame, query)
                    && !replies
                        .iter()
                        .any(|seen| seen.address == reply.address && seen.mac == reply.mac)
                {
                    replies.push(reply);
                }
            }
            None
        });

        if !replies.is_empty() {
            return AttemptOutcome::Answered {
                sent,
                result: ArpSweep { asked, replies },
            };
        }
        // Candidates were counted against every query, so a reply addressed to us about an
        // address nobody asked for is the only way to reach this without an answer.
        if candidates > 0 {
            return AttemptOutcome::InvalidResponse {
                sent,
                rejected: candidates,
            };
        }
        AttemptOutcome::NoResponse { sent }
    })
    .await
    .unwrap_or_else(|error| {
        AttemptOutcome::not_sent(format!("the ARP sweep task did not complete: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> ArpQuery {
        ArpQuery {
            sender_mac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
            sender_ip: Ipv4Addr::new(192, 168, 1, 10),
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
        }
    }

    fn reply_frame(query: &ArpQuery, sender_mac: [u8; 6]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&query.sender_mac);
        frame.extend_from_slice(&sender_mac);
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&HARDWARE_ETHERNET.to_be_bytes());
        frame.extend_from_slice(&PROTOCOL_IPV4.to_be_bytes());
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&OPERATION_REPLY.to_be_bytes());
        frame.extend_from_slice(&sender_mac);
        frame.extend_from_slice(&query.target_ip.octets());
        frame.extend_from_slice(&query.sender_mac);
        frame.extend_from_slice(&query.sender_ip.octets());
        frame
    }

    #[test]
    fn the_request_is_a_broadcast_naming_this_interface_and_the_target() {
        let frame = query().request_frame();
        assert_eq!(frame.len(), ARP_FRAME_LEN);
        assert_eq!(&frame[0..6], &[0xff; 6]);
        assert_eq!(&frame[6..12], &query().sender_mac);
        assert_eq!(&frame[12..14], &ETHERTYPE_ARP.to_be_bytes());
        assert_eq!(&frame[20..22], &OPERATION_REQUEST.to_be_bytes());
        assert_eq!(&frame[22..28], &query().sender_mac);
        assert_eq!(&frame[28..32], &query().sender_ip.octets());
        // The target hardware address is what the request is asking for and must go out
        // empty; filling it in would make this an unsolicited announcement instead.
        assert_eq!(&frame[32..38], &[0u8; 6]);
        assert_eq!(&frame[38..42], &query().target_ip.octets());
    }

    #[test]
    fn a_matching_reply_yields_the_hardware_address_and_its_bytes() {
        let query = query();
        let mac = [0x74, 0x12, 0x13, 0x14, 0x75, 0xdc];
        let frame = reply_frame(&query, mac);
        let reply = parse_arp_reply(&frame, &query).expect("a correlated reply");
        assert_eq!(reply.address, query.target_ip);
        assert_eq!(reply.mac, mac);
        assert_eq!(reply.mac_text(), "74:12:13:14:75:dc");
        assert!(reply.vlan.is_none());
        assert_eq!(reply.raw, frame, "the supporting bytes are retained");
    }

    #[test]
    fn a_reply_about_a_different_address_is_not_our_answer() {
        // The case this exists for: on any active link, ARP replies for other addresses
        // arrive constantly. Accepting one would confirm a host that never spoke.
        let query = query();
        let mut frame = reply_frame(&query, [0x74, 0x12, 0x13, 0x14, 0x75, 0xdc]);
        frame[28] = 192;
        frame[29] = 168;
        frame[30] = 1;
        frame[31] = 99; // sender protocol address: a different host
        assert!(parse_arp_reply(&frame, &query).is_none());
    }

    #[test]
    fn a_reply_addressed_to_another_station_is_rejected() {
        let query = query();
        let mut frame = reply_frame(&query, [0x74, 0x12, 0x13, 0x14, 0x75, 0xdc]);
        frame[0] = 0x06; // link-layer destination is not us
        assert!(parse_arp_reply(&frame, &query).is_none());

        let mut frame = reply_frame(&query, [0x74, 0x12, 0x13, 0x14, 0x75, 0xdc]);
        frame[38] = 192;
        frame[39] = 168;
        frame[40] = 1;
        frame[41] = 77; // target protocol address is not ours
        assert!(parse_arp_reply(&frame, &query).is_none());

        let mut frame = reply_frame(&query, [0x74, 0x12, 0x13, 0x14, 0x75, 0xdc]);
        frame[32] = 0x02;
        frame[33] = 0x99; // target hardware address is not ours
        assert!(parse_arp_reply(&frame, &query).is_none());
    }

    #[test]
    fn a_request_is_never_read_as_a_reply() {
        let query = query();
        let mut frame = reply_frame(&query, [0x74, 0x12, 0x13, 0x14, 0x75, 0xdc]);
        frame[20..22].copy_from_slice(&OPERATION_REQUEST.to_be_bytes());
        assert!(parse_arp_reply(&frame, &query).is_none());
    }

    #[test]
    fn a_group_or_empty_hardware_address_is_not_a_device_identity() {
        let query = query();
        // Multicast bit set in the sender hardware address: no station owns this.
        assert!(parse_arp_reply(&reply_frame(&query, [0x01, 0, 0, 0, 0, 1]), &query).is_none());
        assert!(parse_arp_reply(&reply_frame(&query, [0u8; 6]), &query).is_none());
    }

    #[test]
    fn a_tagged_reply_keeps_its_vlan_rather_than_being_dropped() {
        let query = query();
        let mac = [0x74, 0x12, 0x13, 0x14, 0x75, 0xdc];
        let plain = reply_frame(&query, mac);
        let mut tagged = Vec::new();
        tagged.extend_from_slice(&plain[0..12]);
        tagged.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        tagged.extend_from_slice(&0x0065u16.to_be_bytes()); // priority 0, VLAN 101
        tagged.extend_from_slice(&plain[12..]);

        let reply = parse_arp_reply(&tagged, &query).expect("a tagged reply is still an answer");
        assert_eq!(reply.vlan, Some(101));
        assert_eq!(reply.mac, mac);
    }

    #[test]
    fn truncated_frames_are_refused_rather_than_read_past() {
        let query = query();
        let frame = reply_frame(&query, [0x74, 0x12, 0x13, 0x14, 0x75, 0xdc]);
        for length in 0..frame.len() {
            assert!(
                parse_arp_reply(&frame[..length], &query).is_none(),
                "a {length}-byte frame must not parse as a complete reply"
            );
        }
    }

    /// Live check of the whole path: hardware address lookup, channel open, transmit and
    /// validated receive. Ignored by default because it needs root and a real neighbour;
    /// run it as `sudo ./target/debug/deps/idnx-<hash> --ignored --nocapture arp_probe_live`
    /// with IDNX_ARP_TARGET and IDNX_ARP_INTERFACE set.
    #[tokio::test]
    #[ignore = "needs root and a live on-link neighbour"]
    async fn arp_probe_live() {
        let interface = std::env::var("IDNX_ARP_INTERFACE").expect("IDNX_ARP_INTERFACE");
        let target: Ipv4Addr = std::env::var("IDNX_ARP_TARGET")
            .expect("IDNX_ARP_TARGET")
            .parse()
            .expect("an IPv4 address");
        let source = crate::net::interface::get_interface_by_name(&interface)
            .expect("the interface has an IPv4 address");
        let outcome = confirm_liveness(
            &interface,
            source.cidr,
            source.ip,
            target,
            Duration::from_millis(1500),
        )
        .await;
        println!("{}", outcome.describe("arp"));
        match outcome {
            AttemptOutcome::Answered { result, .. } => {
                assert_eq!(result.address, target);
                println!("{} is at {}", result.address, result.mac_text());
            }
            other => panic!("no validated reply: {other:?}"),
        }
    }

    #[test]
    fn a_candidate_frame_is_recognised_once_regardless_of_how_many_addresses_were_asked() {
        // The test is on the hardware address alone, which is what makes the count per
        // frame. Keying it to a query counted one stray reply once per target, so a single
        // frame on a /24 sweep was reported as 254 failed validations.
        let query = query();
        let stray = {
            let mut frame = reply_frame(&query, [0x74, 0x12, 0x13, 0x14, 0x75, 0xdc]);
            frame[28..32].copy_from_slice(&[192, 168, 1, 99]); // about an address nobody asked for
            frame
        };
        assert!(is_candidate_reply(&stray, &query.sender_mac));
        assert!(
            parse_arp_reply(&stray, &query).is_none(),
            "a candidate that fails correlation is what makes it worth counting"
        );

        // Addressed to another station, so not a candidate at all.
        let mut elsewhere = stray.clone();
        elsewhere[0] = 0x06;
        assert!(!is_candidate_reply(&elsewhere, &query.sender_mac));

        // Our own request, looped back: a request is never a candidate reply.
        assert!(!is_candidate_reply(
            &query.request_frame(),
            &query.sender_mac
        ));
    }

    #[test]
    fn a_sweep_separates_what_was_asked_from_what_answered() {
        // The distinction that makes an absence meaningful: an address nobody asked about
        // and one that was asked and stayed quiet are different facts.
        let sweep = ArpSweep {
            asked: vec![
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 2),
                Ipv4Addr::new(192, 168, 1, 3),
            ],
            replies: vec![ArpReply {
                address: Ipv4Addr::new(192, 168, 1, 2),
                mac: [0x74, 0x12, 0x13, 0x14, 0x75, 0xdc],
                vlan: None,
                raw: Vec::new(),
            }],
        };
        assert_eq!(
            sweep.unconfirmed(),
            vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 3)]
        );
    }

    #[tokio::test]
    async fn a_sweep_with_nothing_on_the_link_to_ask_sends_nothing() {
        let outcome = sweep_liveness(
            "en0",
            "192.168.1.0/24".parse().unwrap(),
            Ipv4Addr::new(192, 168, 1, 10),
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(192, 168, 1, 10)],
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(outcome, AttemptOutcome::NotApplicable { .. }));
        assert!(!outcome.transmitted());
    }

    #[tokio::test]
    async fn an_address_off_the_link_is_refused_instead_of_broadcast() {
        // ARP resolves nothing beyond the link. Broadcasting anyway would record whichever
        // router proxied as the address's own hardware identity.
        let outcome = confirm_liveness(
            "en0",
            "192.168.1.0/24".parse().unwrap(),
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 1),
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(outcome, AttemptOutcome::NotApplicable { .. }));
        assert!(!outcome.transmitted());
    }
}
