//! Pure decoders for passively observed link-layer frames.
//!
//! Every function here is a total function from bytes to facts: no I/O, no sockets, no
//! privileges. That is what makes the decoding testable from byte fixtures, and it keeps
//! the capture plumbing (which cannot be unit-tested) as thin as possible.
//!
//! What passive observation can and cannot establish is a property of the capture point,
//! not of these decoders. A BPDU proves a bridge exists on the segment; it says nothing
//! about routing or about networks behind anything. A VLAN tag proves the VLAN ID and
//! nothing about its prefix. Broadcast traffic isolated behind another router's boundary
//! never reaches this capture point at all.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Ethernet and LLC constants.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_LLDP: u16 = 0x88CC;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ_802_1AD: u16 = 0x88A8;
const ETHERTYPE_QINQ_LEGACY: u16 = 0x9100;

/// Spanning tree is carried in an 802.3 LLC frame with DSAP/SSAP 0x42.
const LLC_SAP_STP: u8 = 0x42;
const STP_MULTICAST_MAC: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00];
const CDP_MULTICAST_MAC: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];

/// Largest 802.3 length value; anything above is an EtherType.
const MAX_802_3_LENGTH: u16 = 1500;

/// A fact recovered from one observed frame.
///
/// These are deliberately protocol-shaped rather than graph-shaped: converting them into
/// topology evidence, with the right confidence grade for each part, is the provider's job.
#[derive(Debug, Clone, PartialEq)]
pub enum FrameFact {
    /// A VLAN ID was observed on the wire. Proves the VLAN exists; proves nothing about
    /// any prefix associated with it.
    Vlan { id: u16 },

    /// A spanning-tree BPDU. Only a bridge emits these.
    Bridge {
        source_mac: String,
        bridge_id: String,
        root_id: String,
        port_id: u16,
    },

    /// An ARP sender's address binding.
    Arp { mac: String, address: Ipv4Addr },

    /// A DHCPv4 server's reply, carrying whatever options it supplied.
    Dhcp {
        server_mac: String,
        /// The address being offered or acknowledged.
        assigned: Option<Ipv4Addr>,
        /// Option 1. The only DHCP field that establishes a prefix.
        subnet_mask: Option<Ipv4Addr>,
        /// Option 3.
        routers: Vec<Ipv4Addr>,
        /// Option 121 classless static routes, as (destination, prefix length, next hop).
        classless_routes: Vec<(Ipv4Addr, u8, Ipv4Addr)>,
    },

    /// An IPv6 router advertisement. Sending one is router behaviour by definition.
    RouterAdvertisement {
        router_mac: String,
        router_address: Option<Ipv6Addr>,
        /// Prefix Information Options. These are the router's assertions, not observations.
        prefixes: Vec<(Ipv6Addr, u8)>,
    },

    /// An IPv6 neighbour's address binding, from a neighbour solicitation or advertisement.
    Neighbor {
        mac: String,
        address: Ipv6Addr,
        /// The router flag on a neighbour advertisement.
        is_router: bool,
    },

    /// An LLDP or CDP neighbour, decoded by the existing parsers.
    LinkLayerNeighbor(crate::probes::lldp::LldpNeighbor),

    /// A MikroTik MNDP beacon.
    Mndp(crate::probes::mndp::MndpNeighbor),
}

/// Decodes one Ethernet frame into whatever facts it carries.
///
/// Unknown or malformed frames yield an empty list rather than an error: a capture sees
/// arbitrary traffic, and a frame we cannot parse is simply not evidence.
pub fn decode_frame(frame: &[u8]) -> Vec<FrameFact> {
    let mut facts = Vec::new();
    if frame.len() < 14 {
        return facts;
    }

    let destination = &frame[0..6];
    let source_mac = format_mac(&frame[6..12]);

    // Unwrap any number of 802.1Q / QinQ tags, recording each VLAN ID seen.
    let mut offset = 12;
    let mut ethertype = read_u16(frame, offset);
    while matches!(
        ethertype,
        Some(ETHERTYPE_VLAN) | Some(ETHERTYPE_QINQ_802_1AD) | Some(ETHERTYPE_QINQ_LEGACY)
    ) {
        let Some(tci) = read_u16(frame, offset + 2) else {
            return facts;
        };
        // Low 12 bits are the VLAN ID; 0 and 4095 are reserved and not real VLANs.
        let vlan_id = tci & 0x0FFF;
        if vlan_id != 0 && vlan_id != 0x0FFF {
            facts.push(FrameFact::Vlan { id: vlan_id });
        }
        offset += 4;
        ethertype = read_u16(frame, offset);
    }

    let Some(ethertype) = ethertype else {
        return facts;
    };
    let payload_start = offset + 2;
    if payload_start > frame.len() {
        return facts;
    }
    let payload = &frame[payload_start..];

    // An 802.3 frame carries a length here, not a type, and an LLC header follows.
    if ethertype <= MAX_802_3_LENGTH {
        decode_llc(frame, destination, &source_mac, payload, &mut facts);
        return facts;
    }

    match ethertype {
        ETHERTYPE_ARP => {
            if let Some(fact) = decode_arp(payload) {
                facts.push(fact);
            }
        }
        ETHERTYPE_IPV4 => decode_ipv4(&source_mac, payload, &mut facts),
        ETHERTYPE_IPV6 => decode_ipv6(&source_mac, payload, &mut facts),
        ETHERTYPE_LLDP => {
            if let Some(n) = crate::probes::lldp::parse_lldp_frame(frame) {
                facts.push(FrameFact::LinkLayerNeighbor(n));
            }
        }
        _ => {}
    }

    facts
}

/// Decodes an 802.3 LLC payload: spanning tree, or SNAP-encapsulated CDP.
fn decode_llc(
    frame: &[u8],
    destination: &[u8],
    source_mac: &str,
    payload: &[u8],
    facts: &mut Vec<FrameFact>,
) {
    if payload.len() < 3 {
        return;
    }
    let dsap = payload[0];
    let ssap = payload[1];

    if dsap == LLC_SAP_STP && ssap == LLC_SAP_STP && destination == STP_MULTICAST_MAC {
        if let Some(fact) = decode_bpdu(source_mac, &payload[3..]) {
            facts.push(fact);
        }
        return;
    }

    // SNAP: AA AA 03, then a 3-byte OUI and a 2-byte protocol id. CDP is OUI 00:00:0C with
    // protocol 0x2000. The existing parser walks from the Ethernet header, so it is handed
    // the whole frame rather than duplicating the TLV walk here.
    if dsap == 0xAA
        && ssap == 0xAA
        && destination == CDP_MULTICAST_MAC
        && let Some(n) = crate::probes::lldp::parse_lldp_frame(frame)
    {
        facts.push(FrameFact::LinkLayerNeighbor(n));
    }
}

/// Decodes a Configuration BPDU (STP or RSTP).
///
/// Only bridges transmit these, so the frame itself is evidence of bridge behaviour. The
/// bridge and root identifiers inside are the bridge's own assertions.
pub fn decode_bpdu(source_mac: &str, body: &[u8]) -> Option<FrameFact> {
    // protocol id (2) | version (1) | bpdu type (1) | flags (1)
    // | root id (8) | root path cost (4) | bridge id (8) | port id (2)
    if body.len() < 35 {
        return None;
    }
    if read_u16(body, 0)? != 0x0000 {
        return None;
    }
    // 0x00 = Configuration BPDU (STP), 0x02 = RST BPDU (RSTP/MSTP).
    let bpdu_type = body[3];
    if bpdu_type != 0x00 && bpdu_type != 0x02 {
        return None;
    }

    let root_id = format_bridge_id(&body[5..13]);
    let bridge_id = format_bridge_id(&body[17..25]);
    let port_id = read_u16(body, 25)?;

    Some(FrameFact::Bridge {
        source_mac: source_mac.to_string(),
        bridge_id,
        root_id,
        port_id,
    })
}

/// Decodes an ARP packet's sender binding.
pub fn decode_arp(payload: &[u8]) -> Option<FrameFact> {
    // htype(2) ptype(2) hlen(1) plen(1) oper(2) sha(6) spa(4) tha(6) tpa(4)
    if payload.len() < 28 {
        return None;
    }
    if read_u16(payload, 2)? != ETHERTYPE_IPV4 || payload[4] != 6 || payload[5] != 4 {
        return None;
    }

    let mac = format_mac(&payload[8..14]);
    let address = Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]);
    if address.is_unspecified() {
        // An ARP probe uses 0.0.0.0 as the sender; it binds nothing.
        return None;
    }

    Some(FrameFact::Arp { mac, address })
}

fn decode_ipv4(source_mac: &str, payload: &[u8], facts: &mut Vec<FrameFact>) {
    if payload.len() < 20 {
        return;
    }
    let ihl = ((payload[0] & 0x0F) as usize) * 4;
    if ihl < 20 || payload.len() < ihl + 8 {
        return;
    }
    // UDP only; DHCP is the sole IPv4 payload passive discovery decodes.
    if payload[9] != 17 {
        return;
    }

    let udp = &payload[ihl..];
    let (Some(src_port), Some(dst_port)) = (read_u16(udp, 0), read_u16(udp, 2)) else {
        return;
    };
    if udp.len() < 8 {
        return;
    }
    let body = &udp[8..];

    if matches!((src_port, dst_port), (67, 68) | (68, 67) | (67, 67)) {
        if let Some(fact) = decode_dhcp(source_mac, body) {
            facts.push(fact);
        }
        return;
    }

    // MikroTik neighbour beacons are broadcast on UDP 5678.
    if (src_port == 5678 || dst_port == 5678)
        && let Some(n) = crate::probes::mndp::parse_mndp_packet(body)
    {
        facts.push(FrameFact::Mndp(n));
    }
}

/// Decodes a DHCPv4 message body (after the UDP header).
///
/// Only option 1 establishes a prefix. Options 3 and 121 identify routers and routes, which
/// are role and relationship evidence rather than prefix evidence.
pub fn decode_dhcp(server_mac: &str, body: &[u8]) -> Option<FrameFact> {
    // op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
    // ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128) = 236
    const OPTIONS_OFFSET: usize = 236;
    if body.len() < OPTIONS_OFFSET + 4 {
        return None;
    }
    // Magic cookie 99.130.83.99 marks the start of the option block.
    if body[OPTIONS_OFFSET..OPTIONS_OFFSET + 4] != [0x63, 0x82, 0x53, 0x63] {
        return None;
    }

    let yiaddr = Ipv4Addr::new(body[16], body[17], body[18], body[19]);
    let assigned = if yiaddr.is_unspecified() {
        None
    } else {
        Some(yiaddr)
    };

    let mut subnet_mask = None;
    let mut routers = Vec::new();
    let mut classless_routes = Vec::new();

    let mut i = OPTIONS_OFFSET + 4;
    while i < body.len() {
        let code = body[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        if i + 1 >= body.len() {
            break;
        }
        let len = body[i + 1] as usize;
        let value_start = i + 2;
        if value_start + len > body.len() {
            break;
        }
        let value = &body[value_start..value_start + len];

        match code {
            1 if len == 4 => {
                subnet_mask = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            3 => {
                for chunk in value.as_chunks::<4>().0 {
                    routers.push(Ipv4Addr::from(*chunk));
                }
            }
            121 => classless_routes.extend(decode_classless_routes(value)),
            _ => {}
        }

        i = value_start + len;
    }

    if subnet_mask.is_none() && routers.is_empty() && classless_routes.is_empty() {
        return None;
    }

    Some(FrameFact::Dhcp {
        server_mac: server_mac.to_string(),
        assigned,
        subnet_mask,
        routers,
        classless_routes,
    })
}

/// Decodes RFC 3442 classless static routes.
///
/// Each entry is a prefix length, then only the significant octets of the destination,
/// then a four-octet next hop.
pub fn decode_classless_routes(value: &[u8]) -> Vec<(Ipv4Addr, u8, Ipv4Addr)> {
    let mut routes = Vec::new();
    let mut i = 0;
    while i < value.len() {
        let prefix_len = value[i];
        if prefix_len > 32 {
            break;
        }
        let significant = prefix_len.div_ceil(8) as usize;
        let needed = 1 + significant + 4;
        if i + needed > value.len() {
            break;
        }
        let mut dest = [0u8; 4];
        dest[..significant].copy_from_slice(&value[i + 1..i + 1 + significant]);
        let hop_start = i + 1 + significant;
        let next_hop = Ipv4Addr::new(
            value[hop_start],
            value[hop_start + 1],
            value[hop_start + 2],
            value[hop_start + 3],
        );
        routes.push((Ipv4Addr::from(dest), prefix_len, next_hop));
        i += needed;
    }
    routes
}

fn decode_ipv6(source_mac: &str, payload: &[u8], facts: &mut Vec<FrameFact>) {
    if payload.len() < 40 {
        return;
    }
    // Only ICMPv6 carries the neighbour and router discovery messages.
    if payload[6] != 58 {
        return;
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&payload[8..24]);
    let source_address = Ipv6Addr::from(src);

    let icmp = &payload[40..];
    if icmp.len() < 4 {
        return;
    }

    match icmp[0] {
        // Router Advertisement.
        134 => {
            let prefixes = decode_ra_prefixes(icmp);
            facts.push(FrameFact::RouterAdvertisement {
                router_mac: source_mac.to_string(),
                router_address: Some(source_address),
                prefixes,
            });
        }
        // Neighbour Solicitation.
        //
        // The target address is who the sender is *looking for*, not an address the sender
        // holds. Binding it to the sender's MAC attributes one host's address to another,
        // which merged unrelated devices into one node. The sender's own address is the
        // IPv6 source, which is unspecified during duplicate address detection.
        135 => {
            if !source_address.is_unspecified() {
                facts.push(FrameFact::Neighbor {
                    mac: source_mac.to_string(),
                    address: source_address,
                    is_router: false,
                });
            }
        }
        // Neighbour Advertisement: here the target address *is* the sender's own.
        136 => {
            if icmp.len() < 24 {
                return;
            }
            let mut target = [0u8; 16];
            target.copy_from_slice(&icmp[8..24]);
            facts.push(FrameFact::Neighbor {
                mac: source_mac.to_string(),
                address: Ipv6Addr::from(target),
                is_router: (icmp[4] & 0x80) != 0,
            });
        }
        _ => {}
    }
}

/// Extracts Prefix Information Options from a router advertisement.
pub fn decode_ra_prefixes(icmp: &[u8]) -> Vec<(Ipv6Addr, u8)> {
    let mut prefixes = Vec::new();
    // RA header is 16 bytes before options begin.
    let mut i = 16;
    while i + 2 <= icmp.len() {
        let opt_type = icmp[i];
        let opt_len = icmp[i + 1] as usize * 8;
        if opt_len == 0 || i + opt_len > icmp.len() {
            break;
        }
        // Type 3 is Prefix Information: type, length, prefix length, flags,
        // valid lifetime, preferred lifetime, reserved, then a 16-byte prefix.
        if opt_type == 3 && opt_len >= 32 {
            let prefix_len = icmp[i + 2];
            if prefix_len <= 128 {
                let mut raw = [0u8; 16];
                raw.copy_from_slice(&icmp[i + 16..i + 32]);
                prefixes.push((Ipv6Addr::from(raw), prefix_len));
            }
        }
        i += opt_len;
    }
    prefixes
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > bytes.len() {
        return None;
    }
    Some(((bytes[offset] as u16) << 8) | bytes[offset + 1] as u16)
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Formats an 8-byte bridge identifier as priority + MAC, the conventional presentation.
fn format_bridge_id(bytes: &[u8]) -> String {
    if bytes.len() < 8 {
        return String::new();
    }
    let priority = ((bytes[0] as u16) << 8) | bytes[1] as u16;
    format!("{}.{}", priority, format_mac(&bytes[2..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet header helper: destination, source, then an EtherType.
    fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f
    }

    #[test]
    fn vlan_tag_yields_only_the_vlan_id() {
        // A tagged ARP frame. The tag must produce a VLAN fact and never a prefix.
        let mut frame = eth(
            [0xff; 6],
            [0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22],
            ETHERTYPE_VLAN,
        );
        frame.extend_from_slice(&0x0014u16.to_be_bytes()); // VLAN 20, priority 0
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&arp_body(
            [0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22],
            Ipv4Addr::new(10, 0, 0, 5),
        ));

        let facts = decode_frame(&frame);
        assert!(facts.contains(&FrameFact::Vlan { id: 20 }));
        assert!(
            facts.iter().any(|f| matches!(f, FrameFact::Arp { .. })),
            "the tagged payload must still be decoded"
        );
        // Nothing in this frame establishes a prefix for VLAN 20.
        assert!(!facts.iter().any(|f| matches!(f, FrameFact::Dhcp { .. })));
    }

    #[test]
    fn qinq_double_tag_is_unwrapped() {
        let mut frame = eth([0xff; 6], [0x02; 6], ETHERTYPE_QINQ_802_1AD);
        frame.extend_from_slice(&0x0064u16.to_be_bytes()); // outer VLAN 100
        frame.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        frame.extend_from_slice(&0x00c8u16.to_be_bytes()); // inner VLAN 200
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&arp_body([0x02; 6], Ipv4Addr::new(10, 0, 0, 9)));

        let facts = decode_frame(&frame);
        assert!(facts.contains(&FrameFact::Vlan { id: 100 }));
        assert!(facts.contains(&FrameFact::Vlan { id: 200 }));
    }

    #[test]
    fn reserved_vlan_ids_are_ignored() {
        let mut frame = eth([0xff; 6], [0x02; 6], ETHERTYPE_VLAN);
        frame.extend_from_slice(&0x0000u16.to_be_bytes()); // VLAN 0: priority tag only
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&arp_body([0x02; 6], Ipv4Addr::new(10, 0, 0, 9)));

        let facts = decode_frame(&frame);
        assert!(!facts.iter().any(|f| matches!(f, FrameFact::Vlan { .. })));
    }

    fn arp_body(sender_mac: [u8; 6], sender_ip: Ipv4Addr) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&1u16.to_be_bytes()); // htype ethernet
        b.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        b.push(6);
        b.push(4);
        b.extend_from_slice(&1u16.to_be_bytes()); // request
        b.extend_from_slice(&sender_mac);
        b.extend_from_slice(&sender_ip.octets());
        b.extend_from_slice(&[0u8; 6]);
        b.extend_from_slice(&[0u8; 4]);
        b
    }

    #[test]
    fn arp_yields_a_sender_binding() {
        let mut frame = eth(
            [0xff; 6],
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            ETHERTYPE_ARP,
        );
        frame.extend_from_slice(&arp_body(
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            Ipv4Addr::new(192, 168, 4, 20),
        ));

        let facts = decode_frame(&frame);
        assert_eq!(
            facts,
            vec![FrameFact::Arp {
                mac: "de:ad:be:ef:00:01".to_string(),
                address: Ipv4Addr::new(192, 168, 4, 20),
            }]
        );
    }

    #[test]
    fn arp_probe_with_unspecified_sender_binds_nothing() {
        let body = arp_body([0x02; 6], Ipv4Addr::UNSPECIFIED);
        assert!(decode_arp(&body).is_none());
    }

    #[test]
    fn bpdu_yields_bridge_and_root_identity() {
        // Configuration BPDU body, after the LLC header.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x00, 0x00]); // protocol id
        body.push(0x00); // version: STP
        body.push(0x00); // type: configuration
        body.push(0x00); // flags
        body.extend_from_slice(&[0x80, 0x00, 0xbc, 0x24, 0x11, 0x9a, 0x02, 0x01]); // root id
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // root path cost
        body.extend_from_slice(&[0x80, 0x00, 0x44, 0xd9, 0xe7, 0x1c, 0x88, 0x40]); // bridge id
        body.extend_from_slice(&[0x80, 0x03]); // port id
        body.extend_from_slice(&[0u8; 10]); // timers

        let fact = decode_bpdu("44:d9:e7:1c:88:40", &body).expect("decodes");
        match fact {
            FrameFact::Bridge {
                bridge_id,
                root_id,
                port_id,
                ..
            } => {
                assert_eq!(root_id, "32768.bc:24:11:9a:02:01");
                assert_eq!(bridge_id, "32768.44:d9:e7:1c:88:40");
                assert_eq!(port_id, 0x8003);
            }
            other => panic!("expected a bridge fact, got {:?}", other),
        }
    }

    #[test]
    fn rstp_bpdu_is_accepted() {
        let mut body = vec![0x00, 0x00, 0x02, 0x02, 0x3c];
        body.extend_from_slice(&[0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        body.extend_from_slice(&[0u8; 4]);
        body.extend_from_slice(&[0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        body.extend_from_slice(&[0x80, 0x01]);
        body.extend_from_slice(&[0u8; 10]);

        assert!(decode_bpdu("00:11:22:33:44:55", &body).is_some());
    }

    #[test]
    fn a_topology_change_notification_is_not_a_configuration_bpdu() {
        let body = vec![0x00, 0x00, 0x00, 0x80, 0x00];
        assert!(decode_bpdu("00:11:22:33:44:55", &body).is_none());
    }

    /// Minimal DHCP body with a magic cookie and the given options appended.
    fn dhcp_body(yiaddr: Ipv4Addr, options: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 236];
        b[0] = 2; // BOOTREPLY
        b[16..20].copy_from_slice(&yiaddr.octets());
        b.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        b.extend_from_slice(options);
        b.push(255);
        b
    }

    #[test]
    fn dhcp_supplies_mask_and_routers() {
        let options = [
            1, 4, 255, 255, 255, 0, // subnet mask
            3, 4, 192, 168, 8, 1, // router
        ];
        let body = dhcp_body(Ipv4Addr::new(192, 168, 8, 44), &options);

        match decode_dhcp("00:11:22:33:44:55", &body).expect("decodes") {
            FrameFact::Dhcp {
                assigned,
                subnet_mask,
                routers,
                ..
            } => {
                assert_eq!(assigned, Some(Ipv4Addr::new(192, 168, 8, 44)));
                assert_eq!(subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
                assert_eq!(routers, vec![Ipv4Addr::new(192, 168, 8, 1)]);
            }
            other => panic!("expected DHCP, got {:?}", other),
        }
    }

    #[test]
    fn dhcp_without_topology_options_yields_nothing() {
        // A message carrying only a lease time tells us nothing about topology.
        let body = dhcp_body(Ipv4Addr::new(10, 0, 0, 5), &[51, 4, 0, 0, 0, 60]);
        assert!(decode_dhcp("00:11:22:33:44:55", &body).is_none());
    }

    #[test]
    fn classless_static_routes_decode_variable_length_destinations() {
        // 10.0.0.0/8 via 10.9.9.1, then 172.16.5.0/24 via 10.9.9.2.
        let value = [
            8, 10, 10, 9, 9, 1, //
            24, 172, 16, 5, 10, 9, 9, 2,
        ];
        let routes = decode_classless_routes(&value);
        assert_eq!(
            routes,
            vec![
                (Ipv4Addr::new(10, 0, 0, 0), 8, Ipv4Addr::new(10, 9, 9, 1)),
                (Ipv4Addr::new(172, 16, 5, 0), 24, Ipv4Addr::new(10, 9, 9, 2)),
            ]
        );
    }

    #[test]
    fn truncated_classless_route_is_dropped_not_guessed() {
        let value = [24, 192, 168]; // missing the rest
        assert!(decode_classless_routes(&value).is_empty());
    }

    #[test]
    fn router_advertisement_yields_prefix_information() {
        let mut icmp = vec![134, 0, 0, 0]; // type, code, checksum
        icmp.extend_from_slice(&[64, 0]); // cur hop limit, flags
        icmp.extend_from_slice(&[0x07, 0x08]); // router lifetime
        icmp.extend_from_slice(&[0u8; 8]); // reachable + retrans timers
        // Prefix Information Option: 2001:db8::/64
        icmp.push(3);
        icmp.push(4); // 4 * 8 = 32 bytes
        icmp.push(64); // prefix length
        icmp.push(0xC0); // on-link + autonomous
        icmp.extend_from_slice(&[0u8; 4]); // valid lifetime
        icmp.extend_from_slice(&[0u8; 4]); // preferred lifetime
        icmp.extend_from_slice(&[0u8; 4]); // reserved
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        icmp.extend_from_slice(&prefix.octets());

        let prefixes = decode_ra_prefixes(&icmp);
        assert_eq!(prefixes, vec![(prefix, 64)]);
    }

    #[test]
    fn full_ipv6_ra_frame_decodes_end_to_end() {
        let mut icmp = vec![134, 0, 0, 0, 64, 0, 0x07, 0x08];
        icmp.extend_from_slice(&[0u8; 8]);

        let mut ipv6 = vec![0x60, 0, 0, 0];
        ipv6.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
        ipv6.push(58); // ICMPv6
        ipv6.push(255); // hop limit
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        ipv6.extend_from_slice(&src.octets());
        ipv6.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        ipv6.extend_from_slice(&icmp);

        let mut frame = eth(
            [0x33, 0x33, 0, 0, 0, 1],
            [0xc0, 0xf6, 0xec, 0x84, 0xb9, 0x0b],
            ETHERTYPE_IPV6,
        );
        frame.extend_from_slice(&ipv6);

        let facts = decode_frame(&frame);
        match facts.first().expect("one fact") {
            FrameFact::RouterAdvertisement {
                router_mac,
                router_address,
                ..
            } => {
                assert_eq!(router_mac, "c0:f6:ec:84:b9:0b");
                assert_eq!(*router_address, Some(src));
            }
            other => panic!("expected an RA, got {:?}", other),
        }
    }

    /// Wraps an ICMPv6 body in IPv6 and Ethernet headers.
    fn icmpv6_frame(src_mac: [u8; 6], src_ip: &str, icmp: &[u8]) -> Vec<u8> {
        let mut ipv6 = vec![0x60, 0, 0, 0];
        ipv6.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
        ipv6.push(58);
        ipv6.push(255);
        let src: Ipv6Addr = src_ip.parse().unwrap();
        ipv6.extend_from_slice(&src.octets());
        ipv6.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        ipv6.extend_from_slice(icmp);

        let mut frame = eth([0x33, 0x33, 0, 0, 0, 1], src_mac, ETHERTYPE_IPV6);
        frame.extend_from_slice(&ipv6);
        frame
    }

    #[test]
    fn a_solicitation_does_not_bind_the_target_to_the_sender() {
        // The classic error: NS asks "who has X?", and treating X as the sender's own
        // address attributes one host's address to another and merges unrelated devices.
        let target: Ipv6Addr = "fdc5::dead".parse().unwrap();
        let mut icmp = vec![135, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&target.octets());

        let facts = decode_frame(&icmpv6_frame([0xaa, 0xaa, 0xaa, 0, 0, 1], "fdc5::1", &icmp));

        match facts.as_slice() {
            [FrameFact::Neighbor { mac, address, .. }] => {
                assert_eq!(mac, "aa:aa:aa:00:00:01");
                assert_eq!(
                    *address,
                    "fdc5::1".parse::<Ipv6Addr>().unwrap(),
                    "a solicitation binds only the sender's own source address"
                );
                assert_ne!(*address, target);
            }
            other => panic!("expected one neighbour binding, got {:?}", other),
        }
    }

    #[test]
    fn duplicate_address_detection_binds_nothing() {
        // DAD sends from :: , which identifies no one.
        let target: Ipv6Addr = "fdc5::dead".parse().unwrap();
        let mut icmp = vec![135, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&target.octets());

        let facts = decode_frame(&icmpv6_frame([0xaa; 6], "::", &icmp));
        assert!(facts.is_empty());
    }

    #[test]
    fn an_advertisement_binds_the_target_to_the_sender() {
        // In an NA the target address is the sender's own, so the binding is valid.
        let own: Ipv6Addr = "fdc5::42".parse().unwrap();
        let mut icmp = vec![136, 0, 0, 0, 0x80, 0, 0, 0]; // router flag set
        icmp.extend_from_slice(&own.octets());

        let facts = decode_frame(&icmpv6_frame([0xbb; 6], "fdc5::42", &icmp));
        match facts.as_slice() {
            [
                FrameFact::Neighbor {
                    address, is_router, ..
                },
            ] => {
                assert_eq!(*address, own);
                assert!(*is_router, "the router flag must be read from an NA");
            }
            other => panic!("expected a neighbour binding, got {:?}", other),
        }
    }

    #[test]
    fn short_and_malformed_frames_are_not_evidence() {
        assert!(decode_frame(&[]).is_empty());
        assert!(decode_frame(&[0u8; 13]).is_empty());
        assert!(decode_frame(&[0xff; 64]).is_empty());
    }
}
