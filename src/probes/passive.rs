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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv6Net};

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

    /// A routing update heard on the link: RIPv2 on UDP 520, RIPng on UDP 521.
    ///
    /// The sender is advertising reachability, which is router behaviour observed rather
    /// than claimed, and each entry names a prefix outright. Withdrawals are carried too --
    /// a metric of 16 (RIPv2) says the sender can no longer reach the prefix, which is a
    /// statement about the network and not a route to record.
    RoutingUpdate {
        sender_mac: String,
        sender: IpAddr,
        /// "RIPv2" or "RIPng", so the two are never conflated in the evidence trail.
        protocol: &'static str,
        /// Reachable prefixes, each with everything the entry stated.
        routes: Vec<AdvertisedRoute>,
        /// Prefixes the sender withdrew, with the same entry bytes.
        withdrawn: Vec<(IpNet, Vec<u8>)>,
    },

    /// A routing control-plane packet: OSPF or IS-IS, heard and never answered.
    ///
    /// Hellos identify routers, areas and adjacencies and carry no prefix. Only complete,
    /// checksum-valid, prefix-bearing advertisements name networks, and only while they are
    /// current: a withdrawal describes what is going away.
    ControlPlane {
        sender_mac: String,
        /// The IP source, where the protocol runs over IP. IS-IS runs directly over the
        /// link layer and has none.
        sender: Option<IpAddr>,
        protocol: &'static str,
        /// Router-id for OSPF, system id for IS-IS.
        identity: String,
        /// Area for OSPF, area addresses and level for IS-IS.
        scope: String,
        hello: bool,
        /// Whether the packet's own authentication could be verified. When it could not,
        /// the prefixes are reported and not promoted.
        verifiable: bool,
        /// Prefixes that may become current topology.
        current: Vec<PromotedPrefix>,
        /// Prefixes carried but not promotable: withdrawn, or unverifiable.
        reported_only: Vec<ReportedPrefix>,
        /// Sequence numbers seen, so a replay is distinguishable from an advertisement.
        sequences: Vec<u32>,
    },

    /// A datagram on a routing protocol's port that did not survive validation.
    ///
    /// Counted so silence can be told apart from noise. "No valid updates observed" means
    /// something different when nothing arrived on UDP 520 at all than when several
    /// datagrams arrived and none of them parsed.
    RoutingUpdateRejected {
        sender_mac: String,
        protocol: &'static str,
    },

    /// An IPv6 router advertisement. Sending one is router behaviour by definition.
    RouterAdvertisement {
        router_mac: String,
        router_address: Option<Ipv6Addr>,
        /// Prefix Information Options. These are the router's assertions, not observations.
        prefixes: Vec<(Ipv6Addr, u8)>,
        /// Route Information Options (RFC 4191): prefixes reachable *through* this router.
        ///
        /// Carried because they are the only passive evidence that names a network beyond
        /// this link. Decoded by the same parser the solicited path uses, so an unsolicited
        /// advertisement discloses exactly as much as a solicited one.
        routes: Vec<(Ipv6Addr, u8, u32)>,
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

    // IS-IS rides 802.2 LLC with SAP 0xFE, directly over the link layer rather than over
    // IP. That is why it is reachable only from a capture on the selected interface.
    if dsap == 0xFE && ssap == 0xFE {
        facts.push(match crate::probes::isis::parse(&payload[3..]) {
            Some(pdu) => {
                let areas = if pdu.areas.is_empty() {
                    pdu.level.to_string()
                } else {
                    format!("{} area {}", pdu.level, pdu.areas.join(", "))
                };
                let (current, reported_only) = split_isis_prefixes(&pdu);
                FrameFact::ControlPlane {
                    sender_mac: source_mac.to_string(),
                    sender: None,
                    protocol: "IS-IS",
                    identity: pdu.system_id.clone(),
                    scope: areas,
                    hello: pdu.hello,
                    verifiable: !pdu.unverifiable_authentication,
                    current,
                    reported_only,
                    sequences: pdu.sequence.into_iter().collect(),
                }
            }
            None => FrameFact::RoutingUpdateRejected {
                sender_mac: source_mac.to_string(),
                protocol: "IS-IS",
            },
        });
        return;
    }

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
    // OSPFv2 rides IP protocol 89 directly rather than UDP.
    if payload[9] == 89 {
        let mut source = [0u8; 4];
        source.copy_from_slice(&payload[12..16]);
        facts.push(match crate::probes::ospf::parse_v2(&payload[ihl..]) {
            Some(packet) => control_plane_fact(
                source_mac,
                Some(IpAddr::V4(Ipv4Addr::from(source))),
                &packet,
            ),
            None => FrameFact::RoutingUpdateRejected {
                sender_mac: source_mac.to_string(),
                protocol: "OSPFv2",
            },
        });
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

    // RIPv2 responses carry prefixes and masks outright, which is why they are worth
    // decoding passively: a router advertising a table names networks nobody here is
    // attached to. RIPv1 is deliberately not accepted -- it carries no mask, and deriving
    // one from the address class would be inventing a prefix nobody advertised.
    if src_port == 520 || dst_port == 520 {
        let mut source = [0u8; 4];
        source.copy_from_slice(&payload[12..16]);
        facts.push(
            decode_rip_v2(source_mac, Ipv4Addr::from(source), body).unwrap_or(
                FrameFact::RoutingUpdateRejected {
                    sender_mac: source_mac.to_string(),
                    protocol: "RIPv2",
                },
            ),
        );
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
    let mut src = [0u8; 16];
    src.copy_from_slice(&payload[8..24]);
    let source_address = Ipv6Addr::from(src);

    // RIPng rides UDP 521. Decoded before the ICMPv6 branch because it is not ICMPv6 at
    // all, and the next-header check below would discard it.
    if payload[6] == 17 && payload.len() >= 48 {
        let udp = &payload[40..];
        let (Some(src_port), Some(dst_port)) = (read_u16(udp, 0), read_u16(udp, 2)) else {
            return;
        };
        if src_port == 521 || dst_port == 521 {
            facts.push(
                decode_ripng(source_mac, source_address, &udp[8..]).unwrap_or(
                    FrameFact::RoutingUpdateRejected {
                        sender_mac: source_mac.to_string(),
                        protocol: "RIPng",
                    },
                ),
            );
            return;
        }
    }

    // OSPFv3 rides next-header 89.
    if payload[6] == 89 && payload.len() > 40 {
        facts.push(match crate::probes::ospf::parse_v3(&payload[40..]) {
            Some(packet) => {
                control_plane_fact(source_mac, Some(IpAddr::V6(source_address)), &packet)
            }
            None => FrameFact::RoutingUpdateRejected {
                sender_mac: source_mac.to_string(),
                protocol: "OSPFv3",
            },
        });
        return;
    }

    // Only ICMPv6 carries the neighbour and router discovery messages.
    if payload[6] != 58 {
        return;
    }

    let icmp = &payload[40..];
    if icmp.len() < 4 {
        return;
    }

    match icmp[0] {
        // Router Advertisement.
        134 => {
            let mut destination = [0u8; 16];
            destination.copy_from_slice(&payload[24..40]);
            // Hop limit and destination come from the IPv6 header of the captured frame,
            // which is what lets the shared parser apply the same checks here: hop limit
            // 255 and a checksum over the real pseudo-header.
            let parsed = crate::probes::ra::parse_advertisement(
                icmp,
                source_address,
                Ipv6Addr::from(destination),
                payload[7],
            );

            let (prefixes, routes) = match &parsed {
                Some(advertisement) => (
                    advertisement
                        .on_link_prefixes()
                        .map(|prefix| (prefix.prefix.addr(), prefix.prefix.prefix_len()))
                        .collect(),
                    advertisement
                        .usable_routes()
                        .map(|route| {
                            (
                                route.prefix.addr(),
                                route.prefix.prefix_len(),
                                route.lifetime,
                            )
                        })
                        .collect(),
                ),
                // An advertisement that fails validation is not repaired into a weaker one:
                // the frame is recorded as router behaviour and discloses no prefix.
                None => (Vec::new(), Vec::new()),
            };

            facts.push(FrameFact::RouterAdvertisement {
                router_mac: source_mac.to_string(),
                router_address: Some(source_address),
                prefixes,
                routes,
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

/// One advertised route, with the fields that make it traceable: where to send traffic,
/// what it cost the advertiser, the tag it carried, and the exact entry bytes.
pub type AdvertisedRoute = (IpNet, Option<IpAddr>, u32, u16, Vec<u8>);

/// Builds the control-plane fact for one OSPF packet.
///
/// The split is the rule: a prefix is current only when the advertisement is current and
/// the packet's own authentication could be verified. Everything else is reported and
/// counted without becoming topology.
fn control_plane_fact(
    source_mac: &str,
    sender: Option<IpAddr>,
    packet: &crate::probes::ospf::OspfPacket,
) -> FrameFact {
    let mut current = Vec::new();
    let mut reported_only = Vec::new();
    let verifiable = packet.authentication.routes_are_verifiable();

    for prefix in &packet.prefixes {
        let described = format!("{} LSA, metric {}", prefix.lsa_type, prefix.metric);
        if verifiable && !prefix.withdrawn {
            current.push((prefix.prefix, prefix.metric, described));
        } else {
            reported_only.push((
                prefix.prefix,
                if prefix.withdrawn {
                    format!("{described}, at MaxAge (withdrawn)")
                } else {
                    format!(
                        "{described}, {} authentication could not be verified",
                        packet.authentication.label()
                    )
                },
            ));
        }
    }

    FrameFact::ControlPlane {
        sender_mac: source_mac.to_string(),
        sender,
        protocol: packet.protocol,
        identity: packet.router_id.to_string(),
        scope: format!("area {}", packet.area),
        hello: packet.hello,
        verifiable,
        current,
        reported_only,
        sequences: packet.sequences.clone(),
    }
}

/// A prefix that may become current topology, with what stated it.
pub type PromotedPrefix = (IpNet, u32, String);
/// A prefix reported without promotion, with why.
pub type ReportedPrefix = (IpNet, String);

/// The same split for IS-IS, whose withdrawals are absences rather than a MaxAge flag.
fn split_isis_prefixes(
    pdu: &crate::probes::isis::IsisPdu,
) -> (Vec<PromotedPrefix>, Vec<ReportedPrefix>) {
    let mut current = Vec::new();
    let mut reported_only = Vec::new();

    for prefix in &pdu.prefixes {
        let described = match prefix.topology {
            Some(topology) => format!(
                "{}, metric {}, topology {topology}",
                prefix.tlv, prefix.metric
            ),
            None => format!("{}, metric {}", prefix.tlv, prefix.metric),
        };
        if pdu.unverifiable_authentication {
            reported_only.push((
                prefix.prefix,
                format!("{described}, authentication could not be verified"),
            ));
        } else {
            current.push((prefix.prefix, prefix.metric, described));
        }
    }

    (current, reported_only)
}

/// Decodes a RIPv2 response heard on UDP 520.
///
/// Reuses the unicast probe's parser, so a table heard passively and a table returned to a
/// direct request are held to exactly the same standard: version 2 only, a header plus
/// whole 20-byte entries, a zero reserved field, contiguous masks, and metrics inside
/// 1..=16. A metric of 16 is an advertisement of unreachability and is kept apart from the
/// routes rather than dropped -- withdrawing a prefix says the prefix exists.
fn decode_rip_v2(source_mac: &str, sender: Ipv4Addr, body: &[u8]) -> Option<FrameFact> {
    let entries = crate::probes::rip::parse_response(body)?;
    if entries.is_empty() {
        return None;
    }

    let mut routes = Vec::new();
    let mut withdrawn = Vec::new();
    for entry in entries {
        if entry.is_reachable() {
            routes.push((
                entry.prefix,
                entry.next_hop,
                entry.metric,
                entry.tag,
                entry.raw_entry,
            ));
        } else {
            withdrawn.push((entry.prefix, entry.raw_entry));
        }
    }

    Some(FrameFact::RoutingUpdate {
        sender_mac: source_mac.to_string(),
        sender: IpAddr::V4(sender),
        protocol: "RIPv2",
        routes,
        withdrawn,
    })
}

/// Decodes a RIPng response heard on UDP 521 (RFC 2080).
///
/// Entries are twenty bytes: a 16-byte prefix, a two-byte route tag, a prefix length and a
/// metric. Two encodings are not routes and are treated as such -- a metric of 255 is a
/// next-hop entry that applies to the entries following it, and a metric of 16 withdraws
/// the prefix.
fn decode_ripng(source_mac: &str, sender: Ipv6Addr, body: &[u8]) -> Option<FrameFact> {
    const RESPONSE: u8 = 2;
    const NEXT_HOP_METRIC: u8 = 0xff;
    const INFINITY: u8 = 16;

    if body.len() < 4 || body[0] != RESPONSE || body[1] != 1 {
        return None;
    }
    // RFC 2080: the two bytes after the version are reserved and must be zero.
    if body[2] != 0 || body[3] != 0 {
        return None;
    }
    let entries = &body[4..];
    if entries.is_empty() || !entries.len().is_multiple_of(20) {
        return None;
    }

    let mut routes = Vec::new();
    let mut withdrawn = Vec::new();
    // A next-hop entry applies to every route table entry that follows it, until another
    // one replaces it (RFC 2080 §2.1.1).
    let mut next_hop: Option<IpAddr> = None;

    for entry in entries.as_chunks::<20>().0 {
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&entry[..16]);
        let address = Ipv6Addr::from(raw);
        let tag = u16::from_be_bytes([entry[16], entry[17]]);
        let prefix_len = entry[18];
        let metric = entry[19];

        if metric == NEXT_HOP_METRIC {
            // Not a route: it names where to send traffic for what follows. The tag and
            // prefix length must be zero for it to be one at all.
            if tag == 0 && prefix_len == 0 {
                next_hop = (!address.is_unspecified()).then_some(IpAddr::V6(address));
            }
            continue;
        }
        if prefix_len > 128 || metric == 0 || metric > INFINITY {
            continue;
        }
        let Ok(prefix) = Ipv6Net::new(address, prefix_len) else {
            continue;
        };
        let prefix = IpNet::V6(prefix.trunc());

        if metric == INFINITY {
            withdrawn.push((prefix, entry.to_vec()));
        } else {
            routes.push((prefix, next_hop, metric as u32, tag, entry.to_vec()));
        }
    }

    if routes.is_empty() && withdrawn.is_empty() {
        return None;
    }
    Some(FrameFact::RoutingUpdate {
        sender_mac: source_mac.to_string(),
        sender: IpAddr::V6(sender),
        protocol: "RIPng",
        routes,
        withdrawn,
    })
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

    /// A RIPv2 response entry: AFI, tag, address, mask, next hop, metric.
    fn rip_entry(
        address: [u8; 4],
        mask: [u8; 4],
        next_hop: [u8; 4],
        metric: u32,
        tag: u16,
    ) -> Vec<u8> {
        let mut entry = vec![0, 2];
        entry.extend_from_slice(&tag.to_be_bytes());
        entry.extend_from_slice(&address);
        entry.extend_from_slice(&mask);
        entry.extend_from_slice(&next_hop);
        entry.extend_from_slice(&metric.to_be_bytes());
        entry
    }

    /// Wraps a UDP payload in IPv4 and Ethernet headers.
    fn udp_v4_frame(src_mac: [u8; 6], src_ip: [u8; 4], port: u16, body: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 0];
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&src_ip);
        ip.extend_from_slice(&[224, 0, 0, 9]); // the RIPv2 multicast group
        let mut udp = Vec::new();
        udp.extend_from_slice(&port.to_be_bytes());
        udp.extend_from_slice(&port.to_be_bytes());
        udp.extend_from_slice(&((body.len() + 8) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(body);
        ip.extend_from_slice(&udp);

        let mut frame = eth([0x01, 0, 0x5e, 0, 0, 9], src_mac, ETHERTYPE_IPV4);
        frame.extend_from_slice(&ip);
        frame
    }

    #[test]
    fn a_ripv2_response_on_the_wire_names_prefixes_and_their_withdrawals() {
        // The reason this is worth decoding passively: a router advertising its table names
        // networks nobody here is attached to, and it does so unprompted.
        let mut body = vec![2, 2, 0, 0]; // response, version 2, reserved
        body.extend_from_slice(&rip_entry(
            [192, 168, 51, 0],
            [255, 255, 255, 0],
            [0, 0, 0, 0],
            2,
            7,
        ));
        body.extend_from_slice(&rip_entry(
            [10, 9, 0, 0],
            [255, 255, 0, 0],
            [0, 0, 0, 0],
            16,
            0,
        ));

        let frame = udp_v4_frame([0x02, 0, 0, 0, 0, 0x11], [192, 168, 1, 1], 520, &body);
        let facts = decode_frame(&frame);

        match facts.first().expect("a routing update") {
            FrameFact::RoutingUpdate {
                sender,
                protocol,
                routes,
                withdrawn,
                ..
            } => {
                assert_eq!(*protocol, "RIPv2");
                assert_eq!(*sender, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(routes.len(), 1);
                assert_eq!(routes[0].0.to_string(), "192.168.51.0/24");
                assert_eq!(routes[0].2, 2, "the metric is carried, not flattened");
                assert_eq!(routes[0].3, 7, "so is the route tag");
                assert_eq!(routes[0].4.len(), 20, "and the exact entry bytes");

                // Metric 16 withdraws the prefix. It is a statement about a network that
                // exists, kept apart from the routes rather than dropped.
                assert_eq!(withdrawn.len(), 1);
                assert_eq!(withdrawn[0].0.to_string(), "10.9.0.0/16");
            }
            other => panic!("expected a routing update, got {other:?}"),
        }
    }

    #[test]
    fn a_ripv1_message_establishes_nothing() {
        // Version 1 carries no mask, and deriving one from the address class would be
        // inventing a prefix nobody advertised.
        let mut body = vec![2, 1, 0, 0];
        body.extend_from_slice(&rip_entry(
            [192, 168, 51, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            2,
            0,
        ));
        let frame = udp_v4_frame([0x02, 0, 0, 0, 0, 0x11], [192, 168, 1, 1], 520, &body);
        // Counted as a datagram that failed validation, which is not the same as silence.
        assert!(matches!(
            decode_frame(&frame).first(),
            Some(FrameFact::RoutingUpdateRejected {
                protocol: "RIPv2",
                ..
            })
        ));
    }

    #[test]
    fn a_ripng_next_hop_entry_is_not_a_route() {
        // RFC 2080 §2.1.1: metric 255 marks a next-hop entry that applies to the entries
        // after it. Reading it as a route would put ::/0 into the graph with a metric of
        // 255 attached to nothing.
        let mut body = vec![2, 1, 0, 0];
        let mut next_hop = Vec::new();
        next_hop.extend_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        next_hop.extend_from_slice(&[0, 0]); // tag zero
        next_hop.push(0); // prefix length zero
        next_hop.push(0xff); // the next-hop metric
        body.extend_from_slice(&next_hop);

        let mut route = Vec::new();
        route.extend_from_slice(&"2001:db8:51::".parse::<Ipv6Addr>().unwrap().octets());
        route.extend_from_slice(&[0, 3]); // tag
        route.push(48); // prefix length
        route.push(4); // metric
        body.extend_from_slice(&route);

        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend_from_slice(&((body.len() + 8) as u16).to_be_bytes());
        ip.push(17); // UDP
        ip.push(255);
        let src: Ipv6Addr = "fe80::2".parse().unwrap();
        ip.extend_from_slice(&src.octets());
        ip.extend_from_slice(&"ff02::9".parse::<Ipv6Addr>().unwrap().octets());
        ip.extend_from_slice(&521u16.to_be_bytes());
        ip.extend_from_slice(&521u16.to_be_bytes());
        ip.extend_from_slice(&((body.len() + 8) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0]);
        ip.extend_from_slice(&body);

        let mut frame = eth(
            [0x33, 0x33, 0, 0, 0, 9],
            [0x02, 0, 0, 0, 0, 0x22],
            ETHERTYPE_IPV6,
        );
        frame.extend_from_slice(&ip);

        match decode_frame(&frame).first().expect("a routing update") {
            FrameFact::RoutingUpdate {
                protocol,
                routes,
                withdrawn,
                ..
            } => {
                assert_eq!(*protocol, "RIPng");
                assert!(withdrawn.is_empty());
                assert_eq!(routes.len(), 1, "the next-hop entry is not itself a route");
                assert_eq!(routes[0].0.to_string(), "2001:db8:51::/48");
                assert_eq!(
                    routes[0].1,
                    Some(IpAddr::V6("fe80::1".parse().unwrap())),
                    "it names where the routes after it are reached through"
                );
                assert_eq!(routes[0].2, 4);
                assert_eq!(routes[0].3, 3);
            }
            other => panic!("expected a routing update, got {other:?}"),
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
