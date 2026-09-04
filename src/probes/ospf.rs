//! Passive OSPFv2 and OSPFv3 decoding (RFC 2328, RFC 5340).
//!
//! Listen-only, always. Nothing here transmits: no hello, no adjacency, no acknowledgement.
//! A router's link-state advertisements are the most complete description of an enterprise
//! network that exists, and on a link where they are already being flooded, reading them
//! costs nothing and changes nothing.
//!
//! What each message class may establish is kept apart.
//!
//! A hello identifies a router, its area and its neighbours. It carries no prefix and
//! creates no network -- a router-id is not an address space, and an area is not a subnet.
//!
//! Only a complete, checksum-valid, prefix-bearing advertisement creates a network, and
//! only while it is current: an advertisement at MaxAge is being withdrawn from the domain
//! and describes what is going away.
//!
//! Authentication is never rendered. OSPFv2 carries its authentication field in the header,
//! and this decoder zeroes it before keeping any bytes as evidence. Where the field says
//! cryptographic authentication is in use, the digest cannot be verified without the key,
//! so the packet is reported and counted and its routes are not promoted to current
//! topology -- an unverifiable claim about someone else's network is not one to act on.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::probes::path::internet_checksum;

/// OSPF packet types (RFC 2328 §A.2).
const HELLO: u8 = 1;
const LINK_STATE_UPDATE: u8 = 4;

/// OSPFv2 LSA types that can carry a prefix.
const LSA_ROUTER: u8 = 1;
const LSA_NETWORK: u8 = 2;
const LSA_SUMMARY_NETWORK: u8 = 3;
const LSA_SUMMARY_ASBR: u8 = 4;
const LSA_EXTERNAL: u8 = 5;
const LSA_NSSA: u8 = 7;

/// OSPFv3 LSA function codes carrying prefixes (RFC 5340 §A.4.2.1).
const LSA_V3_INTER_AREA_PREFIX: u16 = 0x2003;
const LSA_V3_EXTERNAL: u16 = 0x4005;
const LSA_V3_NSSA: u16 = 0x2007;
const LSA_V3_INTRA_AREA_PREFIX: u16 = 0x2009;

/// An LSA at this age is being withdrawn from the flooding domain (RFC 2328 §14).
const MAX_AGE: u16 = 3600;

/// How a packet was authenticated, which decides whether its routes may be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authentication {
    /// AuType 0: no authentication. The packet stands on its own.
    None,
    /// AuType 1: a cleartext password. Never rendered, and it authenticates nothing that
    /// an observer on the link could not also send.
    Simple,
    /// AuType 2: a cryptographic digest, which cannot be verified without the key.
    Cryptographic,
    /// A value this decoder does not know.
    Unknown(u16),
}

impl Authentication {
    fn from_type(value: u16) -> Self {
        match value {
            0 => Authentication::None,
            1 => Authentication::Simple,
            2 => Authentication::Cryptographic,
            other => Authentication::Unknown(other),
        }
    }

    /// Whether routes from this packet may be promoted to current topology.
    ///
    /// A cryptographic digest we cannot check is exactly the case where the packet's claims
    /// are unverifiable: it is recorded and counted, and it does not create networks.
    pub fn routes_are_verifiable(&self) -> bool {
        matches!(self, Authentication::None | Authentication::Simple)
    }

    pub fn label(&self) -> String {
        match self {
            Authentication::None => "none".to_string(),
            Authentication::Simple => "simple password".to_string(),
            Authentication::Cryptographic => "cryptographic digest".to_string(),
            Authentication::Unknown(value) => format!("unknown type {value}"),
        }
    }
}

/// One prefix an advertisement carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertisedPrefix {
    pub prefix: IpNet,
    pub metric: u32,
    /// The LSA type that carried it, for the evidence trail.
    pub lsa_type: String,
    /// Whether the advertisement was at MaxAge, which withdraws it.
    pub withdrawn: bool,
}

/// What one OSPF packet disclosed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfPacket {
    /// "OSPFv2" or "OSPFv3".
    pub protocol: &'static str,
    pub router_id: Ipv4Addr,
    pub area: Ipv4Addr,
    pub authentication: Authentication,
    /// True for a hello, which identifies routers and creates no network.
    pub hello: bool,
    /// Neighbours the hello listed, which are router-ids and not addresses.
    pub neighbours: Vec<Ipv4Addr>,
    /// Prefixes from complete prefix-bearing LSAs.
    pub prefixes: Vec<AdvertisedPrefix>,
    /// LSA sequence numbers seen, so a replay is distinguishable from a new advertisement.
    pub sequences: Vec<u32>,
    /// The packet with its authentication field zeroed.
    pub raw: Vec<u8>,
}

impl OspfPacket {
    /// Prefixes that may become current topology: current, and from a verifiable packet.
    pub fn current_prefixes(&self) -> impl Iterator<Item = &AdvertisedPrefix> {
        let verifiable = self.authentication.routes_are_verifiable();
        self.prefixes
            .iter()
            .filter(move |prefix| verifiable && !prefix.withdrawn)
    }
}

/// Decodes an OSPFv2 packet (IP protocol 89).
///
/// The header checksum is verified with the authentication field zeroed, which is how RFC
/// 2328 §D.4.3 defines it. A packet that fails is not repaired into a weaker one.
pub fn parse_v2(payload: &[u8]) -> Option<OspfPacket> {
    if payload.len() < 24 || payload[0] != 2 {
        return None;
    }
    let length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if length < 24 || length > payload.len() {
        return None;
    }

    // Authentication never leaves this function: the field is zeroed before the bytes are
    // kept, and the checksum is defined over that same zeroed form.
    let mut packet = payload[..length].to_vec();
    packet[16..24].fill(0);
    if internet_checksum(&packet) != 0 {
        return None;
    }

    let router_id = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
    let area = Ipv4Addr::new(payload[8], payload[9], payload[10], payload[11]);
    let authentication = Authentication::from_type(u16::from_be_bytes([payload[14], payload[15]]));
    let body = &packet[24..];

    let mut decoded = OspfPacket {
        protocol: "OSPFv2",
        router_id,
        area,
        authentication,
        hello: payload[1] == HELLO,
        neighbours: Vec::new(),
        prefixes: Vec::new(),
        sequences: Vec::new(),
        raw: packet.clone(),
    };

    match payload[1] {
        // A hello names the sender's neighbours by router-id. No prefix, no network.
        HELLO if body.len() >= 20 => {
            for neighbour in body[20..].as_chunks::<4>().0 {
                decoded.neighbours.push(Ipv4Addr::from(*neighbour));
            }
        }
        LINK_STATE_UPDATE => {
            if body.len() < 4 {
                return None;
            }
            let count = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
            let mut cursor = 4;
            for _ in 0..count.min(256) {
                let Some(lsa) = read_v2_lsa(&body[cursor..]) else {
                    break;
                };
                decoded.sequences.push(lsa.sequence);
                decoded.prefixes.extend(lsa.prefixes);
                cursor += lsa.length;
                if cursor >= body.len() {
                    break;
                }
            }
        }
        _ => {}
    }

    Some(decoded)
}

/// One decoded LSA and how far it extended.
struct DecodedLsa {
    length: usize,
    sequence: u32,
    prefixes: Vec<AdvertisedPrefix>,
}

/// Reads one OSPFv2 LSA from the head of `body`.
fn read_v2_lsa(body: &[u8]) -> Option<DecodedLsa> {
    if body.len() < 20 {
        return None;
    }
    let age = u16::from_be_bytes([body[0], body[1]]);
    let kind = body[3];
    let link_state_id = Ipv4Addr::new(body[4], body[5], body[6], body[7]);
    // Bytes 8..12 are the advertising router; the sequence follows it.
    let sequence = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
    let length = u16::from_be_bytes([body[18], body[19]]) as usize;
    if length < 20 || length > body.len() {
        return None;
    }
    let withdrawn = age >= MAX_AGE;
    let contents = &body[20..length];
    let mut prefixes = Vec::new();

    match kind {
        // Summary and external LSAs carry a network and its mask outright, which is what
        // makes them the ones worth reading: they name networks elsewhere in the domain.
        LSA_SUMMARY_NETWORK | LSA_SUMMARY_ASBR | LSA_EXTERNAL | LSA_NSSA => {
            if contents.len() >= 8 {
                let mask = Ipv4Addr::new(contents[0], contents[1], contents[2], contents[3]);
                if let Some(bits) = crate::probes::icmp_mask::prefix_length(mask)
                    && let Ok(prefix) = Ipv4Net::new(link_state_id, bits)
                {
                    prefixes.push(AdvertisedPrefix {
                        prefix: IpNet::V4(prefix.trunc()),
                        metric: u32::from_be_bytes([0, contents[5], contents[6], contents[7]]),
                        lsa_type: v2_lsa_name(kind).to_string(),
                        withdrawn,
                    });
                }
            }
        }
        // A router LSA describes links, and its stub links carry a network and mask.
        LSA_ROUTER => {
            if contents.len() >= 4 {
                let links = u16::from_be_bytes([contents[2], contents[3]]) as usize;
                let mut cursor = 4;
                for _ in 0..links.min(128) {
                    if cursor + 12 > contents.len() {
                        break;
                    }
                    let link = &contents[cursor..cursor + 12];
                    // Type 3 is a stub network: link id is the network, link data the mask.
                    if link[8] == 3 {
                        let network = Ipv4Addr::new(link[0], link[1], link[2], link[3]);
                        let mask = Ipv4Addr::new(link[4], link[5], link[6], link[7]);
                        if let Some(bits) = crate::probes::icmp_mask::prefix_length(mask)
                            && let Ok(prefix) = Ipv4Net::new(network, bits)
                        {
                            prefixes.push(AdvertisedPrefix {
                                prefix: IpNet::V4(prefix.trunc()),
                                metric: u32::from(u16::from_be_bytes([link[10], link[11]])),
                                lsa_type: "router (stub link)".to_string(),
                                withdrawn,
                            });
                        }
                    }
                    // Each link is 12 bytes plus 4 per additional metric.
                    cursor += 12 + 4 * link[9] as usize;
                }
            }
        }
        // A network LSA carries the mask of the segment it describes, and its link-state id
        // is the designated router's interface address on that segment.
        LSA_NETWORK if contents.len() >= 4 => {
            let mask = Ipv4Addr::new(contents[0], contents[1], contents[2], contents[3]);
            if let Some(bits) = crate::probes::icmp_mask::prefix_length(mask)
                && let Ok(prefix) = Ipv4Net::new(link_state_id, bits)
            {
                prefixes.push(AdvertisedPrefix {
                    prefix: IpNet::V4(prefix.trunc()),
                    metric: 0,
                    lsa_type: "network".to_string(),
                    withdrawn,
                });
            }
        }
        _ => {}
    }

    Some(DecodedLsa {
        length,
        sequence,
        prefixes,
    })
}

fn v2_lsa_name(kind: u8) -> &'static str {
    match kind {
        LSA_ROUTER => "router",
        LSA_NETWORK => "network",
        LSA_SUMMARY_NETWORK => "summary (network)",
        LSA_SUMMARY_ASBR => "summary (ASBR)",
        LSA_EXTERNAL => "AS external",
        LSA_NSSA => "NSSA external",
        _ => "unknown",
    }
}

/// Decodes an OSPFv3 packet (RFC 5340).
///
/// OSPFv3 has no authentication field of its own -- it relies on IPsec -- so there is no
/// digest to be unable to verify and nothing to redact.
pub fn parse_v3(payload: &[u8]) -> Option<OspfPacket> {
    if payload.len() < 16 || payload[0] != 3 {
        return None;
    }
    let length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if length < 16 || length > payload.len() {
        return None;
    }

    let router_id = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
    let area = Ipv4Addr::new(payload[8], payload[9], payload[10], payload[11]);
    let body = &payload[16..length];

    let mut decoded = OspfPacket {
        protocol: "OSPFv3",
        router_id,
        area,
        authentication: Authentication::None,
        hello: payload[1] == HELLO,
        neighbours: Vec::new(),
        prefixes: Vec::new(),
        sequences: Vec::new(),
        raw: payload[..length].to_vec(),
    };

    match payload[1] {
        HELLO if body.len() >= 20 => {
            for neighbour in body[20..].as_chunks::<4>().0 {
                decoded.neighbours.push(Ipv4Addr::from(*neighbour));
            }
        }
        LINK_STATE_UPDATE => {
            if body.len() < 4 {
                return None;
            }
            let count = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
            let mut cursor = 4;
            for _ in 0..count.min(256) {
                let Some(lsa) = read_v3_lsa(&body[cursor..]) else {
                    break;
                };
                decoded.sequences.push(lsa.sequence);
                decoded.prefixes.extend(lsa.prefixes);
                cursor += lsa.length;
                if cursor >= body.len() {
                    break;
                }
            }
        }
        _ => {}
    }

    Some(decoded)
}

/// Reads one OSPFv3 LSA from the head of `body`.
fn read_v3_lsa(body: &[u8]) -> Option<DecodedLsa> {
    if body.len() < 20 {
        return None;
    }
    let age = u16::from_be_bytes([body[0], body[1]]);
    let kind = u16::from_be_bytes([body[2], body[3]]);
    let sequence = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
    let length = u16::from_be_bytes([body[18], body[19]]) as usize;
    if length < 20 || length > body.len() {
        return None;
    }
    let withdrawn = age >= MAX_AGE;
    let contents = &body[20..length];
    let mut prefixes = Vec::new();
    let name = v3_lsa_name(kind);

    match kind {
        // Intra-area prefix LSAs carry a count and then a list of prefixes.
        LSA_V3_INTRA_AREA_PREFIX => {
            if contents.len() >= 12 {
                let count = u16::from_be_bytes([contents[0], contents[1]]) as usize;
                let mut cursor = 12;
                for _ in 0..count.min(128) {
                    let Some((prefix, metric, used)) = read_v3_prefix(&contents[cursor..], true)
                    else {
                        break;
                    };
                    prefixes.push(AdvertisedPrefix {
                        prefix,
                        metric,
                        lsa_type: name.to_string(),
                        withdrawn,
                    });
                    cursor += used;
                }
            }
        }
        // Inter-area, external and NSSA prefix LSAs each carry one prefix after a metric.
        LSA_V3_INTER_AREA_PREFIX | LSA_V3_EXTERNAL | LSA_V3_NSSA if contents.len() >= 8 => {
            let metric = u32::from_be_bytes([0, contents[1], contents[2], contents[3]]);
            if let Some((prefix, _, _)) = read_v3_prefix(&contents[4..], false) {
                prefixes.push(AdvertisedPrefix {
                    prefix,
                    metric,
                    lsa_type: name.to_string(),
                    withdrawn,
                });
            }
        }
        _ => {}
    }

    Some(DecodedLsa {
        length,
        sequence,
        prefixes,
    })
}

/// Reads one OSPFv3 prefix: length, options, a metric or reserved field, then only the
/// significant bytes of the address (RFC 5340 §A.4.1).
fn read_v3_prefix(bytes: &[u8], carries_metric: bool) -> Option<(IpNet, u32, usize)> {
    if bytes.len() < 4 {
        return None;
    }
    let prefix_len = bytes[0];
    if prefix_len > 128 {
        return None;
    }
    let significant = (prefix_len as usize).div_ceil(8);
    // Prefixes are padded to a four-byte boundary.
    let padded = significant.div_ceil(4) * 4;
    if bytes.len() < 4 + padded {
        return None;
    }
    let metric = if carries_metric {
        u32::from(u16::from_be_bytes([bytes[2], bytes[3]]))
    } else {
        0
    };

    let mut raw = [0u8; 16];
    raw[..significant].copy_from_slice(&bytes[4..4 + significant]);
    let prefix = Ipv6Net::new(Ipv6Addr::from(raw), prefix_len).ok()?.trunc();
    Some((IpNet::V6(prefix), metric, 4 + padded))
}

fn v3_lsa_name(kind: u16) -> &'static str {
    match kind {
        LSA_V3_INTRA_AREA_PREFIX => "intra-area prefix",
        LSA_V3_INTER_AREA_PREFIX => "inter-area prefix",
        LSA_V3_EXTERNAL => "AS external",
        LSA_V3_NSSA => "NSSA external",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an OSPFv2 packet with a verifying checksum.
    fn v2_packet(kind: u8, au_type: u16, body: &[u8]) -> Vec<u8> {
        let mut packet = vec![2, kind, 0, 0];
        packet.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets()); // router id
        packet.extend_from_slice(&Ipv4Addr::new(0, 0, 0, 0).octets()); // area
        packet.extend_from_slice(&[0, 0]); // checksum
        packet.extend_from_slice(&au_type.to_be_bytes());
        // Authentication data: a password this decoder must never render.
        packet.extend_from_slice(b"s3cr3t!!");
        packet.extend_from_slice(body);

        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        let mut checksummed = packet.clone();
        checksummed[16..24].fill(0);
        let checksum = internet_checksum(&checksummed);
        packet[12..14].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    /// A summary LSA naming one network.
    fn summary_lsa(network: Ipv4Addr, mask: [u8; 4], age: u16, metric: u32) -> Vec<u8> {
        let mut lsa = Vec::new();
        lsa.extend_from_slice(&age.to_be_bytes());
        lsa.push(0); // options
        lsa.push(LSA_SUMMARY_NETWORK);
        lsa.extend_from_slice(&network.octets()); // link state id
        lsa.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets()); // advertising router
        lsa.extend_from_slice(&0x8000_0005u32.to_be_bytes()); // sequence
        lsa.extend_from_slice(&[0, 0]); // checksum
        lsa.extend_from_slice(&[0, 0]); // length, filled below
        lsa.extend_from_slice(&mask);
        lsa.extend_from_slice(&metric.to_be_bytes());
        let length = lsa.len() as u16;
        lsa[18..20].copy_from_slice(&length.to_be_bytes());
        lsa
    }

    fn update(lsas: &[Vec<u8>]) -> Vec<u8> {
        let mut body = (lsas.len() as u32).to_be_bytes().to_vec();
        for lsa in lsas {
            body.extend_from_slice(lsa);
        }
        body
    }

    #[test]
    fn a_hello_identifies_routers_and_creates_no_network() {
        // A router-id is not an address space and an area is not a subnet.
        let mut body = vec![255, 255, 255, 0]; // network mask
        body.extend_from_slice(&[0, 10]); // hello interval
        body.extend_from_slice(&[0, 0]); // options, priority
        body.extend_from_slice(&[0, 0, 0, 40]); // dead interval
        body.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets()); // designated router
        body.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets()); // backup
        body.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 3).octets()); // a neighbour

        let parsed = parse_v2(&v2_packet(HELLO, 0, &body)).expect("a valid hello");
        assert!(parsed.hello);
        assert_eq!(parsed.router_id, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(parsed.area, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(parsed.neighbours, vec![Ipv4Addr::new(10, 0, 0, 3)]);
        assert!(
            parsed.prefixes.is_empty(),
            "a hello carries no prefix and must create no network"
        );
    }

    #[test]
    fn a_complete_summary_lsa_names_a_network_elsewhere_in_the_domain() {
        // The reason to read OSPF at all: a summary LSA names networks this vantage has no
        // other way to learn about.
        let lsa = summary_lsa(Ipv4Addr::new(192, 168, 51, 0), [255, 255, 255, 0], 120, 10);
        let parsed =
            parse_v2(&v2_packet(LINK_STATE_UPDATE, 0, &update(&[lsa]))).expect("a valid update");

        assert_eq!(parsed.prefixes.len(), 1);
        assert_eq!(parsed.prefixes[0].prefix.to_string(), "192.168.51.0/24");
        assert_eq!(parsed.prefixes[0].metric, 10);
        assert_eq!(parsed.prefixes[0].lsa_type, "summary (network)");
        assert!(!parsed.prefixes[0].withdrawn);
        assert_eq!(parsed.sequences, vec![0x8000_0005]);
        assert_eq!(parsed.current_prefixes().count(), 1);
    }

    #[test]
    fn an_lsa_at_maxage_is_a_withdrawal_and_creates_nothing_current() {
        let lsa = summary_lsa(Ipv4Addr::new(10, 9, 0, 0), [255, 255, 0, 0], MAX_AGE, 20);
        let parsed =
            parse_v2(&v2_packet(LINK_STATE_UPDATE, 0, &update(&[lsa]))).expect("a valid update");

        assert_eq!(parsed.prefixes.len(), 1, "the withdrawal is still recorded");
        assert!(parsed.prefixes[0].withdrawn);
        assert_eq!(
            parsed.current_prefixes().count(),
            0,
            "an advertisement being withdrawn describes what is going away"
        );
    }

    #[test]
    fn a_cryptographically_authenticated_packet_is_reported_but_not_promoted() {
        // The digest cannot be verified without the key, so the packet is recorded and its
        // routes are not treated as current topology.
        let lsa = summary_lsa(Ipv4Addr::new(172, 20, 0, 0), [255, 255, 0, 0], 60, 5);
        let parsed =
            parse_v2(&v2_packet(LINK_STATE_UPDATE, 2, &update(&[lsa]))).expect("a valid update");

        assert_eq!(parsed.authentication, Authentication::Cryptographic);
        assert!(!parsed.authentication.routes_are_verifiable());
        assert_eq!(parsed.prefixes.len(), 1, "it is still reported");
        assert_eq!(
            parsed.current_prefixes().count(),
            0,
            "an unverifiable claim about someone else's network is not one to act on"
        );

        // A simple password authenticates nothing an observer could not also send, so it
        // neither adds trust nor removes it.
        let lsa = summary_lsa(Ipv4Addr::new(172, 21, 0, 0), [255, 255, 0, 0], 60, 5);
        let simple =
            parse_v2(&v2_packet(LINK_STATE_UPDATE, 1, &update(&[lsa]))).expect("a valid update");
        assert_eq!(simple.authentication, Authentication::Simple);
        assert_eq!(simple.current_prefixes().count(), 1);
    }

    #[test]
    fn authentication_material_never_reaches_the_evidence() {
        let lsa = summary_lsa(Ipv4Addr::new(10, 1, 0, 0), [255, 255, 0, 0], 60, 5);
        let packet = v2_packet(LINK_STATE_UPDATE, 1, &update(&[lsa]));
        assert!(
            packet.windows(8).any(|window| window == b"s3cr3t!!"),
            "the fixture must contain the password to be a real test"
        );

        let parsed = parse_v2(&packet).expect("a valid update");
        assert!(
            !parsed.raw.windows(8).any(|window| window == b"s3cr3t!!"),
            "the authentication field must be zeroed before any bytes are kept"
        );
        assert_eq!(&parsed.raw[16..24], &[0u8; 8]);
    }

    #[test]
    fn a_packet_whose_checksum_fails_is_refused_whole() {
        let lsa = summary_lsa(Ipv4Addr::new(10, 2, 0, 0), [255, 255, 0, 0], 60, 5);
        let mut packet = v2_packet(LINK_STATE_UPDATE, 0, &update(&[lsa]));
        packet[30] ^= 0xff;
        assert!(parse_v2(&packet).is_none());

        // A version this decoder does not speak.
        let mut wrong_version = v2_packet(HELLO, 0, &[0; 20]);
        wrong_version[0] = 9;
        assert!(parse_v2(&wrong_version).is_none());

        // Truncated at every length.
        let full = v2_packet(
            LINK_STATE_UPDATE,
            0,
            &update(&[summary_lsa(
                Ipv4Addr::new(10, 3, 0, 0),
                [255, 255, 0, 0],
                60,
                5,
            )]),
        );
        for length in 0..full.len() {
            assert!(parse_v2(&full[..length]).is_none());
        }
    }

    #[test]
    fn a_mask_that_is_not_a_prefix_creates_no_network() {
        // The same rule as everywhere else: choosing which bits were meant would invent it.
        let lsa = summary_lsa(Ipv4Addr::new(10, 4, 0, 0), [255, 0, 255, 0], 60, 5);
        let parsed = parse_v2(&v2_packet(LINK_STATE_UPDATE, 0, &update(&[lsa])))
            .expect("the packet is still valid");
        assert!(parsed.prefixes.is_empty());
    }

    #[test]
    fn an_ospfv3_prefix_lsa_names_an_ipv6_network() {
        let mut lsa = Vec::new();
        lsa.extend_from_slice(&60u16.to_be_bytes()); // age
        lsa.extend_from_slice(&LSA_V3_INTER_AREA_PREFIX.to_be_bytes());
        lsa.extend_from_slice(&[0, 0, 0, 1]); // link state id
        lsa.extend_from_slice(&[10, 0, 0, 1]); // advertising router
        lsa.extend_from_slice(&0x8000_0003u32.to_be_bytes()); // sequence
        lsa.extend_from_slice(&[0, 0]); // checksum
        lsa.extend_from_slice(&[0, 0]); // length
        lsa.extend_from_slice(&[0, 0, 0, 20]); // metric 20
        // Prefix: /48 of 2001:db8:51::, six significant bytes padded to eight.
        lsa.push(48);
        lsa.push(0); // options
        lsa.extend_from_slice(&[0, 0]); // reserved
        lsa.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x51, 0, 0]);
        let length = lsa.len() as u16;
        lsa[18..20].copy_from_slice(&length.to_be_bytes());

        let mut packet = vec![3, LINK_STATE_UPDATE, 0, 0];
        packet.extend_from_slice(&[10, 0, 0, 1]); // router id
        packet.extend_from_slice(&[0, 0, 0, 0]); // area
        packet.extend_from_slice(&[0, 0]); // checksum
        packet.extend_from_slice(&[0, 0]); // instance, reserved
        packet.extend_from_slice(&update(&[lsa]));
        let total = packet.len() as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());

        let parsed = parse_v3(&packet).expect("a valid v3 update");
        assert_eq!(parsed.protocol, "OSPFv3");
        assert_eq!(parsed.prefixes.len(), 1);
        assert_eq!(parsed.prefixes[0].prefix.to_string(), "2001:db8:51::/48");
        assert_eq!(parsed.prefixes[0].metric, 20);
        assert_eq!(parsed.current_prefixes().count(), 1);
    }
}
