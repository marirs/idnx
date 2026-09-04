//! Passive IS-IS decoding (ISO 10589, RFC 1195, RFC 5305, RFC 5308, RFC 5120).
//!
//! Listen-only. IS-IS runs directly over the link layer rather than over IP, so it is
//! reachable only from a capture on the selected interface -- and it is the routing protocol
//! most likely to be carrying an enterprise's real prefix list.
//!
//! The same separation as everywhere else. A hello names an intermediate system, its level
//! and its area, which identifies infrastructure and creates no network. Only a reachability
//! TLV inside a link-state PDU carries a prefix, and only a complete one is read: a TLV
//! whose length disagrees with its contents is discarded rather than repaired, because the
//! bytes after it are not a prefix.
//!
//! Authentication (TLV 10) is never rendered. Where it carries anything other than a
//! cleartext password the digest cannot be verified without the key, so the PDU is reported
//! and counted and its prefixes are not promoted to current topology.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// PDU types (ISO 10589 §9).
const L1_HELLO: u8 = 15;
const L2_HELLO: u8 = 16;
const POINT_TO_POINT_HELLO: u8 = 17;
const L1_LINK_STATE: u8 = 18;
const L2_LINK_STATE: u8 = 20;

/// TLVs this decoder reads.
const TLV_AREA_ADDRESSES: u8 = 1;
const TLV_IP_INTERNAL_REACH: u8 = 128;
const TLV_IP_EXTERNAL_REACH: u8 = 130;
const TLV_AUTHENTICATION: u8 = 10;
const TLV_EXTENDED_IP_REACH: u8 = 135;
const TLV_MT_REACH: u8 = 222;
const TLV_IPV6_REACH: u8 = 236;
const TLV_MT_IPV6_REACH: u8 = 237;

/// Authentication type 1 is a cleartext password; anything else is a digest we cannot check.
const AUTH_CLEARTEXT: u8 = 1;

/// One prefix a reachability TLV carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachablePrefix {
    pub prefix: IpNet,
    pub metric: u32,
    /// Which TLV carried it.
    pub tlv: &'static str,
    /// Multi-topology identifier, where the TLV carried one.
    pub topology: Option<u16>,
    /// The TLV entry's own bytes.
    pub raw_entry: Vec<u8>,
}

/// What one IS-IS PDU disclosed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsisPdu {
    /// "L1", "L2" or "point-to-point".
    pub level: &'static str,
    /// The system id of the sender, as the twelve hex digits it is conventionally written.
    pub system_id: String,
    /// Area addresses the PDU listed.
    pub areas: Vec<String>,
    pub hello: bool,
    /// LSP sequence number, for link-state PDUs.
    pub sequence: Option<u32>,
    /// Whether authentication was present and unverifiable.
    pub unverifiable_authentication: bool,
    pub prefixes: Vec<ReachablePrefix>,
}

impl IsisPdu {
    /// Prefixes that may become current topology.
    pub fn current_prefixes(&self) -> impl Iterator<Item = &ReachablePrefix> {
        let verifiable = !self.unverifiable_authentication;
        self.prefixes.iter().filter(move |_| verifiable)
    }
}

/// Decodes an IS-IS PDU carried in an 802.2 LLC frame.
pub fn parse(pdu: &[u8]) -> Option<IsisPdu> {
    // Common header: intra-domain routeing protocol discriminator, header length, version,
    // system id length, PDU type, version, reserved, maximum area addresses.
    if pdu.len() < 8 || pdu[0] != 0x83 {
        return None;
    }
    let header_length = pdu[1] as usize;
    if header_length < 8 || header_length > pdu.len() {
        return None;
    }
    let pdu_type = pdu[4] & 0x1f;

    let (level, hello, id_at, tlv_at, sequence) = match pdu_type {
        L1_HELLO | L2_HELLO => {
            if pdu.len() < 27 {
                return None;
            }
            // ISO 10589 §9.5: common header (8), circuit type (1), then the source id.
            let level = if pdu_type == L1_HELLO { "L1" } else { "L2" };
            (level, true, 9, 27, None)
        }
        POINT_TO_POINT_HELLO => {
            if pdu.len() < 20 {
                return None;
            }
            // §9.7 has the same prefix, and its TLVs begin after the local circuit id.
            ("point-to-point", true, 9, 20, None)
        }
        L1_LINK_STATE | L2_LINK_STATE => {
            if pdu.len() < 27 {
                return None;
            }
            let level = if pdu_type == L1_LINK_STATE {
                "L1"
            } else {
                "L2"
            };
            let sequence = u32::from_be_bytes([pdu[20], pdu[21], pdu[22], pdu[23]]);
            (level, false, 12, 27, Some(sequence))
        }
        _ => return None,
    };

    if pdu.len() < id_at + 6 {
        return None;
    }
    let system_id = pdu[id_at..id_at + 6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|pair| pair.concat())
        .collect::<Vec<_>>()
        .join(".");

    let mut decoded = IsisPdu {
        level,
        system_id,
        areas: Vec::new(),
        hello,
        sequence,
        unverifiable_authentication: false,
        prefixes: Vec::new(),
    };

    let mut cursor = tlv_at;
    while cursor + 2 <= pdu.len() {
        let code = pdu[cursor];
        let length = pdu[cursor + 1] as usize;
        let end = cursor + 2 + length;
        if end > pdu.len() {
            // A TLV claiming more bytes than arrived: the PDU is truncated, and the bytes
            // after it are not a prefix.
            return None;
        }
        let value = &pdu[cursor + 2..end];

        match code {
            TLV_AUTHENTICATION => {
                // Never rendered. Only the type is read, and only to decide whether the
                // PDU's claims can be verified at all.
                if value.first().is_some_and(|kind| *kind != AUTH_CLEARTEXT) {
                    decoded.unverifiable_authentication = true;
                }
            }
            TLV_AREA_ADDRESSES => {
                let mut at = 0;
                while at < value.len() {
                    let area_length = value[at] as usize;
                    if at + 1 + area_length > value.len() {
                        break;
                    }
                    decoded.areas.push(
                        value[at + 1..at + 1 + area_length]
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<Vec<_>>()
                            .join(""),
                    );
                    at += 1 + area_length;
                }
            }
            TLV_IP_INTERNAL_REACH | TLV_IP_EXTERNAL_REACH => {
                let name = if code == TLV_IP_INTERNAL_REACH {
                    "IP internal reachability"
                } else {
                    "IP external reachability"
                };
                decoded.prefixes.extend(read_legacy_ip_reach(value, name));
            }
            TLV_EXTENDED_IP_REACH => {
                decoded.prefixes.extend(read_extended_ip_reach(
                    value,
                    None,
                    "extended IP reachability",
                ));
            }
            TLV_MT_REACH if value.len() >= 2 => {
                // Multi-topology: a two-byte topology identifier, then the same entries.
                {
                    let topology = u16::from_be_bytes([value[0], value[1]]) & 0x0fff;
                    decoded.prefixes.extend(read_extended_ip_reach(
                        &value[2..],
                        Some(topology),
                        "multi-topology reachability",
                    ));
                }
            }
            TLV_IPV6_REACH => {
                decoded
                    .prefixes
                    .extend(read_ipv6_reach(value, None, "IPv6 reachability"));
            }
            TLV_MT_IPV6_REACH if value.len() >= 2 => {
                let topology = u16::from_be_bytes([value[0], value[1]]) & 0x0fff;
                decoded.prefixes.extend(read_ipv6_reach(
                    &value[2..],
                    Some(topology),
                    "multi-topology IPv6 reachability",
                ));
            }
            _ => {}
        }
        cursor = end;
    }

    Some(decoded)
}

/// RFC 1195 reachability: four metric bytes, then an address and a mask.
fn read_legacy_ip_reach(value: &[u8], tlv: &'static str) -> Vec<ReachablePrefix> {
    let mut out = Vec::new();
    for entry in value.as_chunks::<12>().0 {
        let address = Ipv4Addr::new(entry[4], entry[5], entry[6], entry[7]);
        let mask = Ipv4Addr::new(entry[8], entry[9], entry[10], entry[11]);
        let Some(bits) = crate::probes::icmp_mask::prefix_length(mask) else {
            continue;
        };
        let Ok(prefix) = Ipv4Net::new(address, bits) else {
            continue;
        };
        out.push(ReachablePrefix {
            prefix: IpNet::V4(prefix.trunc()),
            // The default metric, with its supported bit masked off.
            metric: u32::from(entry[0] & 0x3f),
            tlv,
            topology: None,
            raw_entry: entry.to_vec(),
        });
    }
    out
}

/// RFC 5305 extended reachability: a wide metric, a control byte, then only the significant
/// bytes of the prefix.
fn read_extended_ip_reach(
    value: &[u8],
    topology: Option<u16>,
    tlv: &'static str,
) -> Vec<ReachablePrefix> {
    let mut out = Vec::new();
    let mut cursor = 0;

    while cursor + 5 <= value.len() {
        let metric = u32::from_be_bytes([
            value[cursor],
            value[cursor + 1],
            value[cursor + 2],
            value[cursor + 3],
        ]);
        let control = value[cursor + 4];
        let prefix_len = control & 0x3f;
        if prefix_len > 32 {
            return out;
        }
        let significant = (prefix_len as usize).div_ceil(8);
        // Bit 0x40 marks sub-TLVs, whose length byte follows the prefix.
        let has_sub_tlvs = control & 0x40 != 0;
        let sub_at = cursor + 5 + significant;
        let sub_length = if has_sub_tlvs {
            match value.get(sub_at) {
                Some(length) => 1 + *length as usize,
                None => return out,
            }
        } else {
            0
        };
        let end = sub_at + sub_length;
        if end > value.len() {
            return out;
        }

        let mut octets = [0u8; 4];
        octets[..significant].copy_from_slice(&value[cursor + 5..cursor + 5 + significant]);
        if let Ok(prefix) = Ipv4Net::new(Ipv4Addr::from(octets), prefix_len) {
            out.push(ReachablePrefix {
                prefix: IpNet::V4(prefix.trunc()),
                metric,
                tlv,
                topology,
                raw_entry: value[cursor..end].to_vec(),
            });
        }
        cursor = end;
    }
    out
}

/// RFC 5308 IPv6 reachability: a metric, control bits, a prefix length, then the significant
/// bytes of the prefix.
fn read_ipv6_reach(value: &[u8], topology: Option<u16>, tlv: &'static str) -> Vec<ReachablePrefix> {
    let mut out = Vec::new();
    let mut cursor = 0;

    while cursor + 6 <= value.len() {
        let metric = u32::from_be_bytes([
            value[cursor],
            value[cursor + 1],
            value[cursor + 2],
            value[cursor + 3],
        ]);
        let control = value[cursor + 4];
        let prefix_len = value[cursor + 5];
        if prefix_len > 128 {
            return out;
        }
        let significant = (prefix_len as usize).div_ceil(8);
        let sub_at = cursor + 6 + significant;
        let sub_length = if control & 0x20 != 0 {
            match value.get(sub_at) {
                Some(length) => 1 + *length as usize,
                None => return out,
            }
        } else {
            0
        };
        let end = sub_at + sub_length;
        if end > value.len() {
            return out;
        }

        let mut octets = [0u8; 16];
        octets[..significant].copy_from_slice(&value[cursor + 6..cursor + 6 + significant]);
        if let Ok(prefix) = Ipv6Net::new(Ipv6Addr::from(octets), prefix_len) {
            out.push(ReachablePrefix {
                prefix: IpNet::V6(prefix.trunc()),
                metric,
                tlv,
                topology,
                raw_entry: value[cursor..end].to_vec(),
            });
        }
        cursor = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a link-state PDU carrying the given TLVs.
    fn link_state(tlvs: &[u8]) -> Vec<u8> {
        let mut pdu = vec![0x83, 27, 1, 6, L2_LINK_STATE, 1, 0, 3];
        pdu.extend_from_slice(&[0, 0]); // pdu length
        pdu.extend_from_slice(&[0, 30]); // remaining lifetime
        // LSP id: system id, pseudonode, fragment.
        pdu.extend_from_slice(&[0x19, 0x21, 0x68, 0x00, 0x00, 0x01, 0, 0]);
        pdu.extend_from_slice(&0x0000_002au32.to_be_bytes()); // sequence
        pdu.extend_from_slice(&[0, 0]); // checksum
        pdu.push(0x03); // type block
        pdu.extend_from_slice(tlvs);
        pdu
    }

    fn hello(tlvs: &[u8]) -> Vec<u8> {
        let mut pdu = vec![0x83, 27, 1, 6, L2_HELLO, 1, 0, 3];
        pdu.push(1); // circuit type
        pdu.extend_from_slice(&[0x19, 0x21, 0x68, 0x00, 0x00, 0x02]); // system id at 6..12
        pdu.extend_from_slice(&[0, 30]); // holding time
        pdu.extend_from_slice(&[0, 0]); // pdu length
        pdu.push(64); // priority
        pdu.extend_from_slice(&[0x19, 0x21, 0x68, 0x00, 0x00, 0x02, 0]); // LAN id
        while pdu.len() < 27 {
            pdu.push(0);
        }
        pdu.extend_from_slice(tlvs);
        pdu
    }

    #[test]
    fn a_hello_names_an_intermediate_system_and_creates_no_network() {
        let mut tlvs = vec![TLV_AREA_ADDRESSES, 4, 3, 0x49, 0x00, 0x01];
        tlvs.extend_from_slice(&[TLV_AUTHENTICATION, 2, AUTH_CLEARTEXT, b'x']);

        let parsed = parse(&hello(&tlvs)).expect("a valid hello");
        assert!(parsed.hello);
        assert_eq!(parsed.level, "L2");
        assert_eq!(parsed.system_id, "1921.6800.0002");
        assert_eq!(parsed.areas, vec!["490001".to_string()]);
        assert!(
            parsed.prefixes.is_empty(),
            "a hello identifies infrastructure and carries no prefix"
        );
        assert!(!parsed.unverifiable_authentication);
    }

    #[test]
    fn an_extended_reachability_tlv_names_an_ipv4_network() {
        // 192.168.51.0/24 at metric 10: three significant octets.
        let mut entry = 10u32.to_be_bytes().to_vec();
        entry.push(24);
        entry.extend_from_slice(&[192, 168, 51]);
        let mut tlvs = vec![TLV_EXTENDED_IP_REACH, entry.len() as u8];
        tlvs.extend_from_slice(&entry);

        let parsed = parse(&link_state(&tlvs)).expect("a valid LSP");
        assert!(!parsed.hello);
        assert_eq!(parsed.sequence, Some(42));
        assert_eq!(parsed.prefixes.len(), 1);
        assert_eq!(parsed.prefixes[0].prefix.to_string(), "192.168.51.0/24");
        assert_eq!(parsed.prefixes[0].metric, 10);
        assert_eq!(parsed.prefixes[0].tlv, "extended IP reachability");
        assert_eq!(parsed.prefixes[0].topology, None);
        assert_eq!(parsed.current_prefixes().count(), 1);
    }

    #[test]
    fn legacy_and_ipv6_and_multi_topology_reachability_are_all_read() {
        // RFC 1195: metric bytes, address, mask.
        let mut legacy = vec![10u8, 0x80, 0x80, 0x80];
        legacy.extend_from_slice(&[10, 9, 0, 0]);
        legacy.extend_from_slice(&[255, 255, 0, 0]);
        let mut tlvs = vec![TLV_IP_INTERNAL_REACH, legacy.len() as u8];
        tlvs.extend_from_slice(&legacy);

        // RFC 5308: metric, control, prefix length, significant bytes.
        let mut v6 = 20u32.to_be_bytes().to_vec();
        v6.push(0);
        v6.push(48);
        v6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x51]);
        tlvs.push(TLV_IPV6_REACH);
        tlvs.push(v6.len() as u8);
        tlvs.extend_from_slice(&v6);

        // RFC 5120: a topology identifier, then extended entries.
        let mut mt = vec![0x00, 0x02];
        mt.extend_from_slice(&30u32.to_be_bytes());
        mt.push(16);
        mt.extend_from_slice(&[172, 20]);
        tlvs.push(TLV_MT_REACH);
        tlvs.push(mt.len() as u8);
        tlvs.extend_from_slice(&mt);

        let parsed = parse(&link_state(&tlvs)).expect("a valid LSP");
        let named: Vec<String> = parsed
            .prefixes
            .iter()
            .map(|prefix| prefix.prefix.to_string())
            .collect();
        assert!(named.contains(&"10.9.0.0/16".to_string()), "{named:?}");
        assert!(named.contains(&"2001:db8:51::/48".to_string()), "{named:?}");
        assert!(named.contains(&"172.20.0.0/16".to_string()), "{named:?}");

        let topology = parsed
            .prefixes
            .iter()
            .find(|prefix| prefix.topology.is_some())
            .expect("the multi-topology entry keeps its identifier");
        assert_eq!(topology.topology, Some(2));
        for prefix in &parsed.prefixes {
            assert!(!prefix.raw_entry.is_empty(), "entry bytes are retained");
        }
    }

    #[test]
    fn unverifiable_authentication_reports_the_pdu_without_promoting_its_routes() {
        let mut entry = 10u32.to_be_bytes().to_vec();
        entry.push(24);
        entry.extend_from_slice(&[192, 168, 52]);
        let mut tlvs = vec![TLV_EXTENDED_IP_REACH, entry.len() as u8];
        tlvs.extend_from_slice(&entry);
        // Type 54 is HMAC-MD5: a digest this decoder cannot check without the key.
        tlvs.extend_from_slice(&[TLV_AUTHENTICATION, 3, 54, 0xab, 0xcd]);

        let parsed = parse(&link_state(&tlvs)).expect("a valid LSP");
        assert!(parsed.unverifiable_authentication);
        assert_eq!(parsed.prefixes.len(), 1, "the PDU is still reported");
        assert_eq!(
            parsed.current_prefixes().count(),
            0,
            "an unverifiable claim is not promoted to current topology"
        );
    }

    #[test]
    fn a_tlv_longer_than_the_pdu_discards_it_rather_than_reading_past() {
        let mut pdu = link_state(&[TLV_EXTENDED_IP_REACH, 40, 0, 0, 0, 10, 24, 192, 168, 51]);
        assert!(parse(&pdu).is_none());

        // A mask that is not a prefix creates nothing, and the rest still parses.
        let mut legacy = vec![10u8, 0x80, 0x80, 0x80];
        legacy.extend_from_slice(&[10, 9, 0, 0]);
        legacy.extend_from_slice(&[255, 0, 255, 0]);
        let mut tlvs = vec![TLV_IP_INTERNAL_REACH, legacy.len() as u8];
        tlvs.extend_from_slice(&legacy);
        let parsed = parse(&link_state(&tlvs)).expect("the PDU is valid");
        assert!(parsed.prefixes.is_empty());

        // Not IS-IS at all.
        pdu = link_state(&[]);
        pdu[0] = 0x42;
        assert!(parse(&pdu).is_none());

        // Truncated at every length.
        let full = link_state(&[TLV_AREA_ADDRESSES, 4, 3, 0x49, 0x00, 0x01]);
        for length in 0..full.len() {
            let _ = parse(&full[..length]);
        }
    }
}
