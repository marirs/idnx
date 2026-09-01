use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpNeighbor {
    pub device_id: String,
    pub port_id: String,
    pub platform: Option<String>,
    pub software_version: Option<String>,
    pub management_ip: Option<Ipv4Addr>,
    pub native_vlan: Option<u16>,
    pub capabilities: Vec<String>,
}

/// Parses a raw Cisco Discovery Protocol (CDP) frame.
/// Supports both raw LLC/SNAP encapsulated frames and CDP payload directly.
pub fn parse_cdp_frame(payload: &[u8]) -> Option<CdpNeighbor> {
    if payload.len() < 4 {
        return None;
    }

    // Check if Ethernet + LLC/SNAP header is present
    let mut offset = 0;
    if payload.len() >= 22 {
        // Destination MAC 01:00:0c:cc:cc:cc
        if payload[0..6] == [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC] {
            // Check LLC/SNAP: AA AA 03 00 00 0C 20 00
            let snap_offset = 14;
            if payload.len() >= snap_offset + 8
                && payload[snap_offset..snap_offset + 8]
                    == [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00]
            {
                offset = snap_offset + 8;
            }
        }
    }

    if offset + 4 > payload.len() {
        return None;
    }

    let version = payload[offset];
    if version != 1 && version != 2 {
        return None;
    }

    // Skip version (1), ttl (1), checksum (2)
    offset += 4;

    let mut device_id = None;
    let mut port_id = None;
    let mut platform = None;
    let mut software_version = None;
    let mut management_ip = None;
    let mut native_vlan = None;
    let mut capabilities = Vec::new();

    while offset + 4 <= payload.len() {
        let tlv_type = ((payload[offset] as u16) << 8) | (payload[offset + 1] as u16);
        let tlv_len = ((payload[offset + 2] as u16) << 8) | (payload[offset + 3] as u16);

        if tlv_len < 4 || offset + (tlv_len as usize) > payload.len() {
            break;
        }

        let val_len = (tlv_len as usize) - 4;
        let val_start = offset + 4;
        let value = &payload[val_start..val_start + val_len];
        offset += tlv_len as usize;

        match tlv_type {
            0x0001 => {
                // Device ID (Hostname)
                device_id = Some(String::from_utf8_lossy(value).trim().to_string());
            }
            0x0002 => {
                // Addresses TLV
                if value.len() >= 4 {
                    let num_addrs = ((value[0] as u32) << 24)
                        | ((value[1] as u32) << 16)
                        | ((value[2] as u32) << 8)
                        | (value[3] as u32);
                    let mut addr_off = 4;
                    for _ in 0..num_addrs {
                        if addr_off + 4 > value.len() {
                            break;
                        }
                        let proto_type = value[addr_off];
                        let proto_len = value[addr_off + 1] as usize;
                        addr_off += 2;
                        if addr_off + proto_len + 2 > value.len() {
                            break;
                        }
                        // Check if protocol is IPv4 (NLPID 0xCC or 1 byte 0xCC)
                        let is_ip = proto_type == 1 && proto_len == 1 && value[addr_off] == 0xCC;
                        addr_off += proto_len;

                        let addr_len =
                            ((value[addr_off] as usize) << 8) | (value[addr_off + 1] as usize);
                        addr_off += 2;
                        if addr_off + addr_len > value.len() {
                            break;
                        }

                        if is_ip && addr_len == 4 && management_ip.is_none() {
                            management_ip = Some(Ipv4Addr::new(
                                value[addr_off],
                                value[addr_off + 1],
                                value[addr_off + 2],
                                value[addr_off + 3],
                            ));
                        }
                        addr_off += addr_len;
                    }
                }
            }
            0x0003 => {
                // Port ID
                port_id = Some(String::from_utf8_lossy(value).trim().to_string());
            }
            0x0004 => {
                // Capabilities (4 bytes)
                if value.len() >= 4 {
                    let caps = ((value[0] as u32) << 24)
                        | ((value[1] as u32) << 16)
                        | ((value[2] as u32) << 8)
                        | (value[3] as u32);
                    if caps & 0x01 != 0 {
                        capabilities.push("Router".to_string());
                    }
                    if caps & 0x02 != 0 {
                        capabilities.push("Transparent Bridge".to_string());
                    }
                    if caps & 0x04 != 0 {
                        capabilities.push("Source Route Bridge".to_string());
                    }
                    if caps & 0x08 != 0 {
                        capabilities.push("Switch".to_string());
                    }
                    if caps & 0x10 != 0 {
                        capabilities.push("Host".to_string());
                    }
                    if caps & 0x20 != 0 {
                        capabilities.push("IGMP".to_string());
                    }
                    if caps & 0x40 != 0 {
                        capabilities.push("Repeater".to_string());
                    }
                }
            }
            0x0005 => {
                // Software Version
                software_version = Some(String::from_utf8_lossy(value).trim().to_string());
            }
            0x0006 => {
                // Platform (Hardware Model)
                platform = Some(String::from_utf8_lossy(value).trim().to_string());
            }
            0x000a if value.len() >= 2 => {
                // Native VLAN (2 bytes)
                native_vlan = Some(((value[0] as u16) << 8) | (value[1] as u16));
            }
            _ => {}
        }
    }

    if let (Some(dev), Some(port)) = (device_id, port_id) {
        Some(CdpNeighbor {
            device_id: dev,
            port_id: port,
            platform,
            software_version,
            management_ip,
            native_vlan,
            capabilities,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cdp_synthetic_frame() {
        let mut frame = Vec::new();
        // Ethernet Header: Dest MAC 01:00:0c:cc:cc:cc + Src MAC + EtherType 0x0064
        frame.extend_from_slice(&[0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&[0x00, 0x64]); // Length

        // LLC/SNAP header
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00]);

        // CDP Header: Version 2, TTL 180, Checksum 0x0000
        frame.extend_from_slice(&[0x02, 0xB4, 0x00, 0x00]);

        // TLV 1: Device ID = "Cisco-Core-SW1"
        let dev_id = b"Cisco-Core-SW1";
        frame.extend_from_slice(&[0x00, 0x01]);
        frame.extend_from_slice(&((dev_id.len() + 4) as u16).to_be_bytes());
        frame.extend_from_slice(dev_id);

        // TLV 3: Port ID = "GigabitEthernet0/1"
        let port_id = b"GigabitEthernet0/1";
        frame.extend_from_slice(&[0x00, 0x03]);
        frame.extend_from_slice(&((port_id.len() + 4) as u16).to_be_bytes());
        frame.extend_from_slice(port_id);

        // TLV 6: Platform = "cisco WS-C2960-24TT-L"
        let platform = b"cisco WS-C2960-24TT-L";
        frame.extend_from_slice(&[0x00, 0x06]);
        frame.extend_from_slice(&((platform.len() + 4) as u16).to_be_bytes());
        frame.extend_from_slice(platform);

        // TLV 0x0a: Native VLAN = 10
        frame.extend_from_slice(&[0x00, 0x0A, 0x00, 0x06, 0x00, 0x0A]);

        let parsed = parse_cdp_frame(&frame).expect("Should parse CDP frame");
        assert_eq!(parsed.device_id, "Cisco-Core-SW1");
        assert_eq!(parsed.port_id, "GigabitEthernet0/1");
        assert_eq!(parsed.platform.as_deref(), Some("cisco WS-C2960-24TT-L"));
        assert_eq!(parsed.native_vlan, Some(10));
    }
}
