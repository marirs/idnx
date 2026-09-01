use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MndpNeighbor {
    pub identity: String,
    pub mac_address: String,
    pub board_name: Option<String>,
    pub software_version: Option<String>,
    pub interface_name: Option<String>,
    pub ipv4_address: Option<Ipv4Addr>,
}

/// Parses a raw MikroTik MNDP UDP packet
pub fn parse_mndp_packet(payload: &[u8]) -> Option<MndpNeighbor> {
    if payload.len() < 8 {
        return None;
    }

    // Skip 4-byte MNDP header (seq / reserved)
    let mut offset = 4;

    let mut identity = None;
    let mut mac_address = None;
    let mut board_name = None;
    let mut software_version = None;
    let mut interface_name = None;
    let mut ipv4_address = None;

    while offset + 4 <= payload.len() {
        let tlv_type = ((payload[offset] as u16) << 8) | (payload[offset + 1] as u16);
        let tlv_len = ((payload[offset + 2] as usize) << 8) | (payload[offset + 3] as usize);
        offset += 4;

        if offset + tlv_len > payload.len() {
            break;
        }

        let value = &payload[offset..offset + tlv_len];
        offset += tlv_len;

        match tlv_type {
            0x0001 => {
                // MAC address (6 bytes)
                if value.len() == 6 {
                    mac_address = Some(format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        value[0], value[1], value[2], value[3], value[4], value[5]
                    ));
                }
            }
            0x0005 => {
                // Identity (RouterOS Name)
                identity = Some(String::from_utf8_lossy(value).trim().to_string());
            }
            0x0007 => {
                // Version
                software_version = Some(String::from_utf8_lossy(value).trim().to_string());
            }
            0x0008 => {
                // Platform (usually "MikroTik")
            }
            0x000c => {
                // Board name (e.g. RB5009, hEX)
                board_name = Some(String::from_utf8_lossy(value).trim().to_string());
            }
            0x0010 => {
                // Interface name
                interface_name = Some(String::from_utf8_lossy(value).trim().to_string());
            }
            0x0011 if value.len() == 4 => {
                // IPv4 Address (4 bytes)
                ipv4_address = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            _ => {}
        }
    }

    if let (Some(id), Some(mac)) = (identity, mac_address) {
        Some(MndpNeighbor {
            identity: id,
            mac_address: mac,
            board_name,
            software_version,
            interface_name,
            ipv4_address,
        })
    } else {
        None
    }
}

/// Listens for MikroTik MNDP broadcast packets on UDP port 5678
pub async fn listen_mndp_neighbors(listen_duration: Duration) -> Vec<MndpNeighbor> {
    let mut neighbors = Vec::new();
    let socket = match UdpSocket::bind("0.0.0.0:5678").await {
        Ok(s) => s,
        Err(_) => return neighbors,
    };

    let mut buf = [0u8; 1500];
    let start = tokio::time::Instant::now();

    while start.elapsed() < listen_duration {
        let remaining = listen_duration.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }

        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _addr))) => {
                if let Some(neighbor) = parse_mndp_packet(&buf[..len])
                    && !neighbors
                        .iter()
                        .any(|n: &MndpNeighbor| n.mac_address == neighbor.mac_address)
                {
                    neighbors.push(neighbor);
                }
            }
            _ => break,
        }
    }

    neighbors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mndp_synthetic_packet() {
        let mut packet = Vec::new();
        // Header (4 bytes)
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);

        // TLV 1: MAC address = 48:8f:5a:12:34:56
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x06]);
        packet.extend_from_slice(&[0x48, 0x8F, 0x5A, 0x12, 0x34, 0x56]);

        // TLV 5: Identity = "MikroTik-Main-Router"
        let ident = b"MikroTik-Main-Router";
        packet.extend_from_slice(&[0x00, 0x05]);
        packet.extend_from_slice(&(ident.len() as u16).to_be_bytes());
        packet.extend_from_slice(ident);

        // TLV 7: Version = "7.14 (stable)"
        let ver = b"7.14 (stable)";
        packet.extend_from_slice(&[0x00, 0x07]);
        packet.extend_from_slice(&(ver.len() as u16).to_be_bytes());
        packet.extend_from_slice(ver);

        // TLV 12 (0x000c): Board = "RB5009UG+S+IN"
        let board = b"RB5009UG+S+IN";
        packet.extend_from_slice(&[0x00, 0x0C]);
        packet.extend_from_slice(&(board.len() as u16).to_be_bytes());
        packet.extend_from_slice(board);

        let parsed = parse_mndp_packet(&packet).expect("Should parse MNDP packet");
        assert_eq!(parsed.identity, "MikroTik-Main-Router");
        assert_eq!(parsed.mac_address, "48:8f:5a:12:34:56");
        assert_eq!(parsed.software_version.as_deref(), Some("7.14 (stable)"));
        assert_eq!(parsed.board_name.as_deref(), Some("RB5009UG+S+IN"));
    }
}
