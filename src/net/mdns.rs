use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Builds a DNS PTR query for `<ip>.in-addr.arpa`
fn build_ptr_query(ip: Ipv4Addr) -> Vec<u8> {
    let octets = ip.octets();
    let mut packet = Vec::with_capacity(64);

    // Header: ID=0, Flags=0, Questions=1, Answer RRs=0, Authority RRs=0, Additional RRs=0
    packet.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    // QNAME: <d>.<c>.<b>.<a>.in-addr.arpa
    for octet in octets.iter().rev() {
        let s = octet.to_string();
        packet.push(s.len() as u8);
        packet.extend_from_slice(s.as_bytes());
    }
    packet.push(7);
    packet.extend_from_slice(b"in-addr");
    packet.push(4);
    packet.extend_from_slice(b"arpa");
    packet.push(0); // Root label

    // QTYPE: PTR (12), QCLASS: IN (1)
    packet.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]);

    packet
}

/// Parses domain name from DNS packet at given offset
fn parse_dns_name(packet: &[u8], mut offset: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut loop_count = 0;

    while offset < packet.len() && loop_count < 15 {
        loop_count += 1;
        let len = packet[offset] as usize;
        if len == 0 {
            break;
        }

        // Pointer (compression)
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                return None;
            }
            let ptr_offset = ((len & 0x3F) << 8) | (packet[offset + 1] as usize);
            if ptr_offset >= packet.len() {
                return None;
            }
            if !jumped {
                jumped = true;
            }
            offset = ptr_offset;
            continue;
        }

        offset += 1;
        if offset + len > packet.len() {
            return None;
        }

        if let Ok(label) = std::str::from_utf8(&packet[offset..offset + len]) {
            labels.push(label);
        }
        offset += len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Discovers mDNS hostnames for all provided IPs using multicast DNS queries
pub async fn resolve_mdns_hostnames(
    ips: &[Ipv4Addr],
    timeout_duration: Duration,
) -> HashMap<Ipv4Addr, String> {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return HashMap::new(),
    };

    let _ = socket.set_broadcast(true);
    let mdns_dest = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);

    // Send PTR query for each IP
    for &ip in ips {
        let q = build_ptr_query(ip);
        let _ = socket.send_to(&q, mdns_dest).await;
    }

    let mut results = HashMap::new();
    let mut buf = [0u8; 2048];
    let start = tokio::time::Instant::now();

    while start.elapsed() < timeout_duration {
        let remaining = timeout_duration.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }

        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                if let std::net::SocketAddr::V4(v4) = src {
                    let sender_ip = *v4.ip();
                    if ips.contains(&sender_ip) {
                        let packet = &buf[..len];
                        if packet.len() > 12 {
                            let ancount = ((packet[6] as u16) << 8) | (packet[7] as u16);
                            if ancount > 0 {
                                // Find PTR target in answer section
                                // Scan for .local or name labels
                                if let Some(name) = extract_ptr_target(packet) {
                                    let clean_name = name
                                        .trim_end_matches(".local")
                                        .trim_end_matches('.')
                                        .to_string();
                                    if !clean_name.is_empty() && !clean_name.contains("in-addr") {
                                        results.insert(sender_ip, clean_name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => break,
        }
    }

    results
}

fn extract_ptr_target(packet: &[u8]) -> Option<String> {
    // Quick scan for question section skip
    if packet.len() < 12 {
        return None;
    }
    let qdcount = ((packet[4] as u16) << 8) | (packet[5] as u16);
    let mut offset = 12;

    // Skip questions
    for _ in 0..qdcount {
        while offset < packet.len() && packet[offset] != 0 {
            if (packet[offset] & 0xC0) == 0xC0 {
                offset += 2;
                break;
            }
            offset += 1 + (packet[offset] as usize);
        }
        if offset < packet.len() && packet[offset] == 0 {
            offset += 1;
        }
        offset += 4; // QTYPE + QCLASS
    }

    // Parse answer RRs
    if offset < packet.len() {
        // Skip NAME
        if (packet[offset] & 0xC0) == 0xC0 {
            offset += 2;
        } else {
            while offset < packet.len() && packet[offset] != 0 {
                offset += 1 + (packet[offset] as usize);
            }
            offset += 1;
        }

        if offset + 10 <= packet.len() {
            let rtype = ((packet[offset] as u16) << 8) | (packet[offset + 1] as u16);
            let rdlength = ((packet[offset + 8] as usize) << 8) | (packet[offset + 9] as usize);
            offset += 10;

            if rtype == 12 && offset + rdlength <= packet.len() {
                // PTR record
                return parse_dns_name(packet, offset);
            }
        }
    }

    None
}
