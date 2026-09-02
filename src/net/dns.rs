use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::time::timeout;

/// Asynchronously resolves reverse DNS (PTR) records for a list of IPv4 addresses
/// using a specified DNS server (typically the subnet gateway router running dnsmasq).
pub async fn resolve_unicast_dns_ptrs(
    ips: &[Ipv4Addr],
    dns_server: Ipv4Addr,
    binding: &crate::net::socket::SocketBinding,
    timeout_duration: Duration,
) -> HashMap<Ipv4Addr, String> {
    let mut results = HashMap::new();
    if ips.is_empty() {
        return results;
    }

    let server_addr = SocketAddrV4::new(dns_server, 53);
    let socket = match binding
        .udp_socket(&std::net::SocketAddr::V4(server_addr))
        .await
    {
        Ok(s) => s,
        Err(_) => return results,
    };

    for (idx, &ip) in ips.iter().enumerate() {
        let octets = ip.octets();
        let ptr_name = format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        );

        // Build DNS query packet
        let tx_id = (0x5000 + (idx as u16)).to_be_bytes();
        let flags = [0x01, 0x00]; // Standard query with recursion
        let qdcount = [0x00, 0x01];
        let ancount = [0x00, 0x00];
        let nscount = [0x00, 0x00];
        let arcount = [0x00, 0x00];

        let mut packet = Vec::with_capacity(64);
        packet.extend_from_slice(&tx_id);
        packet.extend_from_slice(&flags);
        packet.extend_from_slice(&qdcount);
        packet.extend_from_slice(&ancount);
        packet.extend_from_slice(&nscount);
        packet.extend_from_slice(&arcount);

        for label in ptr_name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label
        packet.extend_from_slice(&[0x00, 0x0c]); // Type PTR (12)
        packet.extend_from_slice(&[0x00, 0x01]); // Class IN (1)

        let _ = socket.send_to(&packet, server_addr).await;
    }

    let mut buf = [0u8; 1024];
    let start = tokio::time::Instant::now();

    while start.elapsed() < timeout_duration {
        let remaining = timeout_duration.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }

        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                if len > 12 {
                    let data = &buf[..len];
                    let ancount = ((data[6] as u16) << 8) | (data[7] as u16);
                    if ancount > 0 {
                        // Locate answer section (after question)
                        let mut offset = 12;
                        while offset < len && data[offset] != 0 {
                            let l = data[offset] as usize;
                            if l & 0xC0 == 0xC0 {
                                offset += 2;
                                break;
                            }
                            offset += 1 + l;
                        }
                        if offset < len && data[offset] == 0 {
                            offset += 1;
                        }
                        offset += 4; // Skip QTYPE and QCLASS

                        if offset + 12 <= len {
                            // Skip NAME (pointer 2 bytes or labels)
                            if data[offset] & 0xC0 == 0xC0 {
                                offset += 2;
                            } else {
                                while offset < len && data[offset] != 0 {
                                    offset += 1 + (data[offset] as usize);
                                }
                                if offset < len {
                                    offset += 1;
                                }
                            }
                            offset += 8; // Skip TYPE, CLASS, TTL
                            if offset + 2 <= len {
                                let rdlength =
                                    ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
                                offset += 2;
                                if offset + rdlength <= len {
                                    let mut name_parts = Vec::new();
                                    let mut cur = offset;
                                    let end = offset + rdlength;
                                    while cur < end && data[cur] != 0 {
                                        if data[cur] & 0xC0 == 0xC0 {
                                            break;
                                        }
                                        let l = data[cur] as usize;
                                        cur += 1;
                                        if cur + l <= end {
                                            name_parts.push(
                                                String::from_utf8_lossy(&data[cur..cur + l])
                                                    .to_string(),
                                            );
                                            cur += l;
                                        } else {
                                            break;
                                        }
                                    }

                                    if !name_parts.is_empty() {
                                        let hostname = name_parts[0].clone();
                                        // Match transaction ID back to IP
                                        let tx_id = ((data[0] as u16) << 8) | (data[1] as u16);
                                        let idx = tx_id.saturating_sub(0x5000) as usize;
                                        if idx < ips.len() {
                                            results.insert(ips[idx], hostname);
                                        }
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
