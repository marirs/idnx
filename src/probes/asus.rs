use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct AsusRouterDiscovery {
    pub ip: Ipv4Addr,
    pub model_name: Option<String>,
    pub mac_address: Option<String>,
    pub firmware_version: Option<String>,
    pub ssid: Option<String>,
}

/// Probes the ASUS proprietary Device Discovery service on UDP port 9999 / 18017
/// Used by ASUSWRT routers (RT-BE, RT-AX, GT, etc.)
pub async fn discover_asus_routers(timeout_duration: Duration) -> Vec<AsusRouterDiscovery> {
    let mut discovered = Vec::new();

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(_) => return discovered,
    };

    let _ = socket.set_broadcast(true);

    let payloads: &[&[u8]] = &[b"\x0c\x15\x00\x00", b"IBOX\x00\x00\x00\x00", b"INFO"];
    let bcast_addr = SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), 9999);
    for payload in payloads {
        let _ = socket.send_to(payload, bcast_addr).await;
    }

    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + timeout_duration;

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, peer))) => {
                if let std::net::SocketAddr::V4(v4) = peer {
                    let data = &buf[..len];
                    let raw_str = String::from_utf8_lossy(data);

                    let mut model_name = None;
                    let mut ssid = None;

                    for part in raw_str.split('\0') {
                        let part = part.trim();
                        if part.starts_with("RT-")
                            || part.starts_with("GT-")
                            || part.starts_with("BE")
                        {
                            model_name = Some(part.to_string());
                        } else if part.len() > 3 && !part.contains('.') && ssid.is_none() {
                            ssid = Some(part.to_string());
                        }
                    }

                    discovered.push(AsusRouterDiscovery {
                        ip: *v4.ip(),
                        model_name,
                        mac_address: None,
                        firmware_version: None,
                        ssid,
                    });
                }
            }
            _ => break,
        }
    }

    discovered
}
