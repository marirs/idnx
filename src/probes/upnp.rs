use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UpnpDevice {
    pub ip: Ipv4Addr,
    pub location: Option<String>,
    pub server: Option<String>,
    pub device_type: Option<String>,
}

/// Broadcasts SSDP M-SEARCH query to discover UPnP/IGD routers and gateways on the LAN
pub async fn discover_upnp_devices(timeout_duration: Duration) -> Vec<UpnpDevice> {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let _ = socket.set_broadcast(true);

    let msg = b"M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 1\r\n\
ST: ssdp:all\r\n\r\n";

    if socket.send_to(msg, "239.255.255.250:1900").await.is_err() {
        return Vec::new();
    }

    let mut devices_map: HashMap<Ipv4Addr, UpnpDevice> = HashMap::new();
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
                    let ip = *v4.ip();
                    let raw = String::from_utf8_lossy(&buf[..len]);

                    let mut location = None;
                    let mut server = None;
                    let mut st = None;

                    for line in raw.lines() {
                        let lower = line.to_lowercase();
                        if lower.starts_with("location:") {
                            location = Some(line[9..].trim().to_string());
                        } else if lower.starts_with("server:") {
                            server = Some(line[7..].trim().to_string());
                        } else if lower.starts_with("st:") {
                            st = Some(line[3..].trim().to_string());
                        }
                    }

                    devices_map.entry(ip).or_insert(UpnpDevice {
                        ip,
                        location,
                        server,
                        device_type: st,
                    });
                }
            }
            _ => break,
        }
    }

    devices_map.into_values().collect()
}
