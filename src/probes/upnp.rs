use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UpnpDevice {
    pub ip: Ipv4Addr,
    pub friendly_name: Option<String>,
    pub model_name: Option<String>,
    pub model_description: Option<String>,
    pub manufacturer: Option<String>,
    pub location: Option<String>,
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let val = xml[start..end].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

/// Fetches UPnP device description XML from a location URL (e.g. http://192.168.1.1:49153/wps_device.xml)
async fn fetch_upnp_description(
    location_url: &str,
) -> Option<(
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
)> {
    // Parse URL: http://host:port/path
    let stripped = location_url.strip_prefix("http://")?;
    let slash_pos = stripped.find('/')?;
    let host_port = &stripped[..slash_pos];
    let path = &stripped[slash_pos..];

    let (host, port) = if let Some(colon) = host_port.find(':') {
        let h = &host_port[..colon];
        let p: u16 = host_port[colon + 1..].parse().ok()?;
        (h, p)
    } else {
        (host_port, 80)
    };

    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(Duration::from_millis(600), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host_port
    );
    timeout(Duration::from_millis(600), stream.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 1024];
    while let Ok(Ok(n)) = timeout(Duration::from_millis(400), stream.read(&mut temp)).await {
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&temp[..n]);
        if buf.len() > 16384 {
            break;
        }
    }

    let xml = String::from_utf8_lossy(&buf);
    let friendly_name = extract_tag(&xml, "friendlyName");
    let model_name = extract_tag(&xml, "modelName");
    let model_desc = extract_tag(&xml, "modelDescription");
    let manufacturer = extract_tag(&xml, "manufacturer");

    Some((friendly_name, model_name, model_desc, manufacturer))
}

/// Broadcasts SSDP M-SEARCH query and fetches device descriptions for routers/gateways
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

    let mut locations: HashMap<Ipv4Addr, String> = HashMap::new();
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

                    for line in raw.lines() {
                        let lower = line.to_lowercase();
                        if lower.starts_with("location:") {
                            let loc = line[9..].trim().to_string();
                            locations.entry(ip).or_insert(loc);
                        }
                    }
                }
            }
            _ => break,
        }
    }

    let mut devices = Vec::new();
    for (ip, loc) in locations {
        let (friendly_name, model_name, model_desc, manufacturer) = fetch_upnp_description(&loc)
            .await
            .unwrap_or((None, None, None, None));

        devices.push(UpnpDevice {
            ip,
            friendly_name,
            model_name,
            model_description: model_desc,
            manufacturer,
            location: Some(loc),
        });
    }

    devices
}
