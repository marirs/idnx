use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::net::socket::SocketBinding;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UpnpDevice {
    pub ip: Ipv4Addr,
    pub friendly_name: Option<String>,
    pub model_name: Option<String>,
    pub model_description: Option<String>,
    pub manufacturer: Option<String>,
    pub location: Option<String>,
    /// UPnP `deviceType` URN, e.g.
    /// `urn:schemas-upnp-org:device:InternetGatewayDevice:2`.
    ///
    /// A device declaring itself an InternetGatewayDevice is asserting that it routes.
    /// That is behavioural role evidence available without any credential, which is why it
    /// is captured rather than discarded with the rest of the descriptor.
    pub device_type: Option<String>,
    /// Every device and service URN the responder announced over SSDP.
    pub announced_types: Vec<String>,
}

impl UpnpDevice {
    /// True when the device advertises the UPnP InternetGatewayDevice profile.
    ///
    /// Checks the announced URNs as well as the fetched descriptor: a router may refuse a
    /// connection to its own description document while still announcing the profile, and
    /// the announcement alone is sufficient evidence that it routes.
    pub fn is_internet_gateway(&self) -> bool {
        let in_descriptor = self
            .device_type
            .as_deref()
            .is_some_and(|t| t.contains("InternetGatewayDevice"));
        in_descriptor
            || self
                .announced_types
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("internetgatewaydevice"))
    }
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
/// Fields extracted from a UPnP device description document.
struct UpnpDescription {
    friendly_name: Option<String>,
    model_name: Option<String>,
    model_description: Option<String>,
    manufacturer: Option<String>,
    device_type: Option<String>,
}

async fn fetch_upnp_description(
    location_url: &str,
    binding: &SocketBinding,
) -> Option<UpnpDescription> {
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

    // Resolved rather than passed as a string, so the connection can be bound to the
    // interface the advertisement arrived on.
    let destination: std::net::SocketAddr = format!("{host}:{port}").parse().ok()?;
    let mut stream = binding
        .tcp_connect(destination, Duration::from_millis(600))
        .await
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
    Some(UpnpDescription {
        friendly_name: extract_tag(&xml, "friendlyName"),
        model_name: extract_tag(&xml, "modelName"),
        model_description: extract_tag(&xml, "modelDescription"),
        manufacturer: extract_tag(&xml, "manufacturer"),
        device_type: extract_tag(&xml, "deviceType"),
    })
}

/// Broadcasts SSDP M-SEARCH query and fetches device descriptions for routers/gateways
pub async fn discover_upnp_devices(
    binding: &SocketBinding,
    timeout_duration: Duration,
) -> Vec<UpnpDevice> {
    // SSDP is link-local multicast. Sent from the wrong interface it reaches a different
    // link entirely, and every answer would be attributed to a vantage that never sent it.
    let socket = match binding.udp_broadcast().await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let msg = b"M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 1\r\n\
ST: ssdp:all\r\n\r\n";

    if socket.send_to(msg, "239.255.255.250:1900").await.is_err() {
        return Vec::new();
    }

    // Per responder: every advertised descriptor location, and every device/service URN it
    // announced. Keeping only the first location loses working descriptors when a device
    // publishes several, and the URNs are themselves evidence.
    let mut locations: HashMap<Ipv4Addr, Vec<String>> = HashMap::new();
    let mut urns: HashMap<Ipv4Addr, Vec<String>> = HashMap::new();
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
                            let entry = locations.entry(ip).or_default();
                            if !entry.contains(&loc) {
                                entry.push(loc);
                            }
                        } else if let Some(rest) = lower
                            .strip_prefix("st:")
                            .or_else(|| lower.strip_prefix("nt:"))
                        {
                            // The ST/NT header names the device or service type directly.
                            // This is the reliable route to identifying an
                            // InternetGatewayDevice: it needs no HTTP fetch, and routers
                            // are observed resetting connections to their own descriptor.
                            let urn = rest.trim().to_string();
                            if urn.contains("urn:") {
                                let entry = urns.entry(ip).or_default();
                                if !entry.contains(&urn) {
                                    entry.push(urn);
                                }
                            }
                        }
                    }
                }
            }
            _ => break,
        }
    }

    let mut responders: Vec<Ipv4Addr> = locations.keys().copied().collect();
    for ip in urns.keys() {
        if !responders.contains(ip) {
            responders.push(*ip);
        }
    }
    responders.sort();

    let mut devices = Vec::new();
    for ip in responders {
        let device_locations = locations.get(&ip).cloned().unwrap_or_default();

        // Try every advertised descriptor and keep the first that answers. A device may
        // publish several and refuse some of them.
        let mut described = None;
        for loc in &device_locations {
            if let Some(d) = fetch_upnp_description(loc, binding).await {
                described = Some(d);
                break;
            }
        }

        // Fall back to the announced URNs when no descriptor could be retrieved, so an
        // unreachable descriptor never hides that the device is a gateway.
        let device_type = described
            .as_ref()
            .and_then(|d| d.device_type.clone())
            .or_else(|| {
                urns.get(&ip).and_then(|list| {
                    list.iter()
                        .find(|u| u.contains(":device:"))
                        .map(|u| u.to_string())
                })
            });

        devices.push(UpnpDevice {
            ip,
            friendly_name: described.as_ref().and_then(|d| d.friendly_name.clone()),
            model_name: described.as_ref().and_then(|d| d.model_name.clone()),
            model_description: described.as_ref().and_then(|d| d.model_description.clone()),
            manufacturer: described.as_ref().and_then(|d| d.manufacturer.clone()),
            location: device_locations.first().cloned(),
            device_type,
            announced_types: urns.get(&ip).cloned().unwrap_or_default(),
        });
    }

    // Deterministic ordering: SSDP replies arrive in arbitrary order, and unstable output
    // would defeat comparing two runs.
    devices.sort_by_key(|d| d.ip);
    devices
}
