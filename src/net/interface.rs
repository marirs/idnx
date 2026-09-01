use get_if_addrs::{IfAddr, get_if_addrs};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct LocalNetworkInfo {
    pub interface_name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    #[allow(dead_code)]
    pub prefix_len: u8,
    pub cidr: Ipv4Net,
}

impl LocalNetworkInfo {
    pub fn new(interface_name: String, ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<Self, String> {
        let prefix_len = u32::from(netmask).count_ones() as u8;
        let cidr = Ipv4Net::new(ip, prefix_len)
            .map_err(|e| format!("Invalid CIDR for {}/{}: {}", ip, prefix_len, e))?
            .trunc();

        Ok(Self {
            interface_name,
            ip,
            netmask,
            prefix_len,
            cidr,
        })
    }
}

/// Finds an interface by its name (e.g. "en0", "eth0", "wlan0")
pub fn get_interface_by_name(name: &str) -> Result<LocalNetworkInfo, String> {
    let all = list_ipv4_interfaces()?;
    all.into_iter()
        .find(|iface| iface.interface_name.eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            format!(
                "Interface '{}' not found or has no active IPv4 address.",
                name
            )
        })
}

/// Detects the primary local network information (active interface, IP, netmask, and CIDR subnet).
pub fn detect_local_network() -> Result<LocalNetworkInfo, String> {
    let all_interfaces = list_ipv4_interfaces()?;

    if all_interfaces.is_empty() {
        return Err("No active IPv4 network interfaces found on system.".to_string());
    }

    // Attempt 1: Query the OS kernel routing table for the outbound IP
    if let Ok(outbound_ip) = get_outbound_ip() {
        if let Some(matched) = all_interfaces.iter().find(|info| info.ip == outbound_ip) {
            return Ok(matched.clone());
        }
    }

    // Attempt 2: Pick the first non-virtual / non-loopback interface
    let preferred = all_interfaces.iter().find(|info| {
        let name = info.interface_name.to_lowercase();
        (name.starts_with("en") || name.starts_with("eth") || name.starts_with("wl"))
            && !name.contains("docker")
            && !name.contains("utun")
            && !name.contains("bridge")
            && !name.contains("vbox")
    });

    if let Some(info) = preferred {
        return Ok(info.clone());
    }

    // Fallback: Return the first available IPv4 interface
    Ok(all_interfaces[0].clone())
}

/// Lists all non-loopback IPv4 network interfaces
pub fn list_ipv4_interfaces() -> Result<Vec<LocalNetworkInfo>, String> {
    let ifaddrs =
        get_if_addrs().map_err(|e| format!("Failed to read network interfaces: {}", e))?;
    let mut results = Vec::new();

    for iface in ifaddrs {
        if iface.is_loopback() {
            continue;
        }

        if let IfAddr::V4(v4) = iface.addr {
            // Ignore link-local (169.254.x.x) or unspecified (0.0.0.0)
            if v4.ip.is_link_local() || v4.ip.is_unspecified() {
                continue;
            }

            if let Ok(info) = LocalNetworkInfo::new(iface.name, v4.ip, v4.netmask) {
                results.push(info);
            }
        }
    }

    Ok(results)
}

/// Resolves user input (interface name, CIDR, IP, or auto) into a canonical CIDR and interface context
pub fn resolve_target(
    target_opt: Option<&str>,
    interface_opt: Option<&str>,
) -> Result<(Ipv4Net, Option<LocalNetworkInfo>), String> {
    // 1. Explicit --interface flag
    if let Some(iface_name) = interface_opt {
        let info = get_interface_by_name(iface_name)?;
        return Ok((info.cidr, Some(info)));
    }

    // 2. Target string handling
    let target = match target_opt {
        Some("auto") | None => {
            let info = detect_local_network()?;
            return Ok((info.cidr, Some(info)));
        }
        Some(t) => t.trim(),
    };

    // Check if target is an interface name (e.g. --scan en0)
    if let Ok(info) = get_interface_by_name(target) {
        return Ok((info.cidr, Some(info)));
    }

    // Handle user inputs like "192.168.1.1/0" or "192.168.1.0/0"
    if target.ends_with("/0") {
        let base_ip = target.trim_end_matches("/0");
        if let Ok(ip) = Ipv4Addr::from_str(base_ip) {
            // If it's a private subnet, assume /24
            let cidr = Ipv4Net::new(ip, 24)
                .map_err(|e| format!("Invalid IP: {}", e))?
                .trunc();
            eprintln!(
                "Note: Converting non-routable prefix '{}/0' to standard local subnet '{}'",
                base_ip, cidr
            );
            return Ok((cidr, None));
        }
    }

    // Handle target ending in .0 with no slash (e.g. 192.168.1.0)
    if target.ends_with(".0") && !target.contains('/') {
        let normalized = format!("{}/24", target);
        let cidr = Ipv4Net::from_str(&normalized)
            .map_err(|e| format!("Invalid CIDR '{}': {}", normalized, e))?;
        return Ok((cidr, None));
    }

    // Standard CIDR or single IP
    let normalized = if target.contains('/') {
        target.to_string()
    } else {
        format!("{}/32", target)
    };

    let cidr = Ipv4Net::from_str(&normalized)
        .map_err(|e| format!("Invalid CIDR or IP target '{}': {}", target, e))?
        .trunc();

    Ok((cidr, None))
}

/// Queries the OS kernel for the default outbound IP address via a dummy UDP socket connect.
fn get_outbound_ip() -> Result<Ipv4Addr, String> {
    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

    socket
        .connect("8.8.8.8:80")
        .map_err(|e| format!("Failed to resolve outbound route: {}", e))?;

    match socket.local_addr() {
        Ok(addr) => match addr.ip() {
            IpAddr::V4(v4) => Ok(v4),
            IpAddr::V6(_) => Err("Outbound IP resolved to IPv6".to_string()),
        },
        Err(e) => Err(format!("Failed to retrieve local address: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_network_info_creation() {
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let info = LocalNetworkInfo::new("en0".to_string(), ip, mask).unwrap();

        assert_eq!(info.prefix_len, 24);
        assert_eq!(info.cidr.network(), Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn test_resolve_target_slash_zero() {
        let (cidr, _) = resolve_target(Some("192.168.1.1/0"), None).unwrap();
        assert_eq!(cidr.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(cidr.prefix_len(), 24);
    }

    #[test]
    fn test_resolve_target_dot_zero() {
        let (cidr, _) = resolve_target(Some("192.168.1.0"), None).unwrap();
        assert_eq!(cidr.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(cidr.prefix_len(), 24);
    }
}
