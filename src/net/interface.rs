use if_addrs::{IfAddr, get_if_addrs};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct LocalNetworkInfo {
    pub interface_name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    #[allow(dead_code)]
    pub prefix_len: u8,
    pub cidr: Ipv4Net,
    pub default_gateway: Option<Ipv4Addr>,
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
            default_gateway: None,
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

    // Attempt 1: Query the OS kernel routing table for the default route without external
    // network packets.
    let kernel_default_route = get_kernel_default_route();
    let default_gateway = kernel_default_route.as_ref().and_then(|(_, gw)| *gw);

    if let Some((iface_identifier, gw_opt)) = kernel_default_route.as_ref()
        && let Some(matched) = all_interfaces.iter().find(|info| {
            info.interface_name.eq_ignore_ascii_case(iface_identifier)
                || info.ip.to_string() == *iface_identifier
        })
    {
        let mut res = matched.clone();
        res.default_gateway = *gw_opt;
        return Ok(res);
    }

    // Attempt 2: Pick the preferred non-virtual physical interface (en*, eth*, wl*)
    let preferred = all_interfaces.iter().find(|info| {
        let name = info.interface_name.to_lowercase();
        (name.starts_with("en") || name.starts_with("eth") || name.starts_with("wl"))
            && !name.contains("docker")
            && !name.contains("utun")
            && !name.contains("bridge")
            && !name.contains("vbox")
    });

    // The default gateway is a property of the system, not of whichever interface these
    // fallbacks happen to select, so it is carried through rather than dropped. It is the
    // first pivot the deep engine interrogates; losing it here silently removes the single
    // most informative router from discovery.
    if let Some(info) = preferred {
        let mut res = info.clone();
        res.default_gateway = default_gateway;
        return Ok(res);
    }

    // Fallback: Return the first available IPv4 interface
    let mut res = all_interfaces[0].clone();
    res.default_gateway = default_gateway;
    Ok(res)
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

    // Reject ambiguous user inputs like "192.168.1.1/0" or "192.168.1.0/0"
    if target.ends_with("/0") {
        return Err(format!(
            "Ambiguous target '{}': /0 prefix is not a valid local subnet. Please specify an explicit CIDR (e.g. 192.168.1.0/24).",
            target
        ));
    }

    // Reject target ending in .0 with no slash (e.g. 192.168.1.0)
    if target.ends_with(".0") && !target.contains('/') {
        return Err(format!(
            "Ambiguous target '{}': IP addresses ending in .0 must specify an explicit prefix length (e.g. {}/24).",
            target, target
        ));
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

/// Queries the OS kernel for the default route without external network packets or internet access
fn get_kernel_default_route() -> Option<(String, Option<Ipv4Addr>)> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("netstat")
            .args(["-rn", "-f", "inet"])
            .output()
            && let Ok(text) = String::from_utf8(output.stdout)
        {
            let mut in_table = false;
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("Destination") {
                    in_table = true;
                    continue;
                }
                if in_table {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 4 && parts[0] == "default" {
                        let gw = parts[1].parse::<Ipv4Addr>().ok();
                        let iface = parts[3].to_string();
                        return Some((iface, gw));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 3 && fields[1] == "00000000" {
                    let iface = fields[0].to_string();
                    let gw = u32::from_str_radix(fields[2], 16)
                        .ok()
                        .map(|hex| Ipv4Addr::from(hex.to_be()));
                    return Some((iface, gw));
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("route")
            .args(["print", "-4"])
            .output()
            && let Ok(text) = String::from_utf8(output.stdout)
        {
            let mut in_active_routes = false;
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.contains("Active Routes:") {
                    in_active_routes = true;
                    continue;
                }
                if in_active_routes {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 5 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                        let gw = parts[2].parse::<Ipv4Addr>().ok();
                        let iface_ip = parts[3];
                        return Some((iface_ip.to_string(), gw));
                    }
                }
            }
        }
    }

    None
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
        assert!(resolve_target(Some("192.168.1.1/0"), None).is_err());
    }

    #[test]
    fn test_resolve_target_dot_zero() {
        assert!(resolve_target(Some("192.168.1.0"), None).is_err());
    }
}
