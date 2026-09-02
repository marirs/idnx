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

/// An address configured on a local interface, in either family.
#[derive(Debug, Clone)]
pub struct InterfaceAddress {
    pub interface_name: String,
    pub ip: std::net::IpAddr,
    pub cidr: ipnet::IpNet,
}

/// Lists every non-loopback address on every interface, IPv4 and IPv6.
///
/// Two different questions are asked of a local address, and they do not have the same
/// answer. This one asks *what networks is this host attached to*, so it excludes addresses
/// that name no routable network. Use [`list_socket_sources`] to ask *what can a probe
/// originate from*, which is a strictly larger set.
///
/// The IPv4-only view hid attached IPv6 prefixes entirely, so a link carrying only an IPv6
/// network appeared to have none at all.
pub fn list_interface_addresses() -> Vec<InterfaceAddress> {
    list_addresses(AddressUse::NetworkPrefix)
}

/// Lists every address a probe can originate from, per interface.
///
/// Includes link-local addresses, which [`list_interface_addresses`] deliberately omits. A
/// link-local address names no network anyone routes to -- emitting it as a prefix would
/// invent a network -- but it is a perfectly good source address, and on many links it is
/// the only IPv6 source a host has. Filtering it out before socket binding left those
/// interfaces with no IPv6 source at all.
pub fn list_socket_sources() -> Vec<InterfaceAddress> {
    list_addresses(AddressUse::SocketSource)
}

/// Which question is being asked of a local address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressUse {
    /// Networks this host is attached to. Link-local addresses are excluded: they name no
    /// network, and treating one as a prefix would create a Network node for a fiction.
    NetworkPrefix,
    /// Addresses a probe can be sent from. Link-local addresses are included.
    SocketSource,
}

fn list_addresses(purpose: AddressUse) -> Vec<InterfaceAddress> {
    let Ok(ifaddrs) = get_if_addrs() else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for iface in ifaddrs {
        if iface.is_loopback() {
            continue;
        }
        let (ip, prefix_len): (std::net::IpAddr, u8) = match &iface.addr {
            IfAddr::V4(v4) => {
                if v4.ip.is_unspecified() {
                    continue;
                }
                // An IPv4 link-local address means DHCP failed. It is not a network, and
                // it is not a source anything useful can be reached from either.
                if v4.ip.is_link_local() {
                    continue;
                }
                (
                    std::net::IpAddr::V4(v4.ip),
                    u32::from(v4.netmask).count_ones() as u8,
                )
            }
            IfAddr::V6(v6) => {
                if v6.ip.is_unspecified() {
                    continue;
                }
                if crate::net::endpoint::is_link_local(&v6.ip)
                    && purpose == AddressUse::NetworkPrefix
                {
                    continue;
                }
                let bits: u32 = u128::from(v6.netmask).count_ones();
                (std::net::IpAddr::V6(v6.ip), bits as u8)
            }
        };

        if let Ok(cidr) = ipnet::IpNet::new(ip, prefix_len) {
            out.push(InterfaceAddress {
                interface_name: iface.name.clone(),
                ip,
                cidr: cidr.trunc(),
            });
        }
    }

    out
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

/// Reports whether an interface is wireless.
///
/// This matters for Layer 2 discovery, not for scanning. LLDP and CDP are link-local
/// multicast frames, and access points do not bridge them to wireless clients — so a
/// capture on a Wi-Fi interface finds no switches no matter how correct the decoder is.
/// Without this check that outcome is indistinguishable from "there are no switches".
pub fn is_wireless_interface(name: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        // The kernel exposes a `wireless` directory (or a phy80211 link) only for 802.11 devices.
        std::path::Path::new(&format!("/sys/class/net/{}/wireless", name)).exists()
            || std::path::Path::new(&format!("/sys/class/net/{}/phy80211", name)).exists()
    }

    #[cfg(target_os = "macos")]
    {
        // `networksetup` maps each device to its hardware port; the Wi-Fi radio is the only
        // port reported as "Wi-Fi" (or "AirPort" on older releases).
        let Ok(output) = std::process::Command::new("networksetup")
            .arg("-listallhardwareports")
            .output()
        else {
            return false;
        };
        let text = String::from_utf8_lossy(&output.stdout);
        parse_macos_wireless_ports(&text)
            .iter()
            .any(|d| d.eq_ignore_ascii_case(name))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = name;
        false
    }
}

/// Extracts the device names of wireless hardware ports from `networksetup` output.
#[cfg(any(target_os = "macos", test))]
pub fn parse_macos_wireless_ports(text: &str) -> Vec<String> {
    let mut wireless = Vec::new();
    let mut current_is_wireless = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(port) = trimmed.strip_prefix("Hardware Port:") {
            let port = port.trim().to_ascii_lowercase();
            current_is_wireless = port == "wi-fi" || port == "airport";
        } else if let Some(device) = trimmed.strip_prefix("Device:")
            && current_is_wireless
        {
            wireless.push(device.trim().to_string());
        }
    }

    wireless
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
    fn test_parse_macos_wireless_ports() {
        let sample = "\
Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 68:5e:dd:8f:75:56

Hardware Port: Ethernet Adapter (en3)
Device: en3
Ethernet Address: 1e:dc:68:29:ce:2b

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 36:14:e0:ee:4c:00
";
        assert_eq!(parse_macos_wireless_ports(sample), vec!["en0".to_string()]);
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
