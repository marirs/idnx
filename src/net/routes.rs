//! Cross-platform OS kernel routing table harvester.
//!
//! Extracts active network routes, default gateways, and interface subnets directly
//! from the OS kernel routing table (macOS Darwin, Linux, Windows) without any hardcoded IPs.

use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::str::FromStr;
use tokio::process::Command;

/// Represents a route learned directly from the kernel routing table
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelRoute {
    pub destination: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub interface: Option<String>,
}

/// Harvests active IPv4 routes and gateways from the operating system
pub async fn harvest_kernel_routes() -> Vec<KernelRoute> {
    #[cfg(target_os = "macos")]
    {
        harvest_macos_routes().await
    }

    #[cfg(target_os = "linux")]
    {
        harvest_linux_routes().await
    }

    #[cfg(target_os = "windows")]
    {
        harvest_windows_routes().await
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}

/// Parses macOS `netstat -rn -f inet` output
pub fn parse_macos_netstat_routes(output: &str) -> Vec<KernelRoute> {
    let mut routes = Vec::new();
    let mut in_internet_table = false;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Internet:") {
            in_internet_table = true;
            continue;
        }
        if !in_internet_table || trimmed.starts_with("Destination") || trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let dest_str = parts[0];
        let gw_str = parts[1];
        let iface = parts.get(3).map(|s| s.to_string());

        // Parse Gateway
        let gateway = Ipv4Addr::from_str(gw_str).ok();

        // Parse Destination
        if dest_str == "default" {
            if let Some(gw) = gateway {
                routes.push(KernelRoute {
                    destination: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                    gateway: Some(gw),
                    interface: iface,
                });
            }
            continue;
        }

        // Handle forms like "10.242/16", "192.168.51", "172.29"
        if let Some(net) = parse_macos_dest_cidr(dest_str) {
            routes.push(KernelRoute {
                destination: net,
                gateway,
                interface: iface,
            });
        }
    }

    routes
}

fn parse_macos_dest_cidr(dest: &str) -> Option<Ipv4Net> {
    if let Ok(net) = Ipv4Net::from_str(dest) {
        return Some(net);
    }

    // Handle slash notation e.g. "10.242/16"
    if let Some((ip_part, mask_part)) = dest.split_once('/') {
        let prefix: u8 = mask_part.parse().ok()?;
        let octets: Vec<u8> = ip_part
            .split('.')
            .filter_map(|s| s.parse::<u8>().ok())
            .collect();
        let mut full_octets = [0u8; 4];
        for (i, &o) in octets.iter().enumerate().take(4) {
            full_octets[i] = o;
        }
        return Ipv4Net::new(Ipv4Addr::from(full_octets), prefix).ok();
    }

    // Handle abbreviated e.g. "192.168.51" -> /24
    let octets: Vec<u8> = dest
        .split('.')
        .filter_map(|s| s.parse::<u8>().ok())
        .collect();
    match octets.len() {
        1 => Ipv4Net::new(Ipv4Addr::new(octets[0], 0, 0, 0), 8).ok(),
        2 => Ipv4Net::new(Ipv4Addr::new(octets[0], octets[1], 0, 0), 16).ok(),
        3 => Ipv4Net::new(Ipv4Addr::new(octets[0], octets[1], octets[2], 0), 24).ok(),
        4 => Ipv4Net::new(
            Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
            32,
        )
        .ok(),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
async fn harvest_macos_routes() -> Vec<KernelRoute> {
    if let Ok(output) = Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .await
        && let Ok(text) = String::from_utf8(output.stdout)
    {
        parse_macos_netstat_routes(&text)
    } else {
        Vec::new()
    }
}

/// Parses Linux `ip route show` output
pub fn parse_linux_ip_route(output: &str) -> Vec<KernelRoute> {
    let mut routes = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let mut gateway = None;
        let mut interface = None;

        for (i, &word) in parts.iter().enumerate() {
            if word == "via" && i + 1 < parts.len() {
                gateway = Ipv4Addr::from_str(parts[i + 1]).ok();
            }
            if word == "dev" && i + 1 < parts.len() {
                interface = Some(parts[i + 1].to_string());
            }
        }

        if parts[0] == "default" {
            if let Some(gw) = gateway {
                routes.push(KernelRoute {
                    destination: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                    gateway: Some(gw),
                    interface,
                });
            }
        } else if let Ok(cidr) = Ipv4Net::from_str(parts[0]) {
            routes.push(KernelRoute {
                destination: cidr,
                gateway,
                interface,
            });
        }
    }

    routes
}

#[cfg(target_os = "linux")]
async fn harvest_linux_routes() -> Vec<KernelRoute> {
    if let Ok(output) = Command::new("ip").args(["route", "show"]).output().await
        && let Ok(text) = String::from_utf8(output.stdout)
    {
        parse_linux_ip_route(&text)
    } else {
        Vec::new()
    }
}

/// Parses Windows `route print -4` output
pub fn parse_windows_route_print(output: &str) -> Vec<KernelRoute> {
    let mut routes = Vec::new();
    let mut in_active_routes = false;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Active Routes:") {
            in_active_routes = true;
            continue;
        }
        if !in_active_routes || trimmed.starts_with("Network Destination") {
            continue;
        }
        if trimmed.starts_with("Persistent Routes:") {
            break;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 4
            && let (Ok(dest), Ok(mask), Ok(gw)) = (
                Ipv4Addr::from_str(parts[0]),
                Ipv4Addr::from_str(parts[1]),
                Ipv4Addr::from_str(parts[2]),
            )
        {
            let prefix = u32::from(mask).count_ones() as u8;
            if let Ok(cidr) = Ipv4Net::new(dest, prefix) {
                routes.push(KernelRoute {
                    destination: cidr,
                    gateway: if gw.is_unspecified() { None } else { Some(gw) },
                    interface: parts.get(3).map(|s| s.to_string()),
                });
            }
        }
    }

    routes
}

#[cfg(target_os = "windows")]
async fn harvest_windows_routes() -> Vec<KernelRoute> {
    if let Ok(output) = Command::new("route").args(["print", "-4"]).output().await
        && let Ok(text) = String::from_utf8(output.stdout)
    {
        parse_windows_route_print(&text)
    } else {
        Vec::new()
    }
}

/// Reads DHCP option 3 (Router) from the OS DHCP lease state for an interface.
///
/// This reads the lease the OS already holds rather than emitting a fresh DHCP packet,
/// so it needs no privileges and cannot perturb the network. The value usually matches
/// the kernel default gateway; when it does it corroborates that gateway, and when the
/// kernel route parse fails it is an independent way to recover it.
pub async fn harvest_dhcp_routers(interface: Option<&str>) -> Vec<Ipv4Addr> {
    let mut routers = Vec::new();

    #[cfg(target_os = "macos")]
    {
        if let Some(iface) = interface
            && let Ok(out) = Command::new("ipconfig")
                .args(["getoption", iface, "router"])
                .output()
                .await
            && let Ok(text) = String::from_utf8(out.stdout)
            && let Ok(ip) = text.trim().parse::<Ipv4Addr>()
            && !ip.is_unspecified()
        {
            routers.push(ip);
        }
    }

    #[cfg(target_os = "linux")]
    {
        let _ = interface;
        for dir in [
            "/var/lib/dhcp",
            "/var/lib/dhclient",
            "/var/lib/NetworkManager",
        ] {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("leases")
                    && !path.to_string_lossy().contains("lease")
                {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(&path) {
                    for ip in parse_dhclient_lease_routers(&text) {
                        if !routers.contains(&ip) {
                            routers.push(ip);
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let _ = interface;
        if let Ok(out) = Command::new("ipconfig").arg("/all").output().await
            && let Ok(text) = String::from_utf8(out.stdout)
        {
            for ip in parse_windows_dhcp_routers(&text) {
                if !routers.contains(&ip) {
                    routers.push(ip);
                }
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = interface;
    }

    routers
}

/// Extracts `option routers <ip>;` values from an ISC dhclient lease file.
pub fn parse_dhclient_lease_routers(text: &str) -> Vec<Ipv4Addr> {
    let mut routers = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("option routers") else {
            continue;
        };
        let value = rest.trim().trim_end_matches(';').trim();
        // A lease may list several routers, comma separated.
        for part in value.split(',') {
            if let Ok(ip) = part.trim().parse::<Ipv4Addr>()
                && !routers.contains(&ip)
            {
                routers.push(ip);
            }
        }
    }
    routers
}

/// Extracts default gateways from `ipconfig /all` for adapters that have DHCP enabled.
///
/// The gateway line itself carries no DHCP marker, so the "DHCP Enabled . . . : Yes"
/// line earlier in the same adapter block is what qualifies it as option 3 evidence.
pub fn parse_windows_dhcp_routers(text: &str) -> Vec<Ipv4Addr> {
    let mut routers = Vec::new();
    let mut dhcp_enabled = false;

    for line in text.lines() {
        let trimmed = line.trim();

        // A new adapter block resets the DHCP state.
        if trimmed.ends_with(':') && trimmed.to_lowercase().contains("adapter") {
            dhcp_enabled = false;
            continue;
        }

        if trimmed.starts_with("DHCP Enabled")
            && let Some((_, value)) = trimmed.split_once(':')
        {
            dhcp_enabled = value.trim().eq_ignore_ascii_case("yes");
            continue;
        }

        if dhcp_enabled
            && trimmed.starts_with("Default Gateway")
            && let Some((_, value)) = trimmed.split_once(':')
            && let Ok(ip) = value.trim().parse::<Ipv4Addr>()
            && !ip.is_unspecified()
            && !routers.contains(&ip)
        {
            routers.push(ip);
        }
    }

    routers
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_macos_netstat_synthetic() {
        let sample = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0       
10.242/16          link#36            UC                feth466      !
172.29             link#47            UC               feth4106      !
192.168.1          link#11            UCS                   en0      !
192.168.1.1        60:cf:84:37:1b:70  UHLWIir               en0   1155
";
        let routes = parse_macos_netstat_routes(sample);
        assert!(!routes.is_empty());
        let def = routes
            .iter()
            .find(|r| r.gateway == Some(Ipv4Addr::new(192, 168, 1, 1)))
            .unwrap();
        assert_eq!(def.interface.as_deref(), Some("en0"));

        let ten = routes
            .iter()
            .find(|r| r.destination.addr() == Ipv4Addr::new(10, 242, 0, 0))
            .unwrap();
        assert_eq!(ten.destination.prefix_len(), 16);
    }

    #[test]
    fn test_parse_linux_ip_route_synthetic() {
        let sample = "\
default via 10.0.0.1 dev eth0 proto dhcp metric 100 
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.50 metric 100 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown 
";
        let routes = parse_linux_ip_route(sample);
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].gateway, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            routes[2].destination,
            Ipv4Net::from_str("172.17.0.0/16").unwrap()
        );
    }

    #[test]
    fn test_parse_dhclient_lease_routers() {
        let sample = "\
lease {
  interface \"eth0\";
  fixed-address 10.0.0.50;
  option subnet-mask 255.255.255.0;
  option routers 10.0.0.1;
}
lease {
  option routers 10.0.0.1, 10.0.0.2;
}
";
        let routers = parse_dhclient_lease_routers(sample);
        assert_eq!(
            routers,
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
    }

    #[test]
    fn test_parse_windows_dhcp_routers_requires_dhcp_enabled() {
        let sample = "\
Ethernet adapter Ethernet:

   DHCP Enabled. . . . . . . . . . . : No
   Default Gateway . . . . . . . . . : 10.1.1.1

Wireless LAN adapter Wi-Fi:

   DHCP Enabled. . . . . . . . . . . : Yes
   Default Gateway . . . . . . . . . : 10.2.2.1
";
        // The statically configured adapter must not be reported as DHCP option 3 evidence.
        assert_eq!(
            parse_windows_dhcp_routers(sample),
            vec![Ipv4Addr::new(10, 2, 2, 1)]
        );
    }
}
