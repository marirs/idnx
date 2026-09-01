//! Cross-platform OS kernel routing table harvester.
//!
//! Extracts active network routes, default gateways, and interface subnets directly
//! from the OS kernel routing table (macOS Darwin, Linux, Windows) without any hardcoded IPs.

use ipnet::Ipv4Net;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;
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
        let octets: Vec<u8> = ip_part.split('.').filter_map(|s| s.parse::<u8>().ok()).collect();
        let mut full_octets = [0u8; 4];
        for (i, &o) in octets.iter().enumerate().take(4) {
            full_octets[i] = o;
        }
        return Ipv4Net::new(Ipv4Addr::from(full_octets), prefix).ok();
    }

    // Handle abbreviated e.g. "192.168.51" -> /24
    let octets: Vec<u8> = dest.split('.').filter_map(|s| s.parse::<u8>().ok()).collect();
    match octets.len() {
        1 => Ipv4Net::new(Ipv4Addr::new(octets[0], 0, 0, 0), 8).ok(),
        2 => Ipv4Net::new(Ipv4Addr::new(octets[0], octets[1], 0, 0), 16).ok(),
        3 => Ipv4Net::new(Ipv4Addr::new(octets[0], octets[1], octets[2], 0), 24).ok(),
        4 => Ipv4Net::new(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]), 32).ok(),
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

/// Identifies the evidence source that discovered a network route
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoverySource {
    KernelRoute,
    SnmpRouteTable,
    UpnpSsdp,
    DhcpOption3,
    LldpCdp,
    ExplicitSubnet,
    HeuristicSweep,
}

impl DiscoverySource {
    pub fn display_name(&self) -> &'static str {
        match self {
            DiscoverySource::KernelRoute => "Kernel Routing Table",
            DiscoverySource::SnmpRouteTable => "SNMP MIB-II ipRouteTable",
            DiscoverySource::UpnpSsdp => "UPnP / SSDP",
            DiscoverySource::DhcpOption3 => "DHCP Default Gateway",
            DiscoverySource::LldpCdp => "Layer 2 LLDP/CDP",
            DiscoverySource::ExplicitSubnet => "Explicit Subnet",
            DiscoverySource::HeuristicSweep => "Heuristic Sweep",
        }
    }
}

/// Represents an active network route with its responding gateway and verified prefix
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiscoveredRoute {
    pub gateway: Ipv4Addr,
    pub network: Ipv4Net,
    pub source: DiscoverySource,
}

/// Discovers adjacent candidate routes from OS kernel routing tables, network interfaces,
/// and live wire advertisements (UPnP / SSDP) without blind guessing.
pub async fn derive_candidate_routes(
    parent_cidr: &Ipv4Net,
    enable_heuristic_sweep: bool,
) -> Vec<DiscoveredRoute> {
    let mut candidates = HashSet::new();

    // 1. Ingest all gateways and subnets from OS kernel routing table
    let kernel_routes = harvest_kernel_routes().await;
    for route in kernel_routes {
        let prefix = route.destination.prefix_len();

        // Direct routed destination network with known prefix (e.g. /16, /20, /24)
        if prefix > 0 && prefix < 32 && &route.destination != parent_cidr {
            let gw = route.gateway.unwrap_or_else(|| route.destination.network());
            candidates.insert(DiscoveredRoute {
                gateway: gw,
                network: route.destination,
                source: DiscoverySource::KernelRoute,
            });
        }

        // If route has an explicit gateway outside parent_cidr
        if let Some(gw) = route.gateway
            && is_rfc1918(&gw)
            && !parent_cidr.contains(&gw)
        {
            let net = if route.destination.contains(&gw) && prefix > 0 && prefix < 32 {
                route.destination
            } else if let Ok(n) = Ipv4Net::new(Ipv4Addr::new(gw.octets()[0], gw.octets()[1], gw.octets()[2], 0), 24) {
                n
            } else {
                continue;
            };
            candidates.insert(DiscoveredRoute {
                gateway: gw,
                network: net,
                source: DiscoverySource::KernelRoute,
            });
        }
    }

    // 2. Ingest secondary network interfaces with their exact interface CIDR
    if let Ok(ifaces) = crate::net::interface::list_ipv4_interfaces() {
        for iface in ifaces {
            if &iface.cidr != parent_cidr && is_rfc1918(&iface.ip) {
                candidates.insert(DiscoveredRoute {
                    gateway: iface.ip,
                    network: iface.cidr,
                    source: DiscoverySource::KernelRoute,
                });
            }
        }
    }

    // 3. Ingest active UPnP/SSDP discovered device endpoints
    let upnp_devices =
        crate::probes::upnp::discover_upnp_devices(Duration::from_millis(300)).await;
    for dev in upnp_devices {
        if !parent_cidr.contains(&dev.ip) && is_rfc1918(&dev.ip) {
            let octets = dev.ip.octets();
            if let Ok(sub) = Ipv4Net::new(Ipv4Addr::new(octets[0], octets[1], octets[2], 0), 24) {
                candidates.insert(DiscoveredRoute {
                    gateway: dev.ip,
                    network: sub,
                    source: DiscoverySource::UpnpSsdp,
                });
            }
        }
    }

    // 4. Heuristic sweep option: strictly opt-in via --heuristic-sweep flag
    if enable_heuristic_sweep {
        let octets = parent_cidr.addr().octets();
        if octets[0] == 192 && octets[1] == 168 {
            for third in 0..=255 {
                let gw1 = Ipv4Addr::new(192, 168, third, 1);
                let gw254 = Ipv4Addr::new(192, 168, third, 254);
                if let Ok(net) = Ipv4Net::new(Ipv4Addr::new(192, 168, third, 0), 24) {
                    if !parent_cidr.contains(&gw1) {
                        candidates.insert(DiscoveredRoute {
                            gateway: gw1,
                            network: net,
                            source: DiscoverySource::HeuristicSweep,
                        });
                    }
                    if !parent_cidr.contains(&gw254) {
                        candidates.insert(DiscoveredRoute {
                            gateway: gw254,
                            network: net,
                            source: DiscoverySource::HeuristicSweep,
                        });
                    }
                }
            }
        }
    }

    candidates.into_iter().collect()
}

fn is_rfc1918(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    (o[0] == 10)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
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
        let def = routes.iter().find(|r| r.gateway == Some(Ipv4Addr::new(192, 168, 1, 1))).unwrap();
        assert_eq!(def.interface.as_deref(), Some("en0"));

        let ten = routes.iter().find(|r| r.destination.addr() == Ipv4Addr::new(10, 242, 0, 0)).unwrap();
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
        assert_eq!(routes[2].destination, Ipv4Net::from_str("172.17.0.0/16").unwrap());
    }

    #[test]
    fn test_discovered_route_topology_preservation() {
        let route = DiscoveredRoute {
            gateway: Ipv4Addr::new(10, 20, 30, 17),
            network: Ipv4Net::from_str("10.20.30.0/24").unwrap(),
            source: DiscoverySource::KernelRoute,
        };
        assert_eq!(route.gateway, Ipv4Addr::new(10, 20, 30, 17));
        assert_eq!(route.source.display_name(), "Kernel Routing Table");
        assert_ne!(route.gateway, Ipv4Addr::new(10, 20, 30, 1));
    }
}
