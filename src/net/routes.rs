//! Cross-platform OS kernel routing table harvester.
//!
//! Extracts active routes and gateways directly from the OS kernel routing table on
//! macOS, Linux and Windows. Dual-stack throughout: an IPv6-only routed subnet is as real
//! as an IPv4 one, and harvesting only one family silently hides half the topology.

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use tokio::process::Command;

/// A route learned directly from the kernel routing table.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelRoute {
    pub destination: IpNet,
    pub gateway: Option<IpAddr>,
    /// Interface zone of a scoped gateway.
    ///
    /// An IPv6 link-local next hop is only meaningful within its zone: `fe80::1%en0` and
    /// `fe80::1%eth1` are different addresses on different links, so the zone is kept
    /// rather than discarded with the `%` suffix.
    pub gateway_zone: Option<String>,
    pub interface: Option<String>,
}

impl KernelRoute {
    /// True when this is a default route, which carries a gateway but no network of its own.
    pub fn is_default(&self) -> bool {
        self.destination.prefix_len() == 0
    }
}

/// Harvests active IPv4 and IPv6 routes from the operating system.
pub async fn harvest_kernel_routes() -> Vec<KernelRoute> {
    #[cfg(target_os = "macos")]
    {
        let mut routes = harvest_macos_routes("inet").await;
        routes.extend(harvest_macos_routes("inet6").await);
        routes
    }

    #[cfg(target_os = "linux")]
    {
        let mut routes = harvest_linux_routes("-4").await;
        routes.extend(harvest_linux_routes("-6").await);
        routes
    }

    #[cfg(target_os = "windows")]
    {
        let mut routes = harvest_windows_routes_v4().await;
        routes.extend(harvest_windows_routes_v6().await);
        routes
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}

/// Splits a possibly scoped address such as `fe80::1%en0` into address and zone.
pub fn parse_scoped_address(text: &str) -> Option<(IpAddr, Option<String>)> {
    let (addr_part, zone) = match text.split_once('%') {
        Some((addr, zone)) => (addr, Some(zone.to_string())),
        None => (text, None),
    };
    addr_part.parse::<IpAddr>().ok().map(|addr| (addr, zone))
}

/// Parses macOS/BSD `netstat -rn -f inet` or `-f inet6` output.
///
/// Both families share the column layout `Destination Gateway Flags Netif Expire`, so one
/// parser serves both.
pub fn parse_netstat_routes(output: &str) -> Vec<KernelRoute> {
    let mut routes = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("Destination")
            || trimmed.starts_with("Routing tables")
            || trimmed.starts_with("Internet")
        {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let interface = parts.get(3).map(|s| s.to_string());

        // `link#11` and a MAC both mean "directly attached", not a next hop.
        let (gateway, gateway_zone) = match parse_scoped_address(parts[1]) {
            Some((addr, zone)) => (Some(addr), zone),
            None => (None, None),
        };

        let destination = if parts[0] == "default" {
            // A default route has no network of its own; represent it as the zero prefix
            // so callers can recognise and skip it rather than inventing a network.
            match gateway {
                Some(IpAddr::V6(_)) => IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()),
                _ => IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()),
            }
        } else if let Some(net) = parse_netstat_destination(parts[0]) {
            net
        } else {
            continue;
        };

        routes.push(KernelRoute {
            destination,
            gateway,
            gateway_zone,
            interface,
        });
    }

    routes
}

/// Parses a macOS destination, which may be a CIDR, a bare address, or an abbreviated
/// IPv4 form such as `192.168.51` or `10.242/16`.
pub fn parse_netstat_destination(dest: &str) -> Option<IpNet> {
    // Strip any zone: a scoped destination such as `fe80::%en0/64` is still that prefix.
    let cleaned = match dest.split_once('%') {
        Some((head, rest)) => match rest.split_once('/') {
            Some((_, prefix)) => format!("{head}/{prefix}"),
            None => head.to_string(),
        },
        None => dest.to_string(),
    };

    if let Ok(net) = IpNet::from_str(&cleaned) {
        return Some(net.trunc());
    }
    if let Ok(addr) = cleaned.parse::<IpAddr>() {
        let bits = if addr.is_ipv4() { 32 } else { 128 };
        return IpNet::new(addr, bits).ok();
    }

    // Abbreviated IPv4 forms appear only in the inet table.
    parse_abbreviated_ipv4(&cleaned).map(IpNet::V4)
}

/// Expands macOS shorthand such as `10.242/16` or `192.168.51` into a network.
fn parse_abbreviated_ipv4(dest: &str) -> Option<Ipv4Net> {
    if let Some((ip_part, mask_part)) = dest.split_once('/') {
        let prefix: u8 = mask_part.parse().ok()?;
        let octets: Vec<u8> = ip_part
            .split('.')
            .filter_map(|s| s.parse::<u8>().ok())
            .collect();
        if octets.is_empty() {
            return None;
        }
        let mut full = [0u8; 4];
        for (i, &o) in octets.iter().enumerate().take(4) {
            full[i] = o;
        }
        return Ipv4Net::new(Ipv4Addr::from(full), prefix)
            .ok()
            .map(|n| n.trunc());
    }

    let octets: Vec<u8> = dest
        .split('.')
        .filter_map(|s| s.parse::<u8>().ok())
        .collect();
    if octets.len() != dest.split('.').count() {
        return None;
    }
    match octets.len() {
        1 => Ipv4Net::new(Ipv4Addr::new(octets[0], 0, 0, 0), 8).ok(),
        2 => Ipv4Net::new(Ipv4Addr::new(octets[0], octets[1], 0, 0), 16).ok(),
        3 => Ipv4Net::new(Ipv4Addr::new(octets[0], octets[1], octets[2], 0), 24).ok(),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
async fn harvest_macos_routes(family: &str) -> Vec<KernelRoute> {
    if let Ok(output) = Command::new("netstat")
        .args(["-rn", "-f", family])
        .output()
        .await
        && let Ok(text) = String::from_utf8(output.stdout)
    {
        parse_netstat_routes(&text)
    } else {
        Vec::new()
    }
}

/// Parses Linux `ip -4 route show` or `ip -6 route show` output.
pub fn parse_linux_ip_route(output: &str) -> Vec<KernelRoute> {
    let mut routes = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let mut gateway = None;
        let mut gateway_zone = None;
        let mut interface = None;

        for (i, &word) in parts.iter().enumerate() {
            if word == "via"
                && i + 1 < parts.len()
                && let Some((addr, zone)) = parse_scoped_address(parts[i + 1])
            {
                gateway = Some(addr);
                gateway_zone = zone;
            }
            if word == "dev" && i + 1 < parts.len() {
                interface = Some(parts[i + 1].to_string());
            }
        }

        // A link-local next hop is scoped by the device it was learned on when `ip` did
        // not spell out a `%zone`.
        if gateway_zone.is_none()
            && let Some(IpAddr::V6(v6)) = gateway
            && (v6.segments()[0] & 0xffc0) == 0xfe80
        {
            gateway_zone = interface.clone();
        }

        let destination = if parts[0] == "default" {
            match gateway {
                Some(IpAddr::V6(_)) => IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()),
                _ => IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()),
            }
        } else if let Ok(net) = IpNet::from_str(parts[0]) {
            net.trunc()
        } else {
            continue;
        };

        routes.push(KernelRoute {
            destination,
            gateway,
            gateway_zone,
            interface,
        });
    }

    routes
}

#[cfg(target_os = "linux")]
async fn harvest_linux_routes(family: &str) -> Vec<KernelRoute> {
    if let Ok(output) = Command::new("ip")
        .args([family, "route", "show"])
        .output()
        .await
        && let Ok(text) = String::from_utf8(output.stdout)
    {
        parse_linux_ip_route(&text)
    } else {
        Vec::new()
    }
}

/// Parses Windows `route print -4` output.
///
/// Columns are `Network Destination / Netmask / Gateway / Interface / Metric`, and the
/// interface is given by address rather than by name.
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
        if trimmed.starts_with("Persistent Routes:") || trimmed.starts_with("=====") {
            if in_active_routes && trimmed.starts_with("Persistent Routes:") {
                break;
            }
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 4
            && let (Ok(dest), Ok(mask)) =
                (Ipv4Addr::from_str(parts[0]), Ipv4Addr::from_str(parts[1]))
        {
            let prefix = u32::from(mask).count_ones() as u8;
            let Ok(cidr) = Ipv4Net::new(dest, prefix) else {
                continue;
            };
            let gateway = Ipv4Addr::from_str(parts[2])
                .ok()
                .filter(|g| !g.is_unspecified())
                .map(IpAddr::V4);

            routes.push(KernelRoute {
                destination: IpNet::V4(cidr.trunc()),
                gateway,
                gateway_zone: None,
                interface: parts.get(3).map(|s| s.to_string()),
            });
        }
    }

    routes
}

/// Parses Windows `route print -6` output.
///
/// The IPv6 table has a different layout from IPv4: `If / Metric / Network Destination /
/// Gateway`, with the interface given as a numeric index.
pub fn parse_windows_route_print_v6(output: &str) -> Vec<KernelRoute> {
    let mut routes = Vec::new();
    let mut in_active_routes = false;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Active Routes:") {
            in_active_routes = true;
            continue;
        }
        if !in_active_routes {
            continue;
        }
        if trimmed.starts_with("If Metric Network Destination") || trimmed.starts_with("=====") {
            continue;
        }
        if trimmed.starts_with("Persistent Routes:") {
            break;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let Ok(index) = parts[0].parse::<u32>() else {
            continue;
        };
        let Ok(destination) = IpNet::from_str(parts[2]) else {
            continue;
        };

        // "On-link" means directly attached rather than a next hop.
        let (gateway, gateway_zone) = if parts[3].eq_ignore_ascii_case("On-link") {
            (None, None)
        } else {
            match parse_scoped_address(parts[3]) {
                Some((addr, zone)) => (Some(addr), zone),
                None => (None, None),
            }
        };

        routes.push(KernelRoute {
            destination: destination.trunc(),
            gateway,
            gateway_zone,
            interface: Some(index.to_string()),
        });
    }

    routes
}

#[cfg(target_os = "windows")]
async fn harvest_windows_routes_v4() -> Vec<KernelRoute> {
    if let Ok(output) = Command::new("route").args(["print", "-4"]).output().await
        && let Ok(text) = String::from_utf8(output.stdout)
    {
        parse_windows_route_print(&text)
    } else {
        Vec::new()
    }
}

#[cfg(target_os = "windows")]
async fn harvest_windows_routes_v6() -> Vec<KernelRoute> {
    if let Ok(output) = Command::new("route").args(["print", "-6"]).output().await
        && let Ok(text) = String::from_utf8(output.stdout)
    {
        parse_windows_route_print_v6(&text)
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
    fn macos_ipv4_routes_parse_including_abbreviated_destinations() {
        let sample = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
10.242/16          link#36            UC                feth466      !
192.168.1          link#11            UCS                   en0      !
192.168.1.1        60:cf:84:37:1b:70  UHLWIir               en0   1155
";
        let routes = parse_netstat_routes(sample);

        let default = routes
            .iter()
            .find(|r| r.is_default())
            .expect("default route");
        assert_eq!(
            default.gateway,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(default.interface.as_deref(), Some("en0"));

        let ten = routes
            .iter()
            .find(|r| r.destination.addr() == IpAddr::V4(Ipv4Addr::new(10, 242, 0, 0)))
            .expect("abbreviated /16");
        assert_eq!(ten.destination.prefix_len(), 16);
    }

    #[test]
    fn macos_ipv6_routed_subnet_is_learned_with_its_scoped_gateway() {
        // The exact shape of a real routed IPv6 subnet one hop away. Harvesting only IPv4
        // hid this entirely, so the subnet never appeared in the topology at all.
        let sample = "\
Routing tables

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::1%en0                             UGcg                  en0
fd84:3bfe:bf84::/64                     fe80::1812:faa5:e4ee:1b9%en0            UGc                   en0
fdc5:3da0:fee0:47fa::/64                link#11                                 UC                    en0
fe80::%en0/64                           link#11                                 UCI                   en0
fdc5:3da0:fee0:47fa:5d00:58ef:7705:5e3d 4c:bb:47:0:48:f8                        UHLWIi                en0
";
        let routes = parse_netstat_routes(sample);

        let routed = routes
            .iter()
            .find(|r| r.destination.to_string() == "fd84:3bfe:bf84::/64")
            .expect("the routed IPv6 subnet must be parsed");
        assert_eq!(
            routed.gateway,
            Some("fe80::1812:faa5:e4ee:1b9".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            routed.gateway_zone.as_deref(),
            Some("en0"),
            "the zone of a link-local next hop must be preserved"
        );
        assert!(!routed.is_default());

        // The directly attached prefix is present and has no next hop.
        let attached = routes
            .iter()
            .find(|r| r.destination.to_string() == "fdc5:3da0:fee0:47fa::/64")
            .expect("attached IPv6 prefix");
        assert!(attached.gateway.is_none(), "link#11 is not a next hop");
    }

    #[test]
    fn linux_dual_stack_routes_parse() {
        let v4 = "\
default via 10.0.0.1 dev eth0 proto dhcp metric 100
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.50 metric 100
172.17.0.0/16 dev docker0 proto kernel scope link linkdown
";
        let routes = parse_linux_ip_route(v4);
        assert_eq!(routes.len(), 3);
        assert_eq!(
            routes[0].gateway,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            routes[2].destination,
            IpNet::from_str("172.17.0.0/16").unwrap()
        );

        let v6 = "\
fd84:3bfe:bf84::/64 via fe80::1812:faa5:e4ee:1b9 dev eth0 metric 1024 pref medium
fdc5:3da0:fee0:47fa::/64 dev eth0 proto kernel metric 256 pref medium
default via fe80::1 dev eth0 metric 1024 pref medium
";
        let routes = parse_linux_ip_route(v6);
        let routed = routes
            .iter()
            .find(|r| r.destination.to_string() == "fd84:3bfe:bf84::/64")
            .expect("routed IPv6 subnet");
        assert_eq!(
            routed.gateway,
            Some("fe80::1812:faa5:e4ee:1b9".parse::<IpAddr>().unwrap())
        );
        // `ip -6` omits the %zone, so it is taken from the device the route sits on.
        assert_eq!(routed.gateway_zone.as_deref(), Some("eth0"));
    }

    #[test]
    fn windows_ipv6_route_table_parses_its_own_column_layout() {
        // The IPv6 table is If / Metric / Destination / Gateway, unlike the IPv4 one.
        let sample = "\
IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  5    271 ::/0                     fe80::1
 11    281 fd84:3bfe:bf84::/64      fe80::1812:faa5:e4ee:1b9
 11    281 fdc5:3da0:fee0:47fa::/64 On-link
===========================================================================
Persistent Routes:
  None
";
        let routes = parse_windows_route_print_v6(sample);

        let routed = routes
            .iter()
            .find(|r| r.destination.to_string() == "fd84:3bfe:bf84::/64")
            .expect("routed IPv6 subnet");
        assert_eq!(
            routed.gateway,
            Some("fe80::1812:faa5:e4ee:1b9".parse::<IpAddr>().unwrap())
        );
        assert_eq!(routed.interface.as_deref(), Some("11"));

        let attached = routes
            .iter()
            .find(|r| r.destination.to_string() == "fdc5:3da0:fee0:47fa::/64")
            .expect("attached prefix");
        assert!(attached.gateway.is_none(), "On-link is not a next hop");
    }

    #[test]
    fn windows_ipv4_route_table_still_parses() {
        let sample = "\
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
     192.168.1.0    255.255.255.0         On-link       192.168.1.50    281
===========================================================================
Persistent Routes:
  None
";
        let routes = parse_windows_route_print(sample);
        assert!(routes.iter().any(|r| r.is_default()));
        assert!(
            routes
                .iter()
                .any(|r| r.destination.to_string() == "192.168.1.0/24")
        );
    }

    #[test]
    fn scoped_addresses_keep_their_zone() {
        assert_eq!(
            parse_scoped_address("fe80::1%en0"),
            Some(("fe80::1".parse().unwrap(), Some("en0".to_string())))
        );
        assert_eq!(
            parse_scoped_address("10.0.0.1"),
            Some(("10.0.0.1".parse().unwrap(), None))
        );
        // A MAC or `link#11` in the gateway column is not a next hop.
        assert_eq!(parse_scoped_address("link#11"), None);
        assert_eq!(parse_scoped_address("4c:bb:47:0:48:f8"), None);
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
