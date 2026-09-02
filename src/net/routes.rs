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

/// Identifies the evidence source that discovered a network route
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoverySource {
    KernelRoute,
    UpstreamHop,
    SnmpRouteTable,
    SnmpAddrTable,
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
            DiscoverySource::UpstreamHop => "Upstream Routed Gateway (TTL Hop)",
            DiscoverySource::SnmpRouteTable => "SNMP MIB-II ipRouteTable",
            DiscoverySource::SnmpAddrTable => "SNMP MIB-II ipAddrTable",
            DiscoverySource::UpnpSsdp => "UPnP / SSDP",
            DiscoverySource::DhcpOption3 => "DHCP Default Gateway",
            DiscoverySource::LldpCdp => "Layer 2 LLDP/CDP",
            DiscoverySource::ExplicitSubnet => "Explicit Subnet",
            DiscoverySource::HeuristicSweep => "Heuristic Sweep",
        }
    }
}

/// How much weight the evidence behind a route or pivot actually carries.
///
/// This is deliberately coarse. The point is that the renderers and exports can never
/// present a guessed network as if it were an observed one — every downstream consumer
/// is forced to carry the distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiscoveryConfidence {
    /// Derived by assumption, not observation (e.g. a TTL hop widened to a /24).
    /// Never emitted unless the operator explicitly opts in.
    Inferred,
    /// A control-plane source told us the network exists (SNMP route/address table,
    /// an LLDP/CDP management address, a DHCP option 3 router). We believe the device,
    /// but we have not reached the network ourselves.
    Advertised,
    /// The operator supplied it on the command line.
    UserSupplied,
    /// The local kernel holds a route for it, or we got a response from the gateway itself.
    Verified,
}

impl DiscoveryConfidence {
    pub fn display_name(&self) -> &'static str {
        match self {
            DiscoveryConfidence::Inferred => "inferred",
            DiscoveryConfidence::Advertised => "advertised",
            DiscoveryConfidence::UserSupplied => "user-supplied",
            DiscoveryConfidence::Verified => "verified",
        }
    }

    /// Short marker used in the topology tree and graph so the evidence grade is visible
    /// at a glance without reading the legend.
    pub fn marker(&self) -> &'static str {
        match self {
            DiscoveryConfidence::Inferred => "~",
            DiscoveryConfidence::Advertised => "+",
            DiscoveryConfidence::UserSupplied => "=",
            DiscoveryConfidence::Verified => "*",
        }
    }
}

/// A network we believe exists, together with the evidence that produced it.
///
/// `gateway` is optional on purpose: a directly connected interface subnet and an
/// operator-supplied CIDR both have a real network but no router address we have observed.
/// Inventing one (the old `cidr.addr()` behaviour) manufactured topology that was never seen.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiscoveredRoute {
    pub gateway: Option<Ipv4Addr>,
    pub network: Ipv4Net,
    pub source: DiscoverySource,
    pub confidence: DiscoveryConfidence,
}

/// A router we have evidence for, but whose attached networks we have NOT learned.
///
/// This is the honest representation of a traceroute hop, an LLDP/CDP management address,
/// or a DHCP option 3 router: we know the device is there and is worth interrogating,
/// but nothing so far tells us which prefixes hang off it. Pivots are interrogated
/// (SNMP) to turn them into real routes; they never become networks by assumption.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GatewayPivot {
    pub ip: Ipv4Addr,
    pub source: DiscoverySource,
    pub confidence: DiscoveryConfidence,
}

/// Everything the local machine could learn about adjacent topology without
/// yet talking to any router.
#[derive(Debug, Clone, Default)]
pub struct RouteDiscovery {
    /// Networks with a known prefix.
    pub routes: Vec<DiscoveredRoute>,
    /// Routers worth interrogating whose networks are still unknown.
    pub pivots: Vec<GatewayPivot>,
}

/// Options controlling how aggressively candidate topology is derived.
#[derive(Debug, Clone, Default)]
pub struct RouteDiscoveryOptions {
    /// Brute-force 192.168.x.1/.254 candidate sweep. Guessing, and labelled as such.
    pub enable_heuristic_sweep: bool,
    /// Widen an upstream TTL hop into an assumed /24. A hop proves that one router
    /// interface exists on the path; it proves nothing about the prefix length or about
    /// which networks that router actually serves. Off by default for that reason.
    pub infer_hop_subnets: bool,
    /// Off-link destination for TTL hop discovery. When `None`, a non-private system
    /// DNS resolver is used, and hop discovery is skipped entirely if there is none.
    pub trace_target: Option<Ipv4Addr>,
}

/// Reads the system resolver configuration and returns the first non-private,
/// non-loopback nameserver.
///
/// Used as the off-link destination for TTL hop discovery. Deriving the target from the
/// host's own configuration keeps idNX from shipping a hardcoded third-party address
/// (it previously always traced toward 1.1.1.1) and guarantees the destination is one
/// this machine is already configured to reach. If every configured resolver is private
/// (the common case where the router itself is the resolver), there is no derived target
/// and hop discovery is skipped rather than guessed.
pub fn system_offlink_probe_target() -> Option<Ipv4Addr> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
        parse_resolv_conf_offlink_target(&text)
    }

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("ipconfig")
            .arg("/all")
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        parse_windows_dns_offlink_target(&text)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

/// Extracts the first public `nameserver` entry from resolv.conf-format text.
pub fn parse_resolv_conf_offlink_target(text: &str) -> Option<Ipv4Addr> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        if let Ok(ip) = rest.trim().parse::<Ipv4Addr>()
            && is_routable_offlink(&ip)
        {
            return Some(ip);
        }
    }
    None
}

/// Extracts the first public DNS server from `ipconfig /all` output.
pub fn parse_windows_dns_offlink_target(text: &str) -> Option<Ipv4Addr> {
    let mut in_dns_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("DNS Servers") {
            in_dns_block = true;
            if let Some((_, value)) = trimmed.split_once(':')
                && let Ok(ip) = value.trim().parse::<Ipv4Addr>()
                && is_routable_offlink(&ip)
            {
                return Some(ip);
            }
            continue;
        }
        if in_dns_block {
            // Continuation lines carry only an indented address; anything else ends the block.
            match trimmed.parse::<Ipv4Addr>() {
                Ok(ip) if is_routable_offlink(&ip) => return Some(ip),
                Ok(_) => {}
                Err(_) => in_dns_block = false,
            }
        }
    }
    None
}

/// True for addresses that are usable as an off-link traceroute destination.
fn is_routable_offlink(ip: &Ipv4Addr) -> bool {
    !is_rfc1918(ip)
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_unspecified()
}

/// Discovers upstream router interfaces by reading private addresses out of TTL-limited
/// probe responses.
///
/// The return value is intentionally just a list of router addresses. A hop is evidence
/// that an L3 device forwarded a packet on the path to `target` — nothing more. It does not
/// establish the hop's prefix length, and it does not enumerate the other networks that
/// router serves. Turning hops into networks is the caller's opt-in decision
/// (`RouteDiscoveryOptions::infer_hop_subnets`); the default path feeds them in as pivots
/// to be interrogated instead.
pub async fn harvest_upstream_hops(
    parent_cidr: &Ipv4Net,
    trace_target: Option<Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    let mut hops = Vec::new();

    let Some(target) = trace_target.or_else(system_offlink_probe_target) else {
        // No off-link destination is derivable from this host's configuration.
        // Skipping is correct here: a fabricated destination would be a hardcoded IP.
        return hops;
    };
    let target_str = target.to_string();

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let output_res = Command::new("traceroute")
            .args(["-n", "-m", "4", "-q", "1", "-w", "1", &target_str])
            .output()
            .await;

        if let Ok(out) = output_res
            && let Ok(text) = String::from_utf8(out.stdout)
        {
            collect_hop_addresses(&text, parent_cidr, &mut hops);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let output_res = Command::new("tracert")
            .args(["-d", "-h", "4", "-w", "1000", &target_str])
            .output()
            .await;

        if let Ok(out) = output_res
            && let Ok(text) = String::from_utf8(out.stdout)
        {
            collect_hop_addresses(&text, parent_cidr, &mut hops);
        }
    }

    hops
}

/// Pulls the first private address out of each hop line of traceroute/tracert output.
pub fn collect_hop_addresses(text: &str, parent_cidr: &Ipv4Net, hops: &mut Vec<Ipv4Addr>) {
    for line in text.lines() {
        for token in line.split_whitespace() {
            if let Ok(ip) = token.parse::<Ipv4Addr>() {
                if is_rfc1918(&ip) && !parent_cidr.contains(&ip) && !hops.contains(&ip) {
                    hops.push(ip);
                }
                break;
            }
        }
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

/// Derives adjacent candidate topology from every local, passive evidence source:
/// the OS kernel routing table, local interface addresses, the DHCP lease, live
/// UPnP/SSDP advertisements, Layer 2 LLDP/CDP management addresses, and TTL hops.
///
/// Nothing here contacts a router. Networks whose prefix is actually known become
/// `routes`; routers whose networks are unknown become `pivots` for the deep engine to
/// interrogate. The split is what keeps an observed hop from being reported as an
/// observed subnet.
pub async fn derive_route_discovery(
    parent_cidr: &Ipv4Net,
    interface: Option<&str>,
    lldp_management_ips: &[Ipv4Addr],
    options: &RouteDiscoveryOptions,
) -> RouteDiscovery {
    let mut candidates: HashSet<DiscoveredRoute> = HashSet::new();
    let mut pivots: HashSet<GatewayPivot> = HashSet::new();

    // 1. Upstream routed gateways seen as TTL hops.
    //
    // A hop is a router address, not a network. It is recorded as a pivot so the deep
    // engine can ask it what it actually serves. Only when the operator opts in is the
    // hop widened into an assumed /24, and then it is explicitly marked `Inferred`.
    let upstream_hops = harvest_upstream_hops(parent_cidr, options.trace_target).await;
    for hop_ip in upstream_hops {
        pivots.insert(GatewayPivot {
            ip: hop_ip,
            source: DiscoverySource::UpstreamHop,
            confidence: DiscoveryConfidence::Advertised,
        });

        if options.infer_hop_subnets {
            let octets = hop_ip.octets();
            if let Ok(net) = Ipv4Net::new(Ipv4Addr::new(octets[0], octets[1], octets[2], 0), 24) {
                candidates.insert(DiscoveredRoute {
                    gateway: Some(hop_ip),
                    network: net,
                    source: DiscoverySource::UpstreamHop,
                    confidence: DiscoveryConfidence::Inferred,
                });
            }
        }
    }

    // 2. Kernel routing table (RFC 1918 private destinations only).
    let kernel_routes = harvest_kernel_routes().await;
    for route in kernel_routes {
        let prefix = route.destination.prefix_len();

        // The default route's destination is 0.0.0.0/0, which carries no network of its
        // own, but its gateway is the single most important pivot on the machine.
        if let Some(gw) = route.gateway
            && is_rfc1918(&gw)
        {
            pivots.insert(GatewayPivot {
                ip: gw,
                source: DiscoverySource::KernelRoute,
                confidence: DiscoveryConfidence::Verified,
            });
        }

        // Restrict automatic expansion strictly to private RFC 1918 networks
        if !is_rfc1918(&route.destination.addr()) {
            continue;
        }

        // Direct routed destination network with known prefix (e.g. /16, /20, /24)
        if prefix > 0 && prefix < 32 && &route.destination != parent_cidr {
            candidates.insert(DiscoveredRoute {
                gateway: route.gateway.filter(is_rfc1918),
                network: route.destination,
                source: DiscoverySource::KernelRoute,
                confidence: DiscoveryConfidence::Verified,
            });
        }

        // A gateway outside the parent subnet is reachable through some other network.
        // When the route's own destination contains it, that destination IS the network;
        // otherwise we do not know the prefix, so it stays a pivot rather than a guess.
        if let Some(gw) = route.gateway
            && is_rfc1918(&gw)
            && !parent_cidr.contains(&gw)
        {
            if route.destination.contains(&gw) && prefix > 0 && prefix < 32 {
                candidates.insert(DiscoveredRoute {
                    gateway: Some(gw),
                    network: route.destination,
                    source: DiscoverySource::KernelRoute,
                    confidence: DiscoveryConfidence::Verified,
                });
            } else {
                pivots.insert(GatewayPivot {
                    ip: gw,
                    source: DiscoverySource::KernelRoute,
                    confidence: DiscoveryConfidence::Verified,
                });
            }
        }
    }

    // 3. Secondary local interfaces contribute their exact configured CIDR.
    if let Ok(ifaces) = crate::net::interface::list_ipv4_interfaces() {
        for iface in ifaces {
            if &iface.cidr != parent_cidr && is_rfc1918(&iface.ip) {
                candidates.insert(DiscoveredRoute {
                    gateway: None, // Interface IP is a local machine address, not a router
                    network: iface.cidr,
                    source: DiscoverySource::KernelRoute,
                    confidence: DiscoveryConfidence::Verified,
                });
            }
        }
    }

    // 4. DHCP option 3 routers from the lease the OS already holds.
    for router_ip in harvest_dhcp_routers(interface).await {
        if is_rfc1918(&router_ip) {
            pivots.insert(GatewayPivot {
                ip: router_ip,
                source: DiscoverySource::DhcpOption3,
                confidence: DiscoveryConfidence::Advertised,
            });
        }
    }

    // 5. Layer 2 LLDP/CDP management addresses.
    //
    // A neighbour that advertises a management address is a switch or router we are
    // physically adjacent to. Its address is a pivot; its networks are unknown until
    // it is interrogated.
    for &mgmt_ip in lldp_management_ips {
        if is_rfc1918(&mgmt_ip) {
            pivots.insert(GatewayPivot {
                ip: mgmt_ip,
                source: DiscoverySource::LldpCdp,
                confidence: DiscoveryConfidence::Advertised,
            });
        }
    }

    // 6. UPnP/SSDP responders outside the parent subnet.
    let upnp_devices = crate::probes::upnp::discover_upnp_devices(Duration::from_millis(500)).await;
    for dev in upnp_devices {
        if !parent_cidr.contains(&dev.ip) && is_rfc1918(&dev.ip) {
            // Only attach to a network we already have a prefix for; never guess a /24.
            if let Some(existing) = candidates.iter().find(|c| c.network.contains(&dev.ip)) {
                let updated = DiscoveredRoute {
                    gateway: Some(dev.ip),
                    network: existing.network,
                    source: DiscoverySource::UpnpSsdp,
                    confidence: DiscoveryConfidence::Advertised,
                };
                candidates.insert(updated);
            } else {
                pivots.insert(GatewayPivot {
                    ip: dev.ip,
                    source: DiscoverySource::UpnpSsdp,
                    confidence: DiscoveryConfidence::Advertised,
                });
            }
        }
    }

    // 7. Opt-in heuristic sweep. This is guessing, and is labelled `Inferred` so it can
    // never be mistaken for observed topology in the tree, graph or export.
    if options.enable_heuristic_sweep {
        let octets = parent_cidr.addr().octets();
        if octets[0] == 192 && octets[1] == 168 {
            for third in 0..=255 {
                let gw1 = Ipv4Addr::new(192, 168, third, 1);
                let gw254 = Ipv4Addr::new(192, 168, third, 254);
                if let Ok(net) = Ipv4Net::new(Ipv4Addr::new(192, 168, third, 0), 24) {
                    if !parent_cidr.contains(&gw1) {
                        candidates.insert(DiscoveredRoute {
                            gateway: Some(gw1),
                            network: net,
                            source: DiscoverySource::HeuristicSweep,
                            confidence: DiscoveryConfidence::Inferred,
                        });
                    }
                    if !parent_cidr.contains(&gw254) {
                        candidates.insert(DiscoveredRoute {
                            gateway: Some(gw254),
                            network: net,
                            source: DiscoverySource::HeuristicSweep,
                            confidence: DiscoveryConfidence::Inferred,
                        });
                    }
                }
            }
        }
    }

    // Pivots inside the local subnet are deliberately KEPT. A managed switch sitting on
    // your own segment is exactly the device most likely to know about other VLANs and
    // uplinks; discarding it because its management address is local would throw away the
    // strongest evidence available. Deduplication happens in the deep engine, which seeds
    // the default gateway first.
    let mut routes: Vec<DiscoveredRoute> = candidates.into_iter().collect();
    let mut pivots: Vec<GatewayPivot> = pivots.into_iter().collect();

    // Deterministic ordering so repeated runs on an unchanged network produce identical
    // output, which is a precondition for the snapshot/diff work.
    routes.sort_by_key(|r| (r.network.addr(), r.network.prefix_len(), r.gateway));
    pivots.sort_by_key(|p| p.ip);

    RouteDiscovery { routes, pivots }
}

pub fn is_rfc1918(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    (o[0] == 10) || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
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
    fn test_discovered_route_topology_preservation() {
        let route = DiscoveredRoute {
            gateway: Some(Ipv4Addr::new(10, 20, 30, 17)),
            network: Ipv4Net::from_str("10.20.30.0/24").unwrap(),
            source: DiscoverySource::KernelRoute,
            confidence: DiscoveryConfidence::Verified,
        };
        assert_eq!(route.gateway, Some(Ipv4Addr::new(10, 20, 30, 17)));
        assert_eq!(route.source.display_name(), "Kernel Routing Table");
        assert_ne!(route.gateway, Some(Ipv4Addr::new(10, 20, 30, 1)));
    }

    #[test]
    fn test_confidence_orders_inferred_below_verified() {
        // Renderers rely on this ordering to pick the strongest evidence for a network.
        assert!(DiscoveryConfidence::Inferred < DiscoveryConfidence::Advertised);
        assert!(DiscoveryConfidence::Advertised < DiscoveryConfidence::UserSupplied);
        assert!(DiscoveryConfidence::UserSupplied < DiscoveryConfidence::Verified);
    }

    #[test]
    fn test_resolv_conf_skips_private_resolvers() {
        // A router-as-resolver setup yields no off-link target, and hop discovery is
        // then skipped rather than falling back to a hardcoded public address.
        let private_only = "# comment\nnameserver 192.168.1.1\nnameserver 10.0.0.1\n";
        assert_eq!(parse_resolv_conf_offlink_target(private_only), None);

        let mixed = "nameserver 192.168.1.1\nnameserver 9.9.9.9\n";
        assert_eq!(
            parse_resolv_conf_offlink_target(mixed),
            Some(Ipv4Addr::new(9, 9, 9, 9))
        );
    }

    #[test]
    fn test_collect_hop_addresses_excludes_parent_subnet() {
        let sample = "\
traceroute to 9.9.9.9, 4 hops max
 1  10.5.0.1  1.204 ms
 2  10.9.9.1  3.881 ms
 3  100.64.0.1  9.113 ms
 4  * * *
";
        let parent = Ipv4Net::from_str("10.5.0.0/24").unwrap();
        let mut hops = Vec::new();
        collect_hop_addresses(sample, &parent, &mut hops);

        // 10.5.0.1 is inside the parent subnet; 100.64.0.1 is CGNAT, not RFC 1918.
        assert_eq!(hops, vec![Ipv4Addr::new(10, 9, 9, 1)]);
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
