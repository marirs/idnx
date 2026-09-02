use crate::engine::scanner::{HostResult, ScanSummary};
use crate::net::routes::{
    DiscoveredRoute, DiscoveryConfidence, DiscoverySource, GatewayPivot, RouteDiscoveryOptions,
    derive_route_discovery, is_rfc1918,
};
use crate::probes::snmp::{SnmpArpEntry, SnmpDeviceInfo, harvest_snmp_device};
use ipnet::Ipv4Net;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// A network that was explored, together with the evidence trail that led to it.
#[derive(Debug, Clone)]
pub struct ChildNetworkResult {
    /// The router we learned this network *from*, when there was one.
    pub parent_router_ip: Option<Ipv4Addr>,
    /// The router address *on* this network. `None` when no router address was observed —
    /// a directly connected interface subnet or an operator-supplied CIDR, for instance.
    pub gateway: Option<Ipv4Addr>,
    pub cidr: Ipv4Net,
    pub label: String,
    pub source: DiscoverySource,
    pub confidence: DiscoveryConfidence,
    /// True when the network was too large to sweep exhaustively, so `summary` holds only
    /// hosts recovered from the router's ARP cache rather than a full enumeration.
    pub sweep_skipped: bool,
    pub summary: ScanSummary,
    pub snmp_system_name: Option<String>,
    pub snmp_system_descr: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnmpProbeConfig {
    pub enabled: bool,
    pub communities: Vec<String>,
    pub port: u16,
}

impl Default for SnmpProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            communities: vec!["public".to_string()],
            port: 161,
        }
    }
}

/// Everything the deep exploration pass needs, grouped so the entry point does not take
/// a dozen positional arguments.
#[derive(Debug, Clone)]
pub struct DeepScanConfig<'a> {
    pub ports: &'a [u16],
    /// Operator-supplied CIDRs (`--subnets`).
    pub extra_subnets: Option<&'a str>,
    /// Interface the primary scan is bound to; used to read the DHCP lease.
    pub interface: Option<&'a str>,
    /// Management addresses advertised by Layer 2 LLDP/CDP neighbours, captured before
    /// the deep pass. Each becomes a pivot to interrogate.
    pub lldp_management_ips: &'a [Ipv4Addr],
    pub concurrency: usize,
    pub timeout: Duration,
    pub snmp: Option<&'a SnmpProbeConfig>,
    pub recursive: bool,
    pub max_depth: usize,
    /// Largest auto-discovered network that will be swept host by host.
    ///
    /// Kernel routing tables routinely carry wide prefixes belonging to VM and container
    /// plumbing — a `/16` on a `feth`/`docker0` style interface is 65,534 addresses, and
    /// sweeping one stalls the run for no useful result. Networks above this bound are
    /// still reported and still interrogated over SNMP; only the exhaustive sweep is
    /// skipped. Operator-supplied `--subnets` are exempt: an explicit request is honoured.
    pub max_sweep_hosts: usize,
    pub route_options: RouteDiscoveryOptions,
}

impl<'a> DeepScanConfig<'a> {
    pub fn new(ports: &'a [u16]) -> Self {
        Self {
            ports,
            extra_subnets: None,
            interface: None,
            lldp_management_ips: &[],
            concurrency: 256,
            timeout: Duration::from_millis(800),
            snmp: None,
            recursive: false,
            max_depth: 2,
            max_sweep_hosts: DEFAULT_MAX_SWEEP_HOSTS,
            route_options: RouteDiscoveryOptions::default(),
        }
    }
}

/// Default ceiling for an exhaustive host sweep of an auto-discovered network (a `/20`).
pub const DEFAULT_MAX_SWEEP_HOSTS: usize = 4096;

/// Upper bound on routers interrogated in the seeding pass.
///
/// Pivots come from traceroute hops, LLDP/CDP neighbours, DHCP and UPnP, so the count is
/// naturally small; the cap only stops a pathological environment from turning seeding
/// into a scan of its own.
const MAX_SEED_PIVOTS: usize = 24;

/// Confirms that a candidate gateway is actually alive.
///
/// A router that answers on any of these is real. SNMP is checked over UDP 161 through the
/// SNMP client itself rather than by probing TCP 161 — SNMP is a UDP service, and a TCP
/// probe of port 161 fails against every correctly configured agent.
async fn gateway_responds(
    gw: Ipv4Addr,
    snmp_config: Option<&SnmpProbeConfig>,
    timeout_duration: Duration,
) -> bool {
    for &p in &[80, 443, 53, 22] {
        let probe = crate::engine::scanner::probe_tcp_port(gw, p, timeout_duration).await;
        if probe.status == crate::engine::scanner::PortStatus::Open {
            return true;
        }
    }

    if let Some(cfg) = snmp_config
        && cfg.enabled
    {
        for community in &cfg.communities {
            if harvest_snmp_device(gw, cfg.port, community, timeout_duration)
                .await
                .is_some()
            {
                return true;
            }
        }
    }

    false
}

/// Queries a router over SNMP, trying each configured community in turn.
async fn interrogate_gateway(
    gw: Ipv4Addr,
    snmp_config: Option<&SnmpProbeConfig>,
    timeout_duration: Duration,
) -> Option<SnmpDeviceInfo> {
    let cfg = snmp_config?;
    if !cfg.enabled {
        return None;
    }

    for community in &cfg.communities {
        if let Some(info) = harvest_snmp_device(gw, cfg.port, community, timeout_duration).await {
            return Some(info);
        }
    }
    None
}

/// Converts a router's SNMP MIB-II tables into networks it has told us about.
///
/// Two tables contribute, and they are not equivalent:
/// - `ipAddrTable` gives the router's own interface addresses and masks, i.e. the networks
///   it is *directly attached to*. The router's address on each is known exactly.
/// - `ipRouteTable` gives everything it forwards toward, including networks reached via a
///   further next hop.
///
/// Both are `Advertised`: the device asserted them, we have not reached them ourselves.
fn networks_advertised_by(info: &SnmpDeviceInfo, router_ip: Ipv4Addr) -> Vec<DiscoveredRoute> {
    let mut out = Vec::new();

    for (addr, mask) in &info.local_ips {
        let prefix_len = u32::from(*mask).count_ones() as u8;
        if !(8..=30).contains(&prefix_len) || !is_rfc1918(addr) {
            continue;
        }
        if let Ok(net) = Ipv4Net::new(*addr, prefix_len) {
            out.push(DiscoveredRoute {
                // The address in ipAddrTable IS this router's interface on that network.
                gateway: Some(*addr),
                network: net.trunc(),
                source: DiscoverySource::SnmpAddrTable,
                confidence: DiscoveryConfidence::Advertised,
            });
        }
    }

    for entry in &info.routes {
        let prefix_len = u32::from(entry.mask).count_ones() as u8;
        if !(8..=30).contains(&prefix_len)
            || entry.dest_network.is_unspecified()
            || entry.dest_network.is_loopback()
            || !is_rfc1918(&entry.dest_network)
        {
            continue;
        }
        let Ok(net) = Ipv4Net::new(entry.dest_network, prefix_len) else {
            continue;
        };
        // A zero next hop means the route is directly connected on the router we just
        // asked, so that router is the gateway. Otherwise the next hop is.
        let gateway = if entry.next_hop.is_unspecified() {
            Some(router_ip)
        } else {
            Some(entry.next_hop)
        };
        out.push(DiscoveredRoute {
            gateway,
            network: net.trunc(),
            source: DiscoverySource::SnmpRouteTable,
            confidence: DiscoveryConfidence::Advertised,
        });
    }

    out
}

/// Probes candidate gateways to confirm which routes are backed by a live router.
///
/// Routes whose gateway answers are upgraded to `Verified`. Routes with no gateway address
/// (a directly connected interface subnet) are passed through unchanged — there is nothing
/// to probe, and the kernel already vouches for them.
pub async fn confirm_routes(
    candidates: Vec<DiscoveredRoute>,
    concurrency: usize,
    timeout_duration: Duration,
    snmp_config: Option<&SnmpProbeConfig>,
) -> Vec<DiscoveredRoute> {
    let sem = Arc::new(Semaphore::new(concurrency.min(128)));
    let mut tasks = Vec::with_capacity(candidates.len());

    for route in candidates {
        let permit_sem = Arc::clone(&sem);
        let to = timeout_duration.min(Duration::from_millis(350));
        let snmp_owned = snmp_config.cloned();
        tasks.push(tokio::spawn(async move {
            let _permit = permit_sem.acquire().await.unwrap();
            match route.gateway {
                Some(gw) => {
                    if gateway_responds(gw, snmp_owned.as_ref(), to).await {
                        Some(DiscoveredRoute {
                            confidence: DiscoveryConfidence::Verified,
                            ..route
                        })
                    } else {
                        // Keep an inferred candidate out of the results entirely when its
                        // assumed gateway never answered; there is no evidence left.
                        if route.confidence == DiscoveryConfidence::Inferred {
                            None
                        } else {
                            Some(route)
                        }
                    }
                }
                None => Some(route),
            }
        }));
    }

    let mut discovered = HashSet::new();
    for task in tasks {
        if let Ok(Some(route)) = task.await {
            discovered.insert(route);
        }
    }

    let mut out: Vec<DiscoveredRoute> = discovered.into_iter().collect();
    out.sort_by_key(|r| (r.network.addr(), r.network.prefix_len(), r.gateway));
    out
}

/// Explores downstream and cascaded networks.
///
/// The pass runs in evidence order:
/// 1. Seed the pivot list with the OS default gateway, then every other router we have
///    passive evidence for (kernel routes, DHCP option 3, LLDP/CDP management addresses,
///    UPnP responders, TTL hops).
/// 2. Interrogate each pivot over SNMP and take the networks it advertises. This is the
///    only step that can turn a bare router address into real topology.
/// 3. Add operator-supplied subnets and kernel-verified routes.
/// 4. Scan each network, harvest the gateway's ARP cache for hosts that never answered,
///    and recurse into whatever its routing table advertises.
///
/// A router address is never widened into a network by assumption anywhere in this flow.
pub async fn explore_downstream_networks(
    parent_cidr: &Ipv4Net,
    config: &DeepScanConfig<'_>,
) -> Vec<ChildNetworkResult> {
    let mut queue = std::collections::VecDeque::new();
    let mut seen = HashSet::new();
    seen.insert(*parent_cidr);

    let effective_max_depth = if config.recursive {
        config.max_depth.max(1)
    } else {
        1
    };

    let discovery = derive_route_discovery(
        parent_cidr,
        config.interface,
        config.lldp_management_ips,
        &config.route_options,
    )
    .await;

    // 1. Assemble the pivot list, default gateway first.
    //
    // The default gateway sits inside the local subnet, so route-derivation deliberately
    // does not emit it as an adjacent network. It is still the single most valuable router
    // to interrogate: it is the one device guaranteed to know what lies upstream.
    let mut pivots: Vec<GatewayPivot> = Vec::new();
    let mut pivot_seen: HashSet<Ipv4Addr> = HashSet::new();

    if let Ok(info) = crate::net::interface::detect_local_network()
        && let Some(default_gw) = info.default_gateway
        && pivot_seen.insert(default_gw)
    {
        pivots.push(GatewayPivot {
            ip: default_gw,
            source: DiscoverySource::KernelRoute,
            confidence: DiscoveryConfidence::Verified,
        });
    }
    for pivot in discovery.pivots {
        if pivot_seen.insert(pivot.ip) {
            pivots.push(pivot);
        }
    }
    pivots.truncate(MAX_SEED_PIVOTS);

    // 2. Interrogate every pivot and enqueue the networks each one advertises.
    //
    // Queried concurrently, but the results are consumed in pivot order so that the `seen`
    // set — and therefore the reported topology — does not depend on which router answered
    // first. Determinism here is a precondition for snapshot/diff work later.
    let mut interrogations = Vec::with_capacity(pivots.len());
    for pivot in &pivots {
        let ip = pivot.ip;
        let snmp_owned = config.snmp.cloned();
        interrogations.push(tokio::spawn(async move {
            interrogate_gateway(ip, snmp_owned.as_ref(), Duration::from_millis(350)).await
        }));
    }

    let mut pivot_results = Vec::with_capacity(pivots.len());
    for handle in interrogations {
        pivot_results.push(handle.await.ok().flatten());
    }

    for (pivot, info) in pivots.iter().zip(pivot_results) {
        let Some(info) = info else {
            continue;
        };

        for route in networks_advertised_by(&info, pivot.ip) {
            if route.network == *parent_cidr || !seen.insert(route.network) {
                continue;
            }
            let label = format!(
                "{} via {} ({})",
                route.source.display_name(),
                pivot.ip,
                route.network
            );
            queue.push_back((route, Some(pivot.ip), label, 1usize));
        }
    }

    // 3. Operator-supplied subnets. No gateway is assumed for these: the operator gave us
    // a network, not a router.
    if let Some(extra) = config.extra_subnets {
        for part in extra.split(',') {
            let part = part.trim();
            if let Ok(cidr) = Ipv4Net::from_str(part)
                && seen.insert(cidr.trunc())
            {
                queue.push_back((
                    DiscoveredRoute {
                        gateway: None,
                        network: cidr.trunc(),
                        source: DiscoverySource::ExplicitSubnet,
                        confidence: DiscoveryConfidence::UserSupplied,
                    },
                    None,
                    format!("Explicit Subnet ({})", cidr.trunc()),
                    1,
                ));
            }
        }
    }

    // 4. Routes derived locally, confirmed against a live gateway where one is known.
    let confirmed = confirm_routes(
        discovery.routes,
        config.concurrency,
        config.timeout,
        config.snmp,
    )
    .await;
    for route in confirmed {
        if seen.insert(route.network) {
            let label = format!(
                "{} ({}, {})",
                route.source.display_name(),
                route.network,
                route.confidence.display_name()
            );
            queue.push_back((route, None, label, 1));
        }
    }

    let mut discovered_networks = Vec::new();

    while let Some((route, parent_gw, label, depth)) = queue.pop_front() {
        let subnet = route.network;
        let gw = route.gateway;

        // An operator who named a subnet explicitly gets it swept whatever its size.
        let sweep_exempt = route.source == DiscoverySource::ExplicitSubnet;
        let host_count = subnet.hosts().count();
        let sweep_skipped = !sweep_exempt && host_count > config.max_sweep_hosts;

        let mut summary = if sweep_skipped {
            ScanSummary {
                total_hosts: host_count,
                active_hosts: Vec::new(),
                elapsed: Duration::ZERO,
            }
        } else {
            crate::engine::scanner::scan_subnet_ext(
                subnet,
                config.ports,
                None,
                config.concurrency,
                config.timeout.max(Duration::from_millis(500)),
                None,
                false,
            )
            .await
        };

        let mut sys_name = None;
        let mut sys_descr = None;
        // A network we actually reached is no longer merely advertised. Reaching it is the
        // observation that upgrades it.
        let mut confidence = route.confidence;
        if !sweep_skipped
            && !summary.active_hosts.is_empty()
            && confidence < DiscoveryConfidence::Verified
        {
            confidence = DiscoveryConfidence::Verified;
        }

        // 5. SNMP harvesting against this network's own gateway, when one is known.
        if let Some(gw_ip) = gw
            && let Some(device_info) =
                interrogate_gateway(gw_ip, config.snmp, Duration::from_millis(300)).await
        {
            sys_name = device_info.sys_name.clone();
            sys_descr = device_info.sys_descr.clone();

            // Recover and actively probe stealth devices from the router's ARP cache.
            // These are hosts that ignored every probe but that the router has spoken to.
            if !device_info.arp_cache.is_empty() {
                let known_ips: HashSet<Ipv4Addr> =
                    summary.active_hosts.iter().map(|h| h.ip).collect();

                let missing_entries: Vec<&SnmpArpEntry> = device_info
                    .arp_cache
                    .iter()
                    .filter(|entry| subnet.contains(&entry.ip) && !known_ips.contains(&entry.ip))
                    .collect();

                if !missing_entries.is_empty() {
                    let missing_ips: Vec<Ipv4Addr> = missing_entries.iter().map(|e| e.ip).collect();
                    let mut ptr_map = crate::net::dns::resolve_unicast_dns_ptrs(
                        &missing_ips,
                        gw_ip,
                        Duration::from_millis(300),
                    )
                    .await;

                    let scan_sem = Arc::new(Semaphore::new(config.concurrency.min(32)));
                    for entry in missing_entries {
                        let hostname = ptr_map.remove(&entry.ip);
                        let vendor = crate::fingerprint::oui::lookup_mac(&entry.mac)
                            .vendor
                            .map(|v| v.to_string());

                        let (_tcp_alive, open_ports, min_lat) =
                            crate::engine::scanner::scan_host_tcp(
                                entry.ip,
                                config.ports,
                                Arc::clone(&scan_sem),
                                config.timeout.max(Duration::from_millis(600)),
                            )
                            .await;

                        let open_port_nums: Vec<u16> = open_ports.iter().map(|p| p.port).collect();
                        let ai_runtime = if open_port_nums.iter().any(|&p| {
                            matches!(p, 11434 | 1234 | 8000 | 8080 | 5000 | 3000 | 80 | 443)
                        }) {
                            crate::probes::ai::probe_ai_runtime(
                                entry.ip,
                                &open_port_nums,
                                Duration::from_millis(500),
                            )
                            .await
                        } else {
                            None
                        };

                        summary.active_hosts.push(HostResult {
                            ip: entry.ip,
                            is_alive: true,
                            hostname,
                            mac_address: Some(entry.mac.clone()),
                            vendor,
                            open_ports,
                            min_latency: min_lat,
                            ipv6_addrs: Vec::new(),
                            ai_runtime,
                        });
                    }
                }
            }

            // Recursive pivot into whatever this router advertises.
            if depth < effective_max_depth {
                for advertised in networks_advertised_by(&device_info, gw_ip) {
                    if advertised.network == *parent_cidr || !seen.insert(advertised.network) {
                        continue;
                    }
                    let child_label = format!(
                        "{} (Depth {}) via {} ({})",
                        advertised.source.display_name(),
                        depth + 1,
                        gw_ip,
                        advertised.network
                    );
                    queue.push_back((advertised, Some(gw_ip), child_label, depth + 1));
                }
            }
        }

        // A skipped sweep is still worth reporting: the network exists and the operator
        // needs to know it was found but deliberately not enumerated.
        if !summary.active_hosts.is_empty() || sweep_skipped {
            discovered_networks.push(ChildNetworkResult {
                parent_router_ip: parent_gw,
                gateway: gw,
                cidr: subnet,
                label,
                source: route.source,
                confidence,
                sweep_skipped,
                summary,
                snmp_system_name: sys_name,
                snmp_system_descr: sys_descr,
            });
        }
    }

    discovered_networks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::snmp::SnmpRouteEntry;

    fn info_with(local: Vec<(Ipv4Addr, Ipv4Addr)>, routes: Vec<SnmpRouteEntry>) -> SnmpDeviceInfo {
        SnmpDeviceInfo {
            sys_descr: None,
            sys_name: None,
            arp_cache: Vec::new(),
            routes,
            local_ips: local,
        }
    }

    #[test]
    fn test_addr_table_yields_router_interface_as_gateway() {
        let info = info_with(
            vec![(Ipv4Addr::new(10, 8, 0, 1), Ipv4Addr::new(255, 255, 255, 0))],
            Vec::new(),
        );
        let nets = networks_advertised_by(&info, Ipv4Addr::new(10, 0, 0, 1));

        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].network, Ipv4Net::from_str("10.8.0.0/24").unwrap());
        // The router's own interface address is the gateway on that network — not a
        // synthesized ".1" and not the network address.
        assert_eq!(nets[0].gateway, Some(Ipv4Addr::new(10, 8, 0, 1)));
        assert_eq!(nets[0].confidence, DiscoveryConfidence::Advertised);
    }

    #[test]
    fn test_route_table_zero_next_hop_uses_queried_router() {
        let info = info_with(
            Vec::new(),
            vec![SnmpRouteEntry {
                dest_network: Ipv4Addr::new(10, 9, 0, 0),
                mask: Ipv4Addr::new(255, 255, 0, 0),
                next_hop: Ipv4Addr::UNSPECIFIED,
            }],
        );
        let nets = networks_advertised_by(&info, Ipv4Addr::new(10, 0, 0, 1));

        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].gateway, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(nets[0].network.prefix_len(), 16);
    }

    #[test]
    fn test_public_and_default_routes_are_rejected() {
        let info = info_with(
            vec![(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(255, 255, 255, 0))],
            vec![
                // Default route: carries no network of its own.
                SnmpRouteEntry {
                    dest_network: Ipv4Addr::UNSPECIFIED,
                    mask: Ipv4Addr::UNSPECIFIED,
                    next_hop: Ipv4Addr::new(10, 0, 0, 254),
                },
                // Public WAN prefix: out of scope for private topology discovery.
                SnmpRouteEntry {
                    dest_network: Ipv4Addr::new(203, 0, 113, 0),
                    mask: Ipv4Addr::new(255, 255, 255, 0),
                    next_hop: Ipv4Addr::UNSPECIFIED,
                },
            ],
        );

        assert!(networks_advertised_by(&info, Ipv4Addr::new(10, 0, 0, 1)).is_empty());
    }
}
