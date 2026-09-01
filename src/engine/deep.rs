use crate::engine::scanner::{HostResult, ScanSummary};
use crate::net::routes::{DiscoveredRoute, DiscoverySource, derive_candidate_routes};
use crate::probes::snmp::{SnmpArpEntry, harvest_snmp_device};
use ipnet::Ipv4Net;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Debug, Clone)]
pub struct ChildNetworkResult {
    pub parent_router_ip: Option<Ipv4Addr>,
    pub gateway: Ipv4Addr,
    pub cidr: Ipv4Net,
    pub label: String,
    pub source: DiscoverySource,
    pub summary: ScanSummary,
    pub snmp_system_name: Option<String>,
    pub snmp_system_descr: Option<String>,
}

/// Discovers verified routed networks by probing candidate gateways identified from
/// kernel routing tables, network interfaces, and live wire advertisements (UPnP / SSDP).
pub async fn discover_routed_gateways(
    parent_cidr: &Ipv4Net,
    concurrency: usize,
    timeout_duration: Duration,
    enable_heuristic_sweep: bool,
) -> Vec<DiscoveredRoute> {
    let candidates = derive_candidate_routes(parent_cidr, enable_heuristic_sweep).await;
    let mut tasks = Vec::with_capacity(candidates.len());
    let sem = Arc::new(Semaphore::new(concurrency.min(128)));

    for route in candidates {
        let permit_sem = Arc::clone(&sem);
        let to = timeout_duration.min(Duration::from_millis(350));
        tasks.push(tokio::spawn(async move {
            let _permit = permit_sem.acquire().await.unwrap();
            for &p in &[80, 443, 53, 22, 161] {
                let probe = crate::engine::scanner::probe_tcp_port(route.gateway, p, to).await;
                if probe.status == crate::engine::scanner::PortStatus::Open {
                    return Some(route);
                }
            }
            None
        }));
    }

    let mut discovered = HashSet::new();
    for task in tasks {
        if let Ok(Some(route)) = task.await {
            discovered.insert(route);
        }
    }
    discovered.into_iter().collect()
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

/// Explores downstream and cascaded networks, preserving verified gateway addresses
/// throughout scanning, SNMP MIB-II route table harvesting, and recursive pivots.
#[allow(clippy::too_many_arguments)]
pub async fn explore_downstream_networks(
    parent_cidr: &Ipv4Net,
    extra_subnets_opt: Option<&str>,
    ports: &[u16],
    concurrency: usize,
    timeout_duration: Duration,
    snmp_config: Option<&SnmpProbeConfig>,
    recursive: bool,
    max_depth: usize,
    enable_heuristic_sweep: bool,
) -> Vec<ChildNetworkResult> {
    let mut queue = std::collections::VecDeque::new();
    let mut seen = HashSet::new();
    seen.insert(*parent_cidr);

    let effective_max_depth = if recursive { max_depth.max(1) } else { 1 };

    // 1. Add any explicitly specified subnets
    if let Some(extra) = extra_subnets_opt {
        for part in extra.split(',') {
            let part = part.trim();
            if let Ok(cidr) = Ipv4Net::from_str(part)
                && seen.insert(cidr)
            {
                let gw = cidr.addr();
                queue.push_back((
                    DiscoveredRoute {
                        gateway: gw,
                        network: cidr,
                        source: DiscoverySource::ExplicitSubnet,
                    },
                    None,
                    format!("Explicit Subnet ({})", cidr),
                    1,
                ));
            }
        }
    }

    // 2. Discover active routed gateways from kernel routes and wire evidence
    let routed_gateways =
        discover_routed_gateways(parent_cidr, concurrency, timeout_duration, enable_heuristic_sweep).await;
    for route in routed_gateways {
        if seen.insert(route.network) {
            queue.push_back((
                route.clone(),
                None,
                format!("{} ({})", route.source.display_name(), route.network),
                1,
            ));
        }
    }

    let mut discovered_networks = Vec::new();

    while let Some((route, parent_gw, label, depth)) = queue.pop_front() {
        let subnet = route.network;
        let gw = route.gateway;

        let mut summary = crate::engine::scanner::scan_subnet_ext(
            subnet,
            ports,
            None,
            concurrency,
            timeout_duration.max(Duration::from_millis(500)),
            None,
            false,
        )
        .await;

        let mut sys_name = None;
        let mut sys_descr = None;

        // 3. SNMP MIB-II Harvesting: Probe verified gateway address directly
        if let Some(cfg) = snmp_config
            && cfg.enabled
        {
            for community in &cfg.communities {
                if let Some(device_info) = harvest_snmp_device(
                    gw,
                    cfg.port,
                    community,
                    Duration::from_millis(300),
                )
                .await
                {
                    sys_name = device_info.sys_name.clone();
                    sys_descr = device_info.sys_descr.clone();

                    // Recover and actively probe stealth devices from router's ARP cache
                    if !device_info.arp_cache.is_empty() {
                        let known_ips: HashSet<Ipv4Addr> =
                            summary.active_hosts.iter().map(|h| h.ip).collect();

                        let missing_entries: Vec<&SnmpArpEntry> = device_info
                            .arp_cache
                            .iter()
                            .filter(|entry| subnet.contains(&entry.ip) && !known_ips.contains(&entry.ip))
                            .collect();

                        if !missing_entries.is_empty() {
                            let missing_ips: Vec<Ipv4Addr> =
                                missing_entries.iter().map(|e| e.ip).collect();
                            let mut ptr_map = crate::net::dns::resolve_unicast_dns_ptrs(
                                &missing_ips,
                                gw,
                                Duration::from_millis(300),
                            )
                            .await;

                            let scan_sem = Arc::new(Semaphore::new(concurrency.min(32)));
                            for entry in missing_entries {
                                let hostname = ptr_map.remove(&entry.ip);
                                let vendor = crate::fingerprint::oui::lookup_mac(&entry.mac)
                                    .vendor
                                    .map(|v| v.to_string());

                                // Actively probe ports and services for recovered host
                                let (_tcp_alive, open_ports, min_lat) =
                                    crate::engine::scanner::scan_host_tcp(
                                        entry.ip,
                                        ports,
                                        Arc::clone(&scan_sem),
                                        timeout_duration.max(Duration::from_millis(600)),
                                    )
                                    .await;

                                let open_port_nums: Vec<u16> =
                                    open_ports.iter().map(|p| p.port).collect();
                                let ai_runtime = if open_port_nums
                                    .iter()
                                    .any(|&p| matches!(p, 11434 | 1234 | 8000 | 8080 | 5000 | 3000 | 80 | 443))
                                {
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

                    // Recursive pivot: extract subnets from routing table and preserve next hop
                    if depth < effective_max_depth {
                        for route_entry in &device_info.routes {
                            let prefix_len = u32::from(route_entry.mask).count_ones() as u8;
                            if (8..=30).contains(&prefix_len)
                                && !route_entry.dest_network.is_unspecified()
                                && !route_entry.dest_network.is_loopback()
                                && let Ok(route_cidr) =
                                    Ipv4Net::new(route_entry.dest_network, prefix_len)
                            {
                                let trunc = route_cidr.trunc();
                                if seen.insert(trunc) {
                                    let next_gw = if !route_entry.next_hop.is_unspecified()
                                        && route_entry.next_hop != Ipv4Addr::UNSPECIFIED
                                    {
                                        route_entry.next_hop
                                    } else {
                                        gw
                                    };
                                    queue.push_back((
                                        DiscoveredRoute {
                                            gateway: next_gw,
                                            network: trunc,
                                            source: DiscoverySource::SnmpRouteTable,
                                        },
                                        Some(gw),
                                        format!(
                                            "SNMP Route Table (Depth {}) via {} ({})",
                                            depth + 1,
                                            gw,
                                            trunc
                                        ),
                                        depth + 1,
                                    ));
                                }
                            }
                        }
                    }

                    break;
                }
            }
        }

        if !summary.active_hosts.is_empty() {
            discovered_networks.push(ChildNetworkResult {
                parent_router_ip: parent_gw,
                gateway: gw,
                cidr: subnet,
                label,
                source: route.source,
                summary,
                snmp_system_name: sys_name,
                snmp_system_descr: sys_descr,
            });
        }
    }

    discovered_networks
}
