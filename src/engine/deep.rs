use crate::engine::scanner::{HostResult, ScanSummary};
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
    pub cidr: Ipv4Net,
    pub label: String,
    pub summary: ScanSummary,
    pub snmp_system_name: Option<String>,
    pub snmp_system_descr: Option<String>,
}

/// Dynamically sweeps candidate gateway addresses inferred from the OS kernel routing table,
/// network interfaces, and adjacent private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// without any hardcoded IP lists.
pub async fn discover_routed_gateways(
    parent_cidr: &Ipv4Net,
    concurrency: usize,
    timeout_duration: Duration,
) -> Vec<Ipv4Net> {
    let candidates = crate::net::routes::derive_adjacent_candidate_gateways(parent_cidr).await;
    let mut tasks = Vec::with_capacity(candidates.len());
    let sem = Arc::new(Semaphore::new(concurrency.min(128)));

    for (gw, subnet) in candidates {
        let permit_sem = Arc::clone(&sem);
        let to = timeout_duration.min(Duration::from_millis(250));
        tasks.push(tokio::spawn(async move {
            let _permit = permit_sem.acquire().await.unwrap();
            for &p in &[80, 443, 53, 22, 161] {
                let probe = crate::engine::scanner::probe_tcp_port(gw, p, to).await;
                if probe.status == crate::engine::scanner::PortStatus::Open {
                    return Some(subnet);
                }
            }
            None
        }));
    }

    let mut discovered = HashSet::new();
    for task in tasks {
        if let Ok(Some(net)) = task.await {
            discovered.insert(net);
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
            communities: vec!["public".to_string(), "private".to_string()],
            port: 161,
        }
    }
}

/// Explores downstream and cascaded networks, using SNMP MIB-II walking
/// to extract router routing tables (`ipRouteTable`) and remote ARP caches (`ipNetToMediaTable`).
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
) -> Vec<ChildNetworkResult> {
    let mut queue = std::collections::VecDeque::new();
    let mut seen = HashSet::new();
    seen.insert(*parent_cidr);

    let effective_max_depth = if recursive { max_depth.max(1) } else { 1 };

    // Query UPnP / SSDP devices on the network
    let _upnp_devices =
        crate::probes::upnp::discover_upnp_devices(Duration::from_millis(400)).await;

    // 1. Add any explicitly specified subnets
    if let Some(extra) = extra_subnets_opt {
        for part in extra.split(',') {
            let part = part.trim();
            if let Ok(cidr) = Ipv4Net::from_str(part)
                && seen.insert(cidr)
            {
                queue.push_back((cidr, format!("Explicit Subnet ({})", cidr), 1));
            }
        }
    }

    // 2. Dynamically discover any active routed /24 gateways across RFC 1918
    let routed_subnets =
        discover_routed_gateways(parent_cidr, concurrency, timeout_duration).await;
    for subnet in routed_subnets {
        if seen.insert(subnet) {
            queue.push_back((
                subnet,
                format!("Dynamically Discovered Gateway ({})", subnet),
                1,
            ));
        }
    }

    let mut discovered_networks = Vec::new();

    while let Some((subnet, label, depth)) = queue.pop_front() {
        let mut summary = crate::engine::scanner::scan_subnet_ext(
            subnet,
            ports,
            None,
            concurrency,
            timeout_duration,
            None,
            false,
        )
        .await;

        let gw = Ipv4Addr::new(
            subnet.addr().octets()[0],
            subnet.addr().octets()[1],
            subnet.addr().octets()[2],
            1,
        );

        let mut sys_name = None;
        let mut sys_descr = None;

        // 3. SNMP MIB-II Harvesting: Probe gateways on discovered subnets
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

                    // Recover stealth firewalled devices from SNMP ARP table
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
                                Duration::from_millis(200),
                            )
                            .await;

                            for entry in missing_entries {
                                let hostname = ptr_map.remove(&entry.ip);
                                let vendor = crate::fingerprint::oui::lookup_mac(&entry.mac)
                                    .vendor
                                    .map(|v| v.to_string());

                                summary.active_hosts.push(HostResult {
                                    ip: entry.ip,
                                    is_alive: true,
                                    hostname,
                                    mac_address: Some(entry.mac.clone()),
                                    vendor,
                                    open_ports: Vec::new(),
                                    min_latency: None,
                                    ipv6_addrs: Vec::new(),
                                    ai_runtime: None,
                                });
                            }
                        }
                    }

                    // Recursive pivot: extract subnets from routing table and enqueue if depth < max_depth
                    if depth < effective_max_depth {
                        for route in &device_info.routes {
                            let prefix_len = u32::from(route.mask).count_ones() as u8;
                            if (16..=30).contains(&prefix_len)
                                && !route.dest_network.is_unspecified()
                                && !route.dest_network.is_loopback()
                                && let Ok(route_cidr) =
                                    Ipv4Net::new(route.dest_network, prefix_len)
                            {
                                let trunc = route_cidr.trunc();
                                if seen.insert(trunc) {
                                    queue.push_back((
                                        trunc,
                                        format!(
                                            "Recursive Pivot (Depth {}) via {} ({})",
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

                    break; // Successfully queried with this community
                }
            }
        }

        if !summary.active_hosts.is_empty() {
            discovered_networks.push(ChildNetworkResult {
                parent_router_ip: Some(gw),
                cidr: subnet,
                label,
                summary,
                snmp_system_name: sys_name,
                snmp_system_descr: sys_descr,
            });
        }
    }

    discovered_networks
}
