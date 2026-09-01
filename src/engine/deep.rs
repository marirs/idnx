use crate::engine::scanner::{HostResult, ScanSummary, scan_subnet};
use crate::probes::snmp::{SnmpArpEntry, harvest_snmp_device};
use ipnet::Ipv4Net;
use std::collections::{HashMap, HashSet};
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

/// Dynamically sweeps RFC 1918 gateway addresses in parallel to discover
/// reachable routed subnets without any hardcoded IP lists.
pub async fn discover_routed_gateways(
    parent_cidr: &Ipv4Net,
    concurrency: usize,
    timeout_duration: Duration,
) -> Vec<Ipv4Net> {
    let mut tasks = Vec::with_capacity(254);
    let sem = Arc::new(Semaphore::new(concurrency.min(128)));
    let octets = parent_cidr.addr().octets();

    // If local network is in 192.168.0.0/16, sweep all 254 possible /24 subnets
    if octets[0] == 192 && octets[1] == 168 {
        for third in 1..=254 {
            let gw = Ipv4Addr::new(192, 168, third, 1);
            if parent_cidr.contains(&gw) {
                continue; // Skip the parent network itself
            }
            let permit_sem = Arc::clone(&sem);
            let to = timeout_duration.min(Duration::from_millis(250));
            tasks.push(tokio::spawn(async move {
                let _permit = permit_sem.acquire().await.unwrap();
                for &p in &[80, 443, 53] {
                    let probe = crate::engine::scanner::probe_tcp_port(gw, p, to).await;
                    if probe.status == crate::engine::scanner::PortStatus::Open {
                        let cidr_str = format!("192.168.{}.0/24", third);
                        if let Ok(c) = Ipv4Net::from_str(&cidr_str) {
                            return Some(c);
                        }
                    }
                }
                None
            }));
        }
    }

    let mut discovered = Vec::new();
    for task in tasks {
        if let Ok(Some(net)) = task.await {
            discovered.push(net);
        }
    }
    discovered
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
pub async fn explore_downstream_networks(
    parent_cidr: &Ipv4Net,
    extra_subnets_opt: Option<&str>,
    ports: &[u16],
    concurrency: usize,
    timeout_duration: Duration,
    snmp_config: Option<&SnmpProbeConfig>,
) -> Vec<ChildNetworkResult> {
    let mut targets_to_test = Vec::new();
    let mut seen = HashSet::new();
    seen.insert(*parent_cidr);

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
                targets_to_test.push((cidr, format!("Explicit Subnet ({})", cidr)));
            }
        }
    }

    // 2. Dynamically discover any active routed /24 gateways across RFC 1918
    let routed_subnets =
        discover_routed_gateways(parent_cidr, concurrency, timeout_duration).await;
    for subnet in routed_subnets {
        if seen.insert(subnet) {
            targets_to_test.push((
                subnet,
                format!("Dynamically Discovered Gateway ({})", subnet),
            ));
        }
    }

    // 3. SNMP MIB-II Harvesting: Probe gateways on all discovered subnets
    let mut snmp_arp_by_subnet: HashMap<Ipv4Net, Vec<SnmpArpEntry>> = HashMap::new();
    let mut snmp_info_by_subnet: HashMap<Ipv4Net, (Option<String>, Option<String>)> =
        HashMap::new();

    if let Some(cfg) = snmp_config
        && cfg.enabled
    {
        let mut new_route_targets = Vec::new();

        for (subnet, _) in &targets_to_test {
            // Standard gateway is typically .1
            let gw = Ipv4Addr::new(
                subnet.addr().octets()[0],
                subnet.addr().octets()[1],
                subnet.addr().octets()[2],
                1,
            );

            for community in &cfg.communities {
                if let Some(device_info) = harvest_snmp_device(
                    gw,
                    cfg.port,
                    community,
                    Duration::from_millis(300),
                )
                .await
                {
                    snmp_info_by_subnet.insert(
                        *subnet,
                        (device_info.sys_name.clone(), device_info.sys_descr.clone()),
                    );

                    if !device_info.arp_cache.is_empty() {
                        snmp_arp_by_subnet
                            .entry(*subnet)
                            .or_default()
                            .extend(device_info.arp_cache);
                    }

                    // Dynamically uncover additional subnets from the router's `ipRouteTable`
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
                                new_route_targets.push((
                                    trunc,
                                    format!(
                                        "SNMP Route via {} ({})",
                                        gw, trunc
                                    ),
                                ));
                            }
                        }
                    }

                    break; // Successfully queried with this community
                }
            }
        }

        targets_to_test.extend(new_route_targets);
    }

    let mut discovered_networks = Vec::new();

    for (subnet, label) in targets_to_test {
        let mut summary =
            scan_subnet(subnet, ports, None, concurrency, timeout_duration, None).await;

        // 4. Enrich hosts with SNMP-harvested ARP cache (recovering stealth firewalled devices)
        if let Some(arp_entries) = snmp_arp_by_subnet.get(&subnet) {
            let known_ips: HashSet<Ipv4Addr> =
                summary.active_hosts.iter().map(|h| h.ip).collect();

            let gw = Ipv4Addr::new(
                subnet.addr().octets()[0],
                subnet.addr().octets()[1],
                subnet.addr().octets()[2],
                1,
            );

            let missing_entries: Vec<&SnmpArpEntry> = arp_entries
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
                    });
                }
            }
        }

        if !summary.active_hosts.is_empty() {
            let (sys_name, sys_descr) = snmp_info_by_subnet
                .remove(&subnet)
                .unwrap_or((None, None));

            let gw = Ipv4Addr::new(
                subnet.addr().octets()[0],
                subnet.addr().octets()[1],
                subnet.addr().octets()[2],
                1,
            );

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
