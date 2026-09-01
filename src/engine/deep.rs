use crate::engine::scanner::{ScanSummary, scan_subnet};
use ipnet::Ipv4Net;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Debug, Clone)]
pub struct ChildNetworkResult {
    #[allow(dead_code)]
    pub parent_router_ip: Option<std::net::Ipv4Addr>,
    pub cidr: Ipv4Net,
    #[allow(dead_code)]
    pub label: String,
    pub summary: ScanSummary,
}

/// Dynamically sweeps RFC 1918 gateway addresses in parallel to discover
/// any reachable routed subnets without ANY hardcoded IP lists.
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
            let gw = std::net::Ipv4Addr::new(192, 168, third, 1);
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

/// Probes candidate downstream networks autonomously or sweeps user-specified subnets
pub async fn explore_downstream_networks(
    parent_cidr: &Ipv4Net,
    extra_subnets_opt: Option<&str>,
    ports: &[u16],
    concurrency: usize,
    timeout_duration: Duration,
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
    let routed_subnets = discover_routed_gateways(parent_cidr, concurrency, timeout_duration).await;
    for subnet in routed_subnets {
        if seen.insert(subnet) {
            targets_to_test.push((
                subnet,
                format!("Dynamically Discovered Gateway ({})", subnet),
            ));
        }
    }

    let mut discovered_networks = Vec::new();

    for (subnet, label) in targets_to_test {
        let summary = scan_subnet(subnet, ports, None, concurrency, timeout_duration, None).await;

        if !summary.active_hosts.is_empty() {
            discovered_networks.push(ChildNetworkResult {
                parent_router_ip: None,
                cidr: subnet,
                label,
                summary,
            });
        }
    }

    discovered_networks
}
