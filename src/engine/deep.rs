use crate::engine::scanner::{scan_subnet, ScanSummary};
use ipnet::Ipv4Net;
use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ChildNetworkResult {
    #[allow(dead_code)]
    pub parent_router_ip: Option<std::net::Ipv4Addr>,
    pub cidr: Ipv4Net,
    #[allow(dead_code)]
    pub label: String,
    pub summary: ScanSummary,
}

/// Candidate default subnets used by cascaded home/lab routers (ASUS, Linksys, TP-Link, Netgear, OpenWrt)
const CANDIDATE_CASCADED_SUBNETS: &[&str] = &[
    "192.168.58.0/24", // ASUS RT-BE58-GO
    "192.168.92.0/24", // ASUS RT-BE92U
    "192.168.50.0/24", // ASUSWRT default LAN
    "192.168.51.0/24", // ASUS secondary router
    "192.168.2.0/24",  // Common secondary router
    "192.168.10.0/24", // IoT / Lab VLAN
];

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
    let _upnp_devices = crate::probes::upnp::discover_upnp_devices(Duration::from_millis(500)).await;

    // 1. Add any explicitly specified subnets
    if let Some(extra) = extra_subnets_opt {
        for part in extra.split(',') {
            let part = part.trim();
            if let Ok(cidr) = Ipv4Net::from_str(part) {
                if seen.insert(cidr) {
                    targets_to_test.push((cidr, format!("Cascaded Subnet ({})", cidr)));
                }
            }
        }
    }

    // 2. Add autonomous blackbox candidate subnets
    for &cand in CANDIDATE_CASCADED_SUBNETS {
        if let Ok(cidr) = Ipv4Net::from_str(cand) {
            if seen.insert(cidr) {
                targets_to_test.push((cidr, format!("Autonomous Heuristic ({})", cand)));
            }
        }
    }

    let mut discovered_networks = Vec::new();

    for (subnet, label) in targets_to_test {
        // Quick host check: probe gateway .1 and .254
        let octets = subnet.network().octets();
        let gateway_ip = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 1);

        // Check if gateway responds on port 80, 443, 53, 22, or 8080
        let is_reachable = {
            let mut reachable = false;
            for &p in &[80, 443, 53, 22, 8080] {
                let probe = crate::engine::scanner::probe_tcp_port(gateway_ip, p, timeout_duration).await;
                if probe.status == crate::engine::scanner::PortStatus::Open
                    || probe.status == crate::engine::scanner::PortStatus::Closed
                {
                    reachable = true;
                    break;
                }
            }
            reachable
        };

        // If gateway is reachable, perform sweep of the discovered child subnet
        if is_reachable {
            let summary = scan_subnet(
                subnet,
                ports,
                None,
                concurrency,
                timeout_duration,
                None,
            )
            .await;

            if !summary.active_hosts.is_empty() {
                discovered_networks.push(ChildNetworkResult {
                    parent_router_ip: None,
                    cidr: subnet,
                    label,
                    summary,
                });
            }
        }
    }

    discovered_networks
}
