use crate::net::arp::{ArpEntry, read_system_arp_table, trigger_kernel_arp_sweep};
use indicatif::ProgressBar;
use ipnet::Ipv4Net;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    /// The probe never left this machine: the socket could not be created or bound.
    ///
    /// Distinct from `Filtered`, which means the packet went out and nothing came back.
    /// Conflating the two reported a local misconfiguration as remote silence, which is
    /// how an interface with no usable source address came to look like a quiet network.
    NotSent,
}

#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub status: PortStatus,
    pub latency: Option<Duration>,
    pub service: &'static str,
    /// Why the probe never left this machine, when it did not.
    pub local_error: Option<String>,
}

/// Whether a connect error means the probe never left this machine.
///
/// These are all failures of socket creation or binding. Anything else -- a timeout, a
/// refusal, an unreachable network -- involved the packet actually going out.
fn is_local_failure(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::AddrInUse
            | std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::Unsupported
    )
}

#[derive(Debug, Clone)]
pub struct HostResult {
    pub ip: Ipv4Addr,
    pub is_alive: bool,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub open_ports: Vec<PortInfo>,
    pub min_latency: Option<Duration>,
    pub ipv6_addrs: Vec<std::net::Ipv6Addr>,
}

#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub total_hosts: usize,
    pub active_hosts: Vec<HostResult>,
    pub elapsed: Duration,
}

/// Resolves well-known service names for common ports
pub fn lookup_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        443 => "https",
        445 => "microsoft-ds",
        993 => "imaps",
        995 => "pop3s",
        1433 => "ms-sql-s",
        1521 => "oracle",
        1723 => "pptp",
        1900 => "upnp/ssdp",
        3306 => "mysql",
        3389 => "ms-wbt-server (rdp)",
        5000 => "upnp/http",
        5432 => "postgresql",
        5678 => "mikrotik-mndp",
        5900 => "vnc",
        6379 => "redis",
        1234 => "lmstudio/llm",
        8000 => "http-alt",
        8080 => "http-proxy",
        8291 => "mikrotik-winbox",
        8443 => "https-alt",
        8888 => "http-alt",
        9000 => "http-alt",
        11434 => "ollama/llm",
        27017 => "mongodb",
        _ => "unknown",
    }
}

/// Parses comma-separated ports and ranges (e.g. "22,80,443", "80-85", "common")
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let input = input.trim();
    if input.eq_ignore_ascii_case("common") || input.eq_ignore_ascii_case("default") {
        return Ok(vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 443, 445, 993, 995, 1234, 1433,
            1521, 1900, 3306, 3389, 5432, 5678, 5900, 6379, 8080, 8291, 8443, 11434,
        ]);
    }

    let mut port_set = HashSet::new();

    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(format!("Invalid port range: {}", part));
            }
            let start = range_parts[0]
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("Invalid start port in range: {}", part))?;
            let end = range_parts[1]
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("Invalid end port in range: {}", part))?;

            if start > end {
                return Err(format!(
                    "Port range start cannot be greater than end: {}",
                    part
                ));
            }

            for p in start..=end {
                port_set.insert(p);
            }
        } else {
            let port = part
                .parse::<u16>()
                .map_err(|_| format!("Invalid port number: {}", part))?;
            port_set.insert(port);
        }
    }

    if port_set.is_empty() {
        return Err("No valid ports specified.".to_string());
    }

    let mut sorted_ports: Vec<u16> = port_set.into_iter().collect();
    sorted_ports.sort_unstable();
    Ok(sorted_ports)
}

/// Probes a single TCP port using asynchronous connect with timeout
pub async fn probe_tcp_port(
    ip: Ipv4Addr,
    port: u16,
    binding: &crate::net::socket::SocketBinding,
    timeout_duration: Duration,
) -> PortInfo {
    probe_tcp_socket(
        SocketAddr::V4(SocketAddrV4::new(ip, port)),
        binding,
        timeout_duration,
    )
    .await
}

/// Probes one TCP port at a fully formed socket address.
///
/// Address-family neutral, so an IPv6 neighbour is interrogated exactly as an IPv4 one is.
/// A link-local destination carries its scope index in the socket address already.
pub async fn probe_tcp_socket(
    addr: SocketAddr,
    binding: &crate::net::socket::SocketBinding,
    timeout_duration: Duration,
) -> PortInfo {
    let port = addr.port();
    let start = Instant::now();

    match binding.tcp_connect(addr, timeout_duration).await {
        Ok(mut stream) => {
            let elapsed = start.elapsed();
            let mut service = lookup_service(port);

            // Active banner grabbing for service identification
            if port == 22 {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 128];
                if let Ok(Ok(n)) = timeout(Duration::from_millis(250), stream.read(&mut buf)).await
                    && n > 0
                {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    if banner.contains("Ubuntu") {
                        service = "ssh (Ubuntu Linux)";
                    } else if banner.contains("Debian") {
                        service = "ssh (Debian Linux)";
                    } else if banner.contains("Raspbian") {
                        service = "ssh (Raspberry Pi)";
                    } else if banner.contains("FreeBSD") {
                        service = "ssh (FreeBSD)";
                    } else if banner.contains("Cisco") {
                        service = "ssh (Cisco)";
                    } else if banner.contains("Dropbear") {
                        service = "ssh (Embedded Linux / Router)";
                    }
                }
            } else if port == 80 || port == 8080 {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let req = format!(
                    "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: idnx/{}\r\nConnection: close\r\n\r\n",
                    addr.ip(),
                    env!("CARGO_PKG_VERSION")
                );
                let _ = stream.write_all(req.as_bytes()).await;
                let mut buf = [0u8; 256];
                if let Ok(Ok(n)) = timeout(Duration::from_millis(250), stream.read(&mut buf)).await
                    && n > 0
                {
                    let res = String::from_utf8_lossy(&buf[..n]);
                    let lower = res.to_ascii_lowercase();
                    if lower.contains("server: nginx") {
                        service = "http (nginx)";
                    } else if lower.contains("server: apache") {
                        service = "http (Apache)";
                    } else if lower.contains("server: lighttpd") {
                        service = "http (Lighttpd)";
                    } else if lower.contains("server: iis") {
                        service = "http (Microsoft-IIS)";
                    }
                }
            }

            PortInfo {
                port,
                status: PortStatus::Open,
                latency: Some(elapsed),
                service,
                local_error: None,
            }
        }
        // A refusal proves the host is alive.
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortInfo {
            port,
            status: PortStatus::Closed,
            latency: Some(start.elapsed()),
            service: lookup_service(port),
            local_error: None,
        },
        // The socket could not be created or bound, so nothing was ever sent. Reporting
        // this as a timeout would attribute a local failure to the remote device.
        Err(e) if is_local_failure(&e) => PortInfo {
            port,
            status: PortStatus::NotSent,
            latency: None,
            service: lookup_service(port),
            local_error: Some(e.to_string()),
        },
        Err(_) => PortInfo {
            port,
            status: PortStatus::Filtered,
            latency: None,
            service: lookup_service(port),
            local_error: None,
        },
    }
}

/// Scans a single host across multiple ports with concurrency control
pub async fn scan_host_tcp(
    ip: Ipv4Addr,
    ports: &[u16],
    channel: &crate::net::socket::ProbeChannel,
    timeout_duration: Duration,
) -> (bool, Vec<PortInfo>, Option<Duration>) {
    let mut tasks = Vec::with_capacity(ports.len());

    for &port in ports {
        let sem = Arc::clone(&channel.permits);
        let binding = Arc::clone(&channel.binding);
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            Some(probe_tcp_port(ip, port, &binding, timeout_duration).await)
        }));
    }

    let mut open_ports = Vec::new();
    let mut is_alive = false;
    let mut min_latency: Option<Duration> = None;

    for task in tasks {
        if let Ok(Some(info)) = task.await {
            if info.status == PortStatus::Open {
                is_alive = true;
                if let Some(lat) = info.latency {
                    min_latency = Some(min_latency.map_or(lat, |m| m.min(lat)));
                }
                open_ports.push(info);
            } else if info.status == PortStatus::Closed {
                is_alive = true;
                if let Some(lat) = info.latency {
                    min_latency = Some(min_latency.map_or(lat, |m| m.min(lat)));
                }
            }
        }
    }

    open_ports.sort_by_key(|p| p.port);
    (is_alive, open_ports, min_latency)
}

/// Fast ICMP ping probe for discovering live hosts across routed/cascaded subnets
pub async fn ping_host(ip: Ipv4Addr, timeout_duration: Duration) -> bool {
    let timeout_ms = (timeout_duration.as_millis() as u64).clamp(300, 1500);

    #[cfg(target_os = "macos")]
    let cmd = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", &timeout_ms.to_string(), &ip.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    #[cfg(target_os = "windows")]
    let cmd = tokio::process::Command::new("ping")
        .args(["-n", "1", "-w", &timeout_ms.to_string(), &ip.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let cmd = tokio::process::Command::new("ping")
        .args([
            "-c",
            "1",
            "-W",
            &(timeout_ms / 1000).max(1).to_string(),
            &ip.to_string(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match tokio::time::timeout(timeout_duration, cmd).await {
        Ok(Ok(s)) => s.success(),
        _ => false,
    }
}

/// Scans an entire CIDR network block using combined ARP + TCP discovery
pub async fn scan_subnet(
    cidr: Ipv4Net,
    ports: &[u16],
    interface_filter: Option<&str>,
    concurrency: usize,
    timeout_duration: Duration,
    progress_bar: Option<ProgressBar>,
) -> ScanSummary {
    scan_subnet_ext(
        cidr,
        ports,
        interface_filter,
        &crate::net::socket::ProbeChannel::unbound(concurrency),
        timeout_duration,
        progress_bar,
        true,
    )
    .await
}

/// Core asynchronous scanning engine with optional IPv6 discovery control
#[allow(clippy::too_many_arguments)]
pub async fn scan_subnet_ext(
    cidr: Ipv4Net,
    ports: &[u16],
    interface_filter: Option<&str>,
    channel: &crate::net::socket::ProbeChannel,
    timeout_duration: Duration,
    progress_bar: Option<ProgressBar>,
    enable_ipv6: bool,
) -> ScanSummary {
    let start_time = Instant::now();
    let hosts: Vec<Ipv4Addr> = cidr.hosts().collect();
    let total_hosts = hosts.len();

    // 1. Trigger kernel-level ARP broadcast sweep for local subnets
    trigger_kernel_arp_sweep(cidr, channel).await;

    // 2. Read system ARP table to find all live L2 devices
    let arp_entries = read_system_arp_table(interface_filter);
    let mut arp_map: HashMap<Ipv4Addr, ArpEntry> = HashMap::new();
    for entry in arp_entries {
        if cidr.contains(&entry.ip) {
            arp_map.insert(entry.ip, entry);
        }
    }

    // 3. Scan TCP ports across all hosts concurrently, on the run-wide probe budget. A
    // semaphore of this scanner's own let its traffic exceed the limit every other path
    // observes.
    let ports_arc = Arc::new(ports.to_vec());
    let mut tcp_tasks = Vec::with_capacity(total_hosts);

    for ip in &hosts {
        let ip = *ip;
        let chan = channel.clone();
        let p_list = Arc::clone(&ports_arc);
        let pb = progress_bar.clone();

        tcp_tasks.push(tokio::spawn(async move {
            let res = scan_host_tcp(ip, &p_list, &chan, timeout_duration).await;
            if let Some(ref bar) = pb {
                bar.inc(1);
            }
            (ip, res)
        }));
    }

    let mut host_results: HashMap<Ipv4Addr, HostResult> = HashMap::new();

    // Populate with ARP-discovered devices first (they are 100% active on the wire!)
    for (&ip, arp) in &arp_map {
        if ip == cidr.broadcast()
            || ip.is_broadcast()
            || arp.mac == "ff:ff:ff:ff:ff:ff"
            || ip.is_multicast()
        {
            continue;
        }
        host_results.insert(
            ip,
            HostResult {
                ip,
                is_alive: true,
                hostname: arp.hostname.clone(),
                mac_address: Some(arp.mac.clone()),
                vendor: arp.vendor.clone(),
                open_ports: Vec::new(),
                min_latency: None,
                ipv6_addrs: Vec::new(),
            },
        );
    }

    // Merge TCP probe findings
    for task in tcp_tasks {
        if let Ok((ip, (tcp_alive, open_ports, min_lat))) = task.await {
            if tcp_alive || !open_ports.is_empty() {
                let entry = host_results.entry(ip).or_insert_with(|| HostResult {
                    ip,
                    is_alive: true,
                    hostname: None,
                    mac_address: None,
                    vendor: None,
                    open_ports: Vec::new(),
                    min_latency: None,
                    ipv6_addrs: Vec::new(),
                });

                entry.is_alive = true;
                entry.open_ports = open_ports;
                if min_lat.is_some() {
                    entry.min_latency = min_lat;
                }
            } else if let Some(entry) = host_results.get_mut(&ip) {
                // Device was seen in ARP, keep open_ports updated
                entry.open_ports = open_ports;
                if min_lat.is_some() {
                    entry.min_latency = min_lat;
                }
            }
        }
    }

    // ICMP Ping Sweep fallback for stealth hosts with no open TCP ports (e.g. Mac-mini, Mac, routers)
    let missing_liveness: Vec<Ipv4Addr> = hosts
        .iter()
        .copied()
        .filter(|ip| !host_results.contains_key(ip))
        .collect();

    if !missing_liveness.is_empty() {
        let ping_sem = Arc::clone(&channel.permits);
        let mut ping_tasks = Vec::with_capacity(missing_liveness.len());
        for &ip in &missing_liveness {
            let p_sem = Arc::clone(&ping_sem);
            let to = timeout_duration.max(Duration::from_millis(750));
            ping_tasks.push(tokio::spawn(async move {
                let _permit = p_sem.acquire().await.unwrap();
                if ping_host(ip, to).await {
                    Some(ip)
                } else {
                    None
                }
            }));
        }

        for task in ping_tasks {
            if let Ok(Some(ip)) = task.await {
                host_results.entry(ip).or_insert_with(|| HostResult {
                    ip,
                    is_alive: true,
                    hostname: None,
                    mac_address: None,
                    vendor: None,
                    open_ports: Vec::new(),
                    min_latency: None,
                    ipv6_addrs: Vec::new(),
                });
            }
        }
    }

    if let Some(ref bar) = progress_bar {
        bar.finish_and_clear();
    }

    // 4. Resolve mDNS hostnames for all active hosts (e.g. Srirams-Mac-Studio)
    let active_ips: Vec<Ipv4Addr> = host_results.keys().copied().collect();
    let mdns_names = crate::net::mdns::resolve_mdns_hostnames(
        &active_ips,
        &channel.binding,
        Duration::from_millis(500),
    )
    .await;
    for (ip, name) in mdns_names {
        if let Some(host) = host_results.get_mut(&ip) {
            let is_generic = host.hostname.as_deref().is_none_or(|h| {
                h == "?"
                    || h == "-"
                    || h.eq_ignore_ascii_case("mac")
                    || h.eq_ignore_ascii_case("unknown")
            });
            if is_generic {
                host.hostname = Some(name);
            }
        }
    }

    // 4b. Resolve Unicast DNS PTR records against the subnet gateway (for routed/cascaded networks)
    let missing_ips: Vec<Ipv4Addr> = host_results
        .values()
        .filter(|h| h.hostname.is_none())
        .map(|h| h.ip)
        .collect();

    if !missing_ips.is_empty() {
        // Pick the resolver deterministically. `host_results` is a HashMap, so taking the
        // first port-53 host out of its iteration order made hostname resolution vary
        // between identical runs — and it preferred an arbitrary DNS host over the router
        // that actually holds the DHCP lease names.
        //
        // Order: the subnet's own gateway, then the numerically lowest host offering DNS,
        // then the default gateway even if it never answered on 53.
        let default_gw = crate::net::interface::detect_local_network()
            .ok()
            .and_then(|info| info.default_gateway);

        let gateway_in_subnet = default_gw.filter(|gw| cidr.contains(gw));

        let lowest_dns_host = {
            let mut dns_hosts: Vec<Ipv4Addr> = host_results
                .values()
                .filter(|h| h.open_ports.iter().any(|p| p.port == 53))
                .map(|h| h.ip)
                .collect();
            dns_hosts.sort();
            dns_hosts.first().copied()
        };

        let dns_server_opt = gateway_in_subnet.or(lowest_dns_host).or(default_gw);

        if let Some(gw_ip) = dns_server_opt {
            let dns_ptrs = crate::net::dns::resolve_unicast_dns_ptrs(
                &missing_ips,
                gw_ip,
                &channel.binding,
                Duration::from_millis(400),
            )
            .await;
            for (ip, name) in dns_ptrs {
                if let Some(host) = host_results.get_mut(&ip)
                    && host.hostname.is_none()
                {
                    host.hostname = Some(name);
                }
            }
        }
    }

    // 5. Query UPnP / SSDP device descriptions for rich hardware metadata
    let upnp_devices =
        crate::probes::upnp::discover_upnp_devices(&channel.binding, Duration::from_millis(500))
            .await;
    for dev in upnp_devices {
        if let Some(host) = host_results.get_mut(&dev.ip) {
            let model_opt = dev.model_description.or(dev.model_name);
            if let Some(ref model) = model_opt {
                if let Some(ref mfg) = dev.manufacturer {
                    host.vendor = Some(format!("{} ({})", mfg, model));
                } else {
                    host.vendor = Some(model.clone());
                }
            }
            if let Some(ref fname) = dev.friendly_name {
                let is_generic = host.hostname.as_deref().is_none_or(|h| {
                    h == "?"
                        || h == "-"
                        || h.eq_ignore_ascii_case("mac")
                        || h.eq_ignore_ascii_case("unknown")
                });
                if is_generic {
                    host.hostname = Some(fname.clone());
                }
            }
        }
    }

    // 6. Targeted Deep Protocol Fingerprinting (TLS X.509 Certificate & SMB Negotiate)
    for host in host_results.values_mut() {
        // Probe SMB if port 445 or 139 is open
        let has_smb = host
            .open_ports
            .iter()
            .any(|p| p.port == 445 || p.port == 139);
        if has_smb
            && let Some(smb_info) = crate::probes::smb::probe_smb(
                &crate::net::endpoint::Endpoint::global(std::net::IpAddr::V4(host.ip)),
                445,
                &channel.binding,
                Duration::from_millis(400),
            )
            .await
            && let Some(comp_name) = smb_info.dns_computer_name.or(smb_info.computer_name)
        {
            let domain_tag = smb_info
                .domain_name
                .map(|d| format!(".{}", d))
                .unwrap_or_default();
            host.hostname = Some(format!("{}{}", comp_name, domain_tag));
        }

        // Probe TLS X.509 Certificate if port 443 or 8443 is open
        let tls_port = host
            .open_ports
            .iter()
            .find(|p| p.port == 443 || p.port == 8443)
            .map(|p| p.port);

        let is_hostname_missing = host.hostname.is_none()
            || host.hostname.as_deref() == Some("?")
            || host.hostname.as_deref() == Some("-");

        if let Some(p) = tls_port
            && is_hostname_missing
            && let Some(tls_info) = crate::probes::tls::probe_tls_certificate(
                &crate::net::endpoint::Endpoint::global(std::net::IpAddr::V4(host.ip)),
                p,
                &channel.binding,
                Duration::from_millis(400),
            )
            .await
            && let Some(cn) = tls_info.common_name
        {
            host.hostname = Some(cn);
        }
    }

    // 7. Dual-Stack IPv6 NDP Neighbor Harvesting & Correlation
    let mut ipv6_only_hosts = Vec::new();
    if enable_ipv6 {
        if let Some(iface) = interface_filter {
            crate::net::ipv6::stimulate_ipv6_neighbors(iface).await;
        }
        let ndp_entries = crate::net::ipv6::harvest_ndp_cache(interface_filter).await;

        let mut matched_ndp_macs = HashSet::new();
        for ndp in &ndp_entries {
            for host in host_results.values_mut() {
                if let Some(ref host_mac) = host.mac_address
                    && host_mac.eq_ignore_ascii_case(&ndp.mac)
                {
                    if !host.ipv6_addrs.contains(&ndp.ip) {
                        host.ipv6_addrs.push(ndp.ip);
                    }
                    matched_ndp_macs.insert(ndp.mac.to_lowercase());
                }
            }
        }

        // Collect all discovered IPv6 addresses for reverse mDNS PTR resolution
        let all_ipv6s: Vec<std::net::Ipv6Addr> = ndp_entries.iter().map(|e| e.ip).collect();
        let ipv6_mdns_names = crate::net::mdns::resolve_ipv6_mdns_hostnames(
            &all_ipv6s,
            &channel.binding,
            Duration::from_millis(400),
        )
        .await;

        // Apply resolved IPv6 mDNS names to matched dual-stack hosts if missing hostname
        for host in host_results.values_mut() {
            if host.hostname.is_none() || host.hostname.as_deref() == Some("?") {
                for ip6 in &host.ipv6_addrs {
                    if let Some(name) = ipv6_mdns_names.get(ip6) {
                        host.hostname = Some(name.clone());
                        break;
                    }
                }
            }
        }

        // Represent IPv6-only hosts: retained instead of discarded
        for ndp in ndp_entries {
            if !matched_ndp_macs.contains(&ndp.mac.to_lowercase()) {
                let vendor = crate::fingerprint::oui::lookup_mac(&ndp.mac).vendor;
                let hostname = ipv6_mdns_names
                    .get(&ndp.ip)
                    .cloned()
                    .or_else(|| Some("[IPv6 Only]".to_string()));
                ipv6_only_hosts.push(HostResult {
                    ip: Ipv4Addr::UNSPECIFIED,
                    is_alive: true,
                    hostname,
                    mac_address: Some(ndp.mac),
                    vendor,
                    open_ports: Vec::new(),
                    min_latency: None,
                    ipv6_addrs: vec![ndp.ip],
                });
            }
        }
    }

    let mut active_hosts: Vec<HostResult> = host_results.into_values().collect();
    active_hosts.extend(ipv6_only_hosts);
    active_hosts.sort_by_key(|h| (h.ip, h.mac_address.clone()));

    ScanSummary {
        total_hosts,
        active_hosts,
        elapsed: start_time.elapsed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_single_and_ranges() {
        let parsed = parse_ports("22, 80, 8080-8082, 443").unwrap();
        assert_eq!(parsed, vec![22, 80, 443, 8080, 8081, 8082]);
    }

    #[test]
    fn test_parse_ports_common() {
        let parsed = parse_ports("common").unwrap();
        assert!(parsed.contains(&22));
        assert!(parsed.contains(&80));
        assert!(parsed.contains(&443));
    }
}
