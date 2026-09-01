use ipnet::Ipv4Net;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub hostname: Option<String>,
    #[allow(dead_code)]
    pub interface: String,
    pub vendor: Option<String>,
}

/// Normalizes MAC address format (e.g. "c4:f7:c1:b:7c:69" -> "c4:f7:c1:0b:7c:69")
pub fn normalize_mac(mac_str: &str) -> String {
    mac_str
        .split(':')
        .map(|octet| {
            if octet.len() == 1 {
                format!("0{}", octet)
            } else {
                octet.to_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(":")
}

/// OUI vendor and randomized MAC lookup using the embedded IEEE database
pub fn lookup_vendor(mac: &str) -> Option<String> {
    let info = crate::fingerprint::oui::lookup_mac(mac);
    if info.vendor.is_some() || info.is_randomized {
        Some(info.display_label())
    } else {
        None
    }
}

/// Reads the operating system's ARP table
pub fn read_system_arp_table(interface_filter: Option<&str>) -> Vec<ArpEntry> {
    // 1. Linux kernel /proc/net/arp (present on all Linux flavours without requiring net-tools)
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            let entries = parse_proc_net_arp(&content, interface_filter);
            if !entries.is_empty() {
                return entries;
            }
        }
    }

    // 2. Standard `arp -a` (macOS, BSD, Windows, Linux)
    let output = match Command::new("arp").arg("-a").output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
        Err(_) => return Vec::new(),
    };

    parse_arp_output(&output, interface_filter)
}

/// Parses the Linux `/proc/net/arp` table
#[allow(dead_code)]
pub fn parse_proc_net_arp(content: &str, interface_filter: Option<&str>) -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let ip_str = parts[0];
        let mac_str = parts[3];
        let iface = parts[5];

        if let Ok(ip) = Ipv4Addr::from_str(ip_str) {
            if mac_str == "00:00:00:00:00:00" || ip.is_multicast() || ip.is_broadcast() {
                continue;
            }
            if let Some(target_iface) = interface_filter
                && !iface.eq_ignore_ascii_case(target_iface)
            {
                continue;
            }
            let mac = normalize_mac(mac_str);
            let vendor = lookup_vendor(&mac);
            entries.push(ArpEntry {
                ip,
                mac,
                hostname: None,
                interface: iface.to_string(),
                vendor,
            });
        }
    }
    entries
}

/// Parses standard Unix/macOS and Windows `arp -a` output
pub fn parse_arp_output(output: &str, interface_filter: Option<&str>) -> Vec<ArpEntry> {
    let mut entries = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.contains("(incomplete)") {
            continue;
        }

        // Check Windows format: "  192.168.1.1           74-12-13-14-75-dc     dynamic"
        if !line.contains('(') {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() >= 2
                && let Ok(ip) = Ipv4Addr::from_str(tokens[0])
                && tokens[1].contains('-')
                && tokens[1].len() >= 17
            {
                let mac = normalize_mac(&tokens[1].replace('-', ":"));
                if mac != "ff:ff:ff:ff:ff:ff" && !ip.is_multicast() && !ip.is_broadcast() {
                    let vendor = lookup_vendor(&mac);
                    entries.push(ArpEntry {
                        ip,
                        mac,
                        hostname: None,
                        interface: String::new(),
                        vendor,
                    });
                    continue;
                }
            }
            continue;
        }

        let ip_start = match line.find('(') {
            Some(idx) => idx + 1,
            None => continue,
        };
        let ip_end = match line[ip_start..].find(')') {
            Some(idx) => ip_start + idx,
            None => continue,
        };
        let ip_str = &line[ip_start..ip_end];
        let ip = match Ipv4Addr::from_str(ip_str) {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };

        // Skip multicast (224.0.0.0/4) or broadcast (255.255.255.255)
        if ip.is_multicast() || ip.is_broadcast() {
            continue;
        }

        // Extract hostname (portion before '(')
        let raw_host = line[..ip_start - 1].trim();
        let hostname = if raw_host.is_empty() || raw_host == "?" {
            None
        } else {
            Some(raw_host.to_string())
        };

        // Extract MAC address after " at " and before " on "
        let at_idx = match line.find(" at ") {
            Some(idx) => idx + 4,
            None => continue,
        };
        let on_idx = match line[at_idx..].find(" on ") {
            Some(idx) => at_idx + idx,
            None => continue,
        };
        let raw_mac = line[at_idx..on_idx].trim();
        let mac = normalize_mac(raw_mac);

        // Extract interface name after " on "
        let iface_start = on_idx + 4;
        let iface_token = line[iface_start..]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim();

        if let Some(target_iface) = interface_filter
            && !iface_token.eq_ignore_ascii_case(target_iface)
        {
            continue;
        }

        if ip.octets()[3] == 255 || mac == "ff:ff:ff:ff:ff:ff" || ip.is_multicast() {
            continue;
        }

        let vendor = lookup_vendor(&mac);

        entries.push(ArpEntry {
            ip,
            mac,
            hostname,
            interface: iface_token.to_string(),
            vendor,
        });
    }

    entries
}

/// Triggers kernel-level ARP resolution for every host in the CIDR block.
///
/// Sends high-speed, non-blocking UDP discovery packets (mDNS 5353 / NetBIOS 137)
/// to each target IP. Because the packets are addressed to the local link, the host OS kernel
/// immediately broadcasts an ARP "Who has IP?" packet for every target.
pub async fn trigger_kernel_arp_sweep(cidr: Ipv4Net, concurrency: usize) {
    let hosts: Vec<Ipv4Addr> = cidr.hosts().collect();
    if hosts.is_empty() {
        return;
    }

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(_) => return,
    };

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = Vec::with_capacity(hosts.len());

    // Payload: lightweight probe
    let payload = b"\x00";

    for ip in hosts {
        let sock = Arc::clone(&socket);
        let sem = Arc::clone(&semaphore);

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            // Send to port 5353 (mDNS)
            let _ = sock.send_to(payload, SocketAddrV4::new(ip, 5353)).await;
            // Also send to port 137 (NetBIOS)
            let _ = sock.send_to(payload, SocketAddrV4::new(ip, 137)).await;
        }));
    }

    for task in tasks {
        let _ = task.await;
    }

    // Brief settling time for ARP responses to arrive and populate the OS kernel cache
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_normalization() {
        assert_eq!(normalize_mac("c4:f7:c1:b:7c:69"), "c4:f7:c1:0b:7c:69");
        assert_eq!(normalize_mac("74:12:13:14:75:dc"), "74:12:13:14:75:dc");
    }

    #[test]
    fn test_parse_arp_line() {
        let sample = "linksys07877 (192.168.1.1) at 74:12:13:14:75:dc on en0 ifscope [ethernet]\n\
                      ? (192.168.1.124) at (incomplete) on en0 ifscope [ethernet]\n\
                      dmaker-fan (192.168.1.166) at 7c:c2:94:a1:d1:43 on en0 ifscope [ethernet]\n";

        let entries = parse_arp_output(sample, Some("en0"));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(entries[0].hostname.as_deref(), Some("linksys07877"));
        assert_eq!(entries[0].vendor.as_deref(), Some("Linksys"));

        assert_eq!(entries[1].ip, Ipv4Addr::new(192, 168, 1, 166));
        assert_eq!(entries[1].hostname.as_deref(), Some("dmaker-fan"));
        assert_eq!(entries[1].vendor.as_deref(), Some("Xiaomi / Smartmi"));
    }

    #[test]
    fn test_parse_proc_net_arp_linux() {
        let sample = "IP address       HW type     Flags       HW address            Mask     Device\n\
                      192.168.1.1      0x1         0x2         74:12:13:14:75:dc     *        eth0\n\
                      192.168.1.53     0x1         0x2         a0:ad:9f:e6:38:00     *        eth0\n\
                      192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0\n";

        let entries = parse_proc_net_arp(sample, Some("eth0"));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(entries[0].vendor.as_deref(), Some("Linksys"));
        assert_eq!(entries[1].ip, Ipv4Addr::new(192, 168, 1, 53));
        assert_eq!(entries[1].vendor.as_deref(), Some("ASUSTek Computer Inc."));
    }

    #[test]
    fn test_parse_windows_arp() {
        let sample = "Interface: 192.168.1.119 --- 0x10\n\
                        Internet Address      Physical Address      Type\n\
                        192.168.1.1           74-12-13-14-75-dc     dynamic\n\
                        192.168.1.53          a0-ad-9f-e6-38-00     dynamic\n\
                        192.168.1.255         ff-ff-ff-ff-ff-ff     static\n";

        let entries = parse_arp_output(sample, None);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(entries[0].vendor.as_deref(), Some("Linksys"));
        assert_eq!(entries[1].ip, Ipv4Addr::new(192, 168, 1, 53));
        assert_eq!(entries[1].vendor.as_deref(), Some("ASUSTek Computer Inc."));
    }
}
