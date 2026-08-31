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

/// Basic OUI vendor lookup for common router and consumer devices
pub fn lookup_vendor(mac: &str) -> Option<String> {
    let normalized = normalize_mac(mac);
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let prefix = format!("{}:{}:{}", parts[0], parts[1], parts[2]).to_lowercase();

    let vendor = match prefix.as_str() {
        "74:12:13" => "Linksys",
        "c4:f7:c1" => "Tuya Smart",
        "7c:c2:94" => "Xiaomi / Smartmi",
        "58:02:05" => "Positive Grid (Spark)",
        "d4:dc:cd" | "68:5e:dd" | "5e:8e:44" | "a0:ad:9f" | "14:d8:81" | "16:c7:37" => "Apple",
        "00:1a:2b" | "00:0c:29" => "Cisco / VMware",
        "b4:fb:e4" | "fc:ec:da" | "24:a0:74" => "Ubiquiti",
        "48:8f:5a" | "cc:2d:e0" => "MikroTik",
        "ec:08:6b" | "08:55:31" => "TP-Link",
        "00:26:86" | "98:fc:11" => "Netgear",
        "00:11:32" => "Synology",
        "2c:fd:a1" | "b8:27:eb" | "dc:a6:32" | "e4:5f:01" => "Raspberry Pi",
        _ => return None,
    };

    Some(vendor.to_string())
}

/// Reads the operating system's ARP table
pub fn read_system_arp_table(interface_filter: Option<&str>) -> Vec<ArpEntry> {
    let output = match Command::new("arp").arg("-a").output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
        Err(_) => return Vec::new(),
    };

    parse_arp_output(&output, interface_filter)
}

/// Parses the standard Unix / macOS `arp -a` output
pub fn parse_arp_output(output: &str, interface_filter: Option<&str>) -> Vec<ArpEntry> {
    let mut entries = Vec::new();

    for line in output.lines() {
        // Example macOS line:
        // linksys07877 (192.168.1.1) at 74:12:13:14:75:dc on en0 ifscope [ethernet]
        // ? (192.168.1.37) at 7a:d5:6:f5:14:6b on en0 ifscope [ethernet]
        // ? (192.168.1.144) at (incomplete) on en0 ifscope [ethernet]
        let line = line.trim();
        if line.is_empty() || line.contains("(incomplete)") {
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

        if let Some(target_iface) = interface_filter {
            if !iface_token.eq_ignore_ascii_case(target_iface) {
                continue;
            }
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
            let _ = sock
                .send_to(payload, SocketAddrV4::new(ip, 5353))
                .await;
            // Also send to port 137 (NetBIOS)
            let _ = sock
                .send_to(payload, SocketAddrV4::new(ip, 137))
                .await;
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
}
