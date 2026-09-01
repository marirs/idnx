//! IPv6 Neighbor Discovery Protocol (NDP) harvester and multi-stack correlator.
//!
//! Provides cross-platform parsing of kernel NDP tables across macOS, Linux, and Windows,
//! link-local all-nodes ICMPv6 multicast neighbor stimulation, and dual-stack MAC correlation.

use crate::net::arp::normalize_mac;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// An IPv6 Neighbor Discovery Protocol (NDP) entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpEntry {
    pub ip: Ipv6Addr,
    pub mac: String,
    pub interface: Option<String>,
    pub is_router: bool,
}

/// Parses output of macOS/BSD `ndp -an`
pub fn parse_macos_ndp(output: &str) -> Vec<NdpEntry> {
    let mut entries = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Neighbor") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        // 1. Parse IP address (strip zone index like %en0 if present)
        let raw_ip = parts[0];
        let clean_ip_str = match raw_ip.split_once('%') {
            Some((ip_part, _)) => ip_part,
            None => raw_ip,
        };

        let ip = match Ipv6Addr::from_str(clean_ip_str) {
            Ok(addr) => addr,
            Err(_) => continue,
        };

        // 2. Parse MAC address (parts[1])
        let raw_mac = parts[1];
        if raw_mac == "(incomplete)" || raw_mac == "(none)" {
            continue;
        }

        let mac = normalize_mac(raw_mac);

        // 3. Interface (parts[2])
        let iface = parts.get(2).map(|s| s.to_string());

        // 4. Flags: 'R' indicates a router
        let is_router = parts.iter().skip(3).any(|p| *p == "R" || p.contains('R'));

        entries.push(NdpEntry {
            ip,
            mac,
            interface: iface,
            is_router,
        });
    }

    entries
}

/// Parses output of Linux `ip -6 neigh show`
pub fn parse_linux_ndp(output: &str) -> Vec<NdpEntry> {
    let mut entries = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        // 1. Parse IP
        let ip = match Ipv6Addr::from_str(parts[0]) {
            Ok(addr) => addr,
            Err(_) => continue,
        };

        let mut mac = None;
        let mut iface = None;
        let is_router = line.contains("router");

        let mut i = 1;
        while i < parts.len() {
            if parts[i] == "dev" && i + 1 < parts.len() {
                iface = Some(parts[i + 1].to_string());
                i += 2;
            } else if parts[i] == "lladdr" && i + 1 < parts.len() {
                mac = Some(normalize_mac(parts[i + 1]));
                i += 2;
            } else {
                i += 1;
            }
        }

        if let Some(m) = mac {
            entries.push(NdpEntry {
                ip,
                mac: m,
                interface: iface,
                is_router,
            });
        }
    }

    entries
}

/// Parses output of Windows `netsh interface ipv6 show neighbors`
pub fn parse_windows_ndp(output: &str) -> Vec<NdpEntry> {
    let mut entries = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("Internet Address")
            || line.starts_with("---")
            || line.starts_with("Interface")
        {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let ip = match Ipv6Addr::from_str(parts[0]) {
            Ok(addr) => addr,
            Err(_) => continue,
        };

        // Windows MAC addresses use dashes (e.g. 54-ef-44-59-48-dc)
        let raw_mac = parts[1].replace('-', ":");
        let mac = normalize_mac(&raw_mac);

        entries.push(NdpEntry {
            ip,
            mac,
            interface: None,
            is_router: false,
        });
    }

    entries
}

/// Stimulates IPv6 neighbors on the local network by sending a brief ICMPv6 multicast echo
pub async fn stimulate_ipv6_neighbors(interface: &str) {
    let _ = interface;
    // Attempt ping to All-Nodes Link-Local Multicast address (ff02::1%<interface>)
    #[cfg(target_os = "macos")]
    let _ = timeout(
        Duration::from_millis(600),
        Command::new("ping6")
            .args(["-c", "1", "-W", "300", "-I", interface, "ff02::1"])
            .output(),
    )
    .await;

    #[cfg(target_os = "linux")]
    let _ = timeout(
        Duration::from_millis(600),
        Command::new("ping")
            .args(["-6", "-c", "1", "-W", "1", "-I", interface, "ff02::1"])
            .output(),
    )
    .await;

    #[cfg(target_os = "windows")]
    let _ = timeout(
        Duration::from_millis(600),
        Command::new("ping")
            .args(["-6", "-n", "1", &format!("ff02::1%{}", interface)])
            .output(),
    )
    .await;
}

/// Harvests the system NDP cache across platforms
pub async fn harvest_ndp_cache(target_interface: Option<&str>) -> Vec<NdpEntry> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("ndp").arg("-an").output().await
            && let Ok(text) = String::from_utf8(output.stdout)
        {
            let all = parse_macos_ndp(&text);
            if let Some(iface) = target_interface {
                all.into_iter()
                    .filter(|e| e.interface.as_deref() == Some(iface))
                    .collect()
            } else {
                all
            }
        } else {
            Vec::new()
        }
    }

    #[cfg(target_os = "linux")]
    {
        let mut cmd = Command::new("ip");
        cmd.args(["-6", "neigh", "show"]);
        if let Some(iface) = target_interface {
            cmd.args(["dev", iface]);
        }
        if let Ok(output) = cmd.output().await
            && let Ok(text) = String::from_utf8(output.stdout)
        {
            parse_linux_ndp(&text)
        } else {
            Vec::new()
        }
    }

    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("netsh");
        cmd.args(["interface", "ipv6", "show", "neighbors"]);
        if let Some(iface) = target_interface {
            cmd.arg(format!("interface=\"{}\"", iface));
        }
        if let Ok(output) = cmd.output().await
            && let Ok(text) = String::from_utf8(output.stdout)
        {
            parse_windows_ndp(&text)
        } else {
            Vec::new()
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = target_interface;
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// UNIT TESTS
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_macos_ndp_synthetic() {
        let sample = "\
Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
fe80::1%lo0                             (incomplete)         lo0 permanent R      
fe80::78:5e2f:3bbd:1e73%en0             ae:2c:f:11:c7:f5     en0 permanent R      
fe80::56ef:44ff:fe59:48dc%en0           54:ef:44:59:48:dc    en0 22h31m9s  S      
2001:db8::42%en0                        60:cf:84:37:1b:70    en0 19m12s    R  R
";
        let parsed = parse_macos_ndp(sample);
        assert_eq!(parsed.len(), 3);

        // Verify MAC normalization (ae:2c:f:11:c7:f5 -> ae:2c:0f:11:c7:f5)
        assert_eq!(parsed[0].mac, "ae:2c:0f:11:c7:f5");
        assert_eq!(
            parsed[0].ip,
            "fe80::78:5e2f:3bbd:1e73".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(parsed[0].interface.as_deref(), Some("en0"));

        assert_eq!(parsed[1].mac, "54:ef:44:59:48:dc");
        assert_eq!(
            parsed[2].ip,
            "2001:db8::42".parse::<Ipv6Addr>().unwrap()
        );
        assert!(parsed[2].is_router);
    }

    #[test]
    fn test_parse_linux_ndp_synthetic() {
        let sample = "\
fe80::1 dev eth0 lladdr 60:cf:84:37:1b:70 router REACHABLE
2001:db8::42 dev eth0 lladdr 54:ef:44:59:48:dc REACHABLE
fe80::2 dev eth0 FAILED
";
        let parsed = parse_linux_ndp(sample);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].mac, "60:cf:84:37:1b:70");
        assert!(parsed[0].is_router);
        assert_eq!(parsed[0].interface.as_deref(), Some("eth0"));
        assert_eq!(parsed[1].mac, "54:ef:44:59:48:dc");
        assert!(!parsed[1].is_router);
    }

    #[test]
    fn test_parse_windows_ndp_synthetic() {
        let sample = "\
Internet Address                             Physical Address   Type
--------------------------------------------  -----------------  -----------
fe80::1                                       60-cf-84-37-1b-70  Reachable
2001:db8::42                                  54-ef-44-59-48-dc  Reachable
";
        let parsed = parse_windows_ndp(sample);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].mac, "60:cf:84:37:1b:70");
        assert_eq!(parsed[1].mac, "54:ef:44:59:48:dc");
    }
}
