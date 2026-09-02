use crate::engine::deep::ChildNetworkResult;
use crate::engine::scanner::ScanSummary;
use chrono::Local;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Json,
    Yaml,
    Xml,
    Csv,
    Text,
}

impl OutputFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            OutputFormat::Json => "json",
            OutputFormat::Yaml => "yaml",
            OutputFormat::Xml => "xml",
            OutputFormat::Csv => "csv",
            OutputFormat::Text => "txt",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkExport {
    pub tool: String,
    pub version: String,
    pub generated_at: String,
    pub primary_subnet: String,
    pub total_active_hosts: usize,
    /// One record per network, carrying the evidence that produced it. Consumers that
    /// only want an asset list can ignore this; consumers reasoning about topology need
    /// to know which networks were observed and which were merely advertised.
    pub networks: Vec<ExportNetwork>,
    /// Routers that were detected but could not be traversed, each with the evidence that
    /// identified it and the reason it could not be explored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unexplored_boundaries: Vec<ExportBoundary>,
    pub hosts: Vec<ExportHost>,
}

/// A router idNX could see but not see past.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportBoundary {
    pub address: String,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub discovery_source: String,
    /// Observations that identified this device as a router.
    pub evidence: Vec<String>,
    /// Why the networks behind it could not be enumerated.
    pub reason: String,
}

/// A network in the result set, with its discovery provenance.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportNetwork {
    pub cidr: String,
    /// `local` for the scanned subnet, `cascaded` for anything reached through discovery.
    pub role: String,
    /// Router address on this network, when one was actually observed.
    pub gateway: Option<String>,
    /// Router this network was learned *from*, when it was learned from one.
    pub parent_router: Option<String>,
    pub discovery_source: String,
    /// `verified`, `advertised`, `user-supplied` or `inferred`.
    pub confidence: String,
    /// False when the network was too wide to enumerate; `active_hosts` then reflects only
    /// hosts recovered from a router's ARP cache.
    pub swept: bool,
    pub total_addresses: usize,
    pub active_hosts: usize,
    pub snmp_system_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportHost {
    pub network: String,
    pub ip: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipv6_addresses: Vec<String>,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_runtime: Option<crate::probes::ai::AiRuntimeInfo>,
    pub status: String,
    pub open_ports: Vec<String>,
    pub latency_ms: Option<f64>,
    /// How the network this host sits on was discovered. `None` for the local subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_source: Option<String>,
    /// Confidence grade of the network this host sits on. `None` for the local subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
}

/// Generates a unified host list from primary scan and cascaded networks.
///
/// `local_gateway` is passed in rather than re-detected here: export must be a pure
/// transformation of data already gathered, not a second round of network I/O.
pub fn build_export_data(
    primary_cidr: &Ipv4Net,
    summary: &ScanSummary,
    child_networks: &[ChildNetworkResult],
    local_gateway: Option<std::net::Ipv4Addr>,
    boundaries: &[crate::engine::deep::UnexploredBoundary],
) -> NetworkExport {
    let mut hosts = Vec::new();
    let mut networks = Vec::new();

    networks.push(ExportNetwork {
        cidr: primary_cidr.to_string(),
        role: "local".to_string(),
        gateway: local_gateway.map(|ip| ip.to_string()),
        parent_router: None,
        discovery_source: "Local Interface".to_string(),
        confidence: crate::net::routes::DiscoveryConfidence::Verified
            .display_name()
            .to_string(),
        swept: true,
        total_addresses: summary.total_hosts,
        active_hosts: summary.active_hosts.len(),
        snmp_system_name: None,
    });

    for h in &summary.active_hosts {
        let ports: Vec<String> = h
            .open_ports
            .iter()
            .map(|p| format!("{}/{}", p.port, p.service))
            .collect();
        let latency_ms = h.min_latency.map(|d| (d.as_micros() as f64) / 1000.0);
        let ipv6_strings: Vec<String> = h.ipv6_addrs.iter().map(|ip| ip.to_string()).collect();
        hosts.push(ExportHost {
            network: format!("{} (Local)", primary_cidr),
            ip: h.ip.to_string(),
            ipv6_addresses: ipv6_strings,
            hostname: h.hostname.clone(),
            mac_address: h.mac_address.clone(),
            vendor: h.vendor.clone(),
            ai_runtime: h.ai_runtime.clone(),
            status: if h.is_alive {
                "UP".to_string()
            } else {
                "DOWN".to_string()
            },
            open_ports: ports,
            latency_ms,
            discovery_source: None,
            confidence: None,
        });
    }

    for child in child_networks {
        networks.push(ExportNetwork {
            cidr: child.cidr.to_string(),
            role: "cascaded".to_string(),
            gateway: child.gateway.map(|ip| ip.to_string()),
            parent_router: child.parent_router_ip.map(|ip| ip.to_string()),
            discovery_source: child.source.display_name().to_string(),
            confidence: child.confidence.display_name().to_string(),
            swept: !child.sweep_skipped,
            total_addresses: child.summary.total_hosts,
            active_hosts: child.summary.active_hosts.len(),
            snmp_system_name: child.snmp_system_name.clone(),
        });

        for h in &child.summary.active_hosts {
            let ports: Vec<String> = h
                .open_ports
                .iter()
                .map(|p| format!("{}/{}", p.port, p.service))
                .collect();
            let latency_ms = h.min_latency.map(|d| (d.as_micros() as f64) / 1000.0);
            let ipv6_strings: Vec<String> = h.ipv6_addrs.iter().map(|ip| ip.to_string()).collect();
            hosts.push(ExportHost {
                network: format!("{} (Cascaded)", child.cidr),
                ip: h.ip.to_string(),
                ipv6_addresses: ipv6_strings,
                hostname: h.hostname.clone(),
                mac_address: h.mac_address.clone(),
                vendor: h.vendor.clone(),
                ai_runtime: h.ai_runtime.clone(),
                status: if h.is_alive {
                    "UP".to_string()
                } else {
                    "DOWN".to_string()
                },
                open_ports: ports,
                latency_ms,
                discovery_source: Some(child.source.display_name().to_string()),
                confidence: Some(child.confidence.display_name().to_string()),
            });
        }
    }

    NetworkExport {
        tool: "idNX".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: Local::now().to_rfc3339(),
        primary_subnet: primary_cidr.to_string(),
        total_active_hosts: hosts.len(),
        networks,
        unexplored_boundaries: boundaries
            .iter()
            .map(|b| ExportBoundary {
                address: if b.ip.is_unspecified() {
                    b.ipv6_addrs
                        .first()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| b.ip.to_string())
                } else {
                    b.ip.to_string()
                },
                mac_address: b.mac_address.clone(),
                vendor: b.vendor.clone(),
                hostname: b.hostname.clone(),
                discovery_source: b.source.display_name().to_string(),
                evidence: b.evidence.clone(),
                reason: b.reason.explain().to_string(),
            })
            .collect(),
        hosts,
    }
}

/// Generates the default filename format: `idnx_YYYYMMDD.<ext>`
pub fn get_default_filename(format: OutputFormat) -> String {
    format!(
        "idnx_{}.{}",
        Local::now().format("%Y%m%d"),
        format.extension()
    )
}

/// Exports network data to the specified file and format
pub fn export_results(
    format: OutputFormat,
    custom_path: Option<&str>,
    primary_cidr: &Ipv4Net,
    summary: &ScanSummary,
    child_networks: &[ChildNetworkResult],
    local_gateway: Option<std::net::Ipv4Addr>,
    boundaries: &[crate::engine::deep::UnexploredBoundary],
) -> Result<PathBuf, String> {
    let export_data = build_export_data(
        primary_cidr,
        summary,
        child_networks,
        local_gateway,
        boundaries,
    );
    let filename = custom_path
        .map(|p| p.to_string())
        .unwrap_or_else(|| get_default_filename(format));
    let path = PathBuf::from(&filename);

    let content = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&export_data)
            .map_err(|e| format!("JSON serialization error: {}", e))?,
        OutputFormat::Yaml => serde_yaml::to_string(&export_data)
            .map_err(|e| format!("YAML serialization error: {}", e))?,
        OutputFormat::Xml => quick_xml::se::to_string(&export_data)
            .map_err(|e| format!("XML serialization error: {}", e))?,
        OutputFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(vec![]);
            wtr.write_record([
                "Network",
                "IP",
                "Hostname",
                "MAC Address",
                "Vendor",
                "Status",
                "Open Ports",
                "Latency (ms)",
                "Discovery Source",
                "Confidence",
            ])
            .map_err(|e| format!("CSV header error: {}", e))?;

            for h in &export_data.hosts {
                let lat = h
                    .latency_ms
                    .map(|l| format!("{:.2}", l))
                    .unwrap_or_default();
                wtr.write_record([
                    &h.network,
                    &h.ip,
                    h.hostname.as_deref().unwrap_or(""),
                    h.mac_address.as_deref().unwrap_or(""),
                    h.vendor.as_deref().unwrap_or(""),
                    &h.status,
                    &h.open_ports.join("; "),
                    &lat,
                    h.discovery_source.as_deref().unwrap_or("Local Interface"),
                    h.confidence.as_deref().unwrap_or("verified"),
                ])
                .map_err(|e| format!("CSV write error: {}", e))?;
            }

            let bytes = wtr
                .into_inner()
                .map_err(|e| format!("CSV flush error: {}", e))?;
            String::from_utf8_lossy(&bytes).to_string()
        }
        OutputFormat::Text => {
            let mut text = String::new();
            text.push_str(&format!(
                "idNX Scan Export - Primary Subnet: {} | Generated: {}\n",
                export_data.primary_subnet, export_data.generated_at
            ));
            text.push_str(&format!(
                "Total Active Hosts: {}\n\n",
                export_data.total_active_hosts
            ));

            text.push_str("NETWORKS AND DISCOVERY EVIDENCE\n");
            text.push_str(&format!(
                "{:<22} {:<10} {:<18} {:<36} {:<14} {:<8}\n",
                "CIDR", "ROLE", "GATEWAY", "DISCOVERED VIA", "CONFIDENCE", "SWEPT"
            ));
            text.push_str(&format!("{}\n", "-".repeat(130)));
            for n in &export_data.networks {
                text.push_str(&format!(
                    "{:<22} {:<10} {:<18} {:<36} {:<14} {:<8}\n",
                    n.cidr,
                    n.role,
                    n.gateway.as_deref().unwrap_or("-"),
                    n.discovery_source,
                    n.confidence,
                    if n.swept { "yes" } else { "no" }
                ));
            }
            text.push('\n');

            if !export_data.unexplored_boundaries.is_empty() {
                text.push_str(
                    "UNEXPLORED BOUNDARIES (routers detected, contents not enumerable)\n",
                );
                for b in &export_data.unexplored_boundaries {
                    text.push_str(&format!(
                        "{}  {}  [{}]\n",
                        b.address,
                        b.mac_address.as_deref().unwrap_or("-"),
                        b.hostname
                            .as_deref()
                            .or(b.vendor.as_deref())
                            .unwrap_or("unidentified")
                    ));
                    for ev in &b.evidence {
                        text.push_str(&format!("    evidence: {}\n", ev));
                    }
                    text.push_str(&format!("    not traversed: {}\n", b.reason));
                }
                text.push('\n');
            }

            text.push_str(&format!(
                "{:<26} {:<16} {:<28} {:<18} {:<24} {:<8} {:<10}\n",
                "NETWORK", "IP", "HOSTNAME", "MAC", "VENDOR", "STATUS", "LATENCY"
            ));
            text.push_str(&format!("{}\n", "-".repeat(130)));

            for h in &export_data.hosts {
                let lat = h
                    .latency_ms
                    .map(|l| format!("{:.2} ms", l))
                    .unwrap_or_else(|| "-".to_string());
                text.push_str(&format!(
                    "{:<26} {:<16} {:<28} {:<18} {:<24} {:<8} {:<10}\n",
                    h.network,
                    h.ip,
                    h.hostname.as_deref().unwrap_or("-"),
                    h.mac_address.as_deref().unwrap_or("-"),
                    h.vendor.as_deref().unwrap_or("-"),
                    h.status,
                    lat
                ));
                if !h.open_ports.is_empty() {
                    text.push_str(&format!("    └── Ports: {}\n", h.open_ports.join(", ")));
                }
            }
            text
        }
    };

    let mut file = File::create(&path)
        .map_err(|e| format!("Failed to create file {}: {}", path.display(), e))?;
    file.write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write file {}: {}", path.display(), e))?;

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::scanner::{HostResult, PortInfo, PortStatus};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;

    fn sample_scan_data() -> (Ipv4Net, ScanSummary, Vec<ChildNetworkResult>) {
        let primary_cidr = Ipv4Net::from_str("192.168.1.0/24").unwrap();
        let summary = ScanSummary {
            total_hosts: 254,
            active_hosts: vec![HostResult {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                is_alive: true,
                hostname: Some("Gateway-Router".to_string()),
                mac_address: Some("00:11:22:33:44:55".to_string()),
                vendor: Some("Linksys".to_string()),
                open_ports: vec![PortInfo {
                    port: 80,
                    status: PortStatus::Open,
                    latency: Some(Duration::from_millis(5)),
                    service: "http",
                }],
                min_latency: Some(Duration::from_millis(5)),
                ipv6_addrs: Vec::new(),
                ai_runtime: None,
            }],
            elapsed: Duration::from_secs(1),
        };
        (primary_cidr, summary, Vec::new())
    }

    #[test]
    fn test_export_formats_roundtrip() {
        let (primary_cidr, summary, children) = sample_scan_data();
        let tmp_dir = std::env::temp_dir();

        for format in [
            OutputFormat::Json,
            OutputFormat::Yaml,
            OutputFormat::Xml,
            OutputFormat::Csv,
            OutputFormat::Text,
        ] {
            let test_file = tmp_dir.join(format!("test_export.{}", format.extension()));
            let test_path = test_file.to_str().unwrap();

            let exported_path = export_results(
                format,
                Some(test_path),
                &primary_cidr,
                &summary,
                &children,
                Some(Ipv4Addr::new(192, 168, 1, 1)),
                &[],
            )
            .expect("Export should succeed");
            assert!(exported_path.exists());

            let content = std::fs::read_to_string(&exported_path).expect("Should read file");
            assert!(content.contains("192.168.1.1"));
            let _ = std::fs::remove_file(&exported_path);
        }
    }
}
