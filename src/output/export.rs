//! Serialises the topology graph.
//!
//! Every format carries the same information: node kinds, relationships, evidence,
//! confidence, scope coverage and opaque boundaries. A format that dropped provenance
//! would turn a graded map back into an undifferentiated address list, which is precisely
//! what this tool exists not to produce.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use chrono::Local;
use serde::{Deserialize, Serialize};

use crate::engine::orchestrator::{DiscoveryReport, is_virtual_network};
use crate::topology::graph::{NodeId, NodeKind, Provenance};
use crate::topology::{Confidence, TopologyGraph};

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

/// The complete serialised topology.
#[derive(Debug, Serialize, Deserialize)]
pub struct TopologyExport {
    pub tool: String,
    pub version: String,
    pub generated_at: String,
    pub vantage: VantageExport,
    pub networks: Vec<NetworkExport>,
    pub vlans: Vec<VlanExport>,
    pub devices: Vec<DeviceExport>,
    pub relationships: Vec<RelationshipExport>,
    pub coverage: Vec<CoverageExport>,
    /// What was attempted against each device and what came back. Separate from `coverage`,
    /// which is per scope: a consumer needs to tell a silent device from an unasked one.
    pub device_coverage: Vec<DeviceCoverageExport>,
    pub summary: SummaryExport,
}

/// Per-device interrogation record.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceCoverageExport {
    /// Canonical device identity. One record per device, however many addresses it has.
    pub device: String,
    /// Every address considered, most preferred first.
    pub addresses: Vec<String>,
    /// The address the full stage set ran against.
    pub primary_address: Option<String>,
    /// Why the device was interrogated: pivot, candidate or host.
    pub tier: String,
    pub discovery_sources: Vec<String>,
    pub stages_run: u8,
    pub tcp_attempted: usize,
    pub tcp_responsive: Vec<u16>,
    pub udp_attempted: Vec<u16>,
    pub protocols_confirmed: Vec<String>,
    /// Ports that refused without credentials, which is a finding rather than an absence.
    pub auth_required: Vec<u16>,
    /// Vendor adapters the device's fingerprint selected.
    pub vendor_adapters: Vec<String>,
    /// Work deliberately not done, and why. Present so a partial pass is never reported as
    /// complete exploration.
    pub omissions: Vec<String>,
    /// Set when the device was never interrogated, saying why.
    pub skipped: Option<String>,
    /// True when the device was asked and answered nothing at all.
    pub silent: bool,
    pub elapsed_ms: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VantageExport {
    pub interface: String,
    pub kind: String,
    /// Frame classes this vantage cannot receive at all.
    pub blind_to: Vec<String>,
    /// Sources that were unavailable, and why.
    pub unavailable: Vec<String>,
    /// Frames passively observed. `None` means capture never started.
    pub observed_frames: Option<u64>,
    /// Topology facts accepted from those frames.
    pub accepted_facts: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkExport {
    pub cidr: String,
    /// `physical` or `virtual`, decided by the interface a network is reached through and
    /// never by its address range.
    pub kind: String,
    pub interfaces: Vec<String>,
    pub confidence: String,
    /// False when the network was too large to enumerate address by address.
    pub enumerated: bool,
    pub evidence: Vec<EvidenceExport>,
}

/// A VLAN observed on the wire.
///
/// `prefix` is always absent: a tag proves the VLAN ID and nothing about any network.
#[derive(Debug, Serialize, Deserialize)]
pub struct VlanExport {
    pub id: u16,
    pub prefix: Option<String>,
    pub note: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceExport {
    pub id: String,
    /// `router`, `switch`, `host` or `opaque boundary`.
    pub kind: String,
    /// The single section this device is presented under. Mutually exclusive, so summing
    /// categories yields the device total with nothing double counted.
    pub category: String,
    pub addresses: Vec<String>,
    pub hostnames: Vec<String>,
    pub vendor: Option<String>,
    pub descriptions: Vec<String>,
    /// Behaviour that established this device's role. Vendor is never among them.
    pub role_evidence: Vec<String>,
    /// What the device was observed doing, independent of the single word its role
    /// collapses to.
    pub capabilities: Vec<String>,
    /// Why visibility stops here, when it does.
    pub opaque_reason: Option<String>,
    pub confidence: String,
    pub evidence: Vec<EvidenceExport>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelationshipExport {
    pub from: String,
    pub to: String,
    pub relationship: String,
    pub confidence: String,
    pub evidence: Vec<EvidenceExport>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceExport {
    pub source: String,
    pub confidence: String,
    pub vantage: String,
    pub detail: Option<String>,
}

/// What each provider produced for one scope or pivot.
#[derive(Debug, Serialize, Deserialize)]
pub struct CoverageExport {
    /// The network or device examined, or `local machine` for the seed pass.
    pub scope: String,
    pub providers: Vec<ProviderOutcomeExport>,
    pub networks_learned: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderOutcomeExport {
    pub provider: String,
    pub facts: usize,
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SummaryExport {
    /// Unique devices, counted once each. Equals routers + switches + boundaries +
    /// ai_systems + other_hosts.
    pub devices: usize,
    pub routers: usize,
    pub switches: usize,
    pub opaque_boundaries: usize,
    /// Devices with a protocol-confirmed AI capability that are not infrastructure.
    pub ai_systems: usize,
    pub other_hosts: usize,
    pub networks: usize,
    pub vlans: usize,
    pub services: usize,
    pub interfaces: usize,
    /// Node count per kind, so `total_nodes` is interpretable rather than an opaque
    /// figure that silently includes networks, interfaces and services.
    pub nodes_by_kind: std::collections::BTreeMap<String, usize>,
    pub observed: usize,
    pub advertised: usize,
    pub inferred: usize,
    pub user_supplied: usize,
    pub total_nodes: usize,
    pub converged: bool,
}

fn node_label(graph: &TopologyGraph, id: &NodeId) -> String {
    match graph.node(id) {
        Some(node) => node.display_name(),
        None => match id {
            NodeId::Interface(n) => n.clone(),
            NodeId::Network(n) => n.to_string(),
            NodeId::Vlan(v) => format!("VLAN {}", v),
            NodeId::Device(d) => d.to_string(),
            NodeId::Service(a, p) => format!("{}:{}", a, p),
        },
    }
}

fn evidence_of(provenance: &[Provenance]) -> Vec<EvidenceExport> {
    // Providers repeat facts as frames repeat; collapse identical provenance so a document
    // describes the topology rather than logging every repetition.
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for p in provenance {
        let key = format!("{}|{}|{}|{:?}", p.source, p.confidence, p.vantage, p.detail);
        if !seen.insert(key) {
            continue;
        }
        out.push(EvidenceExport {
            source: p.source.label().to_string(),
            confidence: p.confidence.label().to_string(),
            vantage: p.vantage.clone(),
            detail: p.detail.clone(),
        });
    }
    out
}

/// Builds the serialisable view of a discovery run.
pub fn build_export(report: &DiscoveryReport) -> TopologyExport {
    let graph = &report.graph;

    let mut networks = Vec::new();
    for net in graph.networks() {
        let interfaces: Vec<String> = graph
            .interfaces_for_network(&net)
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let iface_refs: Vec<&str> = interfaces.iter().map(|s| s.as_str()).collect();
        let node = graph.node(&NodeId::Network(net));
        networks.push(NetworkExport {
            cidr: net.to_string(),
            kind: if is_virtual_network(&iface_refs) {
                "virtual".to_string()
            } else {
                "physical".to_string()
            },
            interfaces,
            confidence: node
                .map(|n| n.confidence.label().to_string())
                .unwrap_or_else(|| Confidence::Observed.label().to_string()),
            enumerated: !report.oversized_scopes.contains(&net),
            evidence: node.map(|n| evidence_of(&n.provenance)).unwrap_or_default(),
        });
    }
    networks.sort_by(|a, b| a.cidr.cmp(&b.cidr));

    let vlans: Vec<VlanExport> = graph
        .vlans_without_prefix()
        .map(|id| VlanExport {
            id,
            prefix: None,
            note: "observed on the wire; no prefix evidence".to_string(),
        })
        .collect();

    let mut devices = Vec::new();
    for node in graph.nodes() {
        if !matches!(
            node.kind,
            NodeKind::Router | NodeKind::Switch | NodeKind::Host | NodeKind::OpaqueBoundary
        ) {
            continue;
        }
        devices.push(DeviceExport {
            id: node.display_name(),
            kind: node.kind.label().to_string(),
            category: crate::topology::graph::categorize(node)
                .map(|c| c.label().to_string())
                .unwrap_or_default(),
            addresses: node.addresses.iter().map(|a| a.to_string()).collect(),
            hostnames: node.hostnames.iter().cloned().collect(),
            vendor: node.vendor.clone(),
            descriptions: node.descriptions.iter().cloned().collect(),
            role_evidence: node.role_signals.iter().cloned().collect(),
            capabilities: node.capabilities.iter().cloned().collect(),
            opaque_reason: node.opaque_reason.clone(),
            confidence: node.confidence.label().to_string(),
            evidence: evidence_of(&node.provenance),
        });
    }
    devices.sort_by(|a, b| a.id.cmp(&b.id));

    let mut relationships: Vec<RelationshipExport> = graph
        .edges()
        .map(|edge| RelationshipExport {
            from: node_label(graph, &edge.from),
            to: node_label(graph, &edge.to),
            relationship: edge.relationship.label().to_string(),
            confidence: edge.confidence.label().to_string(),
            evidence: evidence_of(&edge.provenance),
        })
        .collect();
    relationships.sort_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));

    let mut coverage: Vec<CoverageExport> = report
        .scope_runs
        .iter()
        .map(|run| CoverageExport {
            scope: run
                .scope
                .map(|s| s.to_string())
                .unwrap_or_else(|| "local machine".to_string()),
            providers: run
                .runs
                .iter()
                .map(|r| ProviderOutcomeExport {
                    provider: r.provider.to_string(),
                    facts: r.evidence_count,
                    note: r.note.clone(),
                })
                .collect(),
            networks_learned: Vec::new(),
        })
        .collect();

    coverage.extend(report.pivot_runs.iter().map(|pivot| {
        CoverageExport {
            scope: pivot.address.to_string(),
            providers: pivot
                .runs
                .iter()
                .map(|r| ProviderOutcomeExport {
                    provider: r.provider.to_string(),
                    facts: r.evidence_count,
                    note: r.note.clone(),
                })
                .collect(),
            networks_learned: pivot
                .networks_learned
                .iter()
                .map(|n| n.to_string())
                .collect(),
        }
    }));

    let device_coverage: Vec<DeviceCoverageExport> = report
        .coverage
        .iter()
        .map(|record| DeviceCoverageExport {
            device: record.device.to_string(),
            addresses: record.addresses.clone(),
            primary_address: record.primary_endpoint().map(|e| e.to_string()),
            tier: record.tier.label().to_string(),
            discovery_sources: record.discovery_sources.clone(),
            stages_run: record.stages_run(),
            tcp_attempted: record.tcp_attempted(),
            tcp_responsive: record
                .endpoints
                .iter()
                .flat_map(|e| e.tcp_responsive.iter().copied())
                .collect(),
            udp_attempted: record.udp_attempted.clone(),
            protocols_confirmed: record.protocols_confirmed.clone(),
            auth_required: record.auth_required.clone(),
            vendor_adapters: record.vendor_adapters.clone(),
            omissions: record.omissions(),
            skipped: record.skipped.clone(),
            silent: record.silent(),
            elapsed_ms: record.elapsed.as_millis(),
        })
        .collect();

    let mut nodes_by_kind: std::collections::BTreeMap<String, usize> = Default::default();
    for node in graph.nodes() {
        *nodes_by_kind
            .entry(node.kind.label().to_string())
            .or_default() += 1;
    }

    let counts = graph.counts();
    let mut summary = SummaryExport {
        devices: counts.devices(),
        routers: counts.routers,
        switches: counts.switches,
        opaque_boundaries: counts.opaque_boundaries,
        ai_systems: counts.ai_systems,
        other_hosts: counts.other_hosts,
        networks: counts.networks,
        vlans: counts.vlans,
        services: counts.services,
        interfaces: counts.interfaces,
        nodes_by_kind,
        observed: 0,
        advertised: 0,
        inferred: 0,
        user_supplied: 0,
        total_nodes: graph.node_count(),
        converged: report.converged,
    };
    for node in graph.nodes() {
        match node.confidence {
            Confidence::Observed => summary.observed += 1,
            Confidence::Advertised => summary.advertised += 1,
            Confidence::Inferred => summary.inferred += 1,
            Confidence::UserSupplied => summary.user_supplied += 1,
        }
    }

    TopologyExport {
        tool: "idNX".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: Local::now().to_rfc3339(),
        vantage: VantageExport {
            interface: report.visibility.vantage.interface.clone(),
            kind: report.visibility.vantage.kind.label().to_string(),
            blind_to: report.visibility.blind_to.clone(),
            unavailable: report.visibility.unavailable.clone(),
            observed_frames: report.visibility.observed_frames,
            accepted_facts: report.visibility.accepted_facts,
        },
        networks,
        vlans,
        devices,
        relationships,
        coverage,
        device_coverage,
        summary,
    }
}

pub fn default_filename(format: OutputFormat) -> String {
    format!(
        "idnx_{}.{}",
        Local::now().format("%Y%m%d"),
        format.extension()
    )
}

/// Writes the topology in the requested format.
pub fn export(
    report: &DiscoveryReport,
    format: OutputFormat,
    custom_path: Option<&str>,
) -> Result<PathBuf, String> {
    let data = build_export(report);
    let path = PathBuf::from(
        custom_path
            .map(|p| p.to_string())
            .unwrap_or_else(|| default_filename(format)),
    );

    let content =
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(&data)
                .map_err(|e| format!("JSON serialisation failed: {e}"))?,
            OutputFormat::Yaml => serde_yaml::to_string(&data)
                .map_err(|e| format!("YAML serialisation failed: {e}"))?,
            OutputFormat::Xml => quick_xml::se::to_string(&data)
                .map_err(|e| format!("XML serialisation failed: {e}"))?,
            OutputFormat::Csv => render_csv(&data)?,
            OutputFormat::Text => render_text(&data),
        };

    let mut file = File::create(&path).map_err(|e| format!("Cannot create {path:?}: {e}"))?;
    file.write_all(content.as_bytes())
        .map_err(|e| format!("Cannot write {path:?}: {e}"))?;

    Ok(path)
}

/// CSV is one row per device, carrying the evidence that classified it.
fn render_csv(data: &TopologyExport) -> Result<String, String> {
    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record([
        "Kind",
        "Name",
        "Addresses",
        "Hostnames",
        "Vendor",
        "Confidence",
        "Capabilities",
        "Role Evidence",
        "Evidence Sources",
        "Opaque Reason",
    ])
    .map_err(|e| format!("CSV header error: {e}"))?;

    for d in &data.devices {
        let sources: Vec<String> = d.evidence.iter().map(|e| e.source.clone()).collect();
        wtr.write_record([
            &d.kind,
            &d.id,
            &d.addresses.join("; "),
            &d.hostnames.join("; "),
            d.vendor.as_deref().unwrap_or(""),
            &d.confidence,
            &d.capabilities.join("; "),
            &d.role_evidence.join("; "),
            &sources.join("; "),
            d.opaque_reason.as_deref().unwrap_or(""),
        ])
        .map_err(|e| format!("CSV write error: {e}"))?;
    }

    let bytes = wtr
        .into_inner()
        .map_err(|e| format!("CSV flush error: {e}"))?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

fn render_text(data: &TopologyExport) -> String {
    let mut t = String::new();
    t.push_str(&format!(
        "idNX {} - topology from {} ({})\nGenerated: {}\n\n",
        data.version, data.vantage.interface, data.vantage.kind, data.generated_at
    ));

    if !data.vantage.blind_to.is_empty() {
        t.push_str(&format!(
            "Not visible from this vantage: {}\n",
            data.vantage.blind_to.join(", ")
        ));
    }
    for note in &data.vantage.unavailable {
        t.push_str(&format!("Unavailable: {}\n", note));
    }
    if let Some(frames) = data.vantage.observed_frames {
        t.push_str(&format!(
            "Passive capture: {} frames observed, {} facts accepted\n",
            frames,
            data.vantage.accepted_facts.unwrap_or(0)
        ));
    }

    t.push_str("\nNETWORKS\n");
    for n in &data.networks {
        t.push_str(&format!(
            "  {:<24} {:<10} {:<12} {}\n",
            n.cidr,
            n.kind,
            n.confidence,
            if n.enumerated { "" } else { "(not enumerated)" }
        ));
    }

    if !data.vlans.is_empty() {
        t.push_str("\nVLANS\n");
        for v in &data.vlans {
            t.push_str(&format!("  VLAN {:<6} {}\n", v.id, v.note));
        }
    }

    t.push_str("\nDEVICES\n");
    for d in &data.devices {
        t.push_str(&format!(
            "  {:<18} {:<12} {:<28} {}\n",
            d.kind,
            d.confidence,
            d.addresses.join(","),
            d.id
        ));
        for c in &d.capabilities {
            t.push_str(&format!("      capability: {}\n", c));
        }
        for e in &d.role_evidence {
            t.push_str(&format!("      role: {}\n", e));
        }
        if let Some(reason) = &d.opaque_reason {
            t.push_str(&format!("      boundary: {}\n", reason));
        }
    }

    t.push_str("\nRELATIONSHIPS\n");
    for r in &data.relationships {
        t.push_str(&format!(
            "  {} --{}--> {}  [{}]\n",
            r.from, r.relationship, r.to, r.confidence
        ));
    }

    t.push_str("\nCOVERAGE\n");
    for c in &data.coverage {
        t.push_str(&format!("  {}\n", c.scope));
        for p in &c.providers {
            t.push_str(&format!(
                "    {:<20} {}\n",
                p.provider,
                p.note
                    .clone()
                    .unwrap_or_else(|| format!("{} facts", p.facts))
            ));
        }
    }

    t.push_str(&format!(
        "\n{} observed, {} advertised, {} inferred, {} nodes{}\n",
        data.summary.observed,
        data.summary.advertised,
        data.summary.inferred,
        data.summary.total_nodes,
        if data.summary.converged {
            ""
        } else {
            " (stopped at the safety budget)"
        }
    ));

    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::orchestrator::{ScopeRun, VisibilityReport};
    use crate::providers::{Vantage, VantageKind};
    use crate::topology::TopologyEvidence;
    use crate::topology::evidence::{DeviceKey, EvidenceSource, Fact, RoleSignal};

    fn sample_report() -> DiscoveryReport {
        let mut graph = TopologyGraph::new();
        let mac = DeviceKey::mac("74:12:13:14:75:dc");

        for ev in [
            TopologyEvidence::new(
                Fact::Network {
                    prefix: "192.168.1.0/24".parse().unwrap(),
                },
                EvidenceSource::InterfaceAddress,
                Confidence::Observed,
                "en0",
            ),
            TopologyEvidence::new(
                Fact::InterfaceNetwork {
                    interface: "en0".to_string(),
                    prefix: "192.168.1.0/24".parse().unwrap(),
                },
                EvidenceSource::InterfaceAddress,
                Confidence::Observed,
                "en0",
            ),
            TopologyEvidence::new(
                Fact::DeviceAddress {
                    device: mac.clone(),
                    address: "192.168.1.1".parse().unwrap(),
                },
                EvidenceSource::ArpCache,
                Confidence::Observed,
                "en0",
            ),
            TopologyEvidence::new(
                Fact::DeviceRoleSignal {
                    device: mac.clone(),
                    signal: RoleSignal::DefaultGateway,
                },
                EvidenceSource::DefaultGateway,
                Confidence::Observed,
                "en0",
            ),
            TopologyEvidence::new(
                Fact::Vlan { id: 20 },
                EvidenceSource::Stp,
                Confidence::Observed,
                "en0",
            ),
        ] {
            graph.absorb(ev);
        }
        graph.finalize_roles();

        DiscoveryReport {
            graph,
            scope_runs: vec![ScopeRun {
                scope: None,
                runs: Vec::new(),
            }],
            pivot_runs: Vec::new(),
            coverage: Vec::new(),
            enrichment_elapsed: std::time::Duration::ZERO,
            enrichment_sequential_equivalent: std::time::Duration::ZERO,
            probes_attempted: 0,
            visibility: VisibilityReport {
                vantage: Vantage {
                    interface: "en0".to_string(),
                    kind: VantageKind::Wired,
                    index: 0,
                    capture_available: true,
                },
                blind_to: vec!["switched unicast".to_string()],
                unavailable: Vec::new(),
                observed_frames: Some(42),
                accepted_facts: Some(3),
            },
            oversized_scopes: Vec::new(),
            converged: true,
        }
    }

    #[test]
    fn export_preserves_roles_relationships_and_evidence() {
        let data = build_export(&sample_report());

        let router = data
            .devices
            .iter()
            .find(|d| d.kind == "router")
            .expect("the gateway is classified as a router");
        assert!(
            router
                .role_evidence
                .iter()
                .any(|e| e.contains("default gateway")),
            "role evidence must survive serialisation"
        );
        assert!(!router.evidence.is_empty(), "provenance must be preserved");
        assert!(
            !data.relationships.is_empty(),
            "relationships must be serialised"
        );
    }

    #[test]
    fn device_categories_sum_to_the_device_total_without_double_counting() {
        let data = build_export(&sample_report());
        let s = &data.summary;

        assert_eq!(
            s.routers + s.switches + s.opaque_boundaries + s.ai_systems + s.other_hosts,
            s.devices,
            "every device must fall in exactly one category"
        );

        // Each exported device carries exactly one category, and they tally.
        let mut counted = std::collections::BTreeMap::new();
        for device in &data.devices {
            *counted.entry(device.category.clone()).or_insert(0usize) += 1;
        }
        assert_eq!(
            counted.values().sum::<usize>(),
            s.devices,
            "the device list and the summary must agree"
        );
    }

    #[test]
    fn the_graph_node_total_is_explained_by_its_composition() {
        let data = build_export(&sample_report());
        let s = &data.summary;

        assert_eq!(
            s.nodes_by_kind.values().sum::<usize>(),
            s.total_nodes,
            "the per-kind breakdown must account for every graph node"
        );
        assert!(
            s.total_nodes >= s.devices,
            "the graph holds devices plus networks, interfaces and services"
        );
    }

    #[test]
    fn exported_vlan_never_carries_a_prefix() {
        let data = build_export(&sample_report());
        let vlan = data.vlans.first().expect("VLAN 20 was observed");
        assert_eq!(vlan.id, 20);
        assert!(
            vlan.prefix.is_none(),
            "a VLAN tag must never be serialised with an invented prefix"
        );
    }

    #[test]
    fn every_format_round_trips_to_disk() {
        let report = sample_report();
        let dir = std::env::temp_dir();

        for format in [
            OutputFormat::Json,
            OutputFormat::Yaml,
            OutputFormat::Xml,
            OutputFormat::Csv,
            OutputFormat::Text,
        ] {
            let path = dir.join(format!("idnx_export_test.{}", format.extension()));
            let written = export(&report, format, path.to_str()).expect("export succeeds");
            let content = std::fs::read_to_string(&written).expect("readable");

            assert!(
                content.contains("192.168.1.1") || content.contains("192.168.1.0/24"),
                "{:?} export lost the topology",
                format
            );
            let _ = std::fs::remove_file(&written);
        }
    }

    #[test]
    fn json_export_carries_vantage_visibility() {
        let report = sample_report();
        let path = std::env::temp_dir().join("idnx_vantage_test.json");
        let written = export(&report, OutputFormat::Json, path.to_str()).unwrap();
        let content = std::fs::read_to_string(&written).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["vantage"]["interface"], "en0");
        assert_eq!(parsed["vantage"]["observed_frames"], 42);
        assert!(!parsed["vantage"]["blind_to"].as_array().unwrap().is_empty());

        let _ = std::fs::remove_file(&written);
    }
}
