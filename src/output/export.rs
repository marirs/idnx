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
    /// What each selected adapter managed to do: unavailable, no response, or answered.
    /// Selection is not interrogation, and a consumer must be able to tell them apart.
    pub adapter_outcomes: Vec<String>,
    /// Probes that never left this machine, with the local error. A consumer must not read
    /// these as evidence about the device.
    pub not_sent: Vec<String>,
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
    /// How strictly active probes were tied to this interface: `unbound (ordinary
    /// routing)`, `source-address bound`, or `interface bound`. A consumer merging results
    /// from several vantages needs to know which guarantee actually held.
    pub binding_mode: String,
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
    /// The identity domain this network belongs to. Part of its identity, not decoration:
    /// two peers can each hold a 10.0.0.0/24, and merging by prefix alone would fuse two
    /// different networks.
    ///
    /// Says nothing about who observed it: a public prefix a peer reported shares the
    /// global identity domain and was never seen here. Use `observed_by`.
    pub identity_domain: DomainExport,
    /// Everyone who observed this network: the local machine, and each peer that reported
    /// it.
    pub observed_by: Vec<ObserverExport>,
    /// True when something on this machine observed it, which is also what decides whether
    /// it can be traversed from here.
    pub locally_observed: bool,
    /// What the run established about reaching into this network, as state a consumer can
    /// act on. `None` means nothing probed into it at all -- which is not the same as
    /// nothing answering, and the two must never collapse into one empty field.
    pub reachability: Option<ReachabilityExport>,
    pub evidence: Vec<EvidenceExport>,
}

/// An observation domain, in full.
///
/// Carries the complete peer identity rather than the short display form. Two peers sharing
/// the first sixteen hex characters -- which can be ground out deliberately, and which
/// chance eventually produces -- would otherwise be indistinguishable to anything consuming
/// an export, reintroducing at the boundary the exact collision the internal identities
/// were made full-length to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainExport {
    /// `local` or `peer`.
    pub kind: String,
    /// Full 64-character peer identity, for a peer domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// The peer's own name for the interface it observed from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vantage: Option<String>,
}

impl DomainExport {
    fn of(realm: &crate::topology::realm::Realm) -> Self {
        match realm {
            crate::topology::realm::Realm::Local => Self {
                kind: "local".to_string(),
                peer: None,
                vantage: None,
            },
            crate::topology::realm::Realm::Peer { peer, vantage } => Self {
                kind: "peer".to_string(),
                peer: Some(peer.clone()),
                vantage: Some(vantage.clone()),
            },
        }
    }

    /// Flat form, for the tabular formats.
    fn flat(&self) -> String {
        match (&self.peer, &self.vantage) {
            (Some(peer), Some(vantage)) => format!("peer:{peer}/{vantage}"),
            _ => self.kind.clone(),
        }
    }
}

/// One observer of a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverExport {
    /// `local` or `peer`.
    pub kind: String,
    /// Full peer identity, for a remote observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vantage: Option<String>,
}

impl ObserverExport {
    fn of(origin: Option<&crate::topology::evidence::PeerOrigin>) -> Self {
        match origin {
            None => Self {
                kind: "local".to_string(),
                peer: None,
                vantage: None,
            },
            Some(origin) => Self {
                kind: "peer".to_string(),
                peer: Some(origin.peer.clone()),
                vantage: Some(origin.vantage.clone()),
            },
        }
    }

    fn flat(&self) -> String {
        match (&self.peer, &self.vantage) {
            (Some(peer), Some(vantage)) => format!("peer:{peer}/{vantage}"),
            _ => self.kind.clone(),
        }
    }
}

/// Everyone who observed a node, in full.
fn observers_of(node: &crate::topology::Node) -> Vec<ObserverExport> {
    let mut out: Vec<ObserverExport> = Vec::new();
    for provenance in &node.provenance {
        let observer = ObserverExport::of(provenance.origin.as_ref());
        if !out.contains(&observer) {
            out.push(observer);
        }
    }
    // Local first, then peers in a stable order.
    out.sort_by(|a, b| {
        (a.kind != "local")
            .cmp(&(b.kind != "local"))
            .then_with(|| a.peer.cmp(&b.peer))
            .then_with(|| a.vantage.cmp(&b.vantage))
    });
    out
}

/// A VLAN observed on the wire.
///
/// `prefix` is always absent: a tag proves the VLAN ID and nothing about any network.
#[derive(Debug, Serialize, Deserialize)]
pub struct VlanExport {
    pub id: u16,
    /// The switched domain that uses this tag, with the full peer identity where it is a
    /// peer's. Two peers' VLAN 20 are two VLANs.
    pub observed_in: DomainExport,
    /// Present only where a single observation stated the tag and the prefix together.
    pub prefix: Option<String>,
    /// That observation. A binding without its evidence is indistinguishable from a guess,
    /// so the two are exported together or not at all.
    pub evidence: Vec<EvidenceExport>,
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
    /// Everyone who observed this device: the local machine, and each peer that reported
    /// it, each with a complete identity.
    pub observed_by: Vec<ObserverExport>,
    /// Why visibility stops here, when it does.
    pub opaque_reason: Option<String>,
    pub confidence: String,
    pub evidence: Vec<EvidenceExport>,
}

/// One network's reachability, in a shape that survives serialisation.
///
/// `state` is the machine-readable discriminant; `note` is the sentence rendered from it.
/// Consumers read `state`, never the sentence.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReachabilityExport {
    /// `reachable`, `probed_unreachable` or `not_enumerated`.
    pub state: String,
    /// Addresses that answered during the run. Never a neighbour-cache entry.
    pub responders: Vec<String>,
    /// Unique addresses at least one probe actually left this machine for. Kept even when
    /// something answered: "1 of 254 answered" and "1 of 1 answered" are different results
    /// and only the coverage tells them apart.
    pub attempted: usize,
    /// Probes that never left this machine, which is a local fault and not remote silence.
    pub not_sent: usize,
    /// Why nothing answered, or why nothing was tried.
    pub reasons: Vec<String>,
    /// How the network came to be known. Held apart from the probe result, since a failed
    /// sweep says nothing about whether a router advertised the prefix.
    pub discovery: Vec<String>,
    pub note: String,
}

impl ReachabilityExport {
    fn of(reachability: &crate::providers::NetworkReachability) -> Self {
        Self {
            state: reachability.state().wire().to_string(),
            responders: reachability
                .responders
                .iter()
                .map(|address| address.to_string())
                .collect(),
            attempted: reachability.attempted(),
            not_sent: reachability.not_sent,
            reasons: reachability.reasons.clone(),
            discovery: reachability.discovery.clone(),
            note: reachability.describe(),
        }
    }
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
    /// forwarding_interfaces + ai_systems + other_hosts.
    pub devices: usize,
    pub routers: usize,
    pub switches: usize,
    /// Devices that bridge and route at once, counted apart from both.
    pub layer3_switches: usize,
    pub opaque_boundaries: usize,
    /// Interfaces observed forwarding traffic, with no evidence of who owns them.
    pub forwarding_interfaces: usize,
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
            NodeId::Interface(n, _) => n.clone(),
            NodeId::Network(n, _) => n.to_string(),
            NodeId::Vlan(v, _) => format!("VLAN {}", v),
            NodeId::Device(d) => d.to_string(),
            NodeId::Service(a, p, _) => format!("{}:{}", a, p),
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
    for net in graph.network_refs() {
        let interfaces: Vec<String> = graph
            .interfaces_for_network(&net)
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let iface_refs: Vec<&str> = interfaces.iter().map(|s| s.as_str()).collect();
        let node = graph.network_ref_node(&net);
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
            enumerated: !report.oversized_scopes.contains(&net.prefix),
            // The identity domain: two peers can each hold a 10.0.0.0/24, and a consumer
            // merging exports by prefix alone would fuse them.
            identity_domain: DomainExport::of(&net.realm),
            // Who actually saw it, taken from provenance rather than from the identity
            // domain. A public prefix reported only by a peer carries a shared identity
            // and is still not something this vantage observed; a corroborated network has
            // several observers and must not be reduced to one.
            observed_by: node.map(observers_of).unwrap_or_default(),
            locally_observed: node.is_some_and(|n| n.locally_observed()),
            // By reference, not by prefix: a peer's 10.0.0.0/24 must never be handed the
            // local sweep's result.
            reachability: report
                .network_reachability
                .get(&net)
                .map(ReachabilityExport::of),
            evidence: node.map(|n| evidence_of(&n.provenance)).unwrap_or_default(),
        });
    }
    networks.sort_by(|a, b| {
        a.cidr
            .cmp(&b.cidr)
            .then_with(|| a.identity_domain.flat().cmp(&b.identity_domain.flat()))
    });

    // Both kinds of VLAN, each carrying what it is entitled to. A bound VLAN exports the
    // prefix *and* the observation that joined them, so a consumer can check the claim
    // rather than take it; an unbound one exports no prefix at all.
    let mut vlans: Vec<VlanExport> = graph
        .vlans_without_prefix()
        .map(|vlan| VlanExport {
            id: vlan.id,
            // The switched domain the tag belongs to. Two peers' VLAN 20 are two VLANs, and
            // a consumer merging by number alone would fuse them.
            observed_in: DomainExport::of(&vlan.realm),
            prefix: None,
            evidence: Vec::new(),
            note: "observed on the wire; no prefix evidence".to_string(),
        })
        .collect();
    vlans.extend(
        graph
            .vlan_networks()
            .into_iter()
            .map(|(vlan, prefix, provenance)| VlanExport {
                id: vlan.id,
                observed_in: DomainExport::of(&vlan.realm),
                prefix: Some(prefix.to_string()),
                evidence: evidence_of(&provenance),
                note: "one observation stated both the tag and the prefix".to_string(),
            }),
    );
    vlans.sort_by(|a, b| (a.id, &a.prefix).cmp(&(b.id, &b.prefix)));

    let mut devices = Vec::new();
    for node in graph.nodes() {
        if !matches!(
            node.kind,
            NodeKind::Router
                | NodeKind::Switch
                | NodeKind::Layer3Switch
                | NodeKind::Host
                | NodeKind::OpaqueBoundary
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
            // Device- and peer-chosen text. Neutralised on the way out: an export is read
            // by a terminal, a spreadsheet or a browser, and none of them should receive
            // control characters a device put in its own name.
            hostnames: crate::output::safe::all(node.hostnames.iter()),
            vendor: node.vendor.as_deref().map(crate::output::safe::text),
            descriptions: crate::output::safe::all(node.descriptions.iter()),
            role_evidence: crate::output::safe::all(node.role_signals.iter()),
            capabilities: crate::output::safe::all(node.capabilities.iter()),
            opaque_reason: node.opaque_reason.as_deref().map(crate::output::safe::text),
            // Full identities, so a consumer can tell two peers apart even when their
            // display forms coincide.
            observed_by: observers_of(node),
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
            adapter_outcomes: record.adapter_outcomes.clone(),
            not_sent: record.local_failures(),
            omissions: record.omissions(),
            skipped: record.skipped.clone(),
            silent: record.silent(),
            elapsed_ms: record.elapsed.as_millis(),
        })
        .collect();

    let mut nodes_by_kind: std::collections::BTreeMap<String, usize> = Default::default();
    for node in graph.nodes() {
        // The wire name, not the display label: these become XML element names, which
        // cannot contain the spaces a human-facing label has.
        *nodes_by_kind
            .entry(node.kind.wire().to_string())
            .or_default() += 1;
    }

    let counts = graph.counts();
    let mut summary = SummaryExport {
        devices: counts.devices(),
        routers: counts.routers,
        switches: counts.switches,
        layer3_switches: counts.layer3_switches,
        opaque_boundaries: counts.opaque_boundaries,
        forwarding_interfaces: counts.forwarding_interfaces,
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
            binding_mode: report.visibility.binding_mode.label().to_string(),
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

    let content = render(&data, format)?;

    let mut file = File::create(&path).map_err(|e| format!("Cannot create {path:?}: {e}"))?;
    file.write_all(content.as_bytes())
        .map_err(|e| format!("Cannot write {path:?}: {e}"))?;

    Ok(path)
}

/// Serialises an export in one format.
///
/// Separate from writing it so the same bytes can be examined without touching a disk.
pub fn render(data: &TopologyExport, format: OutputFormat) -> Result<String, String> {
    Ok(match format {
        OutputFormat::Json => serde_json::to_string_pretty(data)
            .map_err(|e| format!("JSON serialisation failed: {e}"))?,
        OutputFormat::Yaml => {
            serde_yaml::to_string(data).map_err(|e| format!("YAML serialisation failed: {e}"))?
        }
        OutputFormat::Xml => {
            quick_xml::se::to_string(data).map_err(|e| format!("XML serialisation failed: {e}"))?
        }
        OutputFormat::Csv => render_csv(data)?,
        OutputFormat::Text => render_text(data),
    })
}

/// CSV is one row per device, carrying the evidence that classified it.
/// CSV as typed records: one row per topology object, not one row per device.
///
/// It was a device inventory, which contradicted the contract every other format keeps --
/// networks, VLANs, relationships and reachability existed in JSON and vanished here, so a
/// consumer reading the CSV saw a device list and no topology at all. Each row now names
/// its own record type in the first column, and the columns that do not apply to that type
/// are left empty rather than repurposed.
fn render_csv(data: &TopologyExport) -> Result<String, String> {
    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record([
        "Record",
        "Kind",
        "Name",
        "Addresses",
        "Hostnames",
        "Vendor",
        "Confidence",
        "Capabilities",
        "Role Evidence",
        "Evidence Sources",
        "Observed By",
        "Detail",
    ])
    .map_err(|e| format!("CSV header error: {e}"))?;

    let flatten = |observers: &[ObserverExport]| {
        observers
            .iter()
            .map(|observer| observer.flat())
            .collect::<Vec<_>>()
            .join("; ")
    };

    for network in &data.networks {
        let sources: Vec<String> = network
            .evidence
            .iter()
            .map(|item| item.source.clone())
            .collect();
        // Reachability travels with the network, in the same shape the other formats use:
        // state, then the coverage that backs it.
        let reachability = match &network.reachability {
            Some(state) => format!(
                "reachability={}; probed={}; responders={}; not_sent={}{}",
                state.state,
                state.attempted,
                state.responders.join(" "),
                state.not_sent,
                if state.discovery.is_empty() {
                    String::new()
                } else {
                    format!("; discovered={}", state.discovery.join(" | "))
                }
            ),
            None => "reachability=not_probed".to_string(),
        };
        let detail = format!(
            "{reachability}; enumerated={}; interfaces={}",
            network.enumerated,
            network.interfaces.join(" ")
        );
        wtr.write_record([
            "network",
            &network.kind,
            &network.cidr,
            "",
            "",
            "",
            &network.confidence,
            "",
            "",
            &sources.join("; "),
            &flatten(&network.observed_by),
            &detail,
        ])
        .map_err(|e| format!("CSV write error: {e}"))?;
    }

    for vlan in &data.vlans {
        let sources: Vec<String> = vlan
            .evidence
            .iter()
            .map(|item| item.source.clone())
            .collect();
        wtr.write_record([
            "vlan",
            "vlan",
            &format!("VLAN {}", vlan.id),
            vlan.prefix.as_deref().unwrap_or(""),
            "",
            "",
            "",
            "",
            "",
            &sources.join("; "),
            &vlan.observed_in.flat(),
            &vlan.note,
        ])
        .map_err(|e| format!("CSV write error: {e}"))?;
    }

    for device in &data.devices {
        let sources: Vec<String> = device
            .evidence
            .iter()
            .map(|item| item.source.clone())
            .collect();
        wtr.write_record([
            "device",
            &device.kind,
            &device.id,
            &device.addresses.join("; "),
            &device.hostnames.join("; "),
            device.vendor.as_deref().unwrap_or(""),
            &device.confidence,
            &device.capabilities.join("; "),
            &device.role_evidence.join("; "),
            &sources.join("; "),
            // Flattened, with full peer identities: the tabular formats have no place for
            // a structure, and a truncated identity would let two peers collide here.
            &flatten(&device.observed_by),
            device.opaque_reason.as_deref().unwrap_or(""),
        ])
        .map_err(|e| format!("CSV write error: {e}"))?;
    }

    for relationship in &data.relationships {
        let sources: Vec<String> = relationship
            .evidence
            .iter()
            .map(|item| item.source.clone())
            .collect();
        wtr.write_record([
            "relationship",
            &relationship.relationship,
            &relationship.from,
            &relationship.to,
            "",
            "",
            &relationship.confidence,
            "",
            "",
            &sources.join("; "),
            "",
            "",
        ])
        .map_err(|e| format!("CSV write error: {e}"))?;
    }

    for scope in &data.coverage {
        let providers: Vec<String> = scope
            .providers
            .iter()
            .map(|provider| provider.provider.clone())
            .collect();
        let notes: Vec<String> = scope
            .providers
            .iter()
            .map(|provider| {
                format!(
                    "{}: {}",
                    provider.provider,
                    provider.note.as_deref().unwrap_or("no note")
                )
            })
            .collect();
        wtr.write_record([
            "coverage",
            "scope",
            &scope.scope,
            &scope.networks_learned.join("; "),
            "",
            "",
            "",
            "",
            "",
            &providers.join("; "),
            "",
            &notes.join(" | "),
        ])
        .map_err(|e| format!("CSV write error: {e}"))?;
    }

    for record in &data.device_coverage {
        wtr.write_record([
            "device_coverage",
            &record.tier,
            &record.device,
            &record.addresses.join("; "),
            "",
            "",
            "",
            &record.protocols_confirmed.join("; "),
            "",
            &record.discovery_sources.join("; "),
            "",
            &record.skipped.clone().unwrap_or_default(),
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
        // Rendered from the reachability state. A network nothing answered on stays listed
        // and says so; one never probed says that instead.
        if let Some(reachability) = &n.reachability {
            t.push_str(&format!("      {}\n", reachability.note));
        }
    }

    if !data.vlans.is_empty() {
        t.push_str("\nVLANS\n");
        for v in &data.vlans {
            match &v.prefix {
                Some(prefix) => {
                    t.push_str(&format!("  VLAN {:<6} {:<20} {}\n", v.id, prefix, v.note))
                }
                None => t.push_str(&format!("  VLAN {:<6} {:<20} {}\n", v.id, "-", v.note)),
            }
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
            network_reachability: Default::default(),
            visibility: VisibilityReport {
                vantage: Vantage {
                    interface: "en0".to_string(),
                    kind: VantageKind::Wired,
                    index: 0,
                    capture_available: true,
                },
                blind_to: vec!["switched unicast".to_string()],
                unavailable: Vec::new(),
                binding_mode: crate::net::socket::BindingMode::SourceAddress,
                observed_frames: Some(42),
                routing_updates: None,
                control_plane: None,
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
            s.routers
                + s.switches
                + s.opaque_boundaries
                + s.forwarding_interfaces
                + s.ai_systems
                + s.other_hosts,
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
    fn reachability_is_exported_as_state_and_not_only_as_a_sentence() {
        // An export consumer must be able to tell "probed, nothing answered" from "never
        // probed" without matching on English. Both produce an empty host list.
        let mut report = sample_report();
        let prefix: ipnet::IpNet = "192.168.1.0/24".parse().expect("a literal prefix");
        report.network_reachability.insert(
            crate::topology::graph::NetworkRef {
                prefix,
                realm: crate::topology::realm::network_realm(
                    &prefix,
                    &crate::topology::realm::Realm::Local,
                ),
            },
            crate::providers::NetworkReachability::probed(
                Vec::new(),
                (1..=254u8)
                    .map(|host| std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, host))),
                0,
                vec!["swept; nothing answered".to_string()],
            )
            .discovered_by("attached to this vantage"),
        );

        let data = build_export(&report);
        let network = data
            .networks
            .iter()
            .find(|n| n.cidr == "192.168.1.0/24")
            .expect("the network is exported");
        let reachability = network
            .reachability
            .as_ref()
            .expect("its reachability is exported");
        assert_eq!(reachability.state, "probed_unreachable");
        assert_eq!(reachability.attempted, 254);
        assert!(!reachability.reasons.is_empty());
        assert_eq!(
            reachability.discovery,
            vec!["attached to this vantage".to_string()],
            "how it was found is exported apart from what answered"
        );
        assert!(reachability.note.contains("none answered"));

        // Serialisation keeps the discriminant, which is the part a consumer reads.
        let json = serde_json::to_string(&data).expect("the export serialises");
        assert!(json.contains("probed_unreachable"));
    }

    #[test]
    fn a_bound_vlan_exports_its_prefix_together_with_the_observation_that_bound_it() {
        // A prefix on a VLAN without the evidence that put it there is indistinguishable
        // from a guess, so the two are exported together or not at all.
        let mut report = sample_report();
        report.graph.absorb(
            TopologyEvidence::new(
                Fact::VlanNetwork {
                    vlan: 30,
                    network: "203.0.113.0/24".parse().expect("a literal prefix"),
                },
                EvidenceSource::DhcpLease,
                Confidence::Observed,
                "en0",
            )
            .with_detail("client-facing DHCP ACK, tagged, with option 1"),
        );

        let data = build_export(&report);
        let bound = data
            .vlans
            .iter()
            .find(|vlan| vlan.id == 30)
            .expect("the bound VLAN is exported");
        assert_eq!(bound.prefix.as_deref(), Some("203.0.113.0/24"));
        assert!(
            !bound.evidence.is_empty(),
            "the observation that bound it travels with it"
        );

        let unbound = data
            .vlans
            .iter()
            .find(|vlan| vlan.id == 20)
            .expect("the unbound VLAN is still exported");
        assert!(
            unbound.prefix.is_none() && unbound.evidence.is_empty(),
            "a tag of unknown extent exports no prefix and no binding evidence"
        );

        // The binding is also a relationship, with its own provenance.
        assert!(
            data.relationships
                .iter()
                .any(|rel| rel.relationship == "carries" && !rel.evidence.is_empty()),
            "the VLAN-to-network edge is exported with its evidence"
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
