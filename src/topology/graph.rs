//! The vendor-neutral topology graph.
//!
//! Every provider's output lands here and nowhere else. The graph owns identity
//! resolution (which addresses belong to which device), relationship formation, and the
//! provenance trail behind every node and edge.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use ipnet::IpNet;

use super::evidence::{Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal, TopologyEvidence};
use super::role::{DeviceRole, score_role};

/// How a device is presented to an operator.
///
/// Mutually exclusive by construction, so the section counts sum to the number of unique
/// devices. A router that also hosts an AI runtime stays under `Router` and carries the
/// capability as an annotation rather than being counted twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeviceCategory {
    OpaqueBoundary,
    Router,
    Switch,
    /// A non-infrastructure device with a *confirmed* AI capability.
    AiSystem,
    Host,
}

impl DeviceCategory {
    pub fn label(&self) -> &'static str {
        match self {
            DeviceCategory::OpaqueBoundary => "opaque boundary",
            DeviceCategory::Router => "router",
            DeviceCategory::Switch => "switch",
            DeviceCategory::AiSystem => "AI system",
            DeviceCategory::Host => "host",
        }
    }
}

/// Capability labels that qualify a device as an AI system.
///
/// Membership requires a confirmed capability. An open port on 11434 or 3000 is not one:
/// those ports host far more non-AI software than AI software.
const AI_CAPABILITY_LABELS: &[&str] = &["AI runtime", "AI agent", "MCP server"];

/// True when a device has a confirmed AI capability.
pub fn has_confirmed_ai(node: &Node) -> bool {
    node.capabilities.iter().any(|capability| {
        AI_CAPABILITY_LABELS
            .iter()
            .any(|label| capability.starts_with(label))
    })
}

/// Places a device in exactly one presentation category.
pub fn categorize(node: &Node) -> Option<DeviceCategory> {
    match node.kind {
        NodeKind::OpaqueBoundary => Some(DeviceCategory::OpaqueBoundary),
        // Infrastructure placement wins: a router hosting AI is still a router.
        NodeKind::Router => Some(DeviceCategory::Router),
        NodeKind::Switch => Some(DeviceCategory::Switch),
        NodeKind::Host => Some(if has_confirmed_ai(node) {
            DeviceCategory::AiSystem
        } else {
            DeviceCategory::Host
        }),
        NodeKind::Interface | NodeKind::Network | NodeKind::Vlan | NodeKind::Service => None,
    }
}

/// Counts of everything an operator asked about, plus the internal graph total.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TopologyCounts {
    pub routers: usize,
    pub switches: usize,
    pub opaque_boundaries: usize,
    pub ai_systems: usize,
    pub other_hosts: usize,
    pub networks: usize,
    pub vlans: usize,
    pub services: usize,
    pub interfaces: usize,
    /// Every node in the graph, which is necessarily larger than the device count.
    pub graph_nodes: usize,
}

impl TopologyCounts {
    /// Unique physical or logical devices. Each is counted exactly once.
    pub fn devices(&self) -> usize {
        self.routers + self.switches + self.opaque_boundaries + self.ai_systems + self.other_hosts
    }
}

/// Hostname tokens that suggest network equipment.
///
/// Matched on token boundaries, never as substrings. A bare `contains("ap")` classified
/// `dmaker-fan-p30_miapD143` -- a desk fan -- as an access point, which then consumed
/// interrogation budget sending it SNMP queries.
const INFRASTRUCTURE_HOSTNAME_TOKENS: &[&str] = &[
    "router",
    "gateway",
    "gw",
    "switch",
    "ap",
    "accesspoint",
    "firewall",
    "modem",
    "bridge",
    "wifi",
    "wlan",
    "edgerouter",
    "unifi",
    "openwrt",
];

/// True when a hostname carries an infrastructure token as a whole word.
///
/// A token matches when it equals a keyword, or when it is a keyword followed only by
/// digits -- `ap1`, `gw02` -- which is how such devices are conventionally numbered. Two
/// adjacent tokens are also joined and tested, so `access-point-lobby` matches while
/// `dmaker-fan-p30_miapD143` does not: `miapd143` neither equals nor begins with a keyword.
pub fn hostname_suggests_infrastructure(hostname: &str) -> bool {
    let lowered = hostname.to_ascii_lowercase();
    let tokens: Vec<&str> = lowered
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();

    let matches = |token: &str| {
        INFRASTRUCTURE_HOSTNAME_TOKENS.iter().any(|keyword| {
            token == *keyword
                || token.strip_prefix(keyword).is_some_and(|rest| {
                    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
                })
        })
    };

    if tokens.iter().any(|t| matches(t)) {
        return true;
    }
    tokens
        .windows(2)
        .any(|pair| matches(&format!("{}{}", pair[0], pair[1])))
}

/// Manufacturers whose registrations commonly cover network equipment.
///
/// Used only to decide who is worth interrogating. It never contributes to a role: plenty
/// of these organizations also make laptops, cameras and NAS boxes, and a router from an
/// unlisted manufacturer is still a router once it behaves like one.
const NETWORK_EQUIPMENT_VENDORS: &[&str] = &[
    "asustek",
    "asus",
    "linksys",
    "netgear",
    "tp-link",
    "d-link",
    "mikrotik",
    "ubiquiti",
    "cisco",
    "meraki",
    "zyxel",
    "draytek",
    "fortinet",
    "juniper",
    "aruba",
    "ruckus",
    "belkin",
    "tenda",
    "huawei",
    "openwrt",
    "netcomm",
    "sagemcom",
    "technicolor",
    "arris",
    "actiontec",
    "eero",
];

/// True when a prefix represents real topology.
///
/// Loopback, link-local, multicast and unspecified ranges are protocol machinery, not
/// networks anyone administers. This is deliberately not an RFC 1918 filter: public,
/// CGNAT, VPN and IPv6 global prefixes are all legitimate internal topology and are kept.
pub fn is_topology_network(net: &IpNet) -> bool {
    if net.prefix_len() == 0 {
        return false;
    }
    match net {
        IpNet::V4(v4) => {
            let a = v4.addr();
            !a.is_loopback() && !a.is_link_local() && !a.is_multicast() && !a.is_unspecified()
        }
        IpNet::V6(v6) => {
            let a = v6.addr();
            !a.is_loopback() && !a.is_multicast() && !a.is_unspecified() && !is_v6_link_local(&a)
        }
    }
}

/// True when an address is worth sending a query to.
pub fn is_interrogable(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !v4.is_loopback() && !v4.is_link_local() && !v4.is_multicast() && !v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback() && !v6.is_multicast() && !v6.is_unspecified() && !is_v6_link_local(v6)
        }
    }
}

/// `Ipv6Addr::is_unicast_link_local` is still unstable, so the fe80::/10 test is written out.
fn is_v6_link_local(addr: &std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// Stable identity for a graph node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NodeId {
    Interface(String),
    Network(IpNet),
    Vlan(u16),
    Device(DeviceKey),
    Service(IpAddr, u16),
}

/// What a node represents.
///
/// `Router`, `Switch` and `Host` are all device nodes; which one a device becomes is
/// decided by role scoring over corroborated behaviour, never by its manufacturer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeKind {
    Interface,
    Network,
    Vlan,
    Router,
    Switch,
    Host,
    Service,
    OpaqueBoundary,
}

impl NodeKind {
    pub fn label(&self) -> &'static str {
        match self {
            NodeKind::Interface => "interface",
            NodeKind::Network => "network",
            NodeKind::Vlan => "vlan",
            NodeKind::Router => "router",
            NodeKind::Switch => "switch",
            NodeKind::Host => "host",
            NodeKind::Service => "service",
            NodeKind::OpaqueBoundary => "opaque boundary",
        }
    }
}

/// How two nodes relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Relationship {
    AttachedTo,
    RoutesTo,
    GatewayFor,
    Advertises,
    ObservedBehind,
    PossibleUplink,
    NatBoundary,
    ResolvedAs,
}

impl Relationship {
    pub fn label(&self) -> &'static str {
        match self {
            Relationship::AttachedTo => "attached to",
            Relationship::RoutesTo => "routes to",
            Relationship::GatewayFor => "gateway for",
            Relationship::Advertises => "advertises",
            Relationship::ObservedBehind => "observed behind",
            Relationship::PossibleUplink => "possible uplink",
            Relationship::NatBoundary => "NAT boundary",
            Relationship::ResolvedAs => "resolved as",
        }
    }
}

/// Provenance attached to a node or edge.
#[derive(Debug, Clone)]
pub struct Provenance {
    pub source: EvidenceSource,
    pub confidence: Confidence,
    pub vantage: String,
    pub detail: Option<String>,
}

impl Provenance {
    fn from_evidence(ev: &TopologyEvidence) -> Self {
        Self {
            source: ev.source,
            confidence: ev.confidence,
            vantage: ev.vantage.clone(),
            detail: ev.detail.clone(),
        }
    }
}

/// A node in the topology.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    pub addresses: BTreeSet<IpAddr>,
    pub hostnames: BTreeSet<String>,
    pub vendor: Option<String>,
    pub descriptions: BTreeSet<String>,
    /// Behaviour observed for this device, used by role scoring.
    pub role_signals: BTreeSet<String>,
    /// What the device was observed doing, rendered alongside its role.
    pub capabilities: BTreeSet<String>,
    /// Reason this node terminates visibility, when it does.
    pub opaque_reason: Option<String>,
    /// Best (strongest) confidence supporting the node's existence.
    pub confidence: Confidence,
    pub provenance: Vec<Provenance>,
}

impl Node {
    fn new(id: NodeId, kind: NodeKind, confidence: Confidence) -> Self {
        Self {
            id,
            kind,
            addresses: BTreeSet::new(),
            hostnames: BTreeSet::new(),
            vendor: None,
            descriptions: BTreeSet::new(),
            role_signals: BTreeSet::new(),
            capabilities: BTreeSet::new(),
            opaque_reason: None,
            confidence,
            provenance: Vec::new(),
        }
    }

    /// Distinct evidence sources that contributed to this node.
    ///
    /// Reported per device so that "discovered by ARP alone" is distinguishable from
    /// "discovered by ARP, DHCP and a router advertisement".
    pub fn evidence_sources(&self) -> Vec<String> {
        let mut sources: Vec<String> = self
            .provenance
            .iter()
            .map(|p| p.source.label().to_string())
            .collect();
        sources.sort();
        sources.dedup();
        sources
    }

    /// Best display name available, preferring what the device called itself.
    pub fn display_name(&self) -> String {
        if let Some(name) = self.hostnames.iter().next() {
            return name.clone();
        }
        if let Some(addr) = self.addresses.iter().next() {
            return addr.to_string();
        }
        match &self.id {
            NodeId::Interface(n) => n.clone(),
            NodeId::Network(n) => n.to_string(),
            NodeId::Vlan(v) => format!("VLAN {}", v),
            NodeId::Device(d) => d.to_string(),
            NodeId::Service(a, p) => format!("{}:{}", a, p),
        }
    }
}

/// A directed relationship between two nodes.
#[derive(Debug, Clone)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub relationship: Relationship,
    pub confidence: Confidence,
    pub provenance: Vec<Provenance>,
}

/// The topology built from every provider's evidence.
#[derive(Debug, Default)]
pub struct TopologyGraph {
    nodes: BTreeMap<NodeId, Node>,
    edges: BTreeMap<(NodeId, NodeId, Relationship), Edge>,
    /// Maps an address to the device holding it, so a later fact about the same address
    /// merges into the same device rather than creating a second one.
    /// Keyed by address *and* zone: a link-local address is only unique within its link,
    /// so a global key would merge unrelated devices that share one.
    address_owner: HashMap<(IpAddr, Option<String>), DeviceKey>,
    /// VLAN IDs seen without any prefix-bearing evidence.
    vlans_without_prefix: BTreeSet<u16>,
    /// Structured role signals per device. Kept separate from `Node::role_signals`, which
    /// holds only rendered strings, so scoring operates on typed values.
    role_weights: HashMap<NodeId, BTreeSet<RoleSignal>>,
}

impl TopologyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    pub fn edges(&self) -> impl Iterator<Item = &Edge> {
        self.edges.values()
    }

    pub fn node(&self, id: &NodeId) -> Option<&Node> {
        self.nodes.get(id)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn nodes_of_kind(&self, kind: NodeKind) -> impl Iterator<Item = &Node> {
        self.nodes.values().filter(move |n| n.kind == kind)
    }

    /// Networks currently known, each backed by prefix-bearing evidence.
    pub fn networks(&self) -> Vec<IpNet> {
        self.nodes
            .keys()
            .filter_map(|id| match id {
                NodeId::Network(net) => Some(*net),
                _ => None,
            })
            .collect()
    }

    /// VLANs observed with no prefix evidence, reported as such rather than invented.
    pub fn vlans_without_prefix(&self) -> impl Iterator<Item = u16> + '_ {
        self.vlans_without_prefix.iter().copied()
    }

    /// Counts for presentation, computed once so every renderer agrees.
    pub fn counts(&self) -> TopologyCounts {
        let mut counts = TopologyCounts {
            graph_nodes: self.nodes.len(),
            ..Default::default()
        };

        for node in self.nodes.values() {
            match node.kind {
                NodeKind::Network => counts.networks += 1,
                NodeKind::Vlan => counts.vlans += 1,
                NodeKind::Service => counts.services += 1,
                NodeKind::Interface => counts.interfaces += 1,
                _ => match categorize(node) {
                    Some(DeviceCategory::Router) => counts.routers += 1,
                    Some(DeviceCategory::Switch) => counts.switches += 1,
                    Some(DeviceCategory::OpaqueBoundary) => counts.opaque_boundaries += 1,
                    Some(DeviceCategory::AiSystem) => counts.ai_systems += 1,
                    Some(DeviceCategory::Host) => counts.other_hosts += 1,
                    None => {}
                },
            }
        }

        counts
    }

    /// Devices in one presentation category.
    pub fn devices_in(&self, category: DeviceCategory) -> Vec<&Node> {
        let mut out: Vec<&Node> = self
            .nodes
            .values()
            .filter(|n| categorize(n) == Some(category))
            .collect();
        out.sort_by_key(|n| (n.addresses.iter().next().copied(), n.display_name()));
        out
    }

    /// Interfaces through which a network is reached.
    ///
    /// Used to separate physical topology from VPN and virtualisation plumbing without
    /// removing anything from the graph.
    pub fn interfaces_for_network(&self, network: &IpNet) -> Vec<&str> {
        let target = NodeId::Network(*network);
        self.edges
            .values()
            .filter(|e| e.relationship == Relationship::AttachedTo && e.to == target)
            .filter_map(|e| match &e.from {
                NodeId::Interface(name) => Some(name.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Addresses of devices with established infrastructure behaviour.
    ///
    /// These have positive evidence of routing or bridging. Membership comes from observed
    /// behaviour only, so a device is never here because of who manufactured it.
    pub fn pivot_addresses(&self) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = self
            .role_weights
            .keys()
            .filter_map(|id| self.nodes.get(id))
            .flat_map(|node| node.addresses.iter().copied())
            // A link-local or loopback address cannot be interrogated meaningfully, and
            // queueing one only produces a guaranteed timeout in the coverage report.
            .filter(is_interrogable)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Addresses worth interrogating for control-plane evidence they may not yet show.
    ///
    /// Interrogating only devices that already carry a role signal is circular: a device
    /// needs router evidence to be interrogated, and interrogation is how router evidence
    /// is obtained. An unknown appliance sitting silently in the ARP table — exactly the
    /// ASUS case — was therefore never asked anything.
    ///
    /// A candidate hint schedules work and nothing more. It never raises confidence and
    /// never appears as topology; only what the interrogation returns can do that.
    pub fn candidate_addresses(&self) -> Vec<IpAddr> {
        let established: std::collections::HashSet<IpAddr> =
            self.pivot_addresses().into_iter().collect();

        let mut out: Vec<IpAddr> = self
            .nodes
            .values()
            .filter(|node| self.is_infrastructure_candidate(node))
            .flat_map(|node| node.addresses.iter().copied())
            .filter(is_interrogable)
            .filter(|a| !established.contains(a))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Weak hints that a device may be network equipment.
    ///
    /// Manufacturer is deliberately included here and nowhere else: it is worthless as
    /// proof but useful for deciding who to ask. The distinction between "worth asking"
    /// and "established fact" is what keeps a vendor name out of the topology.
    fn is_infrastructure_candidate(&self, node: &Node) -> bool {
        if node.kind == NodeKind::Service {
            return false;
        }

        if let Some(vendor) = &node.vendor {
            let lowered = vendor.to_ascii_lowercase();
            if NETWORK_EQUIPMENT_VENDORS
                .iter()
                .any(|v| lowered.contains(v))
            {
                return true;
            }
        }

        if node
            .hostnames
            .iter()
            .any(|h| hostname_suggests_infrastructure(h))
        {
            return true;
        }

        // A device holding several addresses is more likely to be multi-homed
        // infrastructure than an ordinary endpoint.
        node.addresses.iter().filter(|a| is_interrogable(a)).count() > 1
    }

    /// Resolves the canonical device key for an address, if one is already known.
    pub fn device_for_address(&self, addr: &IpAddr) -> Option<&DeviceKey> {
        self.address_owner.get(&(*addr, None)).or_else(|| {
            // Fall back to any zone when the caller did not supply one.
            self.address_owner
                .iter()
                .find(|((a, _), _)| a == addr)
                .map(|(_, owner)| owner)
        })
    }

    /// Folds one piece of evidence into the graph.
    pub fn absorb(&mut self, ev: TopologyEvidence) {
        let prov = Provenance::from_evidence(&ev);
        match ev.fact.clone() {
            Fact::Network { prefix } => {
                // Reaching here means a prefix was actually observed or advertised. The
                // Vlan arm below is the only other way a network-ish node appears, and it
                // deliberately cannot produce a prefix.
                self.upsert_network(prefix, ev.confidence, prov);
            }
            Fact::InterfaceNetwork { interface, prefix } => {
                // Same rule as the Network arm: loopback, link-local and multicast ranges
                // are protocol machinery, not networks. Filtering only there let them back
                // in through this path.
                if !self.upsert_network(prefix, ev.confidence, prov.clone()) {
                    return;
                }
                let iface_id = NodeId::Interface(interface);
                self.upsert(
                    iface_id.clone(),
                    NodeKind::Interface,
                    ev.confidence,
                    prov.clone(),
                );
                self.link(
                    iface_id,
                    NodeId::Network(prefix),
                    Relationship::AttachedTo,
                    ev.confidence,
                    prov,
                );
            }
            Fact::Vlan { id } => {
                let node_id = NodeId::Vlan(id);
                self.upsert(node_id, NodeKind::Vlan, ev.confidence, prov);
                self.vlans_without_prefix.insert(id);
            }
            Fact::DeviceAddress { device, address } => {
                let key = self.canonical_key(&device, Some(address));
                let id = NodeId::Device(key.clone());
                self.upsert(id.clone(), NodeKind::Host, ev.confidence, prov);
                // The evidence's vantage is the zone: a link-local address observed on
                // this interface belongs to this link and no other.
                let zone = if crate::topology::evidence::requires_zone(&address) {
                    Some(ev.vantage.to_ascii_lowercase())
                } else {
                    None
                };
                self.address_owner.insert((address, zone), key);
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.addresses.insert(address);
                }
            }
            Fact::DeviceHostname { device, hostname } => {
                let key = self.canonical_key(&device, None);
                let id = NodeId::Device(key);
                self.upsert(id.clone(), NodeKind::Host, ev.confidence, prov);
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.hostnames.insert(hostname);
                }
            }
            Fact::DeviceVendor { device, vendor } => {
                let key = self.canonical_key(&device, None);
                let id = NodeId::Device(key);
                self.upsert(id.clone(), NodeKind::Host, ev.confidence, prov);
                if let Some(node) = self.nodes.get_mut(&id) {
                    // Vendor is descriptive metadata only. It is never consulted by role
                    // scoring, because who manufactured a device says nothing about
                    // whether it routes.
                    node.vendor = Some(vendor);
                }
            }
            Fact::DeviceDescription { device, text } => {
                let key = self.canonical_key(&device, None);
                let id = NodeId::Device(key);
                self.upsert(id.clone(), NodeKind::Host, ev.confidence, prov);
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.descriptions.insert(text);
                }
            }
            Fact::DeviceRoleSignal { device, signal } => {
                let key = self.canonical_key(&device, None);
                let id = NodeId::Device(key);
                self.upsert(id.clone(), NodeKind::Host, ev.confidence, prov);
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.role_signals.insert(signal.describe());
                }
                self.role_weights
                    .entry(id)
                    .or_default()
                    .insert(signal.clone());
            }
            Fact::DeviceCapability {
                device,
                capability,
                detail,
            } => {
                let key = self.canonical_key(&device, None);
                let id = NodeId::Device(key);
                self.upsert(id.clone(), NodeKind::Host, ev.confidence, prov);
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.capabilities.insert(match detail {
                        Some(d) => format!("{} ({})", capability.label(), d),
                        None => capability.label().to_string(),
                    });
                }
            }
            Fact::GatewayFor { device, network } => {
                let key = self.canonical_key(&device, None);
                let dev_id = NodeId::Device(key);
                let net_id = NodeId::Network(network);
                self.upsert(dev_id.clone(), NodeKind::Host, ev.confidence, prov.clone());
                if !self.upsert_network(network, ev.confidence, prov.clone()) {
                    return;
                }
                self.link(
                    dev_id,
                    net_id,
                    Relationship::GatewayFor,
                    ev.confidence,
                    prov,
                );
            }
            Fact::RoutesTo {
                device,
                network,
                next_hop,
            } => {
                let key = self.canonical_key(&device, None);
                let dev_id = NodeId::Device(key);
                let net_id = NodeId::Network(network);
                self.upsert(dev_id.clone(), NodeKind::Host, ev.confidence, prov.clone());
                if !self.upsert_network(network, ev.confidence, prov.clone()) {
                    return;
                }
                self.link(
                    dev_id,
                    net_id,
                    Relationship::RoutesTo,
                    ev.confidence,
                    prov.clone(),
                );
                if let Some(hop) = next_hop {
                    let hop_key = self.canonical_key(&DeviceKey::Address(hop), Some(hop));
                    let hop_id = NodeId::Device(hop_key);
                    self.upsert(hop_id, NodeKind::Host, ev.confidence, prov);
                }
            }
            Fact::AttachedTo { device, network } => {
                let key = self.canonical_key(&device, None);
                let dev_id = NodeId::Device(key);
                let net_id = NodeId::Network(network);
                self.upsert(dev_id.clone(), NodeKind::Host, ev.confidence, prov.clone());
                if !self.upsert_network(network, ev.confidence, prov.clone()) {
                    return;
                }
                self.link(
                    dev_id,
                    net_id,
                    Relationship::AttachedTo,
                    ev.confidence,
                    prov,
                );
            }
            Fact::BridgeLink {
                bridge_id,
                root_id,
                port,
            } => {
                let bridge = NodeId::Device(DeviceKey::mac(&bridge_id));
                let root = NodeId::Device(DeviceKey::mac(&root_id));
                self.upsert(
                    bridge.clone(),
                    NodeKind::Switch,
                    ev.confidence,
                    prov.clone(),
                );
                self.upsert(root.clone(), NodeKind::Switch, ev.confidence, prov.clone());
                if bridge != root {
                    let mut p = prov.clone();
                    if let Some(port) = port {
                        p.detail = Some(match p.detail {
                            Some(d) => format!("{} (port {})", d, port),
                            None => format!("port {}", port),
                        });
                    }
                    self.link(bridge, root, Relationship::PossibleUplink, ev.confidence, p);
                }
            }
            Fact::ObservedBehind { device, via } => {
                let dev_id = NodeId::Device(self.canonical_key(&device, None));
                let via_id = NodeId::Device(self.canonical_key(&via, None));
                self.upsert(dev_id.clone(), NodeKind::Host, ev.confidence, prov.clone());
                self.upsert(via_id.clone(), NodeKind::Host, ev.confidence, prov.clone());
                self.link(
                    dev_id,
                    via_id,
                    Relationship::ObservedBehind,
                    ev.confidence,
                    prov,
                );
            }
            Fact::OpaqueBoundary { device, why } => {
                let key = self.canonical_key(&device, None);
                let id = NodeId::Device(key);
                self.upsert(id.clone(), NodeKind::Host, ev.confidence, prov);
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.opaque_reason = Some(why);
                }
            }
            Fact::Service {
                address,
                port,
                protocol,
                detail,
            } => {
                let id = NodeId::Service(address, port);
                self.upsert(id.clone(), NodeKind::Service, ev.confidence, prov.clone());
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.descriptions.insert(match detail {
                        Some(d) => format!("{}/{} {}", port, protocol, d),
                        None => format!("{}/{}", port, protocol),
                    });
                }
                if let Some(owner) = self.owner_of(&address, &ev.vantage) {
                    self.link(
                        NodeId::Device(owner),
                        id,
                        Relationship::Advertises,
                        ev.confidence,
                        prov,
                    );
                }
            }
            Fact::ResolvedAs { name, address } => {
                if let Some(owner) = self.owner_of(&address, &ev.vantage) {
                    let id = NodeId::Device(owner);
                    self.upsert(id.clone(), NodeKind::Host, ev.confidence, prov);
                    if let Some(node) = self.nodes.get_mut(&id) {
                        node.hostnames.insert(name);
                    }
                }
            }
        }
    }

    /// Folds address-keyed device nodes into the MAC-keyed node that owns the address.
    ///
    /// Providers learn about the same device at different times and with different
    /// identifiers: the kernel routing table yields a gateway address before the ARP cache
    /// yields its MAC. Without this pass the default gateway appears twice, once per
    /// identifier, splitting its evidence across two nodes.
    /// Folds address-keyed nodes into the MAC-keyed node that owns the same address.
    ///
    /// Public because the engine must run it before every interrogation pass, not only at
    /// the end. A device typically enters the graph twice -- once by address from a kernel
    /// route or DHCP lease, once by MAC from the neighbour cache -- and until they are
    /// merged the queue sees two devices and interrogates the same machine twice.
    /// Idempotent: a second call over an already-merged graph does nothing.
    ///
    /// Returns the aliases it created, absorbed identity first. The engine keys its
    /// interrogation ledger by device, so a device interrogated under an address key and
    /// later merged into a MAC key would otherwise look un-interrogated and be probed and
    /// reported a second time.
    pub fn merge_address_identities(&mut self) -> Vec<(DeviceKey, DeviceKey)> {
        let mut merges: Vec<(NodeId, NodeId)> = Vec::new();
        let mut aliases: Vec<(DeviceKey, DeviceKey)> = Vec::new();
        for id in self.nodes.keys() {
            let NodeId::Device(key) = id else {
                continue;
            };
            // Scoped identities merge too. A kernel route names its next hop by scoped
            // address while the neighbour cache names the same device by MAC; without this
            // the route's relationship stays stranded on a node of its own and the routed
            // network appears unattached to any router.
            let lookup = match key {
                DeviceKey::Address(addr) => Some((*addr, None)),
                DeviceKey::ScopedAddress(addr, zone) => Some((*addr, Some(zone.clone()))),
                DeviceKey::Mac(_) => None,
            };
            let Some(lookup) = lookup else {
                continue;
            };

            if let Some(owner) = self.address_owner.get(&lookup)
                && matches!(owner, DeviceKey::Mac(_))
            {
                merges.push((id.clone(), NodeId::Device(owner.clone())));
            }
        }

        for (from, to) in merges {
            if from == to || !self.nodes.contains_key(&to) {
                continue;
            }
            let Some(source) = self.nodes.remove(&from) else {
                continue;
            };
            if let (NodeId::Device(absorbed), NodeId::Device(surviving)) = (&from, &to) {
                aliases.push((absorbed.clone(), surviving.clone()));
            }

            if let Some(target) = self.nodes.get_mut(&to) {
                target.addresses.extend(source.addresses);
                target.hostnames.extend(source.hostnames);
                target.descriptions.extend(source.descriptions);
                target.role_signals.extend(source.role_signals);
                target.capabilities.extend(source.capabilities);
                target.provenance.extend(source.provenance);
                if target.vendor.is_none() {
                    target.vendor = source.vendor;
                }
                if target.opaque_reason.is_none() {
                    target.opaque_reason = source.opaque_reason;
                }
                if source.confidence > target.confidence {
                    target.confidence = source.confidence;
                }
            }

            if let Some(signals) = self.role_weights.remove(&from) {
                self.role_weights
                    .entry(to.clone())
                    .or_default()
                    .extend(signals);
            }

            // Re-point every edge that referenced the absorbed identity.
            let affected: Vec<(NodeId, NodeId, Relationship)> = self
                .edges
                .keys()
                .filter(|(f, t, _)| *f == from || *t == from)
                .cloned()
                .collect();
            for key in affected {
                let Some(mut edge) = self.edges.remove(&key) else {
                    continue;
                };
                if edge.from == from {
                    edge.from = to.clone();
                }
                if edge.to == from {
                    edge.to = to.clone();
                }
                if edge.from == edge.to {
                    continue;
                }
                self.edges
                    .entry((edge.from.clone(), edge.to.clone(), edge.relationship))
                    .and_modify(|existing| existing.provenance.extend(edge.provenance.clone()))
                    .or_insert(edge);
            }
        }

        aliases
    }

    /// Applies role scoring to every device node.
    ///
    /// Run after all evidence is absorbed so that corroborating signals gathered by
    /// different providers are weighed together rather than in arrival order.
    pub fn finalize_roles(&mut self) {
        let _ = self.merge_address_identities();

        let assignments: Vec<(NodeId, DeviceRole)> = self
            .role_weights
            .iter()
            .map(|(id, signals)| (id.clone(), score_role(signals)))
            .collect();

        for (id, role) in assignments {
            if let Some(node) = self.nodes.get_mut(&id) {
                node.kind = match role {
                    DeviceRole::Router => NodeKind::Router,
                    DeviceRole::Switch => NodeKind::Switch,
                    DeviceRole::Host => node.kind,
                };
            }
        }

        // A device that terminates visibility is presented as a boundary regardless of the
        // role it would otherwise take, because that is the operationally important fact.
        let opaque: Vec<NodeId> = self
            .nodes
            .values()
            .filter(|n| n.opaque_reason.is_some())
            .map(|n| n.id.clone())
            .collect();
        for id in opaque {
            if let Some(node) = self.nodes.get_mut(&id) {
                node.kind = NodeKind::OpaqueBoundary;
            }
        }
    }

    /// Marks a VLAN as having gained prefix evidence, so it stops being reported as unknown.
    pub fn attach_vlan_prefix(&mut self, vlan: u16) {
        self.vlans_without_prefix.remove(&vlan);
    }

    /// Chooses the canonical device key, merging address-only identities into a MAC when
    /// one is known for that address.
    ///
    /// A scoped identity resolves through its own zone: `fe80::1%en0` must never adopt the
    /// owner recorded for `fe80::1%eth1`, because they are different devices.
    fn canonical_key(&self, key: &DeviceKey, address: Option<IpAddr>) -> DeviceKey {
        match key {
            DeviceKey::Mac(_) => key.clone(),
            DeviceKey::Address(_) | DeviceKey::ScopedAddress(_, _) => {
                let zone = match key {
                    DeviceKey::ScopedAddress(_, zone) => Some(zone.clone()),
                    _ => None,
                };
                if let Some(addr) = key.address()
                    && let Some(owner) = self.address_owner.get(&(addr, zone.clone()))
                {
                    return owner.clone();
                }
                if let Some(addr) = address
                    && let Some(owner) = self.address_owner.get(&(addr, zone))
                {
                    return owner.clone();
                }
                key.clone()
            }
        }
    }

    /// Resolves who holds an address, honouring the zone when the address needs one.
    fn owner_of(&self, address: &IpAddr, vantage: &str) -> Option<DeviceKey> {
        let zone = if crate::topology::evidence::requires_zone(address) {
            Some(vantage.to_ascii_lowercase())
        } else {
            None
        };
        self.address_owner.get(&(*address, zone)).cloned()
    }

    fn upsert_network(&mut self, prefix: IpNet, confidence: Confidence, prov: Provenance) -> bool {
        if !is_topology_network(&prefix) {
            return false;
        }
        self.upsert(NodeId::Network(prefix), NodeKind::Network, confidence, prov);
        true
    }

    fn upsert(&mut self, id: NodeId, kind: NodeKind, confidence: Confidence, prov: Provenance) {
        let node = self
            .nodes
            .entry(id.clone())
            .or_insert_with(|| Node::new(id, kind, confidence));
        if confidence > node.confidence {
            node.confidence = confidence;
        }
        node.provenance.push(prov);
    }

    fn link(
        &mut self,
        from: NodeId,
        to: NodeId,
        relationship: Relationship,
        confidence: Confidence,
        prov: Provenance,
    ) {
        let edge = self
            .edges
            .entry((from.clone(), to.clone(), relationship))
            .or_insert_with(|| Edge {
                from,
                to,
                relationship,
                confidence,
                provenance: Vec::new(),
            });
        if confidence > edge.confidence {
            edge.confidence = confidence;
        }
        edge.provenance.push(prov);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::evidence::EvidenceSource;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn ev(fact: Fact, source: EvidenceSource, confidence: Confidence) -> TopologyEvidence {
        TopologyEvidence::new(fact, source, confidence, "test")
    }

    #[test]
    fn vlan_evidence_never_creates_a_network() {
        let mut g = TopologyGraph::new();
        g.absorb(ev(
            Fact::Vlan { id: 20 },
            EvidenceSource::Stp,
            Confidence::Observed,
        ));

        assert!(
            g.networks().is_empty(),
            "a VLAN tag must not produce a network prefix"
        );
        assert_eq!(g.vlans_without_prefix().collect::<Vec<_>>(), vec![20]);
    }

    #[test]
    fn addresses_merge_onto_one_device_via_mac() {
        // A router's LAN and WAN addresses must resolve to a single device, which is what
        // lets the graph show both sides of a NAT boundary as one box.
        let mut g = TopologyGraph::new();
        let mac = DeviceKey::mac("60:cf:84:37:1b:70");

        g.absorb(ev(
            Fact::DeviceAddress {
                device: mac.clone(),
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 125)),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        g.absorb(ev(
            Fact::DeviceAddress {
                device: mac.clone(),
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 51, 1)),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));

        let node = g.node(&NodeId::Device(mac)).expect("device node");
        assert_eq!(node.addresses.len(), 2);
    }

    #[test]
    fn vendor_alone_does_not_make_a_router() {
        let mut g = TopologyGraph::new();
        let mac = DeviceKey::mac("aa:bb:cc:dd:ee:ff");
        g.absorb(ev(
            Fact::DeviceVendor {
                device: mac.clone(),
                vendor: "ASUSTek Computer Inc.".to_string(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        g.finalize_roles();

        let node = g.node(&NodeId::Device(mac)).expect("device node");
        assert_eq!(
            node.kind,
            NodeKind::Host,
            "manufacturer must never imply an infrastructure role"
        );
    }

    #[test]
    fn corroborated_signals_promote_a_router() {
        let mut g = TopologyGraph::new();
        let mac = DeviceKey::mac("11:22:33:44:55:66");
        for signal in [RoleSignal::DefaultGateway, RoleSignal::DhcpRouter] {
            g.absorb(ev(
                Fact::DeviceRoleSignal {
                    device: mac.clone(),
                    signal,
                },
                EvidenceSource::DefaultGateway,
                Confidence::Observed,
            ));
        }
        g.finalize_roles();

        let node = g.node(&NodeId::Device(mac)).expect("device node");
        assert_eq!(node.kind, NodeKind::Router);
    }

    #[test]
    fn a_routed_ipv6_subnet_links_to_the_device_owning_its_gateway() {
        // The end-to-end shape of the real evidence on en0:
        //   fd84:3bfe:bf84::/64 via fe80::1812:faa5:e4ee:1b9%en0
        // where that link-local address belongs to 507-Appt-Room.
        let mut g = TopologyGraph::new();
        let router_mac = DeviceKey::mac("c4:f7:c1:0b:7c:69");
        let gateway: IpAddr = "fe80::1812:faa5:e4ee:1b9".parse().unwrap();
        let routed: IpNet = "fd84:3bfe:bf84::/64".parse().unwrap();

        // The neighbour cache binds the link-local address to the router's MAC.
        g.absorb(ev(
            Fact::DeviceAddress {
                device: router_mac.clone(),
                address: gateway,
            },
            EvidenceSource::NdpCache,
            Confidence::Observed,
        ));
        // Its own routable address, and the name it answers to.
        g.absorb(ev(
            Fact::DeviceHostname {
                device: router_mac.clone(),
                hostname: "507-Appt-Room".to_string(),
            },
            EvidenceSource::Mdns,
            Confidence::Observed,
        ));
        // The kernel route, keyed by the scoped gateway address as the provider emits it.
        g.absorb(ev(
            Fact::RoutesTo {
                device: DeviceKey::scoped_address(gateway, Some("test")),
                network: routed,
                next_hop: Some(gateway),
            },
            EvidenceSource::KernelRoute,
            Confidence::Observed,
        ));
        g.finalize_roles();

        assert!(
            g.networks().contains(&routed),
            "the routed IPv6 subnet must become a network node"
        );

        // The RoutesTo edge must land on the MAC-keyed router, not a second node.
        let router = NodeId::Device(router_mac);
        let linked = g.edges().any(|e| {
            e.relationship == Relationship::RoutesTo
                && e.from == router
                && e.to == NodeId::Network(routed)
        });
        assert!(
            linked,
            "the subnet must be linked through the device that owns the gateway address"
        );

        let node = g.node(&router).expect("router node");
        assert!(node.hostnames.contains("507-Appt-Room"));
    }

    #[test]
    fn link_local_identities_stay_interface_scoped() {
        // fe80::1 exists on almost every link. Keying it globally merged unrelated routers
        // from different interfaces into one node.
        let mut g = TopologyGraph::new();
        let addr: IpAddr = "fe80::1".parse().unwrap();

        g.absorb(TopologyEvidence::new(
            Fact::DeviceAddress {
                device: DeviceKey::mac("aa:aa:aa:00:00:01"),
                address: addr,
            },
            EvidenceSource::NdpCache,
            Confidence::Observed,
            "en0",
        ));
        g.absorb(TopologyEvidence::new(
            Fact::DeviceAddress {
                device: DeviceKey::mac("bb:bb:bb:00:00:02"),
                address: addr,
            },
            EvidenceSource::NdpCache,
            Confidence::Observed,
            "eth1",
        ));

        let holders = g.nodes().filter(|n| n.addresses.contains(&addr)).count();
        assert_eq!(
            holders, 2,
            "the same link-local address on two links is two devices"
        );
    }

    #[test]
    fn an_address_never_migrates_between_two_macs() {
        // A neighbour solicitation once attributed the queried host's address to the
        // sender, which merged unrelated devices. Identity must follow the MAC.
        let mut g = TopologyGraph::new();
        let a = DeviceKey::mac("aa:aa:aa:00:00:01");
        let b = DeviceKey::mac("bb:bb:bb:00:00:02");
        let addr: IpAddr = "fdc5::42".parse().unwrap();

        g.absorb(ev(
            Fact::DeviceAddress {
                device: a.clone(),
                address: addr,
            },
            EvidenceSource::NdpCache,
            Confidence::Observed,
        ));
        g.absorb(ev(
            Fact::DeviceAddress {
                device: b.clone(),
                address: "fdc5::99".parse().unwrap(),
            },
            EvidenceSource::NdpCache,
            Confidence::Observed,
        ));
        g.finalize_roles();

        let node_b = g.node(&NodeId::Device(b)).expect("second device");
        assert!(
            !node_b.addresses.contains(&addr),
            "one device's address must never appear on another"
        );
    }

    #[test]
    fn a_vendor_hint_schedules_interrogation_without_asserting_a_role() {
        // The ASUS case. Previously this device was never interrogated, because only
        // devices that already had router evidence were queued, and it had none.
        let mut g = TopologyGraph::new();
        let mac = DeviceKey::mac("60:cf:84:37:1b:70");

        g.absorb(ev(
            Fact::DeviceAddress {
                device: mac.clone(),
                address: "192.168.1.125".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        g.absorb(ev(
            Fact::DeviceVendor {
                device: mac.clone(),
                vendor: "ASUSTek Computer".to_string(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        g.finalize_roles();

        // It must be queued for interrogation...
        assert!(
            g.candidate_addresses()
                .contains(&"192.168.1.125".parse().unwrap()),
            "a networking manufacturer must schedule interrogation"
        );
        // ...but must not have become a pivot, which requires positive evidence.
        assert!(g.pivot_addresses().is_empty());
        // ...and must still be an unclassified host.
        assert_eq!(
            g.node(&NodeId::Device(mac)).unwrap().kind,
            NodeKind::Host,
            "a manufacturer must never establish a role"
        );
    }

    #[test]
    fn an_established_pivot_is_not_repeated_as_a_candidate() {
        let mut g = TopologyGraph::new();
        let mac = DeviceKey::mac("74:12:13:14:75:dc");
        g.absorb(ev(
            Fact::DeviceAddress {
                device: mac.clone(),
                address: "192.168.1.1".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        g.absorb(ev(
            Fact::DeviceRoleSignal {
                device: mac,
                signal: RoleSignal::DefaultGateway,
            },
            EvidenceSource::DefaultGateway,
            Confidence::Observed,
        ));
        g.finalize_roles();

        let gateway: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(g.pivot_addresses().contains(&gateway));
        assert!(
            !g.candidate_addresses().contains(&gateway),
            "an established pivot must not be queued twice"
        );
    }

    #[test]
    fn hostname_hints_match_whole_tokens_only() {
        // The exact false positive this replaces: a desk fan was treated as an access
        // point because "miapD143" contains the letters "ap".
        assert!(!hostname_suggests_infrastructure("dmaker-fan-p30_miapD143"));
        assert!(!hostname_suggests_infrastructure("grape-pi"));
        assert!(!hostname_suggests_infrastructure("laptop-7"));

        assert!(hostname_suggests_infrastructure("office-ap-3"));
        assert!(hostname_suggests_infrastructure("AP1"));
        assert!(hostname_suggests_infrastructure("core.router.lan"));
        assert!(hostname_suggests_infrastructure("main_gateway"));
        assert!(hostname_suggests_infrastructure("access-point-lobby"));
    }

    #[test]
    fn a_fan_is_not_an_infrastructure_candidate() {
        let mut g = TopologyGraph::new();
        let mac = DeviceKey::mac("7c:c2:94:a1:d1:43");
        g.absorb(ev(
            Fact::DeviceAddress {
                device: mac.clone(),
                address: "192.168.1.166".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        g.absorb(ev(
            Fact::DeviceHostname {
                device: mac,
                hostname: "dmaker-fan-p30_miapD143".to_string(),
            },
            EvidenceSource::Mdns,
            Confidence::Observed,
        ));
        g.finalize_roles();

        assert!(
            g.candidate_addresses().is_empty(),
            "a desk fan must not consume interrogation budget"
        );
    }

    #[test]
    fn an_ordinary_endpoint_is_not_a_candidate() {
        let mut g = TopologyGraph::new();
        let mac = DeviceKey::mac("04:e4:b6:db:57:98");
        g.absorb(ev(
            Fact::DeviceAddress {
                device: mac.clone(),
                address: "192.168.1.130".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        g.absorb(ev(
            Fact::DeviceVendor {
                device: mac,
                vendor: "Samsung Electronics".to_string(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        g.finalize_roles();

        assert!(
            g.candidate_addresses().is_empty(),
            "a consumer endpoint should not consume interrogation budget"
        );
    }

    #[test]
    fn categories_are_mutually_exclusive_and_sum_to_the_device_total() {
        let mut g = TopologyGraph::new();

        // A router that also hosts an AI runtime.
        let router = DeviceKey::mac("aa:00:00:00:00:01");
        g.absorb(ev(
            Fact::DeviceRoleSignal {
                device: router.clone(),
                signal: RoleSignal::DefaultGateway,
            },
            EvidenceSource::DefaultGateway,
            Confidence::Observed,
        ));
        g.absorb(ev(
            Fact::DeviceCapability {
                device: router,
                capability: crate::topology::evidence::Capability::AiRuntime,
                detail: Some("Ollama".to_string()),
            },
            EvidenceSource::AiProtocol,
            Confidence::Observed,
        ));

        // A plain host with a confirmed AI runtime.
        let ai_host = DeviceKey::mac("bb:00:00:00:00:02");
        g.absorb(ev(
            Fact::DeviceCapability {
                device: ai_host,
                capability: crate::topology::evidence::Capability::AiRuntime,
                detail: Some("Ollama".to_string()),
            },
            EvidenceSource::AiProtocol,
            Confidence::Observed,
        ));

        // An ordinary host.
        g.absorb(ev(
            Fact::DeviceAddress {
                device: DeviceKey::mac("cc:00:00:00:00:03"),
                address: "10.0.0.9".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        g.finalize_roles();

        let counts = g.counts();
        assert_eq!(counts.routers, 1);
        assert_eq!(
            counts.ai_systems, 1,
            "only the non-infrastructure AI device"
        );
        assert_eq!(counts.other_hosts, 1);
        assert_eq!(counts.devices(), 3, "each device counted exactly once");

        // The router hosting AI stays under routers and is not double counted.
        assert!(has_confirmed_ai(g.devices_in(DeviceCategory::Router)[0]));
        assert_eq!(g.devices_in(DeviceCategory::AiSystem).len(), 1);
    }

    #[test]
    fn an_open_conventional_port_does_not_make_an_ai_system() {
        // 11434 open is not Ollama confirmed; only a protocol response qualifies.
        let mut g = TopologyGraph::new();
        let mac = DeviceKey::mac("dd:00:00:00:00:04");
        g.absorb(ev(
            Fact::DeviceAddress {
                device: mac,
                address: "10.0.0.11".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        g.absorb(ev(
            Fact::Service {
                address: "10.0.0.11".parse().unwrap(),
                port: 11434,
                protocol: "tcp",
                detail: None,
            },
            EvidenceSource::TcpProbe,
            Confidence::Observed,
        ));
        g.finalize_roles();

        let counts = g.counts();
        assert_eq!(counts.ai_systems, 0);
        assert_eq!(counts.other_hosts, 1);
    }

    #[test]
    fn graph_node_total_exceeds_the_device_total() {
        // The graph holds networks, interfaces and services too, which is exactly why the
        // two figures differ and why both are reported.
        let mut g = TopologyGraph::new();
        g.absorb(ev(
            Fact::Network {
                prefix: IpNet::from_str("10.0.0.0/24").unwrap(),
            },
            EvidenceSource::KernelRoute,
            Confidence::Observed,
        ));
        g.absorb(ev(
            Fact::DeviceAddress {
                device: DeviceKey::mac("ee:00:00:00:00:05"),
                address: "10.0.0.20".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        g.finalize_roles();

        let counts = g.counts();
        assert_eq!(counts.devices(), 1);
        assert_eq!(counts.networks, 1);
        assert_eq!(counts.graph_nodes, 2);
        assert!(counts.graph_nodes > counts.devices());
    }

    #[test]
    fn network_requires_prefix_evidence() {
        let mut g = TopologyGraph::new();
        g.absorb(ev(
            Fact::Network {
                prefix: IpNet::from_str("10.20.0.0/16").unwrap(),
            },
            EvidenceSource::KernelRoute,
            Confidence::Observed,
        ));
        assert_eq!(g.networks().len(), 1);
    }

    #[test]
    fn opaque_boundary_overrides_role_presentation() {
        let mut g = TopologyGraph::new();
        let mac = DeviceKey::mac("de:ad:be:ef:00:01");
        g.absorb(ev(
            Fact::DeviceRoleSignal {
                device: mac.clone(),
                signal: RoleSignal::DefaultGateway,
            },
            EvidenceSource::DefaultGateway,
            Confidence::Observed,
        ));
        g.absorb(ev(
            Fact::OpaqueBoundary {
                device: mac.clone(),
                why: "NAT; downstream not observable".to_string(),
            },
            EvidenceSource::IcmpProbe,
            Confidence::Observed,
        ));
        g.finalize_roles();

        let node = g.node(&NodeId::Device(mac)).expect("device node");
        assert_eq!(node.kind, NodeKind::OpaqueBoundary);
    }
}
