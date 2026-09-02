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
            opaque_reason: None,
            confidence,
            provenance: Vec::new(),
        }
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
    address_owner: HashMap<IpAddr, DeviceKey>,
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

    /// Resolves the canonical device key for an address, if one is already known.
    pub fn device_for_address(&self, addr: &IpAddr) -> Option<&DeviceKey> {
        self.address_owner.get(addr)
    }

    /// Folds one piece of evidence into the graph.
    pub fn absorb(&mut self, ev: TopologyEvidence) {
        let prov = Provenance::from_evidence(&ev);
        match ev.fact.clone() {
            Fact::Network { prefix } => {
                // Reaching here means a prefix was actually observed or advertised. The
                // Vlan arm below is the only other way a network-ish node appears, and it
                // deliberately cannot produce a prefix.
                let id = NodeId::Network(prefix);
                self.upsert(id, NodeKind::Network, ev.confidence, prov);
            }
            Fact::InterfaceNetwork { interface, prefix } => {
                let iface_id = NodeId::Interface(interface);
                let net_id = NodeId::Network(prefix);
                self.upsert(
                    iface_id.clone(),
                    NodeKind::Interface,
                    ev.confidence,
                    prov.clone(),
                );
                self.upsert(
                    net_id.clone(),
                    NodeKind::Network,
                    ev.confidence,
                    prov.clone(),
                );
                self.link(
                    iface_id,
                    net_id,
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
                self.address_owner.insert(address, key);
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
            Fact::GatewayFor { device, network } => {
                let key = self.canonical_key(&device, None);
                let dev_id = NodeId::Device(key);
                let net_id = NodeId::Network(network);
                self.upsert(dev_id.clone(), NodeKind::Host, ev.confidence, prov.clone());
                self.upsert(
                    net_id.clone(),
                    NodeKind::Network,
                    ev.confidence,
                    prov.clone(),
                );
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
                self.upsert(
                    net_id.clone(),
                    NodeKind::Network,
                    ev.confidence,
                    prov.clone(),
                );
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
                self.upsert(
                    net_id.clone(),
                    NodeKind::Network,
                    ev.confidence,
                    prov.clone(),
                );
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
                if let Some(owner) = self.address_owner.get(&address).cloned() {
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
                if let Some(owner) = self.address_owner.get(&address).cloned() {
                    let id = NodeId::Device(owner);
                    self.upsert(id.clone(), NodeKind::Host, ev.confidence, prov);
                    if let Some(node) = self.nodes.get_mut(&id) {
                        node.hostnames.insert(name);
                    }
                }
            }
        }
    }

    /// Applies role scoring to every device node.
    ///
    /// Run after all evidence is absorbed so that corroborating signals gathered by
    /// different providers are weighed together rather than in arrival order.
    pub fn finalize_roles(&mut self) {
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
    fn canonical_key(&self, key: &DeviceKey, address: Option<IpAddr>) -> DeviceKey {
        match key {
            DeviceKey::Mac(_) => key.clone(),
            DeviceKey::Address(addr) => {
                self.address_owner
                    .get(addr)
                    .cloned()
                    .unwrap_or_else(|| match address {
                        Some(a) => self
                            .address_owner
                            .get(&a)
                            .cloned()
                            .unwrap_or_else(|| key.clone()),
                        None => key.clone(),
                    })
            }
        }
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
