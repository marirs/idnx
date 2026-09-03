//! The common evidence record every discovery provider emits.
//!
//! Providers never mutate the topology graph directly. They return
//! [`TopologyEvidence`], and the graph decides what that evidence supports. This is what
//! makes a print-only provider structurally impossible: emitting evidence is the only way
//! for a provider to report anything at all.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

use ipnet::IpNet;

/// How much weight a single fact carries.
///
/// This grades one fact, not a whole device. A captured advertisement is `Observed`
/// evidence that a device transmitted a frame, while the contents of that frame are
/// `Advertised`: the device asserted them and we have not confirmed them independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Derived by assumption rather than observation. Always labelled as such.
    Inferred,
    /// A device asserted it (an RA prefix, an LLDP system name, an SNMP route entry).
    /// We believe the device; we have not verified the claim ourselves.
    Advertised,
    /// The operator supplied it on the command line.
    UserSupplied,
    /// We saw it directly: a frame on the wire, a kernel table entry, a live response.
    Observed,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Inferred => "inferred",
            Confidence::Advertised => "advertised",
            Confidence::UserSupplied => "user-supplied",
            Confidence::Observed => "observed",
        }
    }

    /// Compact marker so the grade is visible in dense output without a legend.
    pub fn marker(&self) -> &'static str {
        match self {
            Confidence::Inferred => "~",
            Confidence::Advertised => "+",
            Confidence::UserSupplied => "=",
            Confidence::Observed => "*",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Where a fact came from.
///
/// Deliberately protocol-level rather than vendor-level: no vendor is privileged, and a
/// proprietary discovery protocol is just another source alongside DHCP or LLDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EvidenceSource {
    InterfaceAddress,
    KernelRoute,
    DefaultGateway,
    ResolverConfig,
    DhcpLease,
    ArpCache,
    NdpCache,
    IcmpProbe,
    TcpProbe,
    Mdns,
    UnicastDns,
    Ssdp,
    Nbns,
    Llmnr,
    Mndp,
    Lldp,
    Cdp,
    Stp,
    RouterAdvertisement,
    Snmp,
    /// A RIP routing update, heard on the link or returned to a direct request.
    Rip,
    VendorDiscovery,
    /// NAT-PMP / PCP gateway response.
    NatPmp,
    /// An AI runtime's own protocol endpoint.
    AiProtocol,
    /// A negotiated Model Context Protocol session.
    Mcp,
    UserSupplied,
}

impl EvidenceSource {
    pub fn label(&self) -> &'static str {
        match self {
            EvidenceSource::InterfaceAddress => "interface address",
            EvidenceSource::KernelRoute => "kernel route",
            EvidenceSource::DefaultGateway => "default gateway",
            EvidenceSource::ResolverConfig => "resolver config",
            EvidenceSource::DhcpLease => "DHCP lease",
            EvidenceSource::ArpCache => "ARP cache",
            EvidenceSource::NdpCache => "NDP cache",
            EvidenceSource::IcmpProbe => "ICMP probe",
            EvidenceSource::TcpProbe => "TCP probe",
            EvidenceSource::Mdns => "mDNS",
            EvidenceSource::UnicastDns => "unicast DNS",
            EvidenceSource::Ssdp => "SSDP/UPnP",
            EvidenceSource::Nbns => "NBNS",
            EvidenceSource::Llmnr => "LLMNR",
            EvidenceSource::Mndp => "MNDP",
            EvidenceSource::Lldp => "LLDP",
            EvidenceSource::Cdp => "CDP",
            EvidenceSource::Stp => "STP/BPDU",
            EvidenceSource::RouterAdvertisement => "IPv6 router advertisement",
            EvidenceSource::Snmp => "SNMP",
            EvidenceSource::Rip => "RIP",
            EvidenceSource::VendorDiscovery => "vendor discovery",
            EvidenceSource::NatPmp => "NAT-PMP",
            EvidenceSource::AiProtocol => "AI runtime protocol",
            EvidenceSource::Mcp => "MCP (negotiated)",
            EvidenceSource::UserSupplied => "user supplied",
        }
    }

    /// True when the source requires elevated privileges to obtain.
    pub fn needs_privilege(&self) -> bool {
        matches!(
            self,
            EvidenceSource::Lldp | EvidenceSource::Cdp | EvidenceSource::Stp
        )
    }
}

impl fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Stable identity for a physical or logical device.
///
/// A MAC identifies a device across every address it holds, which is what lets the graph
/// recognise a router's LAN and WAN addresses as one device. An address-only key is the
/// fallback for devices seen across a routing boundary, where no MAC is available.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DeviceKey {
    Mac(String),
    Address(IpAddr),
    /// An address that is only meaningful inside a zone.
    ///
    /// `fe80::1%en0` and `fe80::1%eth1` are different devices on different links. Keying
    /// link-local addresses globally would merge them into one node.
    ScopedAddress(IpAddr, String),
}

impl DeviceKey {
    pub fn mac(raw: &str) -> Self {
        DeviceKey::Mac(raw.to_ascii_lowercase())
    }

    /// Builds an address identity, attaching the zone only where it actually disambiguates.
    ///
    /// A globally unique address needs no zone; a link-local one is meaningless without it.
    pub fn scoped_address(addr: IpAddr, zone: Option<&str>) -> Self {
        match (requires_zone(&addr), zone) {
            (true, Some(zone)) => DeviceKey::ScopedAddress(addr, zone.to_ascii_lowercase()),
            _ => DeviceKey::Address(addr),
        }
    }

    /// The address this key refers to, if it is address-based.
    pub fn address(&self) -> Option<IpAddr> {
        match self {
            DeviceKey::Address(a) | DeviceKey::ScopedAddress(a, _) => Some(*a),
            DeviceKey::Mac(_) => None,
        }
    }
}

/// True when an address is ambiguous without an interface zone.
pub fn requires_zone(addr: &IpAddr) -> bool {
    match addr {
        // IPv4 link-local is not zoned in practice on a single-homed scope.
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => {
            // fe80::/10 link-local, and ff02::/16 link-local multicast.
            (v6.segments()[0] & 0xffc0) == 0xfe80 || (v6.segments()[0] & 0xff0f) == 0xff02
        }
    }
}

impl fmt::Display for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceKey::Mac(m) => write!(f, "{}", m),
            DeviceKey::Address(a) => write!(f, "{}", a),
            DeviceKey::ScopedAddress(a, zone) => write!(f, "{}%{}", a, zone),
        }
    }
}

/// Behaviour that argues a device performs a network-infrastructure role.
///
/// Roles are scored from corroborated behaviour. A manufacturer OUI is explicitly not on
/// this list: it identifies who built the hardware and nothing about what the device does.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RoleSignal {
    /// This machine's default gateway.
    DefaultGateway,
    /// Handed out a DHCP lease, or was named as the router in one.
    DhcpRouter,
    /// Sent IPv6 router advertisements, or is flagged isRouter in the neighbour table.
    RouterAdvertisement,
    /// LLDP/CDP capability bits claiming router or bridge function.
    LinkLayerCapability(&'static str),
    /// Advertised a UPnP InternetGatewayDevice.
    InternetGatewayDevice,
    /// Answered SNMP with IP forwarding enabled, or returned a routing table.
    SnmpForwarding,
    /// Appeared as an intermediate hop on a path, so it forwarded our traffic.
    ObservedForwarding,
    /// The OS installed a route to a network through this device.
    ///
    /// Unambiguous: the kernel records a next hop because the device advertised itself as
    /// the way to reach that prefix. It stands on its own, unlike a management surface.
    KernelNextHop,
    /// Emitted spanning-tree BPDUs, which only a bridge does.
    SpanningTreeBridge,
    /// Serves DNS and a web management interface: the common SOHO router shape.
    ManagementSurface,
}

impl RoleSignal {
    /// Weight toward a router/switch classification.
    ///
    /// Scoring is explicit so that a single weak signal can never promote a device on its
    /// own; the threshold in `role.rs` requires corroboration.
    pub fn weight(&self) -> u32 {
        match self {
            RoleSignal::DefaultGateway => 100,
            RoleSignal::SnmpForwarding => 90,
            RoleSignal::SpanningTreeBridge => 90,
            RoleSignal::InternetGatewayDevice => 80,
            RoleSignal::DhcpRouter => 80,
            RoleSignal::RouterAdvertisement => 70,
            RoleSignal::LinkLayerCapability(_) => 70,
            RoleSignal::KernelNextHop => 70,
            RoleSignal::ObservedForwarding => 60,
            RoleSignal::ManagementSurface => 30,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            RoleSignal::DefaultGateway => "is this machine's default gateway".to_string(),
            RoleSignal::DhcpRouter => "acts as a DHCP router or server".to_string(),
            RoleSignal::RouterAdvertisement => {
                "advertises itself as an IPv6 router (RFC 4861)".to_string()
            }
            RoleSignal::LinkLayerCapability(c) => {
                format!("LLDP/CDP capability: {}", c)
            }
            RoleSignal::InternetGatewayDevice => {
                "advertises a UPnP InternetGatewayDevice".to_string()
            }
            RoleSignal::SnmpForwarding => "SNMP reports IP forwarding".to_string(),
            RoleSignal::ObservedForwarding => "observed forwarding traffic on a path".to_string(),
            RoleSignal::KernelNextHop => {
                "is the kernel's next hop for a routed network".to_string()
            }
            RoleSignal::SpanningTreeBridge => "emits spanning-tree BPDUs".to_string(),
            RoleSignal::ManagementSurface => {
                "serves DNS and a web management interface".to_string()
            }
        }
    }
}

/// Something a device was observed to *do*, independent of what it is.
///
/// Roles collapse a device into one word; capabilities do not. A device can route IPv6,
/// bridge, serve DHCP and host an AI runtime at once, and an Apple IoT device acting as a
/// Thread border router genuinely routes IPv6 without being the Internet gateway.
/// Reporting capabilities keeps those distinctions instead of flattening them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    DefaultGateway,
    Ipv4Forwarding,
    Ipv6Router,
    NatGateway,
    DhcpServer,
    DnsServer,
    Bridge,
    WirelessAp,
    ManagementInterface,
    AiRuntime,
    AiAgent,
    McpServer,
}

impl Capability {
    pub fn label(&self) -> &'static str {
        match self {
            Capability::DefaultGateway => "default gateway",
            Capability::Ipv4Forwarding => "IPv4 forwarding",
            Capability::Ipv6Router => "IPv6 router",
            Capability::NatGateway => "NAT gateway",
            Capability::DhcpServer => "DHCP server",
            Capability::DnsServer => "DNS server",
            Capability::Bridge => "bridge",
            Capability::WirelessAp => "wireless AP",
            Capability::ManagementInterface => "management interface",
            Capability::AiRuntime => "AI runtime",
            Capability::AiAgent => "AI agent",
            Capability::McpServer => "MCP server",
        }
    }
}

/// A single normalized fact produced by a provider.
#[derive(Debug, Clone)]
pub enum Fact {
    /// A network exists, backed by prefix-bearing evidence.
    ///
    /// Only emitted when a real prefix was observed or advertised. A VLAN tag alone never
    /// produces one of these.
    Network { prefix: IpNet },

    /// A VLAN ID was observed. The prefix is deliberately absent unless separate
    /// prefix-bearing evidence arrives for it.
    Vlan { id: u16 },

    /// A local interface carries a network. Establishes which networks are reached through
    /// which link, which is how virtual and VPN plumbing is told apart from physical
    /// topology at render time.
    InterfaceNetwork { interface: String, prefix: IpNet },

    /// A device holds an address.
    DeviceAddress { device: DeviceKey, address: IpAddr },

    /// A device has a hostname.
    DeviceHostname { device: DeviceKey, hostname: String },

    /// A device's hardware vendor, from its OUI. Descriptive only; never a role.
    DeviceVendor { device: DeviceKey, vendor: String },

    /// Free-form model/description text a device published about itself.
    DeviceDescription { device: DeviceKey, text: String },

    /// Behaviour arguing the device performs an infrastructure role.
    DeviceRoleSignal {
        device: DeviceKey,
        signal: RoleSignal,
    },

    /// Something the device was observed doing, carried alongside its role rather than
    /// collapsed into it.
    DeviceCapability {
        device: DeviceKey,
        capability: Capability,
        /// What established the capability, in the operator's words.
        detail: Option<String>,
    },

    /// A device is the gateway for a network.
    GatewayFor { device: DeviceKey, network: IpNet },

    /// A device routes toward a network, optionally through a next hop.
    RoutesTo {
        device: DeviceKey,
        network: IpNet,
        next_hop: Option<IpAddr>,
    },

    /// A device is attached to a network.
    AttachedTo { device: DeviceKey, network: IpNet },

    /// Two bridges are related by spanning tree.
    BridgeLink {
        bridge_id: String,
        root_id: String,
        port: Option<String>,
    },

    /// A device is reachable only through another, which forwards for it.
    ObservedBehind { device: DeviceKey, via: DeviceKey },

    /// An interface forwarded a probe toward a destination, at a measured distance.
    ///
    /// The complete finding, kept together because the parts are meaningless apart: an
    /// interface forwards *toward something*, from *one vantage*, at *one distance*, and a
    /// different destination may take a different path. It establishes that the interface
    /// forwards IPv4 and nothing else -- not a prefix, not opacity, not ownership.
    ForwardsToward {
        device: DeviceKey,
        /// Where the probe was headed.
        toward: IpAddr,
        /// Hop distance. 1 is this machine's default gateway.
        distance: u8,
        /// The previous responding hop, when one answered.
        previous: Option<DeviceKey>,
    },

    /// A device terminates visibility: it forwards, but nothing behind it is observable.
    OpaqueBoundary { device: DeviceKey, why: String },

    /// A service is exposed on an address.
    Service {
        address: IpAddr,
        port: u16,
        protocol: &'static str,
        detail: Option<String>,
    },

    /// A name resolves to an address.
    ResolvedAs { name: String, address: IpAddr },
}

/// One fact plus the provenance required to justify it.
#[derive(Debug, Clone)]
pub struct TopologyEvidence {
    pub fact: Fact,
    pub source: EvidenceSource,
    pub confidence: Confidence,
    /// Which vantage observed it.
    pub vantage: String,
    pub observed_at: SystemTime,
    /// Human-readable justification, rendered by the explain view.
    pub detail: Option<String>,
    /// The peer that asserted this, when it did not come from this machine.
    ///
    /// `None` means locally observed. Carried on the record itself rather than tracked
    /// alongside, because a fact merged from a peer must remain distinguishable from one
    /// this vantage saw for as long as it exists -- including after it has been folded into
    /// a node that also holds local evidence.
    pub origin: Option<PeerOrigin>,
}

/// Where a remote fact came from.
///
/// Enough to attribute the claim and to reproduce the receiver's decision: which peer, from
/// which of its vantages, in which bundle, and when the peer said it observed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerOrigin {
    /// The peer's public key, hex. Full, not truncated: a short form is for display only.
    pub peer: String,
    /// The peer's own name for the interface it observed from.
    pub vantage: String,
    /// Sequence number of the bundle this arrived in.
    pub sequence: u64,
    /// Seconds since the epoch, as the peer's clock reported.
    pub published_at: u64,
}

impl PeerOrigin {
    /// Short form for display.
    pub fn short(&self) -> String {
        let peer = if self.peer.len() > 16 {
            &self.peer[..16]
        } else {
            &self.peer
        };
        format!("peer {peer} via {}", self.vantage)
    }
}

impl TopologyEvidence {
    pub fn new(
        fact: Fact,
        source: EvidenceSource,
        confidence: Confidence,
        vantage: impl Into<String>,
    ) -> Self {
        Self {
            fact,
            source,
            confidence,
            vantage: vantage.into(),
            observed_at: SystemTime::now(),
            detail: None,
            origin: None,
        }
    }

    /// Marks this record as asserted by a peer rather than observed here.
    pub fn from_peer(mut self, origin: PeerOrigin) -> Self {
        self.origin = Some(origin);
        self
    }

    /// Whether this came from another machine.
    pub fn is_remote(&self) -> bool {
        self.origin.is_some()
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Convenience for the common case of an IPv4 host address.
pub fn v4(addr: Ipv4Addr) -> IpAddr {
    IpAddr::V4(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn confidence_orders_observed_above_inferred() {
        assert!(Confidence::Inferred < Confidence::Advertised);
        assert!(Confidence::Advertised < Confidence::UserSupplied);
        assert!(Confidence::UserSupplied < Confidence::Observed);
    }

    #[test]
    fn device_key_mac_is_case_insensitive() {
        // The same NIC must not become two devices because two sources disagreed on case.
        assert_eq!(
            DeviceKey::mac("AA:BB:CC:00:11:22"),
            DeviceKey::mac("aa:bb:cc:00:11:22")
        );
    }

    #[test]
    fn a_single_weak_signal_scores_below_a_strong_one() {
        // Corroboration matters: a management surface alone must not outweigh being the
        // observed default gateway.
        assert!(RoleSignal::ManagementSurface.weight() < RoleSignal::DefaultGateway.weight());
    }

    #[test]
    fn vlan_fact_carries_no_prefix() {
        // Guards the rule that a VLAN tag proves only the VLAN ID.
        let fact = Fact::Vlan { id: 20 };
        match fact {
            Fact::Vlan { id } => assert_eq!(id, 20),
            _ => panic!("expected a VLAN fact"),
        }
    }

    #[test]
    fn network_fact_requires_an_explicit_prefix() {
        let fact = Fact::Network {
            prefix: IpNet::from_str("10.20.0.0/16").unwrap(),
        };
        match fact {
            Fact::Network { prefix } => assert_eq!(prefix.prefix_len(), 16),
            _ => panic!("expected a network fact"),
        }
    }
}
