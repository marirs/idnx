//! The federation wire format.
//!
//! Peers exchange **evidence**, not finished graphs. A graph is one peer's conclusions;
//! evidence is what it observed, and only evidence can be re-weighed against what the
//! receiver already knows. Merging conclusions would mean accepting another peer's role
//! scoring, its confidence grades and its identity decisions wholesale, and would make a
//! remote assertion indistinguishable from a local observation.
//!
//! Deliberately a separate type from [`TopologyEvidence`] rather than a derive on it. The
//! internal model is free to change; the wire format is versioned and must not. It also
//! rejects what it does not understand instead of guessing: an unknown fact kind from a
//! newer peer is dropped with a reason, never coerced into the nearest known variant.

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::topology::TopologyEvidence;
use crate::topology::evidence::{
    Capability, Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal,
};

/// Wire format version.
///
/// Incremented when the meaning of an existing field changes. A receiver refuses a bundle
/// it cannot interpret rather than reading it partially.
pub const SCHEMA_VERSION: u16 = 1;

/// One fact, in its wire form.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireFact {
    Network {
        prefix: String,
    },
    Vlan {
        id: u16,
    },
    InterfaceNetwork {
        interface: String,
        prefix: String,
    },
    DeviceAddress {
        device: WireDevice,
        address: String,
    },
    DeviceHostname {
        device: WireDevice,
        hostname: String,
    },
    DeviceVendor {
        device: WireDevice,
        vendor: String,
    },
    DeviceDescription {
        device: WireDevice,
        text: String,
    },
    DeviceRoleSignal {
        device: WireDevice,
        signal: String,
        /// Only meaningful for the link-layer capability signal, which carries a label.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    DeviceCapability {
        device: WireDevice,
        capability: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    GatewayFor {
        device: WireDevice,
        network: String,
    },
    RoutesTo {
        device: WireDevice,
        network: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_hop: Option<String>,
    },
    AttachedTo {
        device: WireDevice,
        network: String,
    },
    BridgeLink {
        bridge_id: String,
        root_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<String>,
    },
    ObservedBehind {
        device: WireDevice,
        via: WireDevice,
    },
    OpaqueBoundary {
        device: WireDevice,
        why: String,
    },
    Service {
        address: String,
        port: u16,
        protocol: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    ResolvedAs {
        name: String,
        address: String,
    },
}

/// A device identity in wire form.
///
/// The zone is carried separately rather than folded into the address string, because
/// `fe80::1%en0` observed by a peer names a device on *that peer's* link. Losing the
/// distinction would merge two different devices seen by two different peers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "by", rename_all = "snake_case")]
pub enum WireDevice {
    Mac { mac: String },
    Address { address: String },
    ScopedAddress { address: String, zone: String },
}

impl WireDevice {
    fn from_key(key: &DeviceKey) -> Self {
        match key {
            DeviceKey::Mac(mac) => WireDevice::Mac { mac: mac.clone() },
            DeviceKey::Address(address) => WireDevice::Address {
                address: address.to_string(),
            },
            DeviceKey::ScopedAddress(address, zone) => WireDevice::ScopedAddress {
                address: address.to_string(),
                zone: zone.clone(),
            },
        }
    }

    fn to_key(&self) -> Result<DeviceKey, WireError> {
        Ok(match self {
            WireDevice::Mac { mac } => DeviceKey::mac(mac),
            WireDevice::Address { address } => DeviceKey::Address(parse_address(address)?),
            WireDevice::ScopedAddress { address, zone } => {
                DeviceKey::ScopedAddress(parse_address(address)?, zone.clone())
            }
        })
    }
}

/// One evidence record in wire form, with the provenance a receiver needs to weigh it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WireEvidence {
    pub fact: WireFact,
    pub source: String,
    pub confidence: String,
    /// The *peer's* vantage, not the receiver's. Kept verbatim so a merged fact still says
    /// which link it was observed from.
    pub vantage: String,
    /// Seconds since the Unix epoch. A peer's clock may be wrong; this is what it claimed.
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl WireEvidence {
    /// Converts a record for the wire, or `None` when this format cannot express it.
    ///
    /// A catch-all rather than an exhaustive match, deliberately. The wire format is
    /// versioned and must not change when the internal model does, and an exhaustive match
    /// made every new `Fact` variant a compile error here -- so the evidence model could
    /// not grow without editing the federation code. A fact this version has no
    /// representation for is refused and reported, never approximated into a neighbouring
    /// variant.
    pub fn from_evidence(evidence: &TopologyEvidence) -> Option<Self> {
        let (signal, label) = match &evidence.fact {
            Fact::DeviceRoleSignal { signal, .. } => role_signal_wire(signal),
            _ => ("", None),
        };

        let fact = match &evidence.fact {
            Fact::Network { prefix } => WireFact::Network {
                prefix: prefix.to_string(),
            },
            Fact::Vlan { id } => WireFact::Vlan { id: *id },
            Fact::InterfaceNetwork { interface, prefix } => WireFact::InterfaceNetwork {
                interface: interface.clone(),
                prefix: prefix.to_string(),
            },
            Fact::DeviceAddress { device, address } => WireFact::DeviceAddress {
                device: WireDevice::from_key(device),
                address: address.to_string(),
            },
            Fact::DeviceHostname { device, hostname } => WireFact::DeviceHostname {
                device: WireDevice::from_key(device),
                hostname: hostname.clone(),
            },
            Fact::DeviceVendor { device, vendor } => WireFact::DeviceVendor {
                device: WireDevice::from_key(device),
                vendor: vendor.clone(),
            },
            Fact::DeviceDescription { device, text } => WireFact::DeviceDescription {
                device: WireDevice::from_key(device),
                text: text.clone(),
            },
            Fact::DeviceRoleSignal { device, .. } => WireFact::DeviceRoleSignal {
                device: WireDevice::from_key(device),
                signal: signal.to_string(),
                label,
            },
            Fact::DeviceCapability {
                device,
                capability,
                detail,
            } => WireFact::DeviceCapability {
                device: WireDevice::from_key(device),
                capability: capability_wire(*capability).to_string(),
                detail: detail.clone(),
            },
            Fact::GatewayFor { device, network } => WireFact::GatewayFor {
                device: WireDevice::from_key(device),
                network: network.to_string(),
            },
            Fact::RoutesTo {
                device,
                network,
                next_hop,
            } => WireFact::RoutesTo {
                device: WireDevice::from_key(device),
                network: network.to_string(),
                next_hop: next_hop.map(|h| h.to_string()),
            },
            Fact::AttachedTo { device, network } => WireFact::AttachedTo {
                device: WireDevice::from_key(device),
                network: network.to_string(),
            },
            Fact::BridgeLink {
                bridge_id,
                root_id,
                port,
            } => WireFact::BridgeLink {
                bridge_id: bridge_id.clone(),
                root_id: root_id.clone(),
                port: port.clone(),
            },
            Fact::ObservedBehind { device, via } => WireFact::ObservedBehind {
                device: WireDevice::from_key(device),
                via: WireDevice::from_key(via),
            },
            Fact::OpaqueBoundary { device, why } => WireFact::OpaqueBoundary {
                device: WireDevice::from_key(device),
                why: why.clone(),
            },
            Fact::Service {
                address,
                port,
                protocol,
                detail,
            } => WireFact::Service {
                address: address.to_string(),
                port: *port,
                protocol: protocol.to_string(),
                detail: detail.clone(),
            },
            Fact::ResolvedAs { name, address } => WireFact::ResolvedAs {
                name: name.clone(),
                address: address.to_string(),
            },
            // Anything this version of the format does not represent. Refused rather than
            // mapped onto something close: a receiver would then record a fact the sender
            // never stated.
            _ => return None,
        };

        Some(Self {
            fact,
            source: source_wire(evidence.source).to_string(),
            confidence: confidence_wire(evidence.confidence).to_string(),
            vantage: evidence.vantage.clone(),
            observed_at: evidence
                .observed_at
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            detail: evidence.detail.clone(),
        })
    }

    /// Converts back, rejecting anything this version does not understand.
    pub fn to_evidence(&self) -> Result<TopologyEvidence, WireError> {
        let fact = match &self.fact {
            WireFact::Network { prefix } => Fact::Network {
                prefix: parse_prefix(prefix)?,
            },
            WireFact::Vlan { id } => Fact::Vlan { id: *id },
            WireFact::InterfaceNetwork { interface, prefix } => Fact::InterfaceNetwork {
                interface: interface.clone(),
                prefix: parse_prefix(prefix)?,
            },
            WireFact::DeviceAddress { device, address } => Fact::DeviceAddress {
                device: device.to_key()?,
                address: parse_address(address)?,
            },
            WireFact::DeviceHostname { device, hostname } => Fact::DeviceHostname {
                device: device.to_key()?,
                hostname: hostname.clone(),
            },
            WireFact::DeviceVendor { device, vendor } => Fact::DeviceVendor {
                device: device.to_key()?,
                vendor: vendor.clone(),
            },
            WireFact::DeviceDescription { device, text } => Fact::DeviceDescription {
                device: device.to_key()?,
                text: text.clone(),
            },
            WireFact::DeviceRoleSignal {
                device,
                signal,
                label,
            } => Fact::DeviceRoleSignal {
                device: device.to_key()?,
                signal: role_signal_from_wire(signal, label.as_deref())?,
            },
            WireFact::DeviceCapability {
                device,
                capability,
                detail,
            } => Fact::DeviceCapability {
                device: device.to_key()?,
                capability: capability_from_wire(capability)?,
                detail: detail.clone(),
            },
            WireFact::GatewayFor { device, network } => Fact::GatewayFor {
                device: device.to_key()?,
                network: parse_prefix(network)?,
            },
            WireFact::RoutesTo {
                device,
                network,
                next_hop,
            } => Fact::RoutesTo {
                device: device.to_key()?,
                network: parse_prefix(network)?,
                next_hop: next_hop.as_deref().map(parse_address).transpose()?,
            },
            WireFact::AttachedTo { device, network } => Fact::AttachedTo {
                device: device.to_key()?,
                network: parse_prefix(network)?,
            },
            WireFact::BridgeLink {
                bridge_id,
                root_id,
                port,
            } => Fact::BridgeLink {
                bridge_id: bridge_id.clone(),
                root_id: root_id.clone(),
                port: port.clone(),
            },
            WireFact::ObservedBehind { device, via } => Fact::ObservedBehind {
                device: device.to_key()?,
                via: via.to_key()?,
            },
            WireFact::OpaqueBoundary { device, why } => Fact::OpaqueBoundary {
                device: device.to_key()?,
                why: why.clone(),
            },
            WireFact::Service {
                address,
                port,
                protocol,
                detail,
            } => Fact::Service {
                address: parse_address(address)?,
                port: *port,
                protocol: protocol_from_wire(protocol)?,
                detail: detail.clone(),
            },
            WireFact::ResolvedAs { name, address } => Fact::ResolvedAs {
                name: name.clone(),
                address: parse_address(address)?,
            },
        };

        let mut evidence = TopologyEvidence::new(
            fact,
            source_from_wire(&self.source)?,
            confidence_from_wire(&self.confidence)?,
            self.vantage.clone(),
        );
        evidence.observed_at = UNIX_EPOCH + Duration::from_secs(self.observed_at);
        evidence.detail = self.detail.clone();
        Ok(evidence)
    }
}

impl WireFact {
    /// Every peer-controlled string in this fact, with the field it came from.
    ///
    /// Enumerated exhaustively so that adding a variant without listing its strings is a
    /// compile error rather than a silent gap: an unchecked field is one a peer can make
    /// arbitrarily long, or fill with terminal escapes that reach the display.
    pub fn text_fields(&self) -> Vec<(&'static str, &str)> {
        match self {
            WireFact::Network { prefix } => vec![("prefix", prefix)],
            WireFact::Vlan { .. } => Vec::new(),
            WireFact::InterfaceNetwork { interface, prefix } => {
                vec![("interface", interface), ("prefix", prefix)]
            }
            WireFact::DeviceAddress { device, address } => {
                let mut out = device.text_fields();
                out.push(("address", address));
                out
            }
            WireFact::DeviceHostname { device, hostname } => {
                let mut out = device.text_fields();
                out.push(("hostname", hostname));
                out
            }
            WireFact::DeviceVendor { device, vendor } => {
                let mut out = device.text_fields();
                out.push(("vendor", vendor));
                out
            }
            WireFact::DeviceDescription { device, text } => {
                let mut out = device.text_fields();
                out.push(("description", text));
                out
            }
            WireFact::DeviceRoleSignal {
                device,
                signal,
                label,
            } => {
                let mut out = device.text_fields();
                out.push(("role signal", signal));
                if let Some(label) = label {
                    out.push(("role signal label", label));
                }
                out
            }
            WireFact::DeviceCapability {
                device,
                capability,
                detail,
            } => {
                let mut out = device.text_fields();
                out.push(("capability", capability));
                if let Some(detail) = detail {
                    out.push(("capability detail", detail));
                }
                out
            }
            WireFact::GatewayFor { device, network } => {
                let mut out = device.text_fields();
                out.push(("network", network));
                out
            }
            WireFact::RoutesTo {
                device,
                network,
                next_hop,
            } => {
                let mut out = device.text_fields();
                out.push(("network", network));
                if let Some(next_hop) = next_hop {
                    out.push(("next hop", next_hop));
                }
                out
            }
            WireFact::AttachedTo { device, network } => {
                let mut out = device.text_fields();
                out.push(("network", network));
                out
            }
            WireFact::BridgeLink {
                bridge_id,
                root_id,
                port,
            } => {
                let mut out = vec![
                    ("bridge id", bridge_id.as_str()),
                    ("root id", root_id.as_str()),
                ];
                if let Some(port) = port {
                    out.push(("bridge port", port));
                }
                out
            }
            WireFact::ObservedBehind { device, via } => {
                let mut out = device.text_fields();
                out.extend(via.text_fields());
                out
            }
            WireFact::OpaqueBoundary { device, why } => {
                let mut out = device.text_fields();
                out.push(("boundary reason", why));
                out
            }
            WireFact::Service {
                address,
                protocol,
                detail,
                ..
            } => {
                let mut out = vec![
                    ("address", address.as_str()),
                    ("protocol", protocol.as_str()),
                ];
                if let Some(detail) = detail {
                    out.push(("service detail", detail));
                }
                out
            }
            WireFact::ResolvedAs { name, address } => {
                vec![("resolved name", name), ("address", address)]
            }
        }
    }
}

impl WireDevice {
    /// The peer-controlled strings in a device identity.
    fn text_fields(&self) -> Vec<(&'static str, &str)> {
        match self {
            WireDevice::Mac { mac } => vec![("mac", mac)],
            WireDevice::Address { address } => vec![("device address", address)],
            WireDevice::ScopedAddress { address, zone } => {
                vec![("device address", address), ("device zone", zone)]
            }
        }
    }
}

impl WireEvidence {
    /// Every peer-controlled string in this record.
    pub fn text_fields(&self) -> Vec<(&'static str, &str)> {
        let mut out = self.fact.text_fields();
        out.push(("source", &self.source));
        out.push(("confidence", &self.confidence));
        out.push(("vantage", &self.vantage));
        if let Some(detail) = &self.detail {
            out.push(("detail", detail));
        }
        out
    }
}

/// What went wrong converting a wire record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// A prefix, address or other field could not be parsed.
    Malformed(String),
    /// A name this version does not know. Dropped rather than approximated.
    Unknown(String),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Malformed(what) => write!(f, "malformed {what}"),
            WireError::Unknown(what) => write!(f, "unknown {what}"),
        }
    }
}

impl std::error::Error for WireError {}

fn parse_prefix(text: &str) -> Result<IpNet, WireError> {
    text.parse()
        .map_err(|_| WireError::Malformed(format!("prefix {text:?}")))
}

fn parse_address(text: &str) -> Result<IpAddr, WireError> {
    text.parse()
        .map_err(|_| WireError::Malformed(format!("address {text:?}")))
}

/// Protocol names are interned, because [`Fact::Service`] holds a `&'static str`.
///
/// An unrecognised protocol is refused rather than leaked into a static, which would let a
/// remote peer grow this process's memory without bound.
fn protocol_from_wire(text: &str) -> Result<&'static str, WireError> {
    match text {
        "tcp" => Ok("tcp"),
        "udp" => Ok("udp"),
        other => Err(WireError::Unknown(format!("protocol {other:?}"))),
    }
}

fn confidence_wire(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Observed => "observed",
        Confidence::Advertised => "advertised",
        Confidence::Inferred => "inferred",
        Confidence::UserSupplied => "user_supplied",
    }
}

fn confidence_from_wire(text: &str) -> Result<Confidence, WireError> {
    Ok(match text {
        "observed" => Confidence::Observed,
        "advertised" => Confidence::Advertised,
        "inferred" => Confidence::Inferred,
        "user_supplied" => Confidence::UserSupplied,
        other => return Err(WireError::Unknown(format!("confidence {other:?}"))),
    })
}

macro_rules! wire_names {
    ($to:ident, $from:ident, $ty:ty, $( $variant:ident => $name:literal ),+ $(,)?) => {
        fn $to(value: $ty) -> &'static str {
            match value {
                $( <$ty>::$variant => $name, )+
            }
        }

        fn $from(text: &str) -> Result<$ty, WireError> {
            Ok(match text {
                $( $name => <$ty>::$variant, )+
                other => return Err(WireError::Unknown(format!("{} {other:?}", stringify!($ty)))),
            })
        }
    };
}

wire_names!(
    source_wire,
    source_from_wire,
    EvidenceSource,
    InterfaceAddress => "interface_address",
    KernelRoute => "kernel_route",
    DefaultGateway => "default_gateway",
    ResolverConfig => "resolver_config",
    DhcpLease => "dhcp_lease",
    ArpCache => "arp_cache",
    NdpCache => "ndp_cache",
    IcmpProbe => "icmp_probe",
    TcpProbe => "tcp_probe",
    Mdns => "mdns",
    UnicastDns => "unicast_dns",
    Ssdp => "ssdp",
    Nbns => "nbns",
    Llmnr => "llmnr",
    Mndp => "mndp",
    Lldp => "lldp",
    Cdp => "cdp",
    Stp => "stp",
    RouterAdvertisement => "router_advertisement",
    Snmp => "snmp",
    Rip => "rip",
    VendorDiscovery => "vendor_discovery",
    NatPmp => "nat_pmp",
    AiProtocol => "ai_protocol",
    Mcp => "mcp",
    UserSupplied => "user_supplied",
);

wire_names!(
    capability_wire,
    capability_from_wire,
    Capability,
    DefaultGateway => "default_gateway",
    Ipv4Forwarding => "ipv4_forwarding",
    Ipv6Router => "ipv6_router",
    NatGateway => "nat_gateway",
    DhcpServer => "dhcp_server",
    DnsServer => "dns_server",
    Bridge => "bridge",
    WirelessAp => "wireless_ap",
    ManagementInterface => "management_interface",
    AiRuntime => "ai_runtime",
    AiAgent => "ai_agent",
    McpServer => "mcp_server",
);

/// Role signals carry a label in one variant, so they do not fit the macro.
fn role_signal_wire(signal: &RoleSignal) -> (&'static str, Option<String>) {
    match signal {
        RoleSignal::DefaultGateway => ("default_gateway", None),
        RoleSignal::DhcpRouter => ("dhcp_router", None),
        RoleSignal::RouterAdvertisement => ("router_advertisement", None),
        RoleSignal::LinkLayerCapability(label) => {
            ("link_layer_capability", Some(label.to_string()))
        }
        RoleSignal::InternetGatewayDevice => ("internet_gateway_device", None),
        RoleSignal::SnmpForwarding => ("snmp_forwarding", None),
        RoleSignal::ObservedForwarding => ("observed_forwarding", None),
        RoleSignal::KernelNextHop => ("kernel_next_hop", None),
        RoleSignal::SpanningTreeBridge => ("spanning_tree_bridge", None),
        RoleSignal::ManagementSurface => ("management_surface", None),
    }
}

fn role_signal_from_wire(text: &str, label: Option<&str>) -> Result<RoleSignal, WireError> {
    Ok(match text {
        "default_gateway" => RoleSignal::DefaultGateway,
        "dhcp_router" => RoleSignal::DhcpRouter,
        "router_advertisement" => RoleSignal::RouterAdvertisement,
        "internet_gateway_device" => RoleSignal::InternetGatewayDevice,
        "snmp_forwarding" => RoleSignal::SnmpForwarding,
        "observed_forwarding" => RoleSignal::ObservedForwarding,
        "kernel_next_hop" => RoleSignal::KernelNextHop,
        "spanning_tree_bridge" => RoleSignal::SpanningTreeBridge,
        "management_surface" => RoleSignal::ManagementSurface,
        // The label is a `&'static str` in the domain model, so only known labels are
        // accepted. Interning arbitrary remote strings would let a peer grow this
        // process's memory permanently.
        "link_layer_capability" => match label {
            Some("Router") => RoleSignal::LinkLayerCapability("Router"),
            Some("Bridge") => RoleSignal::LinkLayerCapability("Bridge"),
            Some("Switch") => RoleSignal::LinkLayerCapability("Switch"),
            Some("WLAN AP") => RoleSignal::LinkLayerCapability("WLAN AP"),
            Some(other) => {
                return Err(WireError::Unknown(format!(
                    "link-layer capability {other:?}"
                )));
            }
            None => return Err(WireError::Malformed("link-layer capability".to_string())),
        },
        other => return Err(WireError::Unknown(format!("role signal {other:?}"))),
    })
}

/// The bytes actually signed: schema version, peer, vantage, sequence, time and records.
///
/// Built explicitly rather than by signing serialized JSON, because JSON has no canonical
/// form -- key order and whitespace can change without changing meaning, and a signature
/// over one encoding would not verify against another encoding of the same bundle.
pub fn signing_payload(
    schema_version: u16,
    peer: &str,
    vantage: &str,
    sequence: u64,
    published_at: u64,
    records: &[WireEvidence],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"idnx-federation-v1\n");
    payload.extend_from_slice(schema_version.to_be_bytes().as_slice());
    push_field(&mut payload, peer.as_bytes());
    push_field(&mut payload, vantage.as_bytes());
    payload.extend_from_slice(sequence.to_be_bytes().as_slice());
    payload.extend_from_slice(published_at.to_be_bytes().as_slice());
    payload.extend_from_slice((records.len() as u64).to_be_bytes().as_slice());
    for record in records {
        // One record's own canonical encoding, length-prefixed so that no arrangement of
        // record boundaries can produce the same byte stream as a different bundle.
        let encoded = serde_json::to_vec(record).unwrap_or_default();
        push_field(&mut payload, &encoded);
    }
    payload
}

fn push_field(payload: &mut Vec<u8>, bytes: &[u8]) {
    payload.extend_from_slice((bytes.len() as u64).to_be_bytes().as_slice());
    payload.extend_from_slice(bytes);
}

/// Seconds since the epoch, for a timestamp a peer publishes.
pub fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(fact: Fact) -> TopologyEvidence {
        TopologyEvidence::new(fact, EvidenceSource::ArpCache, Confidence::Observed, "eth0")
            .with_detail("because")
    }

    #[test]
    fn every_fact_kind_round_trips() {
        let device = DeviceKey::mac("02:00:5e:00:00:01");
        let scoped = DeviceKey::ScopedAddress("fe80::1".parse().unwrap(), "eth0".to_string());

        let facts = vec![
            Fact::Network {
                prefix: "192.168.51.0/24".parse().unwrap(),
            },
            Fact::Vlan { id: 42 },
            Fact::InterfaceNetwork {
                interface: "eth0".to_string(),
                prefix: "10.0.0.0/8".parse().unwrap(),
            },
            Fact::DeviceAddress {
                device: device.clone(),
                address: "192.168.51.1".parse().unwrap(),
            },
            Fact::DeviceHostname {
                device: device.clone(),
                hostname: "router".to_string(),
            },
            Fact::DeviceVendor {
                device: device.clone(),
                vendor: "ASUSTek".to_string(),
            },
            Fact::DeviceDescription {
                device: device.clone(),
                text: "RT-AX88U".to_string(),
            },
            Fact::DeviceRoleSignal {
                device: device.clone(),
                signal: RoleSignal::DefaultGateway,
            },
            Fact::DeviceRoleSignal {
                device: device.clone(),
                signal: RoleSignal::LinkLayerCapability("Router"),
            },
            Fact::DeviceCapability {
                device: device.clone(),
                capability: Capability::NatGateway,
                detail: Some("answered NAT-PMP".to_string()),
            },
            Fact::GatewayFor {
                device: device.clone(),
                network: "192.168.51.0/24".parse().unwrap(),
            },
            Fact::RoutesTo {
                device: device.clone(),
                network: "10.9.0.0/24".parse().unwrap(),
                next_hop: Some("192.168.51.2".parse().unwrap()),
            },
            Fact::AttachedTo {
                device: device.clone(),
                network: "192.168.51.0/24".parse().unwrap(),
            },
            Fact::BridgeLink {
                bridge_id: "8000.aabb".to_string(),
                root_id: "8000.ccdd".to_string(),
                port: Some("1".to_string()),
            },
            Fact::ObservedBehind {
                device: scoped.clone(),
                via: device.clone(),
            },
            Fact::OpaqueBoundary {
                device: device.clone(),
                why: "NAT".to_string(),
            },
            Fact::Service {
                address: "192.168.51.1".parse().unwrap(),
                port: 53,
                protocol: "udp",
                detail: Some("dnsmasq".to_string()),
            },
            Fact::ResolvedAs {
                name: "router.lan".to_string(),
                address: "192.168.51.1".parse().unwrap(),
            },
        ];

        for fact in facts {
            let original = evidence(fact);
            let wire = WireEvidence::from_evidence(&original).expect("representable");
            let json = serde_json::to_string(&wire).expect("serialisable");
            let decoded: WireEvidence = serde_json::from_str(&json).expect("deserialisable");
            assert_eq!(decoded, wire, "json round trip");

            let back = decoded.to_evidence().expect("convertible");
            assert_eq!(back.source, original.source);
            assert_eq!(back.confidence, original.confidence);
            assert_eq!(back.vantage, original.vantage);
            assert_eq!(back.detail, original.detail);
            assert_eq!(
                format!("{:?}", back.fact),
                format!("{:?}", original.fact),
                "fact round trip"
            );
        }
    }

    #[test]
    fn a_peers_zone_is_preserved_rather_than_flattened() {
        // fe80::1%eth0 seen by a peer is a device on *that peer's* link. Flattening the
        // zone would merge it with a different device seen locally at the same address.
        let scoped = DeviceKey::ScopedAddress("fe80::1".parse().unwrap(), "eth7".to_string());
        let wire = WireEvidence::from_evidence(&evidence(Fact::DeviceAddress {
            device: scoped.clone(),
            address: "fe80::1".parse().unwrap(),
        }))
        .expect("representable");
        let back = wire.to_evidence().expect("convertible");
        let Fact::DeviceAddress { device, .. } = back.fact else {
            panic!("wrong fact");
        };
        assert_eq!(device, scoped);
    }

    #[test]
    fn an_unknown_name_is_refused_rather_than_approximated() {
        // A newer peer's vocabulary must not be coerced into the nearest known variant:
        // that would silently record something the peer never said.
        assert_eq!(
            confidence_from_wire("extremely_confident"),
            Err(WireError::Unknown(
                "confidence \"extremely_confident\"".to_string()
            ))
        );
        assert!(matches!(
            source_from_wire("telepathy"),
            Err(WireError::Unknown(_))
        ));
        assert!(matches!(
            capability_from_wire("time_travel"),
            Err(WireError::Unknown(_))
        ));
        assert!(matches!(
            role_signal_from_wire("vibes", None),
            Err(WireError::Unknown(_))
        ));
    }

    #[test]
    fn an_arbitrary_protocol_or_capability_label_is_not_interned() {
        // Both end up in `&'static str` fields. Interning remote strings would let a peer
        // grow this process's memory permanently.
        assert!(matches!(
            protocol_from_wire("sctp"),
            Err(WireError::Unknown(_))
        ));
        assert!(matches!(
            role_signal_from_wire("link_layer_capability", Some("Whatever")),
            Err(WireError::Unknown(_))
        ));
        assert!(matches!(
            role_signal_from_wire("link_layer_capability", None),
            Err(WireError::Malformed(_))
        ));
    }

    #[test]
    fn every_peer_controlled_string_is_enumerated() {
        // The list drives the length checks. A fact whose strings are not listed is a
        // field a peer can make arbitrarily long, or fill with terminal escapes.
        let device = DeviceKey::ScopedAddress("fe80::1".parse().unwrap(), "eth0".to_string());

        let cases: Vec<(Fact, &[&str])> = vec![
            (
                Fact::DeviceHostname {
                    device: device.clone(),
                    hostname: "HOSTNAME".to_string(),
                },
                &["HOSTNAME", "fe80::1", "eth0"],
            ),
            (
                Fact::DeviceVendor {
                    device: device.clone(),
                    vendor: "VENDOR".to_string(),
                },
                &["VENDOR"],
            ),
            (
                Fact::DeviceDescription {
                    device: device.clone(),
                    text: "DESCRIPTION".to_string(),
                },
                &["DESCRIPTION"],
            ),
            (
                Fact::InterfaceNetwork {
                    interface: "INTERFACE".to_string(),
                    prefix: "10.0.0.0/8".parse().unwrap(),
                },
                &["INTERFACE", "10.0.0.0/8"],
            ),
            (
                Fact::BridgeLink {
                    bridge_id: "BRIDGE".to_string(),
                    root_id: "ROOT".to_string(),
                    port: Some("PORT".to_string()),
                },
                &["BRIDGE", "ROOT", "PORT"],
            ),
            (
                Fact::DeviceCapability {
                    device: device.clone(),
                    capability: Capability::NatGateway,
                    detail: Some("CAPDETAIL".to_string()),
                },
                &["CAPDETAIL", "nat_gateway"],
            ),
            (
                Fact::Service {
                    address: "10.0.0.1".parse().unwrap(),
                    port: 80,
                    protocol: "tcp",
                    detail: Some("SERVICEDETAIL".to_string()),
                },
                &["SERVICEDETAIL", "tcp", "10.0.0.1"],
            ),
            (
                Fact::OpaqueBoundary {
                    device: device.clone(),
                    why: "WHY".to_string(),
                },
                &["WHY"],
            ),
            (
                Fact::ResolvedAs {
                    name: "NAME".to_string(),
                    address: "10.0.0.1".parse().unwrap(),
                },
                &["NAME"],
            ),
            (
                Fact::DeviceRoleSignal {
                    device,
                    signal: RoleSignal::LinkLayerCapability("Router"),
                },
                &["Router", "link_layer_capability"],
            ),
        ];

        for (fact, expected) in cases {
            let wire = WireEvidence::from_evidence(&evidence(fact)).expect("representable");
            let found: Vec<&str> = wire.text_fields().iter().map(|(_, v)| *v).collect();
            for needle in expected {
                assert!(
                    found.contains(needle),
                    "{needle} is not enumerated among {found:?}"
                );
            }
        }
    }

    #[test]
    fn a_fact_this_format_cannot_express_is_refused_not_approximated() {
        // The wire format is versioned and must not change when the internal model does.
        // A fact it has no representation for is left out; mapping it onto a neighbouring
        // variant would have a receiver record something the sender never said.
        let unrepresentable = evidence(Fact::ForwardsToward {
            device: DeviceKey::mac("02:00:5e:00:00:01"),
            toward: "192.0.2.1".parse().unwrap(),
            distance: 2,
            previous: None,
        });
        assert!(WireEvidence::from_evidence(&unrepresentable).is_none());
    }

    #[test]
    fn a_malformed_address_is_refused() {
        let wire = WireEvidence {
            fact: WireFact::Network {
                prefix: "not-a-prefix".to_string(),
            },
            source: "arp_cache".to_string(),
            confidence: "observed".to_string(),
            vantage: "eth0".to_string(),
            observed_at: 0,
            detail: None,
        };
        assert!(matches!(wire.to_evidence(), Err(WireError::Malformed(_))));
    }

    #[test]
    fn the_signed_payload_changes_when_any_part_of_the_bundle_does() {
        let record = WireEvidence::from_evidence(&evidence(Fact::Vlan { id: 1 })).expect("ok");
        let other = WireEvidence::from_evidence(&evidence(Fact::Vlan { id: 2 })).expect("ok");
        let base = signing_payload(1, "peer", "eth0", 7, 100, std::slice::from_ref(&record));

        assert_ne!(
            base,
            signing_payload(2, "peer", "eth0", 7, 100, std::slice::from_ref(&record))
        );
        assert_ne!(
            base,
            signing_payload(1, "other", "eth0", 7, 100, std::slice::from_ref(&record))
        );
        assert_ne!(
            base,
            signing_payload(1, "peer", "eth1", 7, 100, std::slice::from_ref(&record))
        );
        assert_ne!(
            base,
            signing_payload(1, "peer", "eth0", 8, 100, std::slice::from_ref(&record))
        );
        assert_ne!(
            base,
            signing_payload(1, "peer", "eth0", 7, 101, std::slice::from_ref(&record))
        );
        assert_ne!(base, signing_payload(1, "peer", "eth0", 7, 100, &[other]));
        assert_ne!(base, signing_payload(1, "peer", "eth0", 7, 100, &[]));
    }

    #[test]
    fn record_boundaries_cannot_be_shifted_without_changing_the_payload() {
        // Length prefixes, not delimiters: otherwise two records could be re-split into
        // two different records with the same byte stream, and one signature would cover
        // both readings.
        let a = WireEvidence::from_evidence(&evidence(Fact::Vlan { id: 1 })).expect("ok");
        let b = WireEvidence::from_evidence(&evidence(Fact::Vlan { id: 2 })).expect("ok");
        assert_ne!(
            signing_payload(1, "p", "v", 0, 0, &[a.clone(), b.clone()]),
            signing_payload(1, "p", "v", 0, 0, &[b, a])
        );
    }
}
