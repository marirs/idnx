//! Vendor adapters.
//!
//! Vendor mechanisms are optional amplifiers, never a discovery strategy. The core
//! algorithm must produce the same topology when the manufacturer is unknown, when no
//! adapter exists for it, when the MAC is white-label or randomized, and when the router is
//! software on generic hardware. A network of Cisco, Fortinet, Ubiquiti, TP-Link or
//! entirely unrecognised equipment must map identically given equivalent standard evidence.
//!
//! Two constraints keep that true. An adapter returns [`TopologyEvidence`] and nothing else,
//! so it cannot assign a role, reach into the graph, or influence the scheduler. And no
//! adapter is ever required: recursion never waits on one, and a failure to answer is not
//! evidence about what a device is.
//!
//! Selection is by observed fingerprint. A manufacturer name may *schedule* an adapter,
//! because asking a likely-relevant question first is cheaper, but it never establishes
//! anything on its own.

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::time::Duration;

use crate::topology::TopologyEvidence;
use crate::topology::evidence::{
    Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal, TopologyEvidence as Evidence,
};

/// What is known about a device when choosing adapters.
#[derive(Debug, Clone, Default)]
pub struct DeviceFingerprint {
    /// Registered manufacturer, when known. A hint for selection only.
    pub vendor: Option<String>,
    /// Ports observed open.
    pub open_ports: Vec<u16>,
    /// Names the device answers to.
    pub hostnames: Vec<String>,
    /// Free-form identity text gathered from TLS, HTTP, UPnP, SNMP and similar.
    pub descriptions: Vec<String>,
}

impl DeviceFingerprint {
    /// True when any identity text contains the needle, case-insensitively.
    pub fn mentions(&self, needle: &str) -> bool {
        let needle = needle.to_ascii_lowercase();
        self.descriptions
            .iter()
            .chain(self.hostnames.iter())
            .any(|text| text.to_ascii_lowercase().contains(&needle))
    }

    /// Builds a fingerprint from what this run has already observed about the device.
    ///
    /// Only identity the device itself disclosed is used -- certificate subjects, service
    /// banners, hostnames, the registered manufacturer. Nothing here establishes anything;
    /// it only decides which optional questions are worth asking.
    pub fn from_evidence(evidence: &[TopologyEvidence], open_ports: &[u16]) -> Self {
        let mut fingerprint = Self {
            open_ports: open_ports.to_vec(),
            ..Default::default()
        };
        for record in evidence {
            match &record.fact {
                Fact::DeviceVendor { vendor, .. } => {
                    fingerprint.vendor = Some(vendor.clone());
                }
                Fact::DeviceHostname { hostname, .. } => {
                    fingerprint.hostnames.push(hostname.clone());
                }
                Fact::DeviceDescription { text, .. } => {
                    fingerprint.descriptions.push(text.clone());
                }
                Fact::ResolvedAs { name, .. } => fingerprint.hostnames.push(name.clone()),
                _ => {}
            }
        }
        fingerprint
    }

    /// True when the registered manufacturer matches.
    ///
    /// A manufacturer match schedules an adapter and asserts nothing: plenty of these
    /// organizations also make cameras, laptops and NAS boxes.
    pub fn vendor_is(&self, needle: &str) -> bool {
        self.vendor
            .as_deref()
            .map(|v| {
                v.to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
            })
            .unwrap_or(false)
    }
}

/// Context handed to an adapter.
#[derive(Debug, Clone)]
pub struct VendorContext {
    pub target: Ipv4Addr,
    pub device: DeviceKey,
    pub fingerprint: DeviceFingerprint,
    pub timeout: Duration,
    pub vantage: String,
}

/// Future returned by an adapter.
pub type AdapterFuture<'a> = Pin<Box<dyn Future<Output = Vec<TopologyEvidence>> + Send + 'a>>;

/// A vendor-specific source of evidence.
pub trait VendorAdapter: Send + Sync {
    /// Stable name, used in coverage reporting.
    fn name(&self) -> &'static str;

    /// Whether this adapter is worth running against the device.
    ///
    /// Returning false skips work; it never means the device is not that vendor.
    fn applies(&self, fingerprint: &DeviceFingerprint) -> bool;

    /// Returns evidence. An adapter cannot report a result any other way, which is what
    /// prevents a vendor mechanism from assigning a role directly.
    fn discover<'a>(&'a self, context: &'a VendorContext) -> AdapterFuture<'a>;
}

/// ASUS proprietary discovery.
///
/// One adapter among several, with no special treatment anywhere in the graph or the
/// scheduler. A device that does not answer is not thereby shown to be something else.
pub struct AsusAdapter;

impl VendorAdapter for AsusAdapter {
    fn name(&self) -> &'static str {
        "vendor:asus"
    }

    fn applies(&self, fingerprint: &DeviceFingerprint) -> bool {
        fingerprint.vendor_is("asustek")
            || fingerprint.vendor_is("asus")
            || fingerprint.mentions("asuswrt")
            || fingerprint.mentions("rt-")
    }

    fn discover<'a>(&'a self, context: &'a VendorContext) -> AdapterFuture<'a> {
        Box::pin(async move {
            // The broadcast probe is link-local, so it cannot be aimed at one device; a
            // targeted implementation is pending the protocol audit. Returning nothing is
            // correct in the meantime and asserts nothing about the device.
            let _ = context;
            Vec::new()
        })
    }
}

/// MikroTik RouterOS.
pub struct MikroTikAdapter;

impl VendorAdapter for MikroTikAdapter {
    fn name(&self) -> &'static str {
        "vendor:mikrotik"
    }

    fn applies(&self, fingerprint: &DeviceFingerprint) -> bool {
        fingerprint.vendor_is("mikrotik")
            || fingerprint.mentions("routeros")
            // The RouterOS API port; still only a scheduling hint.
            || fingerprint.open_ports.contains(&8728)
    }

    fn discover<'a>(&'a self, context: &'a VendorContext) -> AdapterFuture<'a> {
        Box::pin(async move {
            let _ = context;
            Vec::new()
        })
    }
}

/// Ubiquiti and UniFi.
pub struct UbiquitiAdapter;

impl VendorAdapter for UbiquitiAdapter {
    fn name(&self) -> &'static str {
        "vendor:ubiquiti"
    }

    fn applies(&self, fingerprint: &DeviceFingerprint) -> bool {
        fingerprint.vendor_is("ubiquiti")
            || fingerprint.mentions("unifi")
            || fingerprint.open_ports.contains(&8443)
    }

    fn discover<'a>(&'a self, context: &'a VendorContext) -> AdapterFuture<'a> {
        Box::pin(async move {
            let _ = context;
            Vec::new()
        })
    }
}

/// A vendor discovery mechanism that can only be broadcast on a link.
///
/// Separate from [`VendorAdapter`] because it cannot be aimed at one device: the answer set
/// is whatever chooses to reply. Same two constraints apply -- evidence only, never required.
pub trait VendorBroadcast: Send + Sync {
    fn name(&self) -> &'static str;

    fn probe<'a>(&'a self, vantage: &'a str, timeout: Duration) -> AdapterFuture<'a>;
}

/// ASUS Device Discovery, UDP 9999.
pub struct AsusBroadcast;

impl VendorBroadcast for AsusBroadcast {
    fn name(&self) -> &'static str {
        "broadcast:asus"
    }

    fn probe<'a>(&'a self, vantage: &'a str, timeout: Duration) -> AdapterFuture<'a> {
        Box::pin(async move {
            let mut out = Vec::new();
            for router in crate::probes::asus::discover_asus_routers(timeout).await {
                let address = std::net::IpAddr::V4(router.ip);
                let device = DeviceKey::Address(address);

                out.push(Evidence::new(
                    Fact::DeviceAddress {
                        device: device.clone(),
                        address,
                    },
                    EvidenceSource::VendorDiscovery,
                    Confidence::Observed,
                    vantage,
                ));

                if let Some(model) = router.model_name.clone() {
                    out.push(Evidence::new(
                        Fact::DeviceDescription {
                            device: device.clone(),
                            text: model,
                        },
                        EvidenceSource::VendorDiscovery,
                        Confidence::Advertised,
                        vantage,
                    ));
                }

                // Answering a router-management discovery protocol is behaviour, not
                // manufacture: the device runs router firmware and said so. It is one
                // signal among several and never decides a role by itself.
                out.push(
                    Evidence::new(
                        Fact::DeviceRoleSignal {
                            device,
                            signal: RoleSignal::LinkLayerCapability("Router"),
                        },
                        EvidenceSource::VendorDiscovery,
                        Confidence::Advertised,
                        vantage,
                    )
                    .with_detail("answered a router management discovery broadcast"),
                );
            }
            out
        })
    }
}

/// Every link-local vendor broadcast. Adding a manufacturer means adding an entry here,
/// not a branch in the engine.
pub fn broadcasts() -> Vec<Box<dyn VendorBroadcast>> {
    vec![Box::new(AsusBroadcast)]
}

/// Runs every vendor broadcast on a link. None gates another and none gates recursion.
pub async fn run_broadcasts(vantage: &str, timeout: Duration) -> Vec<TopologyEvidence> {
    let mut out = Vec::new();
    for broadcast in broadcasts() {
        out.extend(broadcast.probe(vantage, timeout).await);
    }
    out
}

/// Every adapter. Order is irrelevant: each runs independently and none gates another.
pub fn adapters() -> Vec<Box<dyn VendorAdapter>> {
    vec![
        Box::new(AsusAdapter),
        Box::new(MikroTikAdapter),
        Box::new(UbiquitiAdapter),
    ]
}

/// Runs every applicable adapter against a device.
pub async fn run_adapters(context: &VendorContext) -> Vec<TopologyEvidence> {
    let mut out = Vec::new();
    for adapter in adapters() {
        if !adapter.applies(&context.fingerprint) {
            continue;
        }
        out.extend(adapter.discover(context).await);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(vendor: Option<&str>) -> DeviceFingerprint {
        DeviceFingerprint {
            vendor: vendor.map(|v| v.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn an_unknown_manufacturer_selects_no_adapter() {
        // The core algorithm must be unaffected by the absence of any adapter, which is
        // what makes a white-label or software router work identically.
        let unknown = fingerprint(None);
        assert!(adapters().iter().all(|a| !a.applies(&unknown)));

        let whitelabel = fingerprint(Some("Shenzhen Generic Electronics"));
        assert!(adapters().iter().all(|a| !a.applies(&whitelabel)));
    }

    #[test]
    fn a_randomized_mac_selects_no_adapter() {
        // A locally administered address resolves to no organization at all.
        assert!(adapters().iter().all(|a| !a.applies(&fingerprint(None))));
    }

    #[test]
    fn each_vendor_selects_only_its_own_adapter() {
        for (vendor, expected) in [
            ("ASUSTek Computer", "vendor:asus"),
            ("MikroTik", "vendor:mikrotik"),
            ("Ubiquiti Inc", "vendor:ubiquiti"),
        ] {
            let selected: Vec<&'static str> = adapters()
                .iter()
                .filter(|a| a.applies(&fingerprint(Some(vendor))))
                .map(|a| a.name())
                .collect();
            assert_eq!(selected, vec![expected], "for {vendor}");
        }
    }

    #[test]
    fn identity_text_can_select_an_adapter_without_a_manufacturer() {
        // A software router on generic hardware has no useful OUI, but may still identify
        // itself in an HTTP or TLS response.
        let mut fp = DeviceFingerprint::default();
        fp.descriptions.push("RouterOS 7.14 (MikroTik)".to_string());
        assert!(MikroTikAdapter.applies(&fp));
        assert!(!AsusAdapter.applies(&fp));
    }

    #[tokio::test]
    async fn an_adapter_that_finds_nothing_yields_no_evidence() {
        // Silence must never become a fact about the device.
        let context = VendorContext {
            target: "10.0.0.1".parse().unwrap(),
            device: DeviceKey::Address("10.0.0.1".parse().unwrap()),
            fingerprint: fingerprint(Some("ASUSTek Computer")),
            timeout: Duration::from_millis(10),
            vantage: "test0".to_string(),
        };
        assert!(run_adapters(&context).await.is_empty());
    }

    #[test]
    fn a_fingerprint_is_built_only_from_what_the_device_disclosed() {
        let device = DeviceKey::Address("10.0.0.3".parse().unwrap());
        let evidence = vec![
            TopologyEvidence::new(
                Fact::DeviceVendor {
                    device: device.clone(),
                    vendor: "MikroTik".to_string(),
                },
                EvidenceSource::TcpProbe,
                Confidence::Inferred,
                "test0",
            ),
            TopologyEvidence::new(
                Fact::DeviceDescription {
                    device: device.clone(),
                    text: "RouterOS 7.14".to_string(),
                },
                EvidenceSource::TcpProbe,
                Confidence::Advertised,
                "test0",
            ),
            // A fact about something other than identity must not enter the fingerprint.
            TopologyEvidence::new(
                Fact::DeviceRoleSignal {
                    device,
                    signal: RoleSignal::ObservedForwarding,
                },
                EvidenceSource::TcpProbe,
                Confidence::Observed,
                "test0",
            ),
        ];

        let fingerprint = DeviceFingerprint::from_evidence(&evidence, &[8728]);
        assert_eq!(fingerprint.vendor.as_deref(), Some("MikroTik"));
        assert_eq!(fingerprint.descriptions, vec!["RouterOS 7.14".to_string()]);
        assert!(fingerprint.hostnames.is_empty());
        assert!(MikroTikAdapter.applies(&fingerprint));
    }

    #[tokio::test]
    async fn adapters_never_run_for_an_unknown_device() {
        let context = VendorContext {
            target: "10.0.0.2".parse().unwrap(),
            device: DeviceKey::Address("10.0.0.2".parse().unwrap()),
            fingerprint: DeviceFingerprint::default(),
            timeout: Duration::from_millis(10),
            vantage: "test0".to_string(),
        };
        assert!(run_adapters(&context).await.is_empty());
    }
}
