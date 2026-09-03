//! Vendor adapters.
//!
//! Vendor mechanisms are optional amplifiers, never a discovery strategy. The core
//! algorithm must produce the same topology when the manufacturer is unknown, when no
//! adapter exists for it, when the MAC is white-label or randomized, and when the router is
//! software on generic hardware. A network of Cisco, Fortinet, Ubiquiti, TP-Link or
//! entirely unrecognised equipment must map identically given equivalent standard evidence.
//!
//! Two constraints keep that true. An adapter returns [`TopologyEvidence`] and nothing else,
//! so it cannot assign a role, reach into the graph, or influence the scheduler -- and its
//! output is filtered before absorption, so it cannot assert network structure either. It
//! *may* emit behavioural role evidence, such as "answered a router-management protocol",
//! which the graph then scores against everything else observed exactly as it scores any
//! other signal; emitting a signal is not assigning a role. And no adapter is ever
//! required: recursion never waits on one, and a failure to answer is not evidence about
//! what a device is.
//!
//! Selection is by observed fingerprint. A manufacturer name may *schedule* an adapter,
//! because asking a likely-relevant question first is cheaper, but it never establishes
//! anything on its own.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::net::endpoint::Endpoint;
use crate::net::socket::SocketBinding;

use crate::topology::TopologyEvidence;
use crate::topology::evidence::{DeviceKey, Fact};

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

    /// Folds identity out of evidence into this fingerprint.
    ///
    /// Only identity the device itself disclosed is used -- certificate subjects, service
    /// banners, hostnames, the registered manufacturer. Nothing here establishes anything;
    /// it only decides which optional questions are worth asking.
    ///
    /// Additive rather than constructing, because the identity a device is selected on is
    /// mostly older than the interrogation: an OUI manufacturer is recorded when the device
    /// is first seen in an ARP table, long before any port is probed. Building the
    /// fingerprint from interrogation output alone silently lost every one of them.
    pub fn absorb_evidence(&mut self, evidence: &[TopologyEvidence]) {
        for record in evidence {
            match &record.fact {
                Fact::DeviceVendor { vendor, .. } => {
                    self.vendor.get_or_insert_with(|| vendor.clone());
                }
                Fact::DeviceHostname { hostname, .. } => self.hostnames.push(hostname.clone()),
                Fact::DeviceDescription { text, .. } => self.descriptions.push(text.clone()),
                Fact::ResolvedAs { name, .. } => self.hostnames.push(name.clone()),
                _ => {}
            }
        }
        self.hostnames.sort();
        self.hostnames.dedup();
        self.descriptions.sort();
        self.descriptions.dedup();
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
    pub endpoint: Endpoint,
    pub device: DeviceKey,
    pub fingerprint: DeviceFingerprint,
    pub timeout: Duration,
    pub vantage: String,
}

/// What running an adapter actually amounted to.
///
/// The distinction the coverage report was getting wrong. An adapter that was selected and
/// has no implementation, one that ran and heard nothing, and one that ran and found
/// something are three different facts, and reporting the first as though it were the
/// second told the operator a protocol had been tried when no packet had been sent.
#[derive(Debug, Clone)]
pub enum AdapterOutcome {
    /// Selected, but there is nothing here to run.
    ///
    /// A stub. Reported as unavailable so it is never mistaken for a device declining to
    /// answer, which is what "no response" claims.
    Unavailable { reason: String },
    /// Ran, and the device did not answer.
    NoResponse { attempted: Vec<String> },
    /// Ran, and the device answered.
    Answered {
        attempted: Vec<String>,
        evidence: Vec<TopologyEvidence>,
    },
}

impl AdapterOutcome {
    /// A stub, with the reason it cannot run.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        AdapterOutcome::Unavailable {
            reason: reason.into(),
        }
    }

    /// The evidence, if any.
    pub fn evidence(self) -> Vec<TopologyEvidence> {
        match self {
            AdapterOutcome::Answered { evidence, .. } => evidence,
            _ => Vec::new(),
        }
    }

    /// One line for the coverage report, naming what was and was not done.
    pub fn describe(&self, adapter: &str) -> String {
        match self {
            AdapterOutcome::Unavailable { reason } => {
                format!("{adapter} unavailable: {reason}")
            }
            AdapterOutcome::NoResponse { attempted } => {
                format!("{adapter} no response ({})", attempted.join(", "))
            }
            AdapterOutcome::Answered { attempted, .. } => {
                format!("{adapter} answered ({})", attempted.join(", "))
            }
        }
    }
}

/// Future returned by a targeted adapter.
pub type AdapterFuture<'a> = Pin<Box<dyn Future<Output = AdapterOutcome> + Send + 'a>>;

/// What running a link-local broadcast amounted to.
///
/// Five states, because collapsing them loses the distinctions that matter. A protocol
/// whose framing has never been verified is not the same as one that was sent and ignored;
/// a socket that could not be opened is not the same as a device that stayed quiet; and
/// bytes that arrived but failed validation are a finding in their own right.
#[derive(Debug, Clone)]
pub enum BroadcastOutcome {
    /// The protocol's framing has not been established, so nothing is sent.
    Unavailable { reason: String },
    /// Transmission failed locally: no socket, no binding, no packet on the wire.
    NotSent { reason: String },
    /// A verified request went out and nothing came back.
    NoResponse { sent: String },
    /// Bytes arrived and did not survive protocol validation.
    InvalidResponse { sent: String, rejected: usize },
    /// A correlated, structurally valid reply produced evidence.
    Answered {
        sent: String,
        evidence: Vec<TopologyEvidence>,
    },
}

impl BroadcastOutcome {
    pub fn unavailable(reason: impl Into<String>) -> Self {
        BroadcastOutcome::Unavailable {
            reason: reason.into(),
        }
    }

    pub fn not_sent(reason: impl Into<String>) -> Self {
        BroadcastOutcome::NotSent {
            reason: reason.into(),
        }
    }

    pub fn evidence(self) -> Vec<TopologyEvidence> {
        match self {
            BroadcastOutcome::Answered { evidence, .. } => evidence,
            _ => Vec::new(),
        }
    }

    /// Whether a request actually reached the wire.
    ///
    /// This is what separates "the link was quiet" from "nothing was ever asked". Only the
    /// former is a fact about the network; reporting the latter as silence is the same
    /// overclaim as reporting an unanswered device as offline.
    pub fn transmitted(&self) -> bool {
        matches!(
            self,
            BroadcastOutcome::NoResponse { .. }
                | BroadcastOutcome::InvalidResponse { .. }
                | BroadcastOutcome::Answered { .. }
        )
    }

    pub fn describe(&self, broadcast: &str) -> String {
        match self {
            BroadcastOutcome::Unavailable { reason } => {
                format!("{broadcast} unavailable: {reason}")
            }
            BroadcastOutcome::NotSent { reason } => format!("{broadcast} not sent: {reason}"),
            BroadcastOutcome::NoResponse { sent } => format!("{broadcast} no response ({sent})"),
            BroadcastOutcome::InvalidResponse { sent, rejected } => {
                format!("{broadcast} {rejected} reply/replies failed validation ({sent})")
            }
            BroadcastOutcome::Answered { sent, .. } => format!("{broadcast} answered ({sent})"),
        }
    }
}

/// Future returned by a link-local broadcast.
///
/// Broadcasts return evidence directly because, unlike the targeted adapters, they are
/// implemented: the ASUS UDP 9999 probe really does go out on the wire.
pub type BroadcastFuture<'a> = Pin<Box<dyn Future<Output = BroadcastOutcome> + Send + 'a>>;

/// A vendor-specific source of evidence.
pub trait VendorAdapter: Send + Sync {
    /// Stable name, used in coverage reporting.
    fn name(&self) -> &'static str;

    /// Whether this adapter is worth running against the device.
    ///
    /// Returning false skips work; it never means the device is not that vendor.
    fn applies(&self, fingerprint: &DeviceFingerprint) -> bool;

    /// Runs the adapter, reporting what it managed to do.
    ///
    /// Evidence is the only channel for a result, which is what prevents a vendor mechanism
    /// from assigning a role directly -- and the outcome type is what keeps an
    /// unimplemented adapter from being reported as a device that stayed silent.
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
            let _ = context;
            // Not implemented, and said so. The only ASUS-specific code in this crate is a
            // link-local broadcast to UDP 9999, which cannot be aimed at one device and is
            // a separate provider. Targeted discovery would need the request and reply
            // framing for UDP 9999 and UDP 18017 -- two distinct protocol paths -- taken
            // from authoritative material or captured known-good traffic, with opcode,
            // sender and embedded identity all validated. Guessed payloads are not an
            // implementation, and returning an empty vector let this be reported as though
            // the device had been asked and had declined to answer.
            AdapterOutcome::unavailable(
                "targeted ASUS discovery is not implemented; UDP 9999 and 18017 request \
                 and reply framing not yet verified against authoritative material",
            )
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
            AdapterOutcome::unavailable(
                "targeted MikroTik discovery is not implemented; the RouterOS API on 8728 \
                 requires a login exchange, and MNDP is a link-local broadcast handled by \
                 its own provider",
            )
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
            AdapterOutcome::unavailable(
                "targeted Ubiquiti discovery is not implemented; the UBNT discovery \
                 protocol on UDP 10001 has not been verified against authoritative material",
            )
        })
    }
}

/// A vendor discovery mechanism that can only be broadcast on a link.
///
/// Separate from [`VendorAdapter`] because it cannot be aimed at one device: the answer set
/// is whatever chooses to reply. Same two constraints apply -- evidence only, never required.
pub trait VendorBroadcast: Send + Sync {
    fn name(&self) -> &'static str;

    /// `binding` constrains the broadcast to the selected interface. A vendor broadcast
    /// leaving through another link discovers devices this vantage cannot see.
    fn probe<'a>(
        &'a self,
        vantage: &'a str,
        binding: &'a SocketBinding,
        timeout: Duration,
    ) -> BroadcastFuture<'a>;
}

/// ASUS Device Discovery, UDP 9999.
pub struct AsusBroadcast;

impl VendorBroadcast for AsusBroadcast {
    fn name(&self) -> &'static str {
        "broadcast:asus"
    }

    fn probe<'a>(
        &'a self,
        _vantage: &'a str,
        _binding: &'a SocketBinding,
        _timeout: Duration,
    ) -> BroadcastFuture<'a> {
        Box::pin(async move {
            // Not sent, and no evidence produced, until the protocol is established.
            //
            // The existing code broadcasts three payloads nobody has verified and then
            // accepts *any* datagram that arrives on the socket: no header, no opcode, no
            // length, no transaction, no correlation with the request, and a model guessed
            // by string prefix out of NUL-separated text. Anything at all on the link
            // answering that port would have produced a device address and a router
            // capability signal built from arbitrary bytes -- a fabrication path rather
            // than a weak signal, and worse than having no adapter.
            //
            // Establishing it needs, from authoritative material or captured known-good
            // traffic: the destination port or ports, including whether 18017 is part of
            // this protocol at all; the request header, opcode and length; the reply
            // header, opcode and length; correlation between request and reply and the
            // sender; the exact offsets of the model, MAC, firmware and address fields;
            // and defined behaviour for malformed and truncated packets.
            BroadcastOutcome::unavailable(crate::probes::asus::UNVERIFIED_FRAMING)
        })
    }
}

/// Every link-local vendor broadcast. Adding a manufacturer means adding an entry here,
/// not a branch in the engine.
pub fn broadcasts() -> Vec<Box<dyn VendorBroadcast>> {
    vec![Box::new(AsusBroadcast)]
}

/// Runs every vendor broadcast on a link. None gates another and none gates recursion.
/// What one pass of the link-local broadcasts produced.
pub struct BroadcastRun {
    pub evidence: Vec<TopologyEvidence>,
    /// One line per broadcast, saying what it managed to do.
    pub outcomes: Vec<String>,
    /// Whether any broadcast reached the wire at all. False means every one was
    /// unavailable or failed to send, and the link's silence proves nothing.
    pub transmitted: bool,
}

pub async fn run_broadcasts(
    vantage: &str,
    binding: &SocketBinding,
    timeout: Duration,
) -> BroadcastRun {
    let mut evidence = Vec::new();
    let mut outcomes = Vec::new();
    let mut transmitted = false;

    for broadcast in broadcasts() {
        let outcome = broadcast.probe(vantage, binding, timeout).await;
        outcomes.push(outcome.describe(broadcast.name()));
        transmitted |= outcome.transmitted();
        evidence.extend(
            outcome
                .evidence()
                .into_iter()
                .filter(|ev| adapter_may_assert(&ev.fact)),
        );
    }

    BroadcastRun {
        evidence,
        outcomes,
        transmitted,
    }
}

/// Every adapter. Order is irrelevant: each runs independently and none gates another.
pub fn adapters() -> Vec<Box<dyn VendorAdapter>> {
    vec![
        Box::new(AsusAdapter),
        Box::new(MikroTikAdapter),
        Box::new(UbiquitiAdapter),
    ]
}

/// Whether a fact is one an adapter is permitted to assert.
///
/// Returning [`TopologyEvidence`] stops an adapter mutating the graph, but on its own it
/// does not stop an adapter asserting topology: a `Network`, a `GatewayFor` or an
/// `AttachedTo` would enter the graph as structure discovered by a proprietary mechanism
/// nothing else can corroborate, and recursion would then follow it. Those are rejected.
///
/// Behavioural facts are permitted, `DeviceRoleSignal` included. A device answering a
/// router-management protocol is behaviour it exhibited, and a signal is not a role: the
/// graph scores it against everything else observed and may still decline to make the
/// device a router. What an adapter cannot do is assign a role directly or invent topology.
fn adapter_may_assert(fact: &Fact) -> bool {
    !matches!(
        fact,
        Fact::Network { .. }
            | Fact::Vlan { .. }
            | Fact::InterfaceNetwork { .. }
            | Fact::GatewayFor { .. }
            | Fact::RoutesTo { .. }
            | Fact::AttachedTo { .. }
            | Fact::BridgeLink { .. }
            | Fact::ObservedBehind { .. }
            | Fact::OpaqueBoundary { .. }
    )
}

/// Names of the adapters a fingerprint selects.
///
/// Reported in coverage so that selection is observable: an adapter that was never chosen
/// and one that was chosen and found nothing are different outcomes.
pub fn selected_adapters(fingerprint: &DeviceFingerprint) -> Vec<String> {
    adapters()
        .iter()
        .filter(|a| a.applies(fingerprint))
        .map(|a| a.name().to_string())
        .collect()
}

/// Runs every applicable adapter against a device.
///
/// Output is filtered rather than trusted. An adapter is a vendor mechanism, often
/// reverse-engineered and rarely corroborated by anything else on the link; letting one
/// assert network structure would make the topology depend on it.
pub struct AdapterRun {
    pub evidence: Vec<TopologyEvidence>,
    /// One line per selected adapter, saying what it managed to do.
    pub outcomes: Vec<String>,
}

pub async fn run_adapters(context: &VendorContext) -> AdapterRun {
    let mut evidence = Vec::new();
    let mut outcomes = Vec::new();

    for adapter in adapters() {
        if !adapter.applies(&context.fingerprint) {
            continue;
        }
        let outcome = adapter.discover(context).await;
        outcomes.push(outcome.describe(adapter.name()));
        evidence.extend(
            outcome
                .evidence()
                .into_iter()
                .filter(|ev| adapter_may_assert(&ev.fact)),
        );
    }

    AdapterRun { evidence, outcomes }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::evidence::{Confidence, EvidenceSource, RoleSignal};

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
    async fn a_stub_adapter_reports_unavailable_and_not_silence() {
        // The claim this corrects. Every adapter here is a stub, and reporting an empty
        // result as "no response" told the operator the device had been asked a
        // vendor-specific question and had declined to answer. No packet was sent.
        let context = VendorContext {
            endpoint: endpoint("10.0.0.1"),
            device: DeviceKey::Address("10.0.0.1".parse().unwrap()),
            fingerprint: fingerprint(Some("ASUSTek Computer")),
            timeout: Duration::from_millis(10),
            vantage: "test0".to_string(),
        };

        let run = run_adapters(&context).await;
        assert!(run.evidence.is_empty());
        assert_eq!(run.outcomes.len(), 1);
        assert!(
            run.outcomes[0].contains("unavailable"),
            "{:?}",
            run.outcomes
        );
        assert!(
            !run.outcomes[0].contains("no response"),
            "a stub must not be reported as a silent device: {:?}",
            run.outcomes
        );
    }

    #[test]
    fn every_registered_adapter_states_its_implementation_status() {
        // A stub that looks like a completed interrogation is worse than no adapter: the
        // coverage report becomes untrue rather than incomplete.
        for adapter in adapters() {
            let _ = adapter.name();
        }
        assert_eq!(adapters().len(), 3, "asus, mikrotik, ubiquiti");
    }

    #[tokio::test]
    async fn an_adapter_that_finds_nothing_yields_no_evidence() {
        // Silence must never become a fact about the device.
        let context = VendorContext {
            endpoint: endpoint("10.0.0.1"),
            device: DeviceKey::Address("10.0.0.1".parse().unwrap()),
            fingerprint: fingerprint(Some("ASUSTek Computer")),
            timeout: Duration::from_millis(10),
            vantage: "test0".to_string(),
        };
        let run = run_adapters(&context).await;
        assert!(run.evidence.is_empty());
    }

    fn endpoint(addr: &str) -> Endpoint {
        Endpoint::global(addr.parse().unwrap())
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

        let mut fingerprint = DeviceFingerprint {
            open_ports: vec![8728],
            ..Default::default()
        };
        fingerprint.absorb_evidence(&evidence);
        assert_eq!(fingerprint.vendor.as_deref(), Some("MikroTik"));
        assert_eq!(fingerprint.descriptions, vec!["RouterOS 7.14".to_string()]);
        assert!(fingerprint.hostnames.is_empty());
        assert!(MikroTikAdapter.applies(&fingerprint));
    }

    #[test]
    fn prior_identity_survives_absorbing_new_evidence() {
        // The manufacturer comes from the ARP table, recorded long before interrogation.
        // Rebuilding the fingerprint from interrogation output alone lost it, and with it
        // every OUI-based adapter selection.
        let mut fingerprint = DeviceFingerprint {
            vendor: Some("ASUSTek Computer Inc.".to_string()),
            ..Default::default()
        };
        assert!(AsusAdapter.applies(&fingerprint));

        // Interrogation found nothing that names the device. Selection must be unchanged.
        fingerprint.absorb_evidence(&[]);
        assert!(AsusAdapter.applies(&fingerprint));
    }

    #[test]
    fn an_adapter_cannot_assert_network_structure() {
        // Filtering the output is what stops a proprietary mechanism inventing topology
        // that nothing else on the link can corroborate.
        let device = DeviceKey::Address("10.0.0.4".parse().unwrap());
        assert!(!adapter_may_assert(&Fact::Network {
            prefix: "10.9.0.0/24".parse().unwrap(),
        }));
        assert!(!adapter_may_assert(&Fact::GatewayFor {
            device: device.clone(),
            network: "10.9.0.0/24".parse().unwrap(),
        }));

        // Behaviour is permitted: a signal is scored by the graph, not obeyed by it.
        assert!(adapter_may_assert(&Fact::DeviceRoleSignal {
            device: device.clone(),
            signal: RoleSignal::LinkLayerCapability("Router"),
        }));
        assert!(adapter_may_assert(&Fact::DeviceDescription {
            device,
            text: "RT-AX88U".to_string(),
        }));
    }

    #[tokio::test]
    async fn the_asus_broadcast_produces_no_evidence_until_its_framing_is_verified() {
        // What this prevents. The previous implementation broadcast three unverified
        // payloads and accepted any datagram that arrived: no header, no opcode, no
        // length, no correlation, and a model guessed by string prefix. Anything on the
        // link answering that port would have become a router discovery built from
        // arbitrary bytes.
        let run = run_broadcasts(
            "test0",
            &crate::net::socket::SocketBinding::unbound(),
            Duration::from_millis(10),
        )
        .await;

        assert!(run.evidence.is_empty());
        assert_eq!(run.outcomes.len(), 1);
        assert!(
            run.outcomes[0].contains("unavailable"),
            "{:?}",
            run.outcomes
        );
        assert!(
            !run.outcomes[0].contains("no response"),
            "an unverified protocol must not be reported as a silent link: {:?}",
            run.outcomes
        );
    }

    #[test]
    fn a_broadcast_outcome_distinguishes_every_failure_mode() {
        // Collapsing these loses what an operator needs: an unverified protocol, a socket
        // that could not be opened, a link that stayed quiet and bytes that failed
        // validation are four different findings.
        let sent = "UDP 9999".to_string();
        let cases = [
            BroadcastOutcome::unavailable("framing unverified"),
            BroadcastOutcome::not_sent("no IPv4 source address"),
            BroadcastOutcome::NoResponse { sent: sent.clone() },
            BroadcastOutcome::InvalidResponse {
                sent: sent.clone(),
                rejected: 2,
            },
            BroadcastOutcome::Answered {
                sent,
                evidence: Vec::new(),
            },
        ];

        let described: Vec<String> = cases.iter().map(|c| c.describe("broadcast:test")).collect();
        for (index, text) in described.iter().enumerate() {
            for (other, previous) in described.iter().enumerate() {
                assert!(index == other || text != previous, "{text} is ambiguous");
            }
        }
        assert!(described[0].contains("unavailable"));
        assert!(described[1].contains("not sent"));
        assert!(described[2].contains("no response"));
        assert!(described[3].contains("failed validation"));
        assert!(described[4].contains("answered"));

        // Only a validated answer may carry evidence.
        for case in cases {
            let answered = matches!(case, BroadcastOutcome::Answered { .. });
            assert!(case.evidence().is_empty() || answered);
        }
    }

    #[tokio::test]
    async fn adapters_never_run_for_an_unknown_device() {
        let context = VendorContext {
            endpoint: endpoint("10.0.0.2"),
            device: DeviceKey::Address("10.0.0.2".parse().unwrap()),
            fingerprint: DeviceFingerprint::default(),
            timeout: Duration::from_millis(10),
            vantage: "test0".to_string(),
        };
        let run = run_adapters(&context).await;
        assert!(run.evidence.is_empty());
    }
}
