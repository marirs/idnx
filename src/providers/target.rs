//! Per-device interrogation, in stages.
//!
//! Every device the engine discovers runs through this pipeline -- not only pivots with
//! routing evidence and not only candidates that look like network equipment. Restricting
//! interrogation to devices already believed to be infrastructure was circular: a device
//! needed evidence to be asked, and asking was how that evidence was obtained.
//!
//! Work is staged so that breadth is paid for only where it can return something.
//!
//! * Stage 1 is cheap and universal: a small TCP set plus the credential-free UDP control
//!   plane. Every device gets this.
//! * Stage 2 broadens the TCP set. It runs for a device that answered anything in stage 1,
//!   and for pivots and candidates regardless, because a silent appliance is exactly the
//!   case worth pushing on.
//! * Stage 3 is protocol handshakes against ports that actually answered, plus any vendor
//!   adapter the device's own disclosures selected.
//!
//! Two rules hold throughout. An open port is not a service: TCP reachability and protocol
//! confirmation are recorded as separate facts, and nothing is named from its conventional
//! port number alone. And coverage is reported per device, so "we asked and got nothing" is
//! distinguishable from "we never asked" and from "it refused without credentials".

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::DiscoveryContext;
use crate::net::endpoint::Endpoint;
use crate::net::socket::SocketBinding;
use crate::topology::TopologyEvidence;
use crate::topology::evidence::{
    Capability, Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal,
};

/// Stage 1: common services, probed against every device.
///
/// Small on purpose. This is the only port work a quiet host on a large subnet costs.
pub const STAGE_ONE_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 139, 161, 443, 445, 554, 1234, 8000, 8080, 8443, 9100, 11434,
];

/// Stage 2: the broader set, for devices worth pushing on.
///
/// Management, embedded-appliance and vendor-API ports. Disjoint from stage 1 so no port is
/// probed twice.
pub const STAGE_TWO_PORTS: &[u16] = &[
    81, 88, 110, 143, 389, 515, 548, 587, 631, 873, 902, 993, 995, 1080, 1883, 2000, 2049, 3000,
    3128, 3306, 3389, 4443, 5000, 5001, 5060, 5222, 5357, 5432, 5900, 6379, 7547, 8006, 8008, 8081,
    8123, 8181, 8728, 8888, 9000, 9090, 9200, 10000, 32400, 49152, 49153,
];

/// UDP control-plane probes, which need no open TCP port to reach a device.
const CONTROL_PLANE_UDP_PORTS: &[u16] = &[crate::probes::natpmp::NAT_PMP_PORT, 53];

/// Why a device is being interrogated.
///
/// This changes scheduling order and nothing else. It does not reduce the work a device
/// receives, and it never decides what a device's answers mean: role and confidence still
/// come from the evidence alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTier {
    /// Positive routing or bridging evidence already exists for this device.
    EstablishedPivot,
    /// Weak hints only -- an unfamiliar appliance, a router-ish name, several addresses.
    Candidate,
    /// No infrastructure signal. Enriched identically, because that is how one appears.
    Host,
}

impl DeviceTier {
    pub fn label(&self) -> &'static str {
        match self {
            DeviceTier::EstablishedPivot => "pivot",
            DeviceTier::Candidate => "candidate",
            DeviceTier::Host => "host",
        }
    }

    /// Scheduling order. Infrastructure first, so that what a pivot discloses can extend
    /// the same pass rather than forcing another.
    pub fn priority(&self) -> u8 {
        match self {
            DeviceTier::EstablishedPivot => 0,
            DeviceTier::Candidate => 1,
            DeviceTier::Host => 2,
        }
    }
}

impl fmt::Display for DeviceTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One device to interrogate, with everything already known about it.
///
/// Keyed by device rather than by address. A dual-stack device has several addresses and is
/// one device: interrogating each address separately probed the same machine repeatedly and
/// produced several coverage records for it, which would compound badly once federation
/// merges records from several vantages.
#[derive(Debug, Clone)]
pub struct InterrogationTarget {
    /// Canonical identity, as the graph knows it.
    pub device: DeviceKey,
    pub tier: DeviceTier,
    /// Reachable addresses, most preferred first. A global or ULA address is preferred over
    /// a link-local one, and the link-local ones keep the zone they were seen on.
    pub endpoints: Vec<Endpoint>,
    /// Identity the graph already holds -- OUI manufacturer, hostnames, descriptions.
    ///
    /// Vendor adapters are selected from this together with anything interrogation adds.
    /// Selecting from the interrogation output alone lost every OUI, because the
    /// manufacturer was recorded when the device was first seen, long before this runs.
    pub known: crate::providers::vendor::DeviceFingerprint,
    /// How the device became known.
    pub discovery_sources: Vec<String>,
    /// Whether liveness is already established -- an ARP or NDP entry, a captured frame, an
    /// ICMP reply, or any TCP response. A live device is explored in full even when its
    /// stage 1 ports are all silent, because a device whose only service is on a stage 2
    /// port would otherwise be missed entirely.
    pub confirmed_live: bool,
}

/// What was probed at one address, and what answered.
#[derive(Debug, Clone)]
pub struct EndpointCoverage {
    pub endpoint: String,
    /// The address the full stage set ran against.
    pub primary: bool,
    pub stages_run: u8,
    pub tcp_attempted: usize,
    pub tcp_responsive: Vec<u16>,
    /// Probes that never left this machine, with the local error and how many ports it
    /// affected. Kept apart from responsiveness: a socket that could not be bound says
    /// nothing whatever about the device on the other end.
    pub not_sent: Vec<(String, usize)>,
    /// Set when fewer than all stages ran here, saying which were omitted and why.
    pub omitted: Option<String>,
}

/// What was actually attempted against one device, and what came back.
///
/// Exists so that a device reported as yielding nothing can be told apart from one that was
/// never asked. "Target enrichment: no response" answered neither question. One record per
/// device, however many addresses it has.
#[derive(Debug, Clone)]
pub struct DeviceCoverage {
    pub device: DeviceKey,
    /// Every address considered, whether or not it was probed.
    pub addresses: Vec<String>,
    pub tier: DeviceTier,
    /// How the device came to be known, from the evidence already in the graph.
    pub discovery_sources: Vec<String>,
    /// Per-address detail, so an omission at one address is visible rather than averaged.
    pub endpoints: Vec<EndpointCoverage>,
    pub udp_attempted: Vec<u16>,
    /// Protocols confirmed by handshake, not guessed from a port number.
    pub protocols_confirmed: Vec<String>,
    /// Ports that refused without credentials -- a positive finding, not an absence.
    pub auth_required: Vec<u16>,
    /// Vendor adapters this device's fingerprint selected. An adapter never chosen and one
    /// chosen that found nothing are different outcomes, so selection is reported.
    pub vendor_adapters: Vec<String>,
    /// Set when the device was not interrogated at all, saying why.
    pub skipped: Option<String>,
    pub elapsed: Duration,
}

impl DeviceCoverage {
    fn skipped(device: DeviceKey, tier: DeviceTier, reason: impl Into<String>) -> Self {
        Self {
            device,
            addresses: Vec::new(),
            tier,
            discovery_sources: Vec::new(),
            endpoints: Vec::new(),
            udp_attempted: Vec::new(),
            protocols_confirmed: Vec::new(),
            auth_required: Vec::new(),
            vendor_adapters: Vec::new(),
            skipped: Some(reason.into()),
            elapsed: Duration::ZERO,
        }
    }

    /// Address the full stage set ran against, for display.
    pub fn primary_endpoint(&self) -> Option<&str> {
        self.endpoints
            .iter()
            .find(|e| e.primary)
            .map(|e| e.endpoint.as_str())
    }

    pub fn tcp_attempted(&self) -> usize {
        self.endpoints.iter().map(|e| e.tcp_attempted).sum()
    }

    pub fn tcp_responsive(&self) -> usize {
        self.endpoints.iter().map(|e| e.tcp_responsive.len()).sum()
    }

    /// Probes that never left this machine.
    pub fn not_sent(&self) -> usize {
        self.endpoints
            .iter()
            .flat_map(|e| e.not_sent.iter())
            .map(|(_, count)| count)
            .sum()
    }

    /// Local failures, one line each, for reporting.
    pub fn local_failures(&self) -> Vec<String> {
        self.endpoints
            .iter()
            .flat_map(|e| {
                e.not_sent.iter().map(move |(reason, count)| {
                    format!("{}: {count} probe(s) not sent: {reason}", e.endpoint)
                })
            })
            .collect()
    }

    /// Highest stage reached at any address.
    pub fn stages_run(&self) -> u8 {
        self.endpoints
            .iter()
            .map(|e| e.stages_run)
            .max()
            .unwrap_or(0)
    }

    /// Exactly what was left out, if anything. Reported rather than glossed, so a run is
    /// never described as complete exploration when it was not.
    pub fn omissions(&self) -> Vec<String> {
        self.endpoints
            .iter()
            .filter_map(|e| {
                e.omitted
                    .as_ref()
                    .map(|reason| format!("{}: {reason}", e.endpoint))
            })
            .collect()
    }

    /// True when the device answered nothing at all despite being asked.
    ///
    /// Distinct from being skipped: this device was reachable enough to probe and stayed
    /// silent, which is a fact about it rather than a gap in coverage.
    pub fn silent(&self) -> bool {
        self.skipped.is_none()
            && self.tcp_responsive() == 0
            && self.auth_required.is_empty()
            // A device whose probes never left this machine was not asked anything, so it
            // cannot have been silent.
            && self.not_sent() == 0
    }

    /// One-line summary for the coverage report.
    pub fn summary(&self) -> String {
        if let Some(reason) = &self.skipped {
            return format!("skipped: {reason}");
        }
        let mut parts = vec![format!(
            "{}/{} tcp responsive",
            self.tcp_responsive(),
            self.tcp_attempted()
        )];
        if self.not_sent() > 0 {
            parts.push(format!("{} not sent locally", self.not_sent()));
        }
        if !self.udp_attempted.is_empty() {
            parts.push(format!("{} udp attempted", self.udp_attempted.len()));
        }
        if !self.protocols_confirmed.is_empty() {
            parts.push(format!("confirmed {}", self.protocols_confirmed.join(", ")));
        }
        if !self.auth_required.is_empty() {
            let ports: Vec<String> = self.auth_required.iter().map(|p| p.to_string()).collect();
            parts.push(format!("auth required on {}", ports.join(", ")));
        }
        format!(
            "{} stage(s), {}, {}ms",
            self.stages_run(),
            parts.join("; "),
            self.elapsed.as_millis()
        )
    }
}

/// Interrogates one device across every applicable protocol and address family.
pub async fn interrogate_device(
    target: &InterrogationTarget,
    context: &DiscoveryContext,
) -> (Vec<TopologyEvidence>, DeviceCoverage) {
    let Some(primary) = target.endpoints.first().cloned() else {
        return (
            Vec::new(),
            DeviceCoverage::skipped(
                target.device.clone(),
                target.tier,
                "no reachable address: the device is known only by link-layer identity",
            ),
        );
    };

    let started = Instant::now();
    let mut coverage = DeviceCoverage {
        device: target.device.clone(),
        addresses: target.endpoints.iter().map(|e| e.to_string()).collect(),
        tier: target.tier,
        discovery_sources: target.discovery_sources.clone(),
        endpoints: Vec::new(),
        udp_attempted: Vec::new(),
        protocols_confirmed: Vec::new(),
        auth_required: Vec::new(),
        vendor_adapters: Vec::new(),
        skipped: None,
        elapsed: Duration::ZERO,
    };

    let vantage = &context.vantage.interface;
    let device = target.device.clone();
    let timeout = context.timeout.max(Duration::from_millis(400));
    let mut out = Vec::new();

    // Stage 1 on the preferred address.
    let stage_one = sweep_ports(&primary, STAGE_ONE_PORTS, context, timeout).await;
    let mut open_ports = stage_one.open;
    let mut primary_coverage = EndpointCoverage {
        endpoint: primary.to_string(),
        primary: true,
        stages_run: 1,
        tcp_attempted: STAGE_ONE_PORTS.len(),
        tcp_responsive: Vec::new(),
        not_sent: stage_one.not_sent,
        omitted: None,
    };

    // The UDP control plane needs no open TCP port, and NAT-PMP is IPv4 by definition.
    if primary.is_ipv4() {
        coverage.udp_attempted.extend(CONTROL_PLANE_UDP_PORTS);
        out.extend(
            probe_control_plane(
                &primary,
                &device,
                &context.binding,
                timeout,
                vantage,
                &mut coverage,
            )
            .await,
        );
    }

    // Stage 2 broadens. It runs for any device already known to be alive -- an ARP or NDP
    // entry, a captured frame, an ICMP reply, a TCP response -- and not only for one that
    // answered a stage 1 port. A live host whose single service sits on 8728 or 32400 was
    // otherwise probed on seventeen ports and declared silent.
    let broaden = target.confirmed_live || !open_ports.is_empty();
    if broaden {
        primary_coverage.stages_run = 2;
        primary_coverage.tcp_attempted += STAGE_TWO_PORTS.len();
        let stage_two = sweep_ports(&primary, STAGE_TWO_PORTS, context, timeout).await;
        open_ports.extend(stage_two.open);
        merge_failures(&mut primary_coverage.not_sent, stage_two.not_sent);
    } else {
        primary_coverage.omitted = Some(format!(
            "stage 2 ({} ports) not run: liveness never confirmed and no stage 1 port answered",
            STAGE_TWO_PORTS.len()
        ));
    }
    open_ports.sort_unstable();
    open_ports.dedup();
    primary_coverage.tcp_responsive = open_ports.clone();

    // An open port is reachability, not identity. Recorded as its own fact so a later
    // protocol confirmation can be told apart from a mere guess by port number.
    for &port in &open_ports {
        out.push(
            TopologyEvidence::new(
                Fact::Service {
                    address: primary.address,
                    port,
                    protocol: "tcp",
                    detail: None,
                },
                EvidenceSource::TcpProbe,
                Confidence::Observed,
                vantage,
            )
            .with_detail("TCP port open; protocol not yet confirmed".to_string()),
        );
    }

    // Stage 3: confirm what actually speaks on the ports that answered.
    if !open_ports.is_empty() {
        primary_coverage.stages_run = 3;
        out.extend(
            confirm_protocols(
                &primary,
                &device,
                &open_ports,
                &context.binding,
                timeout,
                vantage,
                &mut coverage,
            )
            .await,
        );
        out.extend(
            crate::providers::ai::probe_ai_services(
                &primary,
                &device,
                &open_ports,
                &context.binding,
                timeout.max(Duration::from_millis(600)),
                vantage,
            )
            .await,
        );
    }
    coverage.endpoints.push(primary_coverage);

    // Other address families the same device answers on. Stage 1 only: this is one device,
    // and repeating the full set at every address would probe the same machine several
    // times over. What it does catch is a service bound to one family alone.
    for endpoint in target.endpoints.iter().skip(1) {
        let secondary = sweep_ports(endpoint, STAGE_ONE_PORTS, context, timeout).await;
        let responsive = secondary.open;
        for &port in &responsive {
            out.push(
                TopologyEvidence::new(
                    Fact::Service {
                        address: endpoint.address,
                        port,
                        protocol: "tcp",
                        detail: None,
                    },
                    EvidenceSource::TcpProbe,
                    Confidence::Observed,
                    vantage,
                )
                .with_detail("TCP port open; protocol not yet confirmed".to_string()),
            );
        }
        coverage.endpoints.push(EndpointCoverage {
            endpoint: endpoint.to_string(),
            primary: false,
            stages_run: 1,
            tcp_attempted: STAGE_ONE_PORTS.len(),
            tcp_responsive: responsive,
            not_sent: secondary.not_sent,
            omitted: Some(format!(
                "stages 2-3 ({} ports) run only at {primary}, the preferred address for this device",
                STAGE_TWO_PORTS.len()
            )),
        });
    }

    // Vendor adapters, chosen from what the graph already knew about the device together
    // with what interrogation just added. Selecting from the interrogation output alone
    // lost the manufacturer, which is recorded when a device is first seen. Optional
    // throughout -- no adapter is required, none gates recursion, and a device that selects
    // none (unknown manufacturer, white-label or randomized MAC, or a software router on
    // generic hardware) is mapped identically by the standard protocols.
    let mut fingerprint = target.known.clone();
    fingerprint.absorb_evidence(&out);
    fingerprint.open_ports = open_ports.clone();
    coverage.vendor_adapters = crate::providers::vendor::selected_adapters(&fingerprint);
    out.extend(
        crate::providers::vendor::run_adapters(&crate::providers::vendor::VendorContext {
            endpoint: primary.clone(),
            device,
            fingerprint,
            timeout,
            vantage: vantage.to_string(),
        })
        .await,
    );

    coverage.elapsed = started.elapsed();
    (out, coverage)
}

/// Folds one sweep's local failures into another's.
fn merge_failures(into: &mut Vec<(String, usize)>, more: Vec<(String, usize)>) {
    for (reason, count) in more {
        match into.iter_mut().find(|(existing, _)| *existing == reason) {
            Some((_, total)) => *total += count,
            None => into.push((reason, count)),
        }
    }
}

/// Probes a port set concurrently, drawing on the run-wide probe budget.
/// Result of probing a port set: what answered, and what never left this machine.
struct SweepResult {
    open: Vec<u16>,
    /// Distinct local failures, with how many ports each affected. A source address that
    /// does not exist fails every port identically; reporting it once is enough.
    not_sent: Vec<(String, usize)>,
}

async fn sweep_ports(
    target: &Endpoint,
    ports: &[u16],
    context: &DiscoveryContext,
    timeout: Duration,
) -> SweepResult {
    let mut tasks = Vec::with_capacity(ports.len());
    for &port in ports {
        let permits = Arc::clone(&context.probe_permits);
        let binding = Arc::clone(&context.binding);
        let socket = target.socket_addr(port);
        tasks.push(tokio::spawn(async move {
            let _hold = permits.acquire().await.ok()?;
            let probe = crate::engine::scanner::probe_tcp_socket(socket, &binding, timeout).await;
            Some((port, probe.status, probe.local_error))
        }));
    }

    let mut open = Vec::new();
    let mut failures: std::collections::BTreeMap<String, usize> = Default::default();
    for task in tasks {
        let Ok(Some((port, status, local_error))) = task.await else {
            continue;
        };
        match status {
            crate::engine::scanner::PortStatus::Open => open.push(port),
            // A probe that never left this machine says nothing about the device. Counting
            // it as silence reported a local misconfiguration as a quiet host.
            crate::engine::scanner::PortStatus::NotSent => {
                *failures
                    .entry(local_error.unwrap_or_else(|| "socket unavailable".to_string()))
                    .or_default() += 1;
            }
            _ => {}
        }
    }

    SweepResult {
        open,
        not_sent: failures.into_iter().collect(),
    }
}

/// Confirms protocols on ports that answered.
#[allow(clippy::too_many_arguments)]
async fn confirm_protocols(
    target: &Endpoint,
    device: &DeviceKey,
    open_ports: &[u16],
    binding: &SocketBinding,
    timeout: Duration,
    vantage: &str,
    coverage: &mut DeviceCoverage,
) -> Vec<TopologyEvidence> {
    let address = target.address;
    let mut out = Vec::new();

    // TLS: the certificate names the device far more reliably than any banner.
    for &port in open_ports {
        if !matches!(port, 443 | 8443 | 4443 | 993 | 995 | 8006 | 32400) {
            continue;
        }
        if let Some(cert) =
            crate::probes::tls::probe_tls_certificate(target, port, binding, timeout).await
        {
            coverage.protocols_confirmed.push(format!("tls/{port}"));
            let common_name = cert.common_name.clone().unwrap_or_default();
            let mut description = if common_name.is_empty() {
                "TLS certificate presented".to_string()
            } else {
                format!("TLS certificate subject {common_name}")
            };
            if !cert.alt_names.is_empty() {
                description.push_str(&format!(" (SAN: {})", cert.alt_names.join(", ")));
            }
            if let Some(issuer) = cert.issuer_cn.clone() {
                description.push_str(&format!(" issued by {issuer}"));
            }
            out.push(TopologyEvidence::new(
                Fact::DeviceDescription {
                    device: device.clone(),
                    text: description.clone(),
                },
                EvidenceSource::TcpProbe,
                // The certificate is the device's own assertion of its identity.
                Confidence::Advertised,
                vantage,
            ));
            out.push(TopologyEvidence::new(
                Fact::Service {
                    address,
                    port,
                    protocol: "tcp",
                    detail: Some(if common_name.is_empty() {
                        "TLS".to_string()
                    } else {
                        format!("TLS: {common_name}")
                    }),
                },
                EvidenceSource::TcpProbe,
                Confidence::Observed,
                vantage,
            ));

            // A certificate naming a host is a name for that device.
            // A certificate subject that looks like a hostname is a name; one containing
            // spaces is an organization name and must not be used as one.
            if !common_name.is_empty() && !common_name.contains(' ') {
                out.push(TopologyEvidence::new(
                    Fact::DeviceHostname {
                        device: device.clone(),
                        hostname: common_name.clone(),
                    },
                    EvidenceSource::TcpProbe,
                    Confidence::Advertised,
                    vantage,
                ));
            }
        }
    }

    // SMB identity: hostname and domain, which no port number could tell us.
    if open_ports.contains(&445) || open_ports.contains(&139) {
        let port = if open_ports.contains(&445) { 445 } else { 139 };
        if let Some(smb) = crate::probes::smb::probe_smb(target, port, binding, timeout).await {
            coverage.protocols_confirmed.push(format!("smb/{port}"));
            if let Some(name) = smb.dns_computer_name.clone().or(smb.computer_name.clone()) {
                out.push(TopologyEvidence::new(
                    Fact::DeviceHostname {
                        device: device.clone(),
                        hostname: name,
                    },
                    EvidenceSource::TcpProbe,
                    Confidence::Advertised,
                    vantage,
                ));
            }
            if let Some(domain) = smb.dns_domain_name.clone().or(smb.domain_name.clone()) {
                out.push(TopologyEvidence::new(
                    Fact::DeviceDescription {
                        device: device.clone(),
                        text: format!("SMB domain {domain}"),
                    },
                    EvidenceSource::TcpProbe,
                    Confidence::Advertised,
                    vantage,
                ));
            }
            out.push(TopologyEvidence::new(
                Fact::Service {
                    address,
                    port,
                    protocol: "tcp",
                    detail: Some("SMB (negotiate confirmed)".to_string()),
                },
                EvidenceSource::TcpProbe,
                Confidence::Observed,
                vantage,
            ));
        }
    }

    // DNS over TCP, for a resolver that answers only there. UDP was already attempted in
    // the control plane, so this runs only when that found nothing.
    if open_ports.contains(&53)
        && !coverage
            .protocols_confirmed
            .iter()
            .any(|p| p.starts_with("dns/"))
        && let Some(identity) = crate::probes::dns::confirm_dns_tcp(target, binding, timeout).await
    {
        out.extend(dns_evidence(target, device, &identity, vantage, coverage));
    }

    // HTTP: the status line, Server header and page title are the device describing
    // itself, and on consumer gear they are often the only identity available without
    // credentials. A challenge for credentials is recorded as a finding in its own right.
    for &port in open_ports {
        if !crate::probes::http::HTTP_PORTS.contains(&port) {
            continue;
        }
        let Some(identity) = crate::probes::http::probe_http(target, port, binding, timeout).await
        else {
            continue;
        };
        coverage.protocols_confirmed.push(format!("http/{port}"));
        if identity.requires_authentication() {
            coverage.auth_required.push(port);
        }
        if let Some(text) = identity.description() {
            out.push(TopologyEvidence::new(
                Fact::Service {
                    address,
                    port,
                    protocol: "tcp",
                    detail: Some(text.clone()),
                },
                EvidenceSource::TcpProbe,
                Confidence::Observed,
                vantage,
            ));
            // The server's own words about itself, which is an assertion rather than an
            // observation of behaviour.
            out.push(TopologyEvidence::new(
                Fact::DeviceDescription {
                    device: device.clone(),
                    text,
                },
                EvidenceSource::TcpProbe,
                Confidence::Advertised,
                vantage,
            ));
        }
        if identity.requires_authentication() {
            out.push(
                TopologyEvidence::new(
                    Fact::DeviceCapability {
                        device: device.clone(),
                        capability: Capability::ManagementInterface,
                        detail: Some(format!("authenticated HTTP interface on port {port}")),
                    },
                    EvidenceSource::TcpProbe,
                    Confidence::Observed,
                    vantage,
                )
                .with_detail("refused without credentials"),
            );
        }
    }

    out
}

/// Probes that reach a device without needing a TCP service.
async fn probe_control_plane(
    target: &Endpoint,
    device: &DeviceKey,
    binding: &SocketBinding,
    timeout: Duration,
    vantage: &str,
    coverage: &mut DeviceCoverage,
) -> Vec<TopologyEvidence> {
    let mut out = Vec::new();
    // NAT-PMP is defined over IPv4 only; the caller gates on this already.
    let crate::net::endpoint::Endpoint {
        address: std::net::IpAddr::V4(v4),
        ..
    } = target
    else {
        return out;
    };
    let v4 = *v4;

    // NAT-PMP: only a NAT gateway answers, so a reply is direct role evidence and needs no
    // credentials. This reaches routers that expose no TCP service at all.
    if let Some(external) = crate::probes::natpmp::probe_nat_gateway(v4, binding, timeout).await {
        coverage.protocols_confirmed.push("nat-pmp".to_string());
        out.push(
            TopologyEvidence::new(
                Fact::DeviceCapability {
                    device: device.clone(),
                    capability: Capability::NatGateway,
                    detail: Some("answered NAT-PMP".to_string()),
                },
                EvidenceSource::NatPmp,
                Confidence::Observed,
                vantage,
            )
            .with_detail(match external {
                Some(addr) => format!("external address {addr}"),
                None => "no external address disclosed".to_string(),
            }),
        );
        out.push(TopologyEvidence::new(
            Fact::DeviceRoleSignal {
                device: device.clone(),
                signal: RoleSignal::ObservedForwarding,
            },
            EvidenceSource::NatPmp,
            Confidence::Observed,
            vantage,
        ));
    }

    // RIP: the one routing protocol a router will describe its tables to without
    // credentials. A response carries real prefixes with real netmasks, which is
    // prefix-bearing evidence in the strict sense -- the network exists because a router
    // said so in a protocol field, not because anything was inferred from an address.
    //
    // Unicast and read-only. A request carries no routes and cannot install anything, and
    // no authentication is attempted. RIPng is not sent here: it is IPv6 and link-scoped,
    // and addressing it to an IPv4 router found on a path would be sending a protocol to
    // something that cannot speak it.
    coverage.udp_attempted.push(crate::probes::rip::RIP_PORT);
    if let Some(routes) = crate::probes::rip::request_table(v4, binding, timeout).await {
        coverage.protocols_confirmed.push("rip/520".to_string());
        for route in routes {
            // A metric of 16 is RIP announcing that a route is gone. Recording it would
            // add a network the router just said it cannot reach.
            if !route.is_reachable() {
                continue;
            }

            out.push(
                TopologyEvidence::new(
                    Fact::Network {
                        prefix: route.prefix,
                    },
                    EvidenceSource::Rip,
                    // The router asserted this. It is not something this vantage saw.
                    Confidence::Advertised,
                    vantage,
                )
                .with_detail(route.evidence()),
            );

            out.push(
                TopologyEvidence::new(
                    Fact::RoutesTo {
                        device: device.clone(),
                        network: route.prefix,
                        next_hop: route.next_hop,
                    },
                    EvidenceSource::Rip,
                    Confidence::Advertised,
                    vantage,
                )
                .with_detail(route.evidence()),
            );
        }

        out.push(TopologyEvidence::new(
            Fact::DeviceRoleSignal {
                device: device.clone(),
                signal: RoleSignal::SnmpForwarding,
            },
            EvidenceSource::Rip,
            Confidence::Observed,
            vantage,
        ));
    }

    // DNS over UDP, attempted regardless of whether TCP 53 answered. Gating confirmation
    // on an open TCP port missed every UDP-only resolver and every device with TCP 53
    // filtered -- between them, most resolvers on a home or office network. An open port
    // is reachability, not a protocol; this asks an actual question and requires a
    // well-formed answer carrying the transaction id it sent.
    if let Some(identity) = crate::probes::dns::confirm_dns_udp(target, binding, timeout).await {
        out.extend(dns_evidence(target, device, &identity, vantage, coverage));
    }

    out
}

/// Builds the evidence for a confirmed resolver.
///
/// The transport is recorded rather than assumed: labelling a UDP-only resolver's service
/// "tcp" would be false, and it is exactly the common case.
fn dns_evidence(
    target: &Endpoint,
    device: &DeviceKey,
    identity: &crate::probes::dns::DnsIdentity,
    vantage: &str,
    coverage: &mut DeviceCoverage,
) -> Vec<TopologyEvidence> {
    let transport = identity.transport.label();
    coverage
        .protocols_confirmed
        .push(format!("dns/53/{transport}"));

    let detail = match &identity.version {
        Some(version) => format!("answered a DNS query over {transport} ({version})"),
        None => format!(
            "answered a DNS query over {transport} (rcode {})",
            identity.response_code
        ),
    };

    vec![
        TopologyEvidence::new(
            Fact::DeviceCapability {
                device: device.clone(),
                capability: Capability::DnsServer,
                detail: Some(detail.clone()),
            },
            EvidenceSource::UnicastDns,
            Confidence::Observed,
            vantage,
        ),
        TopologyEvidence::new(
            Fact::Service {
                address: target.address,
                port: 53,
                protocol: transport,
                detail: Some(detail),
            },
            EvidenceSource::UnicastDns,
            Confidence::Observed,
            vantage,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{Vantage, VantageKind};

    fn ctx() -> DiscoveryContext {
        DiscoveryContext::seed(
            Vantage {
                interface: "test0".to_string(),
                kind: VantageKind::Wired,
                index: 0,
                capture_available: false,
            },
            Duration::from_millis(50),
            8,
        )
    }

    #[test]
    fn the_two_stages_do_not_overlap() {
        // A port in both sets would be probed twice against the same device, which is the
        // duplication this staging exists to remove.
        for port in STAGE_ONE_PORTS {
            assert!(
                !STAGE_TWO_PORTS.contains(port),
                "port {port} is in both stages"
            );
        }
    }

    #[test]
    fn stage_one_stays_small_and_stage_two_carries_the_breadth() {
        // Stage 1 is what an unreachable address costs, so it must stay cheap.
        assert!(STAGE_ONE_PORTS.len() <= 20);
        assert!(STAGE_TWO_PORTS.len() > STAGE_ONE_PORTS.len());
        assert!(STAGE_TWO_PORTS.contains(&7547), "TR-069 management");
        assert!(STAGE_TWO_PORTS.contains(&8728), "MikroTik API");
        assert!(STAGE_TWO_PORTS.contains(&49152), "UPnP dynamic range");
    }

    #[test]
    fn each_stage_is_sorted_and_free_of_duplicates() {
        for stage in [STAGE_ONE_PORTS, STAGE_TWO_PORTS] {
            let mut sorted = stage.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                sorted.as_slice(),
                stage,
                "a duplicate or unsorted port would probe the same service twice"
            );
        }
    }

    #[test]
    fn tier_orders_the_queue_and_nothing_else() {
        // It must not reduce coverage: that is decided by confirmed liveness.
        assert!(DeviceTier::EstablishedPivot.priority() < DeviceTier::Candidate.priority());
        assert!(DeviceTier::Candidate.priority() < DeviceTier::Host.priority());
    }

    #[tokio::test]
    async fn a_device_with_no_reachable_address_is_reported_as_skipped() {
        // Known by MAC alone. Claiming to have interrogated it would report coverage that
        // never happened.
        let (evidence, coverage) = interrogate_device(
            &InterrogationTarget {
                device: DeviceKey::mac("02:00:5e:00:00:01"),
                tier: DeviceTier::Host,
                endpoints: Vec::new(),
                known: Default::default(),
                discovery_sources: Vec::new(),
                confirmed_live: true,
            },
            &ctx(),
        )
        .await;
        assert!(evidence.is_empty());
        assert_eq!(coverage.stages_run(), 0);
        assert!(coverage.skipped.expect("a reason").contains("no reachable"));
    }

    #[test]
    fn coverage_distinguishes_silence_from_never_having_asked() {
        let device = DeviceKey::Address("10.0.0.9".parse().unwrap());

        let skipped = DeviceCoverage::skipped(device.clone(), DeviceTier::Host, "out of scope");
        assert!(!skipped.silent());
        assert!(skipped.summary().starts_with("skipped: out of scope"));

        let mut asked = DeviceCoverage::skipped(device, DeviceTier::Host, "x");
        asked.skipped = None;
        asked.endpoints.push(EndpointCoverage {
            endpoint: "10.0.0.9".to_string(),
            primary: true,
            stages_run: 2,
            tcp_attempted: 62,
            tcp_responsive: Vec::new(),
            not_sent: Vec::new(),
            omitted: None,
        });
        assert!(asked.silent());
        assert!(asked.summary().contains("0/62 tcp responsive"));

        // A device that refused without credentials answered; it was not silent.
        asked.auth_required.push(80);
        assert!(!asked.silent());
        assert!(asked.summary().contains("auth required on 80"));
    }

    #[test]
    fn a_probe_that_never_left_this_machine_is_not_remote_silence() {
        // The regression this guards: an interface with no source address in the
        // destination's family failed every probe locally in microseconds, and the device
        // was reported as "asked, no response on any probed port".
        let mut coverage =
            DeviceCoverage::skipped(DeviceKey::mac("02:00:5e:00:00:03"), DeviceTier::Host, "x");
        coverage.skipped = None;
        coverage.endpoints.push(EndpointCoverage {
            endpoint: "fe80::1%en0".to_string(),
            primary: true,
            stages_run: 2,
            tcp_attempted: 62,
            tcp_responsive: Vec::new(),
            not_sent: vec![("no IPv6 source address".to_string(), 62)],
            omitted: None,
        });

        assert_eq!(coverage.not_sent(), 62);
        assert!(
            !coverage.silent(),
            "nothing was asked, so nothing was silent"
        );
        assert!(coverage.summary().contains("62 not sent locally"));

        let failures = coverage.local_failures();
        assert_eq!(failures.len(), 1);
        assert!(
            failures[0].contains("no IPv6 source address"),
            "{failures:?}"
        );
    }

    #[test]
    fn one_record_covers_every_address_of_a_dual_stack_device() {
        // Several addresses are one device. Reporting each separately would double-count
        // it, and would compound once federation merges records from several vantages.
        let mut coverage =
            DeviceCoverage::skipped(DeviceKey::mac("02:00:5e:00:00:02"), DeviceTier::Host, "x");
        coverage.skipped = None;
        coverage.addresses = vec!["10.0.0.2".to_string(), "fd00::2".to_string()];
        coverage.endpoints.push(EndpointCoverage {
            endpoint: "10.0.0.2".to_string(),
            primary: true,
            stages_run: 3,
            tcp_attempted: 62,
            tcp_responsive: vec![80],
            not_sent: Vec::new(),
            omitted: None,
        });
        coverage.endpoints.push(EndpointCoverage {
            endpoint: "fd00::2".to_string(),
            primary: false,
            stages_run: 1,
            tcp_attempted: 17,
            tcp_responsive: vec![],
            not_sent: Vec::new(),
            omitted: Some("stages 2-3 run only at 10.0.0.2".to_string()),
        });

        assert_eq!(coverage.primary_endpoint(), Some("10.0.0.2"));
        assert_eq!(coverage.tcp_attempted(), 79);
        assert_eq!(coverage.tcp_responsive(), 1);
        assert_eq!(coverage.stages_run(), 3);

        // What was left out is stated, so the pass is never described as complete when it
        // was not.
        let omissions = coverage.omissions();
        assert_eq!(omissions.len(), 1);
        assert!(omissions[0].starts_with("fd00::2:"));
    }
}
