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
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::DiscoveryContext;
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
const CONTROL_PLANE_UDP_PORTS: &[u16] = &[crate::probes::natpmp::NAT_PMP_PORT];

/// Why a device is being interrogated.
///
/// This changes only how much work the device is worth, never what its answers mean. Role
/// and confidence still come from the evidence alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTier {
    /// Positive routing or bridging evidence already exists for this device.
    EstablishedPivot,
    /// Weak hints only -- an unfamiliar appliance, a router-ish name, several addresses.
    Candidate,
    /// No infrastructure signal. Enriched anyway, because that is how one appears.
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

    /// Whether stage 2 runs even when stage 1 found nothing.
    fn always_broadens(&self) -> bool {
        !matches!(self, DeviceTier::Host)
    }
}

impl fmt::Display for DeviceTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// What was actually attempted against one device, and what came back.
///
/// Exists so that a device reported as yielding nothing can be told apart from one that was
/// never asked. "Target enrichment: no response" answered neither question.
#[derive(Debug, Clone)]
pub struct DeviceCoverage {
    pub address: IpAddr,
    pub tier: DeviceTier,
    /// How the device came to be known, from the evidence already in the graph.
    pub discovery_sources: Vec<String>,
    /// Stages that ran. Fewer than three means later stages had nothing to work with.
    pub stages_run: u8,
    pub tcp_attempted: usize,
    pub tcp_responsive: Vec<u16>,
    pub udp_attempted: Vec<u16>,
    /// Protocols confirmed by handshake, not guessed from a port number.
    pub protocols_confirmed: Vec<String>,
    /// Ports that refused without credentials -- a positive finding, not an absence.
    pub auth_required: Vec<u16>,
    /// Set when the device was not interrogated at all, saying why.
    pub skipped: Option<String>,
    pub elapsed: Duration,
}

impl DeviceCoverage {
    fn skipped(address: IpAddr, tier: DeviceTier, reason: impl Into<String>) -> Self {
        Self {
            address,
            tier,
            discovery_sources: Vec::new(),
            stages_run: 0,
            tcp_attempted: 0,
            tcp_responsive: Vec::new(),
            udp_attempted: Vec::new(),
            protocols_confirmed: Vec::new(),
            auth_required: Vec::new(),
            skipped: Some(reason.into()),
            elapsed: Duration::ZERO,
        }
    }

    /// True when the device answered nothing at all despite being asked.
    ///
    /// Distinct from being skipped: this device was reachable enough to probe and stayed
    /// silent, which is a fact about it rather than a gap in coverage.
    pub fn silent(&self) -> bool {
        self.skipped.is_none() && self.tcp_responsive.is_empty() && self.auth_required.is_empty()
    }

    /// One-line summary for the coverage report.
    pub fn summary(&self) -> String {
        if let Some(reason) = &self.skipped {
            return format!("skipped: {reason}");
        }
        let mut parts = vec![format!(
            "{}/{} tcp responsive",
            self.tcp_responsive.len(),
            self.tcp_attempted
        )];
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
            self.stages_run,
            parts.join("; "),
            self.elapsed.as_millis()
        )
    }
}

/// Interrogates one device across every applicable protocol.
///
/// `discovery_sources` describes how the device became known; it is carried into the
/// coverage record so the evidence trail is complete even when interrogation finds nothing.
pub async fn interrogate_device(
    context: &DiscoveryContext,
    tier: DeviceTier,
    discovery_sources: Vec<String>,
) -> (Vec<TopologyEvidence>, DeviceCoverage) {
    let Some(address) = context.target else {
        return (
            Vec::new(),
            DeviceCoverage::skipped(IpAddr::V4(Ipv4Addr::UNSPECIFIED), tier, "no target address"),
        );
    };

    let IpAddr::V4(target) = address else {
        // IPv6 devices are reached through neighbour and advertisement evidence. The
        // protocol probes below take an Ipv4Addr, and claiming to have interrogated an
        // IPv6 device would report coverage that never happened.
        return (
            Vec::new(),
            DeviceCoverage::skipped(
                address,
                tier,
                "IPv6 device: enriched from neighbour and advertisement evidence",
            ),
        );
    };

    let started = Instant::now();
    let mut coverage = DeviceCoverage {
        address,
        tier,
        discovery_sources,
        stages_run: 0,
        tcp_attempted: 0,
        tcp_responsive: Vec::new(),
        udp_attempted: Vec::new(),
        protocols_confirmed: Vec::new(),
        auth_required: Vec::new(),
        skipped: None,
        elapsed: Duration::ZERO,
    };

    let vantage = &context.vantage.interface;
    let device = DeviceKey::Address(address);
    let timeout = context.timeout.max(Duration::from_millis(400));
    let mut out = Vec::new();

    // Stage 1: the cheap universal pass.
    coverage.stages_run = 1;
    let mut open_ports = sweep_ports(target, STAGE_ONE_PORTS, context, timeout).await;
    coverage.tcp_attempted += STAGE_ONE_PORTS.len();

    coverage.udp_attempted.extend(CONTROL_PLANE_UDP_PORTS);
    out.extend(probe_control_plane(target, &device, timeout, vantage, &mut coverage).await);

    // Stage 2: broaden, where breadth can still return something.
    if !open_ports.is_empty() || tier.always_broadens() {
        coverage.stages_run = 2;
        open_ports.extend(sweep_ports(target, STAGE_TWO_PORTS, context, timeout).await);
        coverage.tcp_attempted += STAGE_TWO_PORTS.len();
    }
    open_ports.sort_unstable();
    coverage.tcp_responsive = open_ports.clone();

    // An open port is reachability, not identity. Recorded as its own fact so a later
    // protocol confirmation can be told apart from a mere guess by port number.
    for &port in &open_ports {
        out.push(
            TopologyEvidence::new(
                Fact::Service {
                    address,
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
        coverage.stages_run = 3;
        out.extend(
            confirm_protocols(
                target,
                address,
                &device,
                &open_ports,
                timeout,
                vantage,
                &mut coverage,
            )
            .await,
        );
        out.extend(
            crate::providers::ai::probe_ai_services(
                target,
                &device,
                &open_ports,
                timeout.max(Duration::from_millis(600)),
                vantage,
            )
            .await,
        );
    }

    // Vendor adapters, chosen from what the device disclosed in the stages above. Optional
    // throughout -- no adapter is required, none gates recursion, and a device that selects
    // none (unknown manufacturer, white-label or randomized MAC, or a software router on
    // generic hardware) is mapped identically by the standard protocols.
    let fingerprint = crate::providers::vendor::DeviceFingerprint::from_evidence(&out, &open_ports);
    out.extend(
        crate::providers::vendor::run_adapters(&crate::providers::vendor::VendorContext {
            target,
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

/// Probes a port set concurrently, drawing on the run-wide probe budget.
async fn sweep_ports(
    target: Ipv4Addr,
    ports: &[u16],
    context: &DiscoveryContext,
    timeout: Duration,
) -> Vec<u16> {
    let mut tasks = Vec::with_capacity(ports.len());
    for &port in ports {
        let permits = Arc::clone(&context.probe_permits);
        tasks.push(tokio::spawn(async move {
            let _hold = permits.acquire().await.ok()?;
            let probe = crate::engine::scanner::probe_tcp_port(target, port, timeout).await;
            (probe.status == crate::engine::scanner::PortStatus::Open).then_some(port)
        }));
    }

    let mut open = Vec::new();
    for task in tasks {
        if let Ok(Some(port)) = task.await {
            open.push(port);
        }
    }
    open
}

/// Confirms protocols on ports that answered.
#[allow(clippy::too_many_arguments)]
async fn confirm_protocols(
    target: Ipv4Addr,
    address: IpAddr,
    device: &DeviceKey,
    open_ports: &[u16],
    timeout: Duration,
    vantage: &str,
    coverage: &mut DeviceCoverage,
) -> Vec<TopologyEvidence> {
    let mut out = Vec::new();

    // TLS: the certificate names the device far more reliably than any banner.
    for &port in open_ports {
        if !matches!(port, 443 | 8443 | 4443 | 993 | 995 | 8006 | 32400) {
            continue;
        }
        if let Some(cert) = crate::probes::tls::probe_tls_certificate(target, port, timeout).await {
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
        if let Some(smb) = crate::probes::smb::probe_smb(target, port, timeout).await {
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

    // HTTP: the status line, Server header and page title are the device describing
    // itself, and on consumer gear they are often the only identity available without
    // credentials. A challenge for credentials is recorded as a finding in its own right.
    for &port in open_ports {
        if !crate::probes::http::HTTP_PORTS.contains(&port) {
            continue;
        }
        let Some(identity) = crate::probes::http::probe_http(target, port, timeout).await else {
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
    target: Ipv4Addr,
    device: &DeviceKey,
    timeout: Duration,
    vantage: &str,
    coverage: &mut DeviceCoverage,
) -> Vec<TopologyEvidence> {
    let mut out = Vec::new();

    // NAT-PMP: only a NAT gateway answers, so a reply is direct role evidence and needs no
    // credentials. This reaches routers that expose no TCP service at all.
    if let Some(external) = crate::probes::natpmp::probe_nat_gateway(target, timeout).await {
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

    out
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
        // Stage 1 is what every quiet host on a subnet costs, so it must stay cheap.
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
    fn only_hosts_wait_for_a_stage_one_answer_before_broadening() {
        // A silent appliance is exactly the case worth pushing on, so pivots and
        // candidates broaden regardless of what stage 1 found.
        assert!(DeviceTier::EstablishedPivot.always_broadens());
        assert!(DeviceTier::Candidate.always_broadens());
        assert!(!DeviceTier::Host.always_broadens());
    }

    #[tokio::test]
    async fn an_ipv6_device_is_reported_as_skipped_rather_than_silently_dropped() {
        // Claiming to have interrogated it would report coverage that never happened.
        let targeted = ctx().for_target("fd00::1".parse().unwrap());
        let (evidence, coverage) =
            interrogate_device(&targeted, DeviceTier::Host, Vec::new()).await;
        assert!(evidence.is_empty());
        assert_eq!(coverage.stages_run, 0);
        let reason = coverage.skipped.expect("a reason");
        assert!(reason.contains("IPv6"), "{reason}");
    }

    #[test]
    fn coverage_distinguishes_silence_from_never_having_asked() {
        let address: IpAddr = "10.0.0.9".parse().unwrap();

        let skipped = DeviceCoverage::skipped(address, DeviceTier::Host, "out of scope");
        assert!(!skipped.silent());
        assert!(skipped.summary().starts_with("skipped: out of scope"));

        let mut asked = DeviceCoverage::skipped(address, DeviceTier::Host, "x");
        asked.skipped = None;
        asked.stages_run = 2;
        asked.tcp_attempted = 62;
        assert!(asked.silent());
        assert!(asked.summary().contains("0/62 tcp responsive"));

        // A device that refused without credentials answered; it was not silent.
        asked.auth_required.push(80);
        assert!(!asked.silent());
        assert!(asked.summary().contains("auth required on 80"));
    }
}
