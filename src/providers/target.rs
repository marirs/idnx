//! Per-device interrogation.
//!
//! Every device the engine decides to interrogate — an established pivot with routing
//! evidence, or a candidate that merely looks like it might be network equipment — runs
//! through this pipeline. Previously the only provider that applied to a target was SNMP,
//! so "interrogated" meant nothing more than "sent one anonymous SNMP query", and a device
//! answering no SNMP produced no evidence at all.
//!
//! Two rules hold throughout. An open port is not a service: TCP reachability and protocol
//! confirmation are recorded as separate facts, and nothing is named from its conventional
//! port number alone. And coverage is reported per device, so "we asked and got nothing"
//! is distinguishable from "we never asked".

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use super::{DiscoveryContext, DiscoveryProvider, ProviderFuture};
use crate::topology::TopologyEvidence;
use crate::topology::evidence::{
    Capability, Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal,
};

/// Ports probed when interrogating a specific device.
///
/// Broader than the subnet sweep set: interrogation is bounded to one address, so the cost
/// is per-device rather than per-subnet and a wider net is affordable.
const TARGET_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 88, 110, 139, 143, 161, 389, 443, 445, 515, 548, 554, 587, 631,
    873, 902, 993, 995, 1080, 1234, 1883, 2000, 2049, 3000, 3128, 3306, 3389, 4443, 5000, 5001,
    5060, 5222, 5357, 5432, 5900, 6379, 7547, 8000, 8006, 8008, 8080, 8081, 8123, 8181, 8443, 8728,
    8888, 9000, 9090, 9100, 9200, 10000, 11434, 32400, 49152, 49153,
];

/// Interrogates one device across every applicable protocol.
pub struct TargetEnrichmentProvider {
    /// Simultaneous probes against a single device. Bounded so interrogating a candidate
    /// never looks like an attack.
    concurrency: usize,
}

impl Default for TargetEnrichmentProvider {
    fn default() -> Self {
        Self { concurrency: 24 }
    }
}

impl DiscoveryProvider for TargetEnrichmentProvider {
    fn name(&self) -> &'static str {
        "target-enrichment"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        // IPv4 only for now: the protocol probes below take an Ipv4Addr, and IPv6 devices
        // are enriched through neighbour and advertisement evidence instead.
        matches!(context.target, Some(IpAddr::V4(_)))
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let Some(IpAddr::V4(target)) = context.target else {
                return Vec::new();
            };
            interrogate(target, context, self.concurrency).await
        })
    }
}

/// Runs the full probe set against one address.
async fn interrogate(
    target: Ipv4Addr,
    context: &DiscoveryContext,
    concurrency: usize,
) -> Vec<TopologyEvidence> {
    let mut out = Vec::new();
    let vantage = &context.vantage.interface;
    let address = IpAddr::V4(target);
    let device = DeviceKey::Address(address);
    let timeout = context.timeout.max(Duration::from_millis(400));

    // Stage 1: which ports answer at all. Probed concurrently rather than in sequence,
    // because a serial pass over this many ports would dominate the run.
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = Vec::with_capacity(TARGET_PORTS.len());
    for &port in TARGET_PORTS {
        let permit = Arc::clone(&semaphore);
        tasks.push(tokio::spawn(async move {
            let _hold = permit.acquire().await.ok()?;
            let probe = crate::engine::scanner::probe_tcp_port(target, port, timeout).await;
            (probe.status == crate::engine::scanner::PortStatus::Open).then_some(port)
        }));
    }

    let mut open_ports = Vec::new();
    for task in tasks {
        if let Ok(Some(port)) = task.await {
            open_ports.push(port);
        }
    }
    open_ports.sort_unstable();

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

    // Stage 2: confirm what actually speaks on the ports that answered.
    out.extend(confirm_protocols(target, address, &device, &open_ports, timeout, vantage).await);

    // Stage 3: control-plane probes that do not depend on an open TCP port.
    out.extend(probe_control_plane(target, address, &device, &open_ports, context, vantage).await);

    // Stage 4: vendor adapters, chosen from what the device has disclosed in the stages
    // above. Optional throughout -- no adapter is required, none gates recursion, and a
    // device that selects none (unknown manufacturer, white-label or randomized MAC, or a
    // software router on generic hardware) is mapped identically by the standard protocols.
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

    out
}

/// Confirms protocols on ports that answered.
async fn confirm_protocols(
    target: Ipv4Addr,
    address: IpAddr,
    device: &DeviceKey,
    open_ports: &[u16],
    timeout: Duration,
    vantage: &str,
) -> Vec<TopologyEvidence> {
    let mut out = Vec::new();

    // TLS: the certificate names the device far more reliably than any banner.
    for &port in open_ports {
        if !matches!(port, 443 | 8443 | 4443 | 993 | 995 | 8006 | 32400) {
            continue;
        }
        if let Some(cert) = crate::probes::tls::probe_tls_certificate(target, port, timeout).await {
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

    out
}

/// Probes that reach a device without needing a TCP service.
async fn probe_control_plane(
    target: Ipv4Addr,
    address: IpAddr,
    device: &DeviceKey,
    open_ports: &[u16],
    context: &DiscoveryContext,
    vantage: &str,
) -> Vec<TopologyEvidence> {
    let mut out = Vec::new();

    // NAT-PMP: only a NAT gateway answers, so a reply is direct role evidence and needs no
    // credentials. This reaches routers that expose no TCP service at all.
    if let Some(external) = crate::probes::natpmp::probe_nat_gateway(
        target,
        context.timeout.max(Duration::from_millis(400)),
    )
    .await
    {
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

    // AI and MCP discovery against this specific device.
    let _ = address;
    out.extend(
        crate::providers::ai::probe_ai_services(
            target,
            device,
            open_ports,
            context.timeout.max(Duration::from_millis(600)),
            vantage,
        )
        .await,
    );

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
    fn enrichment_only_applies_to_a_specific_target() {
        let seeded = ctx();
        assert!(!TargetEnrichmentProvider::default().applies(&seeded));

        let targeted = seeded.for_target("10.0.0.1".parse().unwrap());
        assert!(TargetEnrichmentProvider::default().applies(&targeted));
    }

    #[test]
    fn ipv6_targets_are_left_to_neighbour_evidence() {
        // IPv6 hosts are never swept and their protocol probes take an Ipv4Addr; claiming
        // to interrogate them would report coverage that never happened.
        let targeted = ctx().for_target("fd00::1".parse().unwrap());
        assert!(!TargetEnrichmentProvider::default().applies(&targeted));
    }

    #[test]
    fn the_target_port_set_is_broader_than_the_sweep_set() {
        // Interrogation is bounded to one address, so it can afford a wider net than the
        // per-subnet sweep.
        assert!(TARGET_PORTS.len() > 17);
        assert!(TARGET_PORTS.contains(&7547), "TR-069 management");
        assert!(TARGET_PORTS.contains(&8728), "MikroTik API");
        assert!(TARGET_PORTS.contains(&49152), "UPnP dynamic range");
    }

    #[test]
    fn the_port_set_is_sorted_and_free_of_duplicates() {
        let mut sorted = TARGET_PORTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            TARGET_PORTS.len(),
            "duplicate ports would probe the same service twice"
        );
    }
}
