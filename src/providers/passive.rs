//! The passive observation provider.
//!
//! Capture opens once at startup and runs concurrently with the rest of discovery. This
//! provider drains whatever has been decoded so far each time it is asked, so observations
//! flow into the graph as they arrive without anyone waiting on a timer. There is no
//! listening flag, no fixed delay, and no separate passive mode.
//!
//! It is strictly opportunistic. If capture cannot start, or the link is silent, every
//! other provider is unaffected and the run proceeds normally.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use super::{DiscoveryContext, DiscoveryProvider, ProviderFuture};
use crate::net::capture::{CaptureError, CaptureSession};
use crate::probes::passive::{FrameFact, decode_frame};
use crate::topology::TopologyEvidence;
use crate::topology::evidence::{Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal};

/// Shared buffer between the capture thread and the provider.
#[derive(Default)]
struct Observed {
    facts: Vec<FrameFact>,
}

/// A running passive observation, owning its capture session.
pub struct PassiveObservation {
    observed: Arc<Mutex<Observed>>,
    session: Option<CaptureSession>,
    /// Why capture is not running, when it is not.
    unavailable: Option<CaptureError>,
    interface: String,
}

impl PassiveObservation {
    /// Attempts to begin observing. Never fails the caller: an error becomes a reported
    /// visibility limitation instead.
    pub fn start(interface: &str) -> Self {
        let observed = Arc::new(Mutex::new(Observed::default()));
        let sink = Arc::clone(&observed);

        // Decoding on the capture thread keeps the shared buffer small: only decoded facts
        // cross the lock, never raw frames.
        let result = crate::net::capture::start(interface, move |frame| {
            let facts = decode_frame(frame);
            if facts.is_empty() {
                return;
            }
            if let Ok(mut guard) = sink.lock() {
                guard.facts.extend(facts);
            }
        });

        match result {
            Ok(session) => Self {
                observed,
                session: Some(session),
                unavailable: None,
                interface: interface.to_string(),
            },
            Err(err) => Self {
                observed,
                session: None,
                unavailable: Some(err),
                interface: interface.to_string(),
            },
        }
    }

    pub fn is_running(&self) -> bool {
        self.session.is_some()
    }

    pub fn unavailable_reason(&self) -> Option<String> {
        self.unavailable.as_ref().map(|e| e.explain())
    }

    pub fn frames_seen(&self) -> u64 {
        self.session.as_ref().map(|s| s.frames_seen()).unwrap_or(0)
    }

    /// Stops capture. Called once discovery converges.
    pub fn stop(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.stop();
        }
    }

    /// Removes and returns everything decoded so far.
    fn drain(&self) -> Vec<FrameFact> {
        match self.observed.lock() {
            Ok(mut guard) => std::mem::take(&mut guard.facts),
            // A poisoned lock means the capture thread panicked. Passive observation is
            // optional, so this degrades to "no evidence" rather than failing the run.
            Err(_) => Vec::new(),
        }
    }
}

/// Provider view over a running observation.
pub struct PassiveProvider {
    observation: Arc<PassiveObservation>,
}

impl PassiveProvider {
    pub fn new(observation: Arc<PassiveObservation>) -> Self {
        Self { observation }
    }
}

impl DiscoveryProvider for PassiveProvider {
    fn name(&self) -> &'static str {
        "passive-capture"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        // Observation belongs to the link, not to a remote device, so it never runs
        // against a specific target.
        self.observation.is_running() && context.target.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let facts = self.observation.drain();
            convert(&facts, &self.observation.interface, context)
        })
    }
}

/// Converts decoded frame facts into graded topology evidence.
///
/// Confidence follows one rule: seeing a frame is `Observed` evidence that the sender
/// exists and behaved that way, while the contents it asserts are `Advertised`. An RA
/// proves a router sent it; the prefix inside is the router's claim.
fn convert(
    facts: &[FrameFact],
    interface: &str,
    context: &DiscoveryContext,
) -> Vec<TopologyEvidence> {
    let mut out = Vec::new();
    // Frames repeat constantly; identical facts would otherwise be re-emitted every drain.
    let mut seen: HashSet<String> = HashSet::new();

    for fact in facts {
        let key = format!("{fact:?}");
        if !seen.insert(key) {
            continue;
        }

        match fact {
            FrameFact::Vlan { id } => {
                // A tag proves the VLAN ID exists on this link. It never produces a prefix.
                out.push(TopologyEvidence::new(
                    Fact::Vlan { id: *id },
                    EvidenceSource::Stp,
                    Confidence::Observed,
                    interface,
                ));
            }

            FrameFact::Bridge {
                source_mac,
                bridge_id,
                root_id,
                port_id,
            } => {
                let device = DeviceKey::mac(source_mac);
                // Only a bridge emits BPDUs, so this is observed bridge behaviour. It is
                // deliberately not router evidence and implies nothing about subnets.
                out.push(
                    TopologyEvidence::new(
                        Fact::DeviceRoleSignal {
                            device,
                            signal: RoleSignal::SpanningTreeBridge,
                        },
                        EvidenceSource::Stp,
                        Confidence::Observed,
                        interface,
                    )
                    .with_detail(format!("BPDU from bridge {bridge_id}, port {port_id:#06x}")),
                );
                out.push(
                    TopologyEvidence::new(
                        Fact::BridgeLink {
                            bridge_id: bridge_id.clone(),
                            root_id: root_id.clone(),
                            port: Some(format!("{port_id:#06x}")),
                        },
                        EvidenceSource::Stp,
                        // The bridge and root identifiers are the bridge's own assertion.
                        Confidence::Advertised,
                        interface,
                    )
                    .with_detail(format!("spanning-tree root {root_id}")),
                );
            }

            FrameFact::Arp { mac, address } => {
                let addr = IpAddr::V4(*address);
                if in_scope(context, &addr) {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: DeviceKey::mac(mac),
                            address: addr,
                        },
                        EvidenceSource::ArpCache,
                        Confidence::Observed,
                        interface,
                    ));
                }
            }

            FrameFact::Dhcp {
                server_mac,
                assigned,
                subnet_mask,
                routers,
                classless_routes,
            } => {
                let server = DeviceKey::mac(server_mac);

                // Option 1 with an assigned address is the only DHCP evidence that
                // establishes a prefix.
                if let (Some(addr), Some(mask)) = (assigned, subnet_mask) {
                    let prefix_len = u32::from(*mask).count_ones() as u8;
                    if (1..=32).contains(&prefix_len)
                        && let Ok(net) = Ipv4Net::new(*addr, prefix_len)
                    {
                        out.push(
                            TopologyEvidence::new(
                                Fact::Network {
                                    prefix: IpNet::V4(net.trunc()),
                                },
                                EvidenceSource::DhcpLease,
                                Confidence::Advertised,
                                interface,
                            )
                            .with_detail("DHCP option 1 subnet mask"),
                        );
                    }
                }

                for router in routers {
                    let router_key = DeviceKey::Address(IpAddr::V4(*router));
                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: router_key.clone(),
                            address: IpAddr::V4(*router),
                        },
                        EvidenceSource::DhcpLease,
                        Confidence::Advertised,
                        interface,
                    ));
                    out.push(
                        TopologyEvidence::new(
                            Fact::DeviceRoleSignal {
                                device: router_key,
                                signal: RoleSignal::DhcpRouter,
                            },
                            EvidenceSource::DhcpLease,
                            Confidence::Advertised,
                            interface,
                        )
                        .with_detail("named as router in DHCP option 3"),
                    );
                }

                // Option 121 routes carry a genuine prefix and a next hop.
                for (dest, prefix_len, next_hop) in classless_routes {
                    let Ok(net) = Ipv4Net::new(*dest, *prefix_len) else {
                        continue;
                    };
                    let network = IpNet::V4(net.trunc());
                    out.push(
                        TopologyEvidence::new(
                            Fact::Network { prefix: network },
                            EvidenceSource::DhcpLease,
                            Confidence::Advertised,
                            interface,
                        )
                        .with_detail("DHCP option 121 classless static route"),
                    );
                    out.push(TopologyEvidence::new(
                        Fact::RoutesTo {
                            device: DeviceKey::Address(IpAddr::V4(*next_hop)),
                            network,
                            next_hop: Some(IpAddr::V4(*next_hop)),
                        },
                        EvidenceSource::DhcpLease,
                        Confidence::Advertised,
                        interface,
                    ));
                }

                // The server itself answered from this link.
                out.push(TopologyEvidence::new(
                    Fact::DeviceRoleSignal {
                        device: server,
                        signal: RoleSignal::DhcpRouter,
                    },
                    EvidenceSource::DhcpLease,
                    Confidence::Observed,
                    interface,
                ));
            }

            FrameFact::RouterAdvertisement {
                router_mac,
                router_address,
                prefixes,
            } => {
                let device = DeviceKey::mac(router_mac);

                // Transmitting an RA is router behaviour, and we saw the frame.
                out.push(
                    TopologyEvidence::new(
                        Fact::DeviceRoleSignal {
                            device: device.clone(),
                            signal: RoleSignal::RouterAdvertisement,
                        },
                        EvidenceSource::RouterAdvertisement,
                        Confidence::Observed,
                        interface,
                    )
                    .with_detail("transmitted an IPv6 router advertisement"),
                );

                if let Some(addr) = router_address {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: device.clone(),
                            address: IpAddr::V6(*addr),
                        },
                        EvidenceSource::RouterAdvertisement,
                        Confidence::Observed,
                        interface,
                    ));
                }

                // The prefixes are what the router claims, not what we verified.
                for (prefix, len) in prefixes {
                    let Ok(net) = Ipv6Net::new(*prefix, *len) else {
                        continue;
                    };
                    let network = IpNet::V6(net.trunc());
                    out.push(
                        TopologyEvidence::new(
                            Fact::Network { prefix: network },
                            EvidenceSource::RouterAdvertisement,
                            Confidence::Advertised,
                            interface,
                        )
                        .with_detail("RA Prefix Information Option"),
                    );
                    out.push(TopologyEvidence::new(
                        Fact::GatewayFor {
                            device: device.clone(),
                            network,
                        },
                        EvidenceSource::RouterAdvertisement,
                        Confidence::Advertised,
                        interface,
                    ));
                }
            }

            FrameFact::Neighbor {
                mac,
                address,
                is_router,
            } => {
                let device = DeviceKey::mac(mac);
                out.push(TopologyEvidence::new(
                    Fact::DeviceAddress {
                        device: device.clone(),
                        address: IpAddr::V6(*address),
                    },
                    EvidenceSource::NdpCache,
                    Confidence::Observed,
                    interface,
                ));
                if *is_router {
                    out.push(
                        TopologyEvidence::new(
                            Fact::DeviceRoleSignal {
                                device,
                                signal: RoleSignal::RouterAdvertisement,
                            },
                            EvidenceSource::NdpCache,
                            Confidence::Observed,
                            interface,
                        )
                        .with_detail("router flag set in a neighbour advertisement"),
                    );
                }
            }

            FrameFact::LinkLayerNeighbor(n) => {
                let device = DeviceKey::mac(&n.chassis_id);

                if let Some(name) = n.system_name.clone() {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceHostname {
                            device: device.clone(),
                            hostname: name,
                        },
                        EvidenceSource::Lldp,
                        Confidence::Advertised,
                        interface,
                    ));
                }
                if let Some(desc) = n.system_description.clone() {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceDescription {
                            device: device.clone(),
                            text: desc,
                        },
                        EvidenceSource::Lldp,
                        Confidence::Advertised,
                        interface,
                    ));
                }
                for cap in &n.capabilities {
                    let signal = if cap.contains("Router") {
                        RoleSignal::LinkLayerCapability("Router")
                    } else if cap.contains("Bridge") || cap.contains("Switch") {
                        RoleSignal::LinkLayerCapability("Bridge/Switch")
                    } else {
                        continue;
                    };
                    out.push(
                        TopologyEvidence::new(
                            Fact::DeviceRoleSignal {
                                device: device.clone(),
                                signal,
                            },
                            EvidenceSource::Lldp,
                            Confidence::Advertised,
                            interface,
                        )
                        .with_detail(format!("port {}", n.port_id)),
                    );
                }
                if let Some(mgmt) = n.management_ip {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device,
                            address: IpAddr::V4(mgmt),
                        },
                        EvidenceSource::Lldp,
                        Confidence::Advertised,
                        interface,
                    ));
                }
            }

            FrameFact::Mndp(n) => {
                let device = DeviceKey::mac(&n.mac_address);
                out.push(TopologyEvidence::new(
                    Fact::DeviceHostname {
                        device: device.clone(),
                        hostname: n.identity.clone(),
                    },
                    EvidenceSource::Mndp,
                    Confidence::Advertised,
                    interface,
                ));
                if let Some(addr) = n.ipv4_address {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: device.clone(),
                            address: IpAddr::V4(addr),
                        },
                        EvidenceSource::Mndp,
                        Confidence::Advertised,
                        interface,
                    ));
                }
                out.push(
                    TopologyEvidence::new(
                        Fact::DeviceRoleSignal {
                            device,
                            signal: RoleSignal::LinkLayerCapability("Router"),
                        },
                        EvidenceSource::Mndp,
                        Confidence::Advertised,
                        interface,
                    )
                    .with_detail("announced itself via MikroTik MNDP"),
                );
            }
        }
    }

    out
}

/// Whether an address belongs to the scope currently being examined.
fn in_scope(context: &DiscoveryContext, address: &IpAddr) -> bool {
    match context.scope {
        Some(scope) => scope.contains(address),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{Vantage, VantageKind};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn ctx() -> DiscoveryContext {
        DiscoveryContext::seed(
            Vantage {
                interface: "test0".to_string(),
                kind: VantageKind::Wired,
                capture_available: true,
            },
            Duration::from_millis(100),
            8,
        )
    }

    #[test]
    fn a_vlan_tag_never_produces_a_network() {
        let evidence = convert(&[FrameFact::Vlan { id: 42 }], "test0", &ctx());
        assert_eq!(evidence.len(), 1);
        assert!(matches!(evidence[0].fact, Fact::Vlan { id: 42 }));
        assert!(
            !evidence
                .iter()
                .any(|e| matches!(e.fact, Fact::Network { .. })),
            "a VLAN ID says nothing about any prefix"
        );
    }

    #[test]
    fn a_bpdu_is_bridge_evidence_and_not_router_evidence() {
        let evidence = convert(
            &[FrameFact::Bridge {
                source_mac: "44:d9:e7:1c:88:40".into(),
                bridge_id: "32768.44:d9:e7:1c:88:40".into(),
                root_id: "32768.bc:24:11:9a:02:01".into(),
                port_id: 0x8003,
            }],
            "test0",
            &ctx(),
        );

        let signals: Vec<&RoleSignal> = evidence
            .iter()
            .filter_map(|e| match &e.fact {
                Fact::DeviceRoleSignal { signal, .. } => Some(signal),
                _ => None,
            })
            .collect();
        assert_eq!(signals, vec![&RoleSignal::SpanningTreeBridge]);

        // A BPDU must never imply routing or a hidden subnet.
        assert!(
            !evidence
                .iter()
                .any(|e| matches!(e.fact, Fact::Network { .. })),
            "spanning tree carries no prefix information"
        );
    }

    #[test]
    fn dhcp_mask_yields_a_network_but_option_3_only_yields_a_role() {
        let evidence = convert(
            &[FrameFact::Dhcp {
                server_mac: "00:11:22:33:44:55".into(),
                assigned: Some(Ipv4Addr::new(192, 168, 8, 44)),
                subnet_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
                routers: vec![Ipv4Addr::new(192, 168, 8, 1)],
                classless_routes: Vec::new(),
            }],
            "test0",
            &ctx(),
        );

        let networks: Vec<String> = evidence
            .iter()
            .filter_map(|e| match &e.fact {
                Fact::Network { prefix } => Some(prefix.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(networks, vec!["192.168.8.0/24".to_string()]);

        assert!(evidence.iter().any(|e| matches!(
            &e.fact,
            Fact::DeviceRoleSignal {
                signal: RoleSignal::DhcpRouter,
                ..
            }
        )));
    }

    #[test]
    fn ra_prefix_is_advertised_while_sending_the_ra_is_observed() {
        let prefix: std::net::Ipv6Addr = "2001:db8::".parse().unwrap();
        let evidence = convert(
            &[FrameFact::RouterAdvertisement {
                router_mac: "c0:f6:ec:84:b9:0b".into(),
                router_address: Some("fe80::1".parse().unwrap()),
                prefixes: vec![(prefix, 64)],
            }],
            "test0",
            &ctx(),
        );

        let role = evidence
            .iter()
            .find(|e| matches!(e.fact, Fact::DeviceRoleSignal { .. }))
            .expect("role signal");
        assert_eq!(role.confidence, Confidence::Observed);

        let network = evidence
            .iter()
            .find(|e| matches!(e.fact, Fact::Network { .. }))
            .expect("network");
        assert_eq!(
            network.confidence,
            Confidence::Advertised,
            "the prefix inside an RA is the router's claim, not our observation"
        );
    }

    #[test]
    fn repeated_frames_do_not_re_emit_the_same_fact() {
        let fact = FrameFact::Vlan { id: 7 };
        let evidence = convert(&[fact.clone(), fact.clone(), fact], "test0", &ctx());
        assert_eq!(evidence.len(), 1);
    }

    #[test]
    fn arp_outside_the_current_scope_is_dropped() {
        let scoped = ctx().for_scope("10.0.0.0/24".parse().unwrap());
        let evidence = convert(
            &[FrameFact::Arp {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                address: Ipv4Addr::new(192, 168, 1, 5),
            }],
            "test0",
            &scoped,
        );
        assert!(evidence.is_empty());
    }

    #[test]
    fn every_observation_carries_the_capture_interface() {
        let evidence = convert(&[FrameFact::Vlan { id: 5 }], "eth7", &ctx());
        assert!(evidence.iter().all(|e| e.vantage == "eth7"));
    }
}
