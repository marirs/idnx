//! Passive link-layer observation.
//!
//! Capture opens once at startup and runs concurrently with the rest of discovery. It is a
//! [`ContinuousSource`](crate::providers::ContinuousSource) rather than a provider, because
//! frames arrive on their own schedule rather than in response to a request: the engine
//! polls it before every convergence decision and finishes it exactly once, so evidence
//! landing moments before the end is still absorbed and can still extend the traversal.
//!
//! This is the only capture path. There is no listening flag, no fixed delay and no
//! separate passive mode, and nothing else opens a capture device.
//!
//! It is strictly opportunistic. If capture cannot start, or the link is silent, every
//! other source is unaffected and the run proceeds normally.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use super::DiscoveryContext;
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
///
/// The session sits behind a lock because the engine stops it through a shared reference:
/// capture must end at convergence, not whenever the last handle happens to be dropped.
pub struct PassiveObservation {
    observed: Arc<Mutex<Observed>>,
    session: Mutex<Option<CaptureSession>>,
    /// Why capture is not running, when it is not.
    unavailable: Option<CaptureError>,
    interface: String,
    /// Frame count sampled at shutdown, so the reported total is final rather than a
    /// reading taken while frames were still arriving.
    final_frames: AtomicU64,
    /// Topology facts actually accepted from those frames.
    ///
    /// A non-zero frame count proves only that the reader delivered packets. It says
    /// nothing about decoding, draining or absorption, and most traffic on any link is not
    /// topology evidence at all. Reporting both numbers distinguishes "the link carries no
    /// discovery protocols" from "the decoder is broken".
    facts_accepted: AtomicU64,
    stopped: AtomicBool,
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
                session: Mutex::new(Some(session)),
                unavailable: None,
                interface: interface.to_string(),
                final_frames: AtomicU64::new(0),
                facts_accepted: AtomicU64::new(0),
                stopped: AtomicBool::new(false),
            },
            Err(err) => Self {
                observed,
                session: Mutex::new(None),
                unavailable: Some(err),
                interface: interface.to_string(),
                final_frames: AtomicU64::new(0),
                facts_accepted: AtomicU64::new(0),
                stopped: AtomicBool::new(true),
            },
        }
    }

    pub fn is_running(&self) -> bool {
        self.unavailable.is_none()
    }

    pub fn unavailable_reason(&self) -> Option<String> {
        self.unavailable.as_ref().map(|e| e.explain())
    }

    /// Frames observed. Final once capture has stopped.
    pub fn frames_seen(&self) -> u64 {
        if self.stopped.load(Ordering::Relaxed) {
            return self.final_frames.load(Ordering::Relaxed);
        }
        self.session
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|s| s.frames_seen()))
            .unwrap_or(0)
    }

    /// Topology facts accepted from observed frames. Final once capture has stopped.
    pub fn facts_accepted(&self) -> u64 {
        self.facts_accepted.load(Ordering::Relaxed)
    }

    /// True once capture has been stopped.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    /// Builds an observation for a vantage where capture was never attempted.
    ///
    /// A vantage the engine already knows cannot carry link-layer evidence — a tunnel, a
    /// loopback, or an unprivileged run — should not have a device opened against it.
    /// Doing so turns "not applicable here" into what looks like a failure.
    pub fn not_applicable(interface: &str, reason: impl Into<String>) -> Self {
        Self {
            observed: Arc::new(Mutex::new(Observed::default())),
            session: Mutex::new(None),
            unavailable: Some(CaptureError::Unsupported(reason.into())),
            interface: interface.to_string(),
            final_frames: AtomicU64::new(0),
            facts_accepted: AtomicU64::new(0),
            stopped: AtomicBool::new(true),
        }
    }

    /// Stops capture and records the final frame count. Idempotent.
    pub fn stop(&self) {
        if self.stopped.swap(true, Ordering::Relaxed) {
            return;
        }
        if let Ok(mut guard) = self.session.lock()
            && let Some(mut session) = guard.take()
        {
            session.stop();
            // Sampled after the reader thread has joined, so no frame is counted late or
            // missed.
            self.final_frames
                .store(session.frames_seen(), Ordering::Relaxed);
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

impl crate::providers::ContinuousSource for PassiveObservation {
    fn drain(&self) -> Vec<TopologyEvidence> {
        let facts = PassiveObservation::drain(self);
        let evidence = convert_unscoped(&facts, &self.interface);
        self.facts_accepted
            .fetch_add(evidence.len() as u64, Ordering::Relaxed);
        evidence
    }

    fn finish(&self) -> Vec<TopologyEvidence> {
        // Stop first, then drain: draining first would race the reader and lose whatever it
        // decoded between the two calls. Both counters are therefore final on return.
        self.stop();
        let facts = PassiveObservation::drain(self);
        let evidence = convert_unscoped(&facts, &self.interface);
        self.facts_accepted
            .fetch_add(evidence.len() as u64, Ordering::Relaxed);
        evidence
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

/// Converts frame facts with no scope filter.
///
/// Used by the continuous path, where evidence is absorbed for the whole vantage rather
/// than for one network under examination.
fn convert_unscoped(facts: &[FrameFact], interface: &str) -> Vec<TopologyEvidence> {
    let context = DiscoveryContext::seed(
        crate::providers::Vantage {
            interface: interface.to_string(),
            kind: crate::providers::VantageKind::Unknown,
            index: crate::net::endpoint::interface_index(interface),
            capture_available: true,
        },
        std::time::Duration::from_millis(0),
        1,
    );
    convert(facts, interface, &context)
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
                index: 0,
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
    fn an_unavailable_observation_reports_itself_stopped() {
        // Capture that never started must not leave the engine waiting to stop it, and its
        // frame count must be zero rather than an uninitialised reading.
        let observation = PassiveObservation {
            observed: Arc::new(Mutex::new(Observed::default())),
            session: Mutex::new(None),
            unavailable: Some(CaptureError::PermissionDenied),
            interface: "test0".to_string(),
            final_frames: AtomicU64::new(0),
            facts_accepted: AtomicU64::new(0),
            stopped: AtomicBool::new(true),
        };

        assert!(!observation.is_running());
        assert!(observation.is_stopped());
        assert_eq!(observation.frames_seen(), 0);
        assert!(
            observation
                .unavailable_reason()
                .unwrap()
                .contains("privileges")
        );
    }

    #[test]
    fn stopping_is_idempotent_and_freezes_the_frame_count() {
        let observation = PassiveObservation {
            observed: Arc::new(Mutex::new(Observed::default())),
            session: Mutex::new(None),
            unavailable: None,
            interface: "test0".to_string(),
            final_frames: AtomicU64::new(11),
            facts_accepted: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
        };

        observation.stop();
        assert!(observation.is_stopped());
        let first = observation.frames_seen();

        // A second stop must not reset or re-sample the total.
        observation.stop();
        assert_eq!(observation.frames_seen(), first);
    }

    #[test]
    fn finish_stops_capture_before_draining() {
        use crate::providers::ContinuousSource;

        let observation = PassiveObservation {
            observed: Arc::new(Mutex::new(Observed {
                facts: vec![FrameFact::Vlan { id: 31 }],
            })),
            session: Mutex::new(None),
            unavailable: None,
            interface: "test0".to_string(),
            final_frames: AtomicU64::new(0),
            facts_accepted: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
        };

        let evidence = ContinuousSource::finish(&observation);
        assert!(observation.is_stopped(), "finish must stop capture");
        assert_eq!(evidence.len(), 1, "buffered facts must still be returned");

        // Nothing remains afterwards.
        assert!(ContinuousSource::finish(&observation).is_empty());
    }

    #[test]
    fn an_ineligible_vantage_never_opens_a_capture_device() {
        // No device is opened: the observation is constructed already stopped, with the
        // reason recorded. Opening one on a tunnel or unprivileged run would report a
        // failure for something that was never applicable.
        let observation = PassiveObservation::not_applicable(
            "utun3",
            "not applicable from a virtual/VPN vantage",
        );

        assert!(!observation.is_running());
        assert!(observation.is_stopped());
        assert!(
            observation.session.lock().unwrap().is_none(),
            "no capture session may exist for an ineligible vantage"
        );
        assert_eq!(observation.frames_seen(), 0);
        assert_eq!(observation.facts_accepted(), 0);
        assert!(
            observation
                .unavailable_reason()
                .unwrap()
                .contains("not applicable")
        );
    }

    #[test]
    fn accepted_facts_are_counted_and_frozen_at_finish() {
        use crate::providers::ContinuousSource;

        let observation = PassiveObservation {
            observed: Arc::new(Mutex::new(Observed {
                facts: vec![FrameFact::Vlan { id: 11 }, FrameFact::Vlan { id: 12 }],
            })),
            session: Mutex::new(None),
            unavailable: None,
            interface: "test0".to_string(),
            final_frames: AtomicU64::new(0),
            facts_accepted: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
        };

        let evidence = ContinuousSource::finish(&observation);
        assert_eq!(evidence.len(), 2);
        assert_eq!(
            observation.facts_accepted(),
            2,
            "accepted facts prove decoding and draining actually worked"
        );

        // Both counters stay put once capture has stopped.
        assert!(ContinuousSource::finish(&observation).is_empty());
        assert_eq!(observation.facts_accepted(), 2);
    }

    #[test]
    fn draining_accumulates_accepted_facts_across_polls() {
        use crate::providers::ContinuousSource;

        let buffer = Arc::new(Mutex::new(Observed {
            facts: vec![FrameFact::Vlan { id: 21 }],
        }));
        let observation = PassiveObservation {
            observed: Arc::clone(&buffer),
            session: Mutex::new(None),
            unavailable: None,
            interface: "test0".to_string(),
            final_frames: AtomicU64::new(0),
            facts_accepted: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
        };

        assert_eq!(ContinuousSource::drain(&observation).len(), 1);
        assert_eq!(observation.facts_accepted(), 1);

        // A frame arriving between polls is counted too.
        buffer
            .lock()
            .unwrap()
            .facts
            .push(FrameFact::Vlan { id: 22 });
        assert_eq!(ContinuousSource::drain(&observation).len(), 1);
        assert_eq!(observation.facts_accepted(), 2);
    }

    #[test]
    fn every_observation_carries_the_capture_interface() {
        let evidence = convert(&[FrameFact::Vlan { id: 5 }], "eth7", &ctx());
        assert!(evidence.iter().all(|e| e.vantage == "eth7"));
    }
}
