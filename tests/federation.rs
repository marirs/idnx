//! Requires the `federation` feature, which is off by default: the subsystem is
//! unapproved and is not part of the shipped build.
#![cfg(feature = "federation")]

//! Federation acceptance: two peers either side of a NAT boundary.
//!
//! The scenario this whole subsystem exists for. Peer A sits on 192.168.1.0/24 and can see
//! the ASUS router at 192.168.1.53 forward traffic, but nothing behind it: no prefix, no
//! hosts, no ARP table. Peer B runs *inside* 192.168.51.0/24 and observes it directly,
//! including a further routed subnet behind another router there.
//!
//! The acceptance condition: A's final topology contains all three scopes, every remotely
//! sourced fact is attributed to the peer that asserted it, and no prefix is synthesized.
//! A never guesses 192.168.51.0/24 -- it appears only because B said so and signed it.

use std::collections::HashSet;

use idnx::federation::bundle::EvidenceBundle;
use idnx::federation::identity::PeerKey;
use idnx::federation::ledger::PeerLedger;
use idnx::topology::TopologyGraph;
use idnx::topology::evidence::{
    Capability, Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal, TopologyEvidence,
};
use idnx::topology::graph::DeviceCategory;

const A_VANTAGE: &str = "en0";
const B_VANTAGE: &str = "br0";

fn observed(fact: Fact, source: EvidenceSource, vantage: &str) -> TopologyEvidence {
    TopologyEvidence::new(fact, source, Confidence::Observed, vantage)
}

/// What peer A can see from 192.168.1.0/24: its own subnet, and a router that forwards.
///
/// Deliberately contains nothing about 192.168.51.0/24. A has no prefix-bearing evidence
/// for it and must not invent one.
fn what_a_observes() -> Vec<TopologyEvidence> {
    let boundary = DeviceKey::Mac("a0:ad:9f:e6:38:00".to_string());
    let gateway = DeviceKey::Mac("74:12:13:14:75:dc".to_string());
    let lan = "192.168.1.0/24".parse().unwrap();

    vec![
        observed(
            Fact::Network { prefix: lan },
            EvidenceSource::InterfaceAddress,
            A_VANTAGE,
        ),
        observed(
            Fact::DeviceAddress {
                device: gateway.clone(),
                address: "192.168.1.1".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            A_VANTAGE,
        ),
        observed(
            Fact::DeviceRoleSignal {
                device: gateway,
                signal: RoleSignal::DefaultGateway,
            },
            EvidenceSource::DefaultGateway,
            A_VANTAGE,
        ),
        observed(
            Fact::DeviceAddress {
                device: boundary.clone(),
                address: "192.168.1.53".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            A_VANTAGE,
        ),
        observed(
            Fact::DeviceVendor {
                device: boundary.clone(),
                vendor: "ASUSTek COMPUTER INC.".to_string(),
            },
            EvidenceSource::ArpCache,
            A_VANTAGE,
        ),
        // It forwards, and it discloses nothing about what is behind it.
        observed(
            Fact::DeviceRoleSignal {
                device: boundary.clone(),
                signal: RoleSignal::ObservedForwarding,
            },
            EvidenceSource::NatPmp,
            A_VANTAGE,
        ),
        observed(
            Fact::DeviceCapability {
                device: boundary.clone(),
                capability: Capability::NatGateway,
                detail: Some("answered NAT-PMP".to_string()),
            },
            EvidenceSource::NatPmp,
            A_VANTAGE,
        ),
        observed(
            Fact::OpaqueBoundary {
                device: boundary,
                why: "performs NAT; nothing behind it is observable from this vantage".to_string(),
            },
            EvidenceSource::NatPmp,
            A_VANTAGE,
        ),
    ]
}

/// What peer B observes from inside 192.168.51.0/24, including a subnet behind it.
fn what_b_observes() -> Vec<TopologyEvidence> {
    let router = DeviceKey::Mac("a0:ad:9f:e6:38:01".to_string());
    let inner_router = DeviceKey::Mac("60:cf:84:37:1b:70".to_string());
    let sensor = DeviceKey::Mac("02:00:5e:51:00:09".to_string());
    let inner_host = DeviceKey::Mac("02:00:5e:77:00:05".to_string());

    let lan = "192.168.51.0/24".parse().unwrap();
    let behind = "10.77.0.0/24".parse().unwrap();

    vec![
        // B's own attached prefix: the only thing that can establish this network exists.
        observed(
            Fact::InterfaceNetwork {
                interface: B_VANTAGE.to_string(),
                prefix: lan,
            },
            EvidenceSource::InterfaceAddress,
            B_VANTAGE,
        ),
        observed(
            Fact::Network { prefix: lan },
            EvidenceSource::InterfaceAddress,
            B_VANTAGE,
        ),
        observed(
            Fact::DeviceAddress {
                device: router.clone(),
                address: "192.168.51.1".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            B_VANTAGE,
        ),
        observed(
            Fact::DeviceRoleSignal {
                device: router.clone(),
                signal: RoleSignal::DefaultGateway,
            },
            EvidenceSource::DefaultGateway,
            B_VANTAGE,
        ),
        observed(
            Fact::GatewayFor {
                device: router,
                network: lan,
            },
            EvidenceSource::KernelRoute,
            B_VANTAGE,
        ),
        observed(
            Fact::DeviceAddress {
                device: sensor.clone(),
                address: "192.168.51.9".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            B_VANTAGE,
        ),
        observed(
            Fact::DeviceHostname {
                device: sensor,
                hostname: "sensor-09".to_string(),
            },
            EvidenceSource::Mdns,
            B_VANTAGE,
        ),
        // A further routed subnet behind another router inside B's network.
        observed(
            Fact::DeviceAddress {
                device: inner_router.clone(),
                address: "192.168.51.2".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            B_VANTAGE,
        ),
        observed(
            Fact::Network { prefix: behind },
            EvidenceSource::KernelRoute,
            B_VANTAGE,
        ),
        observed(
            Fact::RoutesTo {
                device: inner_router.clone(),
                network: behind,
                next_hop: None,
            },
            EvidenceSource::KernelRoute,
            B_VANTAGE,
        ),
        observed(
            Fact::DeviceRoleSignal {
                device: inner_router,
                signal: RoleSignal::KernelNextHop,
            },
            EvidenceSource::KernelRoute,
            B_VANTAGE,
        ),
        observed(
            Fact::DeviceAddress {
                device: inner_host,
                address: "10.77.0.5".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            B_VANTAGE,
        ),
    ]
}

/// Builds A's graph, optionally merging what B published.
fn peer_a_topology(with_peer_b: bool) -> (TopologyGraph, Option<PeerKey>) {
    let mut graph = TopologyGraph::new();
    for record in what_a_observes() {
        graph.absorb(record);
    }

    let mut key = None;
    if with_peer_b {
        let b = PeerKey::generate();

        let mut ledger = PeerLedger::new();
        ledger.pair(b.id());

        let bundle = EvidenceBundle::publish(&b, B_VANTAGE, 1, &what_b_observes());
        let accepted = ledger
            .accept_immediately(&bundle)
            .expect("B is paired and signs correctly");
        // Both peers run this build, so the bundle is accepted whole. One carrying
        // vocabulary this build lacks would be refused entirely, not partially applied.

        for record in accepted.evidence {
            graph.absorb(record);
        }
        key = Some(b);
    }

    graph.finalize_roles();
    (graph, key)
}

fn networks(graph: &TopologyGraph) -> HashSet<String> {
    graph.networks().iter().map(|n| n.to_string()).collect()
}

#[test]
fn without_a_peer_the_far_side_of_the_boundary_stays_invisible() {
    // The honest baseline. From 192.168.1.0/24 nothing can enumerate 192.168.51.0/24, and
    // the tool must not pretend otherwise -- not from the ASUS OUI, not from the NAT-PMP
    // answer, not from the boundary existing at all.
    let (graph, _) = peer_a_topology(false);

    assert_eq!(
        networks(&graph),
        HashSet::from(["192.168.1.0/24".to_string()])
    );
    assert_eq!(
        graph.devices_in(DeviceCategory::OpaqueBoundary).len(),
        1,
        "the boundary itself is visible; what is behind it is not"
    );
}

#[test]
fn a_peer_inside_the_far_network_reveals_it_and_everything_behind_it() {
    let (graph, _) = peer_a_topology(true);

    // All three scopes: A's own, B's, and the subnet routed behind B.
    assert_eq!(
        networks(&graph),
        HashSet::from([
            "192.168.1.0/24".to_string(),
            "192.168.51.0/24".to_string(),
            "10.77.0.0/24".to_string(),
        ])
    );

    // And the devices B saw, which A could never have reached.
    let names: HashSet<String> = graph.nodes().map(|node| node.display_name()).collect();
    assert!(names.contains("sensor-09"), "{names:?}");
    assert!(names.contains("10.77.0.5"), "{names:?}");
}

#[test]
fn every_remote_fact_is_attributed_to_the_peer_that_asserted_it() {
    let (graph, key) = peer_a_topology(true);
    let peer = key.expect("peer B").id().to_hex();

    // A device only B could see carries B's identity and B's vantage, not A's.
    let sensor = graph
        .nodes()
        .find(|n| n.display_name() == "sensor-09")
        .expect("the sensor B reported");
    assert!(
        sensor.provenance.iter().all(|p| p.is_remote()),
        "nothing here was observed locally"
    );
    let origin = sensor.provenance[0].origin.as_ref().expect("attributed");
    assert_eq!(origin.peer, peer);
    assert_eq!(origin.vantage, B_VANTAGE);
    assert_eq!(origin.sequence, 1);

    // A device only A could see carries no peer origin at all.
    let gateway = graph
        .nodes()
        .find(|n| n.addresses.iter().any(|a| a.to_string() == "192.168.1.1"))
        .expect("A's own gateway");
    assert!(
        gateway.provenance.iter().all(|p| !p.is_remote()),
        "a local observation must not be attributed to a peer"
    );
}

#[test]
fn no_prefix_is_synthesized_from_anything_other_than_a_peers_evidence() {
    // The graphs differ by exactly the networks B reported. If A were inventing prefixes
    // -- from the ASUS OUI, from a NAT-PMP reply, from a boundary device existing -- the
    // unfederated run would already contain them.
    let (alone, _) = peer_a_topology(false);
    let (federated, _) = peer_a_topology(true);

    let gained: HashSet<String> = networks(&federated)
        .difference(&networks(&alone))
        .cloned()
        .collect();
    assert_eq!(
        gained,
        HashSet::from(["192.168.51.0/24".to_string(), "10.77.0.0/24".to_string()])
    );

    // Every gained network is backed by a record B actually signed.
    let published: HashSet<String> = what_b_observes()
        .iter()
        .filter_map(|record| match &record.fact {
            Fact::Network { prefix } => Some(prefix.to_string()),
            _ => None,
        })
        .collect();
    for network in &gained {
        assert!(
            published.contains(network),
            "{network} was not published by B"
        );
    }
}

#[test]
fn the_boundary_remains_a_boundary_after_merging() {
    // Learning what is behind a NAT does not mean this vantage can see through it. The
    // boundary is still where A's own visibility ends, and it must keep saying so.
    let (graph, _) = peer_a_topology(true);

    let boundaries = graph.devices_in(DeviceCategory::OpaqueBoundary);
    assert_eq!(boundaries.len(), 1);
    let reason = boundaries[0].opaque_reason.as_ref().expect("a reason");
    assert!(reason.contains("NAT"), "{reason}");
    assert!(
        boundaries[0].provenance.iter().any(|p| !p.is_remote()),
        "the boundary is A's own observation"
    );
}

#[test]
fn a_peer_cannot_overwrite_identity_this_vantage_established_locally() {
    // B claims a different manufacturer for the boundary device A can see directly. A's
    // own OUI lookup stands; B's claim must not silently replace it.
    let mut graph = TopologyGraph::new();
    for record in what_a_observes() {
        graph.absorb(record);
    }

    let b = PeerKey::generate();
    let mut ledger = PeerLedger::new();
    ledger.pair(b.id());

    let contradiction = vec![observed(
        Fact::DeviceVendor {
            device: DeviceKey::Mac("a0:ad:9f:e6:38:00".to_string()),
            vendor: "Definitely Not ASUS".to_string(),
        },
        EvidenceSource::ArpCache,
        B_VANTAGE,
    )];
    let accepted = ledger
        .accept_immediately(&EvidenceBundle::publish(&b, B_VANTAGE, 1, &contradiction))
        .expect("accepted");
    for record in accepted.evidence {
        graph.absorb(record);
    }
    graph.finalize_roles();

    let device = graph
        .nodes()
        .find(|n| n.addresses.iter().any(|a| a.to_string() == "192.168.1.53"))
        .expect("the boundary device");
    assert_eq!(device.vendor.as_deref(), Some("ASUSTek COMPUTER INC."));

    // The peer's claim is still on record, so the disagreement is visible rather than lost.
    assert!(device.provenance.iter().any(|p| p.is_remote()));
}

#[test]
fn a_peer_can_supply_identity_this_vantage_never_learned() {
    // The inverse: where nothing local exists, the peer's claim is used and attributed.
    let (graph, _) = peer_a_topology(true);
    let sensor = graph
        .nodes()
        .find(|n| n.display_name() == "sensor-09")
        .expect("the sensor");
    assert!(sensor.provenance.iter().all(|p| p.is_remote()));
}

/// Two peers on unrelated networks that use the same identifiers.
///
/// This is the ordinary case, not a contrived one: `fe80::1%eth0`, `10.0.0.0/24` and
/// locally administered MACs are what most networks look like. Keyed globally they collide,
/// and A's topology ends up describing one router serving two unrelated subnets.
mod colliding_peers {
    use super::*;
    use idnx::federation::bundle::EvidenceBundle;
    use idnx::federation::identity::PeerKey;
    use idnx::federation::ledger::PeerLedger;
    use std::collections::HashSet;

    /// What one peer reports: a link-local router, a private subnet, and a random-MAC host.
    fn what_a_peer_reports(vantage: &str) -> Vec<TopologyEvidence> {
        let router = DeviceKey::ScopedAddress("fe80::1".parse().unwrap(), vantage.to_string());
        let host = DeviceKey::Mac("02:00:5e:00:00:01".to_string());
        let lan: ipnet::IpNet = "10.0.0.0/24".parse().unwrap();

        vec![
            TopologyEvidence::new(
                Fact::Network { prefix: lan },
                EvidenceSource::InterfaceAddress,
                Confidence::Observed,
                vantage,
            ),
            TopologyEvidence::new(
                Fact::DeviceAddress {
                    device: router.clone(),
                    address: "fe80::1".parse().unwrap(),
                },
                EvidenceSource::NdpCache,
                Confidence::Observed,
                vantage,
            ),
            TopologyEvidence::new(
                Fact::GatewayFor {
                    device: router,
                    network: lan,
                },
                EvidenceSource::KernelRoute,
                Confidence::Observed,
                vantage,
            ),
            TopologyEvidence::new(
                Fact::DeviceAddress {
                    device: host.clone(),
                    address: "10.0.0.9".parse().unwrap(),
                },
                EvidenceSource::ArpCache,
                Confidence::Observed,
                vantage,
            ),
            TopologyEvidence::new(
                Fact::DeviceHostname {
                    device: host,
                    hostname: format!("host-on-{vantage}"),
                },
                EvidenceSource::Mdns,
                Confidence::Observed,
                vantage,
            ),
        ]
    }

    /// Merges two peers' identical-looking reports into one graph.
    fn merged() -> TopologyGraph {
        let mut graph = TopologyGraph::new();
        let mut ledger = PeerLedger::new();

        for vantage in ["eth0", "eth0"] {
            let key = PeerKey::generate();
            ledger.pair(key.id());
            let bundle = EvidenceBundle::publish(&key, vantage, 1, &what_a_peer_reports(vantage));
            let accepted = ledger.accept_immediately(&bundle).expect("accepted");
            for record in accepted.evidence {
                graph.absorb(record);
            }
        }
        graph.finalize_roles();
        graph
    }

    #[test]
    fn two_peers_reporting_fe80_1_on_eth0_are_two_routers() {
        // Merged, A would report one router that is the gateway for two unrelated /24s --
        // a device that does not exist anywhere.
        let graph = merged();
        let routers: Vec<_> = graph
            .nodes()
            .filter(|n| n.addresses.iter().any(|a| a.to_string() == "fe80::1"))
            .collect();
        assert_eq!(routers.len(), 2, "one node per peer, not one shared node");

        // Each is attributed to exactly one peer.
        for router in &routers {
            assert_eq!(
                router.peer_origins().len(),
                1,
                "{:?}",
                router.peer_origins()
            );
        }
        assert_ne!(routers[0].peer_origins(), routers[1].peer_origins());
    }

    #[test]
    fn two_peers_reporting_the_same_private_prefix_are_two_networks() {
        let graph = merged();
        let matching = graph
            .nodes()
            .filter(|n| {
                matches!(&n.id, idnx::topology::NodeId::Network(net, _)
                if net.to_string() == "10.0.0.0/24")
            })
            .count();
        assert_eq!(matching, 2, "10.0.0.0/24 exists on both peers separately");

        // And neither is traversable from here: this machine cannot sweep a peer's subnet.
        assert!(
            graph.local_networks().is_empty(),
            "a peer's network must never be queued for local sweeping"
        );
    }

    #[test]
    fn two_peers_random_mac_hosts_do_not_merge() {
        // 02:00:5e:00:00:01 is locally administered: it identifies nothing beyond its own
        // link, and two peers both holding one is unremarkable.
        let graph = merged();
        let names: HashSet<String> = graph
            .nodes()
            .flat_map(|n| n.hostnames.iter().cloned())
            .collect();
        assert!(names.contains("host-on-eth0"));

        let hosts = graph
            .nodes()
            .filter(|n| n.addresses.iter().any(|a| a.to_string() == "10.0.0.9"))
            .count();
        assert_eq!(hosts, 2);
    }

    #[test]
    fn a_manufacturer_mac_seen_by_two_peers_still_merges() {
        // The inverse must hold, or federation could never corroborate anything: an OUI
        // address is unique worldwide, so two peers seeing it are seeing one device.
        let mut graph = TopologyGraph::new();
        let mut ledger = PeerLedger::new();
        let device = DeviceKey::Mac("74:12:13:14:75:dc".to_string());

        for vantage in ["eth0", "eth1"] {
            let key = PeerKey::generate();
            ledger.pair(key.id());
            let record = TopologyEvidence::new(
                Fact::DeviceAddress {
                    device: device.clone(),
                    address: "203.0.113.7".parse().unwrap(),
                },
                EvidenceSource::ArpCache,
                Confidence::Observed,
                vantage,
            );
            let bundle = EvidenceBundle::publish(&key, vantage, 1, &[record]);
            for evidence in ledger
                .accept_immediately(&bundle)
                .expect("accepted")
                .evidence
            {
                graph.absorb(evidence);
            }
        }
        graph.finalize_roles();

        let matching = graph
            .nodes()
            .filter(|n| n.addresses.iter().any(|a| a.to_string() == "203.0.113.7"))
            .count();
        assert_eq!(matching, 1, "one device, corroborated by two peers");

        let node = graph
            .nodes()
            .find(|n| n.addresses.iter().any(|a| a.to_string() == "203.0.113.7"))
            .expect("the device");
        assert_eq!(node.peer_origins().len(), 2, "both peers are credited");
    }

    #[test]
    fn local_identity_is_unaffected_by_the_scoping() {
        // A run with no peers must produce exactly what it always did.
        let mut graph = TopologyGraph::new();
        for record in what_a_peer_reports("en0") {
            graph.absorb(record);
        }
        graph.finalize_roles();

        assert_eq!(
            graph.local_networks(),
            vec!["10.0.0.0/24".parse::<ipnet::IpNet>().unwrap()]
        );
        assert!(graph.nodes().all(|n| n.peer_origins().is_empty()));
    }
}

/// Domain scoping across every identity kind, and through every output.
mod observation_domains {
    use super::*;
    use idnx::federation::bundle::EvidenceBundle;
    use idnx::federation::identity::PeerKey;
    use idnx::federation::ledger::PeerLedger;
    use idnx::topology::NodeId;
    use idnx::topology::graph::NodeKind;

    /// Merges one bundle per peer into a graph, each peer using the same identifiers.
    fn merged(records: impl Fn(&str) -> Vec<TopologyEvidence>) -> TopologyGraph {
        let mut graph = TopologyGraph::new();
        let mut ledger = PeerLedger::new();

        for vantage in ["eth0", "eth0"] {
            let key = PeerKey::generate();
            ledger.pair(key.id());
            let bundle = EvidenceBundle::publish(&key, vantage, 1, &records(vantage));
            for record in ledger
                .accept_immediately(&bundle)
                .expect("accepted")
                .evidence
            {
                graph.absorb(record);
            }
        }
        graph.finalize_roles();
        graph
    }

    #[test]
    fn two_peers_eth0_interfaces_stay_distinct() {
        // Every machine has an eth0. Shared, one peer's interface would appear to carry the
        // other's networks.
        let graph = merged(|vantage| {
            vec![TopologyEvidence::new(
                Fact::InterfaceNetwork {
                    interface: "eth0".to_string(),
                    prefix: "10.0.0.0/24".parse().unwrap(),
                },
                EvidenceSource::InterfaceAddress,
                Confidence::Observed,
                vantage,
            )]
        });

        let interfaces: Vec<&NodeId> = graph
            .nodes()
            .map(|n| &n.id)
            .filter(|id| matches!(id, NodeId::Interface(name, _) if name == "eth0"))
            .collect();
        assert_eq!(interfaces.len(), 2, "{interfaces:?}");
    }

    #[test]
    fn vlan_20_from_two_peer_vantages_stays_distinct() {
        // A VLAN tag is unique inside one switched domain. VLAN 20 at two sites is two.
        let graph = merged(|vantage| {
            vec![TopologyEvidence::new(
                Fact::Vlan { id: 20 },
                EvidenceSource::Stp,
                Confidence::Observed,
                vantage,
            )]
        });

        let vlans = graph
            .nodes()
            .filter(|n| matches!(&n.id, NodeId::Vlan(20, _)))
            .count();
        assert_eq!(vlans, 2);
    }

    #[test]
    fn two_services_on_the_same_private_address_attach_to_their_own_devices() {
        // 10.0.0.9:443 exists on countless networks. Shared, one peer's TLS service would
        // be listed against the other peer's device.
        let graph = merged(|vantage| {
            let device = DeviceKey::Mac("02:00:5e:00:00:09".to_string());
            vec![
                TopologyEvidence::new(
                    Fact::DeviceAddress {
                        device,
                        address: "10.0.0.9".parse().unwrap(),
                    },
                    EvidenceSource::ArpCache,
                    Confidence::Observed,
                    vantage,
                ),
                TopologyEvidence::new(
                    Fact::Service {
                        address: "10.0.0.9".parse().unwrap(),
                        port: 443,
                        protocol: "tcp",
                        detail: Some(format!("TLS on {vantage}")),
                    },
                    EvidenceSource::TcpProbe,
                    Confidence::Observed,
                    vantage,
                ),
            ]
        });

        let services: Vec<_> = graph
            .nodes()
            .filter(|n| matches!(&n.id, NodeId::Service(a, 443, _) if a.to_string() == "10.0.0.9"))
            .collect();
        assert_eq!(services.len(), 2, "one service node per peer");

        // Each service belongs to exactly one peer, and so does each device.
        for service in &services {
            assert_eq!(service.peer_origins().len(), 1);
        }
        assert_ne!(services[0].peer_origins(), services[1].peer_origins());

        let devices = graph
            .nodes()
            .filter(|n| {
                n.kind != NodeKind::Service
                    && n.addresses.iter().any(|a| a.to_string() == "10.0.0.9")
            })
            .count();
        assert_eq!(devices, 2);
    }

    #[test]
    fn every_output_preserves_two_same_prefix_networks_with_their_own_provenance() {
        // Rendering by prefix alone found whichever network was stored first, so the second
        // appeared twice carrying the first peer's provenance.
        let graph = merged(|vantage| {
            vec![TopologyEvidence::new(
                Fact::Network {
                    prefix: "10.0.0.0/24".parse().unwrap(),
                },
                EvidenceSource::InterfaceAddress,
                Confidence::Observed,
                vantage,
            )]
        });

        let refs = graph.network_refs();
        assert_eq!(refs.len(), 2, "{refs:?}");
        assert_eq!(refs[0].prefix, refs[1].prefix);
        assert_ne!(refs[0].realm, refs[1].realm);

        // Each resolves to its own node, with its own single peer.
        let mut origins = Vec::new();
        for reference in &refs {
            let node = graph.network_ref_node(reference).expect("its own node");
            assert_eq!(node.peer_origins().len(), 1);
            origins.push(node.peer_origins());
        }
        assert_ne!(origins[0], origins[1]);
    }

    #[test]
    fn a_peer_only_public_prefix_is_not_swept_locally() {
        // A public prefix shares one identity so peers can corroborate it. That is a
        // statement about naming: this machine still cannot reach it, and reading identity
        // as reachability would have it sweep the peer's uplink.
        let mut graph = TopologyGraph::new();
        let mut ledger = PeerLedger::new();
        let key = PeerKey::generate();
        ledger.pair(key.id());

        let bundle = EvidenceBundle::publish(
            &key,
            "eth0",
            1,
            &[TopologyEvidence::new(
                Fact::Network {
                    prefix: "203.0.113.0/24".parse().unwrap(),
                },
                EvidenceSource::KernelRoute,
                Confidence::Observed,
                "eth0",
            )],
        );
        for record in ledger
            .accept_immediately(&bundle)
            .expect("accepted")
            .evidence
        {
            graph.absorb(record);
        }
        graph.finalize_roles();

        assert!(
            graph
                .networks()
                .contains(&"203.0.113.0/24".parse::<ipnet::IpNet>().unwrap()),
            "it is known"
        );
        assert!(
            graph.local_networks().is_empty(),
            "but nothing here observed it, so it must not be traversed"
        );
    }

    #[test]
    fn the_same_public_prefix_with_local_evidence_is_swept_once() {
        // The inverse: when this machine has seen it too, it is reachable and appears once,
        // because a public prefix genuinely is one network.
        let prefix: ipnet::IpNet = "203.0.113.0/24".parse().unwrap();
        let mut graph = TopologyGraph::new();
        let mut ledger = PeerLedger::new();
        let key = PeerKey::generate();
        ledger.pair(key.id());

        let bundle = EvidenceBundle::publish(
            &key,
            "eth0",
            1,
            &[TopologyEvidence::new(
                Fact::Network { prefix },
                EvidenceSource::KernelRoute,
                Confidence::Observed,
                "eth0",
            )],
        );
        for record in ledger
            .accept_immediately(&bundle)
            .expect("accepted")
            .evidence
        {
            graph.absorb(record);
        }

        // And this machine sees it directly.
        graph.absorb(TopologyEvidence::new(
            Fact::InterfaceNetwork {
                interface: "en0".to_string(),
                prefix,
            },
            EvidenceSource::InterfaceAddress,
            Confidence::Observed,
            "en0",
        ));
        graph.finalize_roles();

        assert_eq!(graph.local_networks(), vec![prefix], "swept exactly once");
        assert_eq!(graph.network_refs().len(), 1, "one network, corroborated");

        let node = graph
            .network_ref_node(&graph.network_refs()[0])
            .expect("the network");
        assert_eq!(node.peer_origins().len(), 1, "the peer is still credited");
        assert!(
            node.provenance.iter().any(|p| !p.is_remote()),
            "and the local observation is what makes it reachable"
        );
    }
}

/// Lookups, probing and outputs must all respect the observation domain.
mod domain_safety {
    use super::*;
    use idnx::engine::enrich::queue_from_graph;
    use idnx::federation::bundle::EvidenceBundle;
    use idnx::federation::identity::PeerKey;
    use idnx::federation::ledger::PeerLedger;
    use idnx::topology::NodeId;
    use idnx::topology::graph::NodeKind;
    use std::collections::HashSet;

    const VANTAGE: &str = "en0";
    const INDEX: u32 = 3;

    /// Absorbs one bundle per peer, each using identical identifiers.
    fn merged(records: impl Fn(&str) -> Vec<TopologyEvidence>) -> TopologyGraph {
        let mut graph = TopologyGraph::new();
        let mut ledger = PeerLedger::new();

        for vantage in ["eth0", "eth0"] {
            let key = PeerKey::generate();
            ledger.pair(key.id());
            let bundle = EvidenceBundle::publish(&key, vantage, 1, &records(vantage));
            for record in ledger
                .accept_immediately(&bundle)
                .expect("accepted")
                .evidence
            {
                graph.absorb(record);
            }
        }
        graph.finalize_roles();
        graph
    }

    fn service_scenario(vantage: &str) -> Vec<TopologyEvidence> {
        let device = DeviceKey::Mac("02:00:5e:00:00:09".to_string());
        vec![
            TopologyEvidence::new(
                Fact::DeviceAddress {
                    device: device.clone(),
                    address: "10.0.0.9".parse().unwrap(),
                },
                EvidenceSource::ArpCache,
                Confidence::Observed,
                vantage,
            ),
            TopologyEvidence::new(
                Fact::DeviceHostname {
                    device,
                    hostname: format!("box-on-{vantage}"),
                },
                EvidenceSource::Mdns,
                Confidence::Observed,
                vantage,
            ),
            TopologyEvidence::new(
                Fact::Service {
                    address: "10.0.0.9".parse().unwrap(),
                    port: 443,
                    protocol: "tcp",
                    detail: Some(format!("TLS from {vantage}")),
                },
                EvidenceSource::TcpProbe,
                Confidence::Observed,
                vantage,
            ),
        ]
    }

    #[test]
    fn two_identical_services_are_advertised_by_their_own_devices() {
        // Not a count: the edges themselves must connect the right pairs. Matching by
        // address alone attached one peer's TLS service to the other peer's device.
        let graph = merged(service_scenario);

        let devices: Vec<&NodeId> = graph
            .nodes()
            .filter(|n| n.kind != NodeKind::Service && !n.hostnames.is_empty())
            .map(|n| &n.id)
            .collect();
        assert_eq!(devices.len(), 2, "one device per peer");

        // Each device advertises exactly one service, and they are different nodes: the
        // edges pair each peer's service with that peer's device. Matching by address
        // alone gave one device both, or gave one of them the other's.
        let mut advertised: Vec<&NodeId> = Vec::new();
        for device in &devices {
            let services = graph.services_of(device);
            assert_eq!(
                services.len(),
                1,
                "{device:?} advertises {} services",
                services.len()
            );
            advertised.push(&services[0].id);
        }
        assert_ne!(
            advertised[0], advertised[1],
            "both devices were given the same service node"
        );

        // And each service is attributed to the same peer as the device advertising it.
        for (device, service) in devices.iter().zip(advertised.iter()) {
            let device_node = graph.nodes().find(|n| &&n.id == device).expect("device");
            let service_node = graph.nodes().find(|n| &&n.id == service).expect("service");
            assert_eq!(
                device_node.peer_origins(),
                service_node.peer_origins(),
                "a device and the service it advertises must come from one peer"
            );
        }
    }

    #[test]
    fn remote_only_devices_never_enter_the_local_interrogation_queue() {
        // Probing a peer's device sends traffic to whatever holds that address on *this*
        // network and files the answer against a device on someone else's.
        let graph = merged(service_scenario);
        assert!(
            graph.nodes().any(|n| !n.hostnames.is_empty()),
            "peers reported devices"
        );

        let queued = queue_from_graph(&graph, &HashSet::new(), VANTAGE, INDEX);
        assert!(
            queued.is_empty(),
            "{:?}",
            queued
                .iter()
                .map(|t| t.device.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_merged_device_exposes_only_its_locally_observed_addresses() {
        // A manufacturer MAC merges across domains, so one node can hold an address this
        // machine saw and another only a peer did. Only the first is ours to probe.
        let device = DeviceKey::Mac("74:12:13:14:75:dc".to_string());
        let mut graph = TopologyGraph::new();

        graph.absorb(TopologyEvidence::new(
            Fact::DeviceAddress {
                device: device.clone(),
                address: "192.168.1.1".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
            VANTAGE,
        ));

        let mut ledger = PeerLedger::new();
        let key = PeerKey::generate();
        ledger.pair(key.id());
        let bundle = EvidenceBundle::publish(
            &key,
            "eth0",
            1,
            &[TopologyEvidence::new(
                Fact::DeviceAddress {
                    device,
                    address: "10.9.9.9".parse().unwrap(),
                },
                EvidenceSource::ArpCache,
                Confidence::Observed,
                "eth0",
            )],
        );
        for record in ledger
            .accept_immediately(&bundle)
            .expect("accepted")
            .evidence
        {
            graph.absorb(record);
        }
        graph.finalize_roles();

        let queued = queue_from_graph(&graph, &HashSet::new(), VANTAGE, INDEX);
        assert_eq!(queued.len(), 1, "one device");

        let endpoints: Vec<String> = queued[0].endpoints.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            endpoints,
            vec!["192.168.1.1".to_string()],
            "the peer's address must not be probed from here"
        );
    }

    #[test]
    fn a_remote_interface_appears_beside_its_own_network() {
        // Looking interfaces up by prefix alone assumed the local domain, so a peer's
        // interface attached to nothing.
        let graph = merged(|vantage| {
            vec![TopologyEvidence::new(
                Fact::InterfaceNetwork {
                    interface: format!("if-{vantage}"),
                    prefix: "10.0.0.0/24".parse().unwrap(),
                },
                EvidenceSource::InterfaceAddress,
                Confidence::Observed,
                vantage,
            )]
        });

        let refs = graph.network_refs();
        assert_eq!(refs.len(), 2);
        for reference in &refs {
            let interfaces = graph.interfaces_for_network(reference);
            assert_eq!(
                interfaces.len(),
                1,
                "{reference} should have exactly its own interface, got {interfaces:?}"
            );
        }
    }

    #[test]
    fn same_numbered_vlans_stay_distinct_in_every_output() {
        // A tag is unique inside one switched domain. Collapsed, learning a prefix for one
        // silently claimed to have learned it for both.
        let mut graph = merged(|vantage| {
            vec![TopologyEvidence::new(
                Fact::Vlan { id: 20 },
                EvidenceSource::Stp,
                Confidence::Observed,
                vantage,
            )]
        });

        let vlans: Vec<_> = graph.vlans_without_prefix().cloned().collect();
        assert_eq!(vlans.len(), 2, "{vlans:?}");
        assert_eq!(vlans[0].id, vlans[1].id);
        assert_ne!(vlans[0].realm, vlans[1].realm);

        // Learning a prefix for one must not claim it for the other. The binding arrives as
        // evidence, absorbed here, so it lands in the domain that observed it and nowhere
        // else -- a graph mutation keyed on the tag alone would have removed both.
        graph.absorb(TopologyEvidence::new(
            Fact::VlanNetwork {
                vlan: 20,
                network: "192.0.2.0/24".parse().expect("a literal prefix"),
            },
            EvidenceSource::DhcpLease,
            Confidence::Observed,
            "en0",
        ));

        let remaining: Vec<_> = graph.vlans_without_prefix().cloned().collect();
        assert_eq!(
            remaining, vlans,
            "both peers' VLAN 20 keep their unknown extent: {remaining:?}"
        );
        let bound = graph.vlan_networks();
        assert_eq!(bound.len(), 1, "one binding, in one domain: {bound:?}");
        assert!(
            bound[0].0.realm.is_local(),
            "and it belongs to the domain that observed it"
        );
    }

    #[test]
    fn a_peer_only_public_prefix_exports_as_remotely_observed() {
        // Its identity domain is the shared one, so peers can corroborate it. That must not
        // read as "this machine saw it".
        let mut graph = TopologyGraph::new();
        let mut ledger = PeerLedger::new();
        let key = PeerKey::generate();
        ledger.pair(key.id());

        let bundle = EvidenceBundle::publish(
            &key,
            "eth0",
            1,
            &[TopologyEvidence::new(
                Fact::Network {
                    prefix: "203.0.113.0/24".parse().unwrap(),
                },
                EvidenceSource::KernelRoute,
                Confidence::Observed,
                "eth0",
            )],
        );
        for record in ledger
            .accept_immediately(&bundle)
            .expect("accepted")
            .evidence
        {
            graph.absorb(record);
        }
        graph.finalize_roles();

        let node = graph
            .network_ref_node(&graph.network_refs()[0])
            .expect("the network");

        assert!(!node.locally_observed(), "nothing here saw it");
        let observations = node.observations();
        assert_eq!(observations.len(), 1, "{observations:?}");
        assert!(observations[0].starts_with("peer "), "{observations:?}");
        assert!(!observations.contains(&"local".to_string()));
    }

    #[test]
    fn a_corroborated_network_lists_every_observer() {
        // Collapsing to one value lost everyone but the first.
        let prefix: ipnet::IpNet = "203.0.113.0/24".parse().unwrap();
        let mut graph = TopologyGraph::new();
        let mut ledger = PeerLedger::new();

        for vantage in ["eth0", "eth1"] {
            let key = PeerKey::generate();
            ledger.pair(key.id());
            let bundle = EvidenceBundle::publish(
                &key,
                vantage,
                1,
                &[TopologyEvidence::new(
                    Fact::Network { prefix },
                    EvidenceSource::KernelRoute,
                    Confidence::Observed,
                    vantage,
                )],
            );
            for record in ledger
                .accept_immediately(&bundle)
                .expect("accepted")
                .evidence
            {
                graph.absorb(record);
            }
        }
        graph.absorb(TopologyEvidence::new(
            Fact::InterfaceNetwork {
                interface: VANTAGE.to_string(),
                prefix,
            },
            EvidenceSource::InterfaceAddress,
            Confidence::Observed,
            VANTAGE,
        ));
        graph.finalize_roles();

        let node = graph
            .network_ref_node(&graph.network_refs()[0])
            .expect("the network");
        let observations = node.observations();
        assert_eq!(observations.len(), 3, "{observations:?}");
        assert_eq!(observations[0], "local");
    }

    #[test]
    fn a_node_id_never_carries_a_truncated_peer_identity() {
        // A short form is for display. Two peers sharing a 16-character prefix -- which can
        // be ground out -- would otherwise share a namespace.
        let graph = merged(service_scenario);
        for node in graph.nodes() {
            let NodeId::Device(key) = &node.id else {
                continue;
            };
            let rendered = key.to_string();
            if let Some((_, qualifier)) = rendered.split_once('@') {
                let peer = qualifier.split('/').next().expect("peer part");
                assert_eq!(peer.len(), 64, "expected a full identity in {rendered}");
            }
        }
    }
}

/// The remaining cross-realm leaks: identity merging, scheduling, and export identities.
mod cross_realm_leaks {
    use super::*;
    use idnx::engine::enrich::queue_from_graph;
    use idnx::federation::bundle::EvidenceBundle;
    use idnx::federation::identity::{PeerId, PeerKey};
    use idnx::federation::ledger::PeerLedger;
    use idnx::providers::target::DeviceTier;
    use idnx::topology::graph::Relationship;
    use std::collections::HashSet;

    const VANTAGE: &str = "en0";
    const INDEX: u32 = 3;

    /// Wraps a graph in the minimum report an export needs.
    fn sample_report(graph: TopologyGraph) -> idnx::engine::orchestrator::DiscoveryReport {
        use idnx::engine::orchestrator::{DiscoveryReport, VisibilityReport};
        use idnx::providers::{Vantage, VantageKind};

        DiscoveryReport {
            graph,
            scope_runs: Vec::new(),
            pivot_runs: Vec::new(),
            coverage: Vec::new(),
            enrichment_elapsed: std::time::Duration::ZERO,
            enrichment_sequential_equivalent: std::time::Duration::ZERO,
            probes_attempted: 0,
            network_reachability: Default::default(),
            visibility: VisibilityReport {
                vantage: Vantage {
                    interface: VANTAGE.to_string(),
                    kind: VantageKind::Wired,
                    index: INDEX,
                    capture_available: false,
                },
                blind_to: Vec::new(),
                unavailable: Vec::new(),
                binding_mode: idnx::net::socket::BindingMode::Unbound,
                observed_frames: None,
                accepted_facts: None,
                routing_updates: None,
                control_plane: None,
            },
            oversized_scopes: Vec::new(),
            converged: true,
        }
    }

    /// Absorbs one peer's bundle into a graph.
    fn absorb_from(graph: &mut TopologyGraph, key: &PeerKey, records: &[TopologyEvidence]) {
        let mut ledger = PeerLedger::new();
        ledger.pair(key.id());
        let bundle = EvidenceBundle::publish(key, "eth0", 1, records);
        for record in ledger
            .accept_immediately(&bundle)
            .expect("accepted")
            .evidence
        {
            graph.absorb(record);
        }
    }

    #[test]
    fn a_remote_route_address_merges_with_its_arp_mac() {
        // A kernel route names its next hop by address; the ARP table names the same device
        // by MAC. Remotely, the address identity is qualified into a zone while the
        // ownership map keys the interface and the domain separately -- so the lookup
        // missed, the two stayed apart, and the routed network hung off a node of its own.
        let key = PeerKey::generate();
        let gateway_address: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let routed: ipnet::IpNet = "10.9.0.0/24".parse().unwrap();
        let mac = DeviceKey::Mac("aa:bb:cc:dd:ee:01".to_string());

        let mut graph = TopologyGraph::new();

        // Route evidence first: an address-keyed gateway, before any MAC is known.
        absorb_from(
            &mut graph,
            &key,
            &[
                TopologyEvidence::new(
                    Fact::Network { prefix: routed },
                    EvidenceSource::KernelRoute,
                    Confidence::Observed,
                    "eth0",
                ),
                TopologyEvidence::new(
                    Fact::RoutesTo {
                        device: DeviceKey::Address(gateway_address),
                        network: routed,
                        next_hop: None,
                    },
                    EvidenceSource::KernelRoute,
                    Confidence::Observed,
                    "eth0",
                ),
            ],
        );

        // Then the ARP table names the same address by MAC.
        let mut ledger = PeerLedger::new();
        ledger.pair(key.id());
        let bundle = EvidenceBundle::publish(
            &key,
            "eth0",
            2,
            &[TopologyEvidence::new(
                Fact::DeviceAddress {
                    device: mac,
                    address: gateway_address,
                },
                EvidenceSource::ArpCache,
                Confidence::Observed,
                "eth0",
            )],
        );
        for record in ledger
            .accept_immediately(&bundle)
            .expect("accepted")
            .evidence
        {
            graph.absorb(record);
        }
        graph.finalize_roles();

        // One device holding that address, not two.
        let devices: Vec<_> = graph
            .nodes()
            .filter(|n| n.addresses.contains(&gateway_address))
            .collect();
        assert_eq!(
            devices.len(),
            1,
            "{:?}",
            devices.iter().map(|n| n.id.clone()).collect::<Vec<_>>()
        );

        // And the route edge is attached to it.
        let routes: Vec<_> = graph
            .edges()
            .filter(|e| e.relationship == Relationship::RoutesTo && e.from == devices[0].id)
            .collect();
        assert_eq!(routes.len(), 1, "the route must hang off the merged device");
    }

    #[test]
    fn a_remote_pivot_cannot_change_a_local_hosts_queue_tier() {
        // Both networks use 10.0.0.1. The peer's is a router; ours is an ordinary host.
        // Keyed by address, the peer's role signal promoted our host to pivot priority.
        let shared: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let local_device = DeviceKey::Mac("02:00:5e:00:00:aa".to_string());
        let mut graph = TopologyGraph::new();

        graph.absorb(TopologyEvidence::new(
            Fact::DeviceAddress {
                device: local_device.clone(),
                address: shared,
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
            VANTAGE,
        ));

        let key = PeerKey::generate();
        absorb_from(
            &mut graph,
            &key,
            &[
                TopologyEvidence::new(
                    Fact::DeviceAddress {
                        device: DeviceKey::Mac("02:00:5e:00:00:bb".to_string()),
                        address: shared,
                    },
                    EvidenceSource::ArpCache,
                    Confidence::Observed,
                    "eth0",
                ),
                TopologyEvidence::new(
                    Fact::DeviceRoleSignal {
                        device: DeviceKey::Mac("02:00:5e:00:00:bb".to_string()),
                        signal: RoleSignal::DefaultGateway,
                    },
                    EvidenceSource::DefaultGateway,
                    Confidence::Observed,
                    "eth0",
                ),
            ],
        );
        graph.finalize_roles();

        let queued = queue_from_graph(&graph, &HashSet::new(), VANTAGE, INDEX);
        assert_eq!(queued.len(), 1, "only the local device is ours to probe");
        assert_eq!(queued[0].device, local_device);
        assert_eq!(
            queued[0].tier,
            DeviceTier::Host,
            "a peer's router must not raise a local host's priority"
        );

        // Nothing remote reaches the scheduling sets either.
        assert!(graph.pivot_addresses().is_empty());
        assert!(graph.candidate_addresses().is_empty());
    }

    #[test]
    fn device_for_address_ignores_a_peer_only_private_address() {
        // Its contract is "the device this machine can reach at this address". Handing back
        // a peer's device answers a different question.
        let address: std::net::IpAddr = "10.0.0.7".parse().unwrap();
        let mut graph = TopologyGraph::new();

        absorb_from(
            &mut graph,
            &PeerKey::generate(),
            &[TopologyEvidence::new(
                Fact::DeviceAddress {
                    device: DeviceKey::Mac("02:00:5e:00:00:cc".to_string()),
                    address,
                },
                EvidenceSource::ArpCache,
                Confidence::Observed,
                "eth0",
            )],
        );
        graph.finalize_roles();

        assert!(
            graph.nodes().any(|n| n.addresses.contains(&address)),
            "the peer's device is in the graph"
        );
        assert!(
            graph.device_for_address(&address).is_none(),
            "but it is not reachable from here"
        );
    }

    #[test]
    fn two_peers_sharing_a_display_prefix_stay_distinct_in_every_export() {
        // The display form truncates to sixteen characters. Exports must not, or two peers
        // whose identities share a prefix -- which can be ground out -- become one to any
        // consumer.
        let mut graph = TopologyGraph::new();
        let mut peers: Vec<PeerId> = Vec::new();

        for suffix in ['1', '2'] {
            let key = PeerKey::generate();
            peers.push(key.id());
            absorb_from(
                &mut graph,
                &key,
                &[
                    TopologyEvidence::new(
                        Fact::Network {
                            prefix: "10.0.0.0/24".parse().unwrap(),
                        },
                        EvidenceSource::InterfaceAddress,
                        Confidence::Observed,
                        "eth0",
                    ),
                    TopologyEvidence::new(
                        Fact::Vlan { id: 20 },
                        EvidenceSource::Stp,
                        Confidence::Observed,
                        "eth0",
                    ),
                    TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: DeviceKey::Mac(format!("02:00:5e:00:00:{suffix}{suffix}")),
                            address: "10.0.0.5".parse().unwrap(),
                        },
                        EvidenceSource::ArpCache,
                        Confidence::Observed,
                        "eth0",
                    ),
                ],
            );
        }
        graph.finalize_roles();

        let report = sample_report(graph);
        let export = idnx::output::export::build_export(&report);

        // Networks: two, each naming its own peer in full.
        assert_eq!(export.networks.len(), 2);
        let mut named: Vec<String> = export
            .networks
            .iter()
            .filter_map(|n| n.identity_domain.peer.clone())
            .collect();
        named.sort();
        assert_eq!(named.len(), 2);
        assert_ne!(named[0], named[1]);
        for peer in &named {
            assert_eq!(peer.len(), 64, "a full identity, not a display form");
            assert!(peers.iter().any(|p| p.to_hex() == *peer));
        }

        // VLANs: likewise.
        let mut vlan_peers: Vec<String> = export
            .vlans
            .iter()
            .filter_map(|v| v.observed_in.peer.clone())
            .collect();
        vlan_peers.sort();
        assert_eq!(vlan_peers.len(), 2);
        assert_ne!(vlan_peers[0], vlan_peers[1]);

        // Devices: each observed by exactly one peer, identified in full.
        let device_peers: Vec<String> = export
            .devices
            .iter()
            .flat_map(|d| d.observed_by.iter())
            .filter_map(|o| o.peer.clone())
            .collect();
        assert_eq!(device_peers.len(), 2, "{device_peers:?}");
        assert_ne!(device_peers[0], device_peers[1]);

        // And every tabular format keeps them apart too.
        for format in [
            idnx::output::export::OutputFormat::Json,
            idnx::output::export::OutputFormat::Yaml,
            idnx::output::export::OutputFormat::Xml,
            idnx::output::export::OutputFormat::Csv,
        ] {
            let rendered = idnx::output::export::render(&export, format).expect("renders");
            for peer in &named {
                assert!(
                    rendered.contains(peer.as_str()),
                    "{format:?} lost the full identity {peer}"
                );
            }
        }
    }
}
