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
            .accept(&bundle)
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
        .accept(&EvidenceBundle::publish(&b, B_VANTAGE, 1, &contradiction))
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
