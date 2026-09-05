//! The traversal itself, through the real `DiscoveryEngine`.
//!
//! Every other test in this repository proves that some provider produces the right
//! evidence, or that the graph absorbs it correctly. None of them prove the property the
//! whole tool rests on: that a network nobody knew about at the start of the run is
//! discovered, enters the frontier, is examined in its own right, and that the devices
//! found there are then interrogated in turn -- until there is genuinely nothing left,
//! which is the only thing convergence is allowed to mean.
//!
//! So the providers here are scripted and the engine is not. The script stands in for what
//! a router would disclose over SNMP or a routing protocol; the queueing, the fixed-point
//! loop, the device interrogation and the convergence decision are the shipping ones.
//!
//! Addresses are documentation ranges throughout (RFC 5737, RFC 2544), and no scripted
//! reply depends on anything answering.

mod common;

use common::{Call, addr, local, net, run_scripted};

use idnx::providers::ReachabilityState;
use idnx::topology::graph::{DeviceCategory, NodeId, Relationship};

use ipnet::IpNet;

/// Where in `scope_runs` a network was examined, if it was.
fn scope_positions(
    report: &idnx::engine::orchestrator::DiscoveryReport,
    prefix: IpNet,
) -> Vec<usize> {
    report
        .scope_runs
        .iter()
        .enumerate()
        .filter(|(_, run)| run.scope == Some(prefix))
        .map(|(at, _)| at)
        .collect()
}

#[test]
fn a_disclosed_subnet_moves_the_frontier_and_the_cascade_continues() {
    let (report, calls) = run_scripted();

    // The seed pass, then the operator's scope, exactly once each.
    assert_eq!(
        report
            .scope_runs
            .iter()
            .filter(|r| r.scope.is_none())
            .count(),
        1,
        "the local seed runs once"
    );
    let seed_scope = scope_positions(&report, net("192.0.2.0/24"));
    assert_eq!(seed_scope.len(), 1, "the initial scope is examined once");

    // The disclosure the run could not have known at the start.
    let second = scope_positions(&report, net("198.51.100.0/24"));
    assert_eq!(second.len(), 1, "the disclosed subnet is examined once");
    assert!(
        second[0] > seed_scope[0],
        "it can only be examined after the router disclosed it: {:?}",
        report
            .scope_runs
            .iter()
            .map(|r| r.scope.map(|s| s.to_string()))
            .collect::<Vec<_>>()
    );
    // And the router had to be asked before that scope could exist.
    let polled_router = calls
        .iter()
        .position(|call| *call == Call::Device(addr("192.0.2.1")))
        .expect("the border router was interrogated");
    let examined_second = calls
        .iter()
        .position(|call| *call == Call::Scope(net("198.51.100.0/24")))
        .expect("the disclosed subnet was examined");
    assert!(
        polled_router < examined_second,
        "the frontier moved because of the disclosure, not before it: {calls:?}"
    );

    // The device found on the newly disclosed subnet is itself interrogated, and what it
    // discloses continues the cascade a second time.
    assert!(
        calls.contains(&Call::Device(addr("198.51.100.1"))),
        "a device on a disclosed subnet is interrogated: {calls:?}"
    );
    let third = scope_positions(&report, net("203.0.113.0/24"));
    assert_eq!(third.len(), 1, "the second disclosure is examined once");
    assert!(third[0] > second[0], "and later than the first");
    assert!(
        calls.contains(&Call::Device(addr("203.0.113.9"))),
        "an ordinary host on the second subnet is interrogated too: {calls:?}"
    );
}

#[test]
fn what_could_not_be_resolved_survives_the_run_unresolved() {
    let (report, _) = run_scripted();

    // Advertised and unreachable is not the same as not discovered. The network stays on
    // the map, and the reason nothing came back is recorded against it.
    let networks: Vec<String> = report
        .graph
        .network_refs()
        .into_iter()
        .map(|reference| reference.prefix.to_string())
        .collect();
    assert!(
        networks.contains(&"198.18.0.0/24".to_string()),
        "an advertised network stays advertised: {networks:?}"
    );
    let unreachable = report
        .network_reachability
        .get(&local("198.18.0.0/24"))
        .expect("it was probed like any other network");
    assert_eq!(
        unreachable.state(),
        ReachabilityState::ProbedUnreachable,
        "probes went out and nothing answered: {unreachable:?}"
    );
    assert_eq!(unreachable.attempted, 254);
    assert!(unreachable.responders.is_empty());
    // How it was discovered is held apart from what answered: a failed sweep says nothing
    // about whether a router advertised the prefix.
    assert!(
        unreachable
            .discovery
            .iter()
            .any(|how| how.contains("advertised by 198.51.100.1")),
        "its provenance survives the failed sweep: {unreachable:?}"
    );

    // A network that did answer is a different state, and keeps its coverage as well as
    // its responders.
    let reached = report
        .network_reachability
        .get(&local("203.0.113.0/24"))
        .expect("recorded");
    assert_eq!(reached.state(), ReachabilityState::Reachable);
    assert_eq!(reached.responders.len(), 2);
    assert_eq!(reached.attempted, 254, "the sweep's coverage is not erased");
    // The human sentence is rendered from the state and is never the state itself.
    assert!(unreachable.describe().contains("none answered"));

    // A VLAN with no prefix evidence keeps no prefix. Attaching the vantage's own prefix
    // to a tagged network is the invention this refuses.
    let prefixless: Vec<String> = report
        .graph
        .vlans_without_prefix()
        .map(|vlan| vlan.to_string())
        .collect();
    assert!(
        prefixless.iter().any(|vlan| vlan.contains("42")),
        "the VLAN stays prefixless: {prefixless:?}"
    );

    // Something forwarded and never identified itself. It is a boundary, and saying more
    // than that would be asserting an owner nobody named.
    let boundaries = report.graph.devices_in(DeviceCategory::ForwardingInterface);
    assert!(
        boundaries
            .iter()
            .any(|node| node.addresses.contains(&addr("203.0.113.254"))),
        "the silent hop stays an unresolved forwarding interface"
    );
    assert!(
        report
            .graph
            .devices_in(DeviceCategory::Router)
            .iter()
            .all(|node| !node.addresses.contains(&addr("203.0.113.254"))),
        "and is never promoted to a router on forwarding alone"
    );
}

#[test]
fn every_scope_and_device_is_processed_once_and_convergence_waits_for_all_of_them() {
    let (report, calls) = run_scripted();

    let mut scopes: Vec<String> = report
        .scope_runs
        .iter()
        .filter_map(|run| run.scope.map(|s| s.to_string()))
        .collect();
    let total = scopes.len();
    scopes.sort();
    scopes.dedup();
    assert_eq!(
        total,
        scopes.len(),
        "no network is examined twice: {scopes:?}"
    );

    let mut devices: Vec<String> = calls
        .iter()
        .filter_map(|call| match call {
            Call::Device(address) => Some(address.to_string()),
            Call::Scope(_) => None,
        })
        .collect();
    let asked = devices.len();
    devices.sort();
    devices.dedup();
    assert_eq!(
        asked,
        devices.len(),
        "no device is asked twice: {devices:?}"
    );

    let mut covered: Vec<String> = report
        .coverage
        .iter()
        .map(|record| format!("{:?}", record.device))
        .collect();
    let records = covered.len();
    covered.sort();
    covered.dedup();
    assert_eq!(records, covered.len(), "one coverage record per device");

    // Convergence means the frontier is empty, not that a pass happened to be quiet. Every
    // network the run learned about was examined before it was declared.
    assert!(report.converged, "the run converged");
    for prefix in [
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "198.18.0.0/24",
    ] {
        assert_eq!(
            scope_positions(&report, net(prefix)).len(),
            1,
            "{prefix} was examined before convergence was declared"
        );
    }
}

#[test]
fn examining_a_network_is_what_finds_the_devices_in_it() {
    // The ordering the whole cascade depends on. A router names a subnet and says nothing
    // about who is on it; the devices only exist once the subnet itself is examined. If a
    // device were interrogated before its network was examined, the run would have learned
    // of it some other way and this test would be proving nothing about scope discovery.
    let (_, calls) = run_scripted();

    let at = |wanted: Call| {
        calls
            .iter()
            .position(|call| *call == wanted)
            .unwrap_or_else(|| panic!("{wanted:?} never happened: {calls:?}"))
    };

    for (scope, discovered) in [
        (net("198.51.100.0/24"), addr("198.51.100.1")),
        (net("203.0.113.0/24"), addr("203.0.113.9")),
        (net("203.0.113.0/24"), addr("203.0.113.254")),
    ] {
        assert!(
            at(Call::Scope(scope)) < at(Call::Device(discovered)),
            "{discovered} can only be asked after {scope} was examined: {calls:?}"
        );
    }

    // And each network was itself only reachable through the device that disclosed it.
    assert!(
        at(Call::Device(addr("192.0.2.1"))) < at(Call::Scope(net("198.51.100.0/24"))),
        "the border router disclosed the subnet before it could be examined: {calls:?}"
    );
    assert!(
        at(Call::Device(addr("198.51.100.1"))) < at(Call::Scope(net("203.0.113.0/24"))),
        "the switch disclosed the second subnet before it could be examined: {calls:?}"
    );
}

#[test]
fn a_layer_three_switch_is_one_device_that_keeps_both_identities() {
    // A box that bridges and routes is one box. Splitting it -- a switch node from the
    // spanning-tree evidence, a router node from the forwarding evidence -- reports two
    // devices that do not exist, and neither of them holds the whole picture: the routed
    // networks hang off one, the switching identity off the other.
    let (report, _) = run_scripted();

    let switch = addr("198.51.100.1");
    let holders: Vec<_> = report
        .graph
        .nodes()
        .filter(|node| node.addresses.contains(&switch))
        .collect();
    assert_eq!(
        holders.len(),
        1,
        "one box, one node: {:?}",
        holders.iter().map(|n| &n.id).collect::<Vec<_>>()
    );
    let node = holders[0];

    // Both kinds of evidence survive on it. Losing the switching evidence once the device
    // is classified as a router would erase why it is on the map at all.
    let signals: Vec<&String> = node.role_signals.iter().collect();
    assert!(
        signals.iter().any(|s| s.contains("spanning-tree")),
        "its switching evidence is retained: {signals:?}"
    );
    assert!(
        signals.iter().any(|s| s.contains("forward")),
        "and so is its forwarding evidence: {signals:?}"
    );

    // It discloses more than one routed network, and both hang off that single node.
    let routed: Vec<String> = report
        .graph
        .edges()
        .filter(|edge| edge.relationship == Relationship::RoutesTo && edge.from == node.id)
        .filter_map(|edge| match &edge.to {
            NodeId::Network(prefix, _) => Some(prefix.to_string()),
            _ => None,
        })
        .collect();
    for prefix in ["203.0.113.0/24", "198.18.0.0/24"] {
        assert!(
            routed.iter().any(|net| net == prefix),
            "it routes toward {prefix}: {routed:?}"
        );
    }
}

#[test]
fn a_vlan_is_bound_to_a_prefix_only_by_an_observation_that_stated_both() {
    // The positive VLAN case, with its evidence attached. VLAN 77 is bound because one
    // observation carried the tag and the prefix together; VLAN 42 is not, because nothing
    // ever stated its extent. Both survive the run, and the difference between them is
    // visible in the graph rather than implied by an absence.
    let (report, _) = run_scripted();

    let bound = report.graph.vlan_networks();
    assert_eq!(bound.len(), 1, "one binding: {bound:?}");
    let (vlan, prefix, provenance) = &bound[0];
    assert_eq!(vlan.id, 77);
    assert_eq!(prefix.to_string(), "192.0.2.0/24");
    assert!(
        !provenance.is_empty(),
        "the binding carries the observation that made it, so it can be checked"
    );

    // The binding is a graph relationship, not an untraceable mutation of a flag.
    assert!(
        report.graph.edges().any(|edge| {
            edge.relationship == Relationship::CarriesNetwork
                && matches!(&edge.from, NodeId::Vlan(id, _) if *id == 77)
                && !edge.provenance.is_empty()
        }),
        "the VLAN carries the network as an edge with its own evidence"
    );

    assert!(
        report
            .graph
            .vlans_without_prefix()
            .all(|vlan| vlan.id != 77),
        "a bound VLAN is no longer of unknown extent"
    );
}

#[test]
fn the_acceptance_is_not_vacuous() {
    // Guards the three tests above: dedup assertions pass trivially against empty lists,
    // and an ordering assertion proves nothing if the later scope was never reached. This
    // states the sizes those tests depend on.
    let (report, calls) = run_scripted();

    let devices: Vec<String> = calls
        .iter()
        .filter_map(|call| match call {
            Call::Device(address) => Some(address.to_string()),
            Call::Scope(_) => None,
        })
        .collect();
    for expected in ["192.0.2.1", "198.51.100.1", "203.0.113.9", "203.0.113.254"] {
        assert!(
            devices.iter().any(|asked| asked == expected),
            "{expected} was interrogated: {devices:?}"
        );
    }
    assert_eq!(
        report.coverage.len(),
        devices.len(),
        "one coverage record per interrogation: {:?}",
        report
            .coverage
            .iter()
            .map(|record| record.addresses.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        report
            .scope_runs
            .iter()
            .filter(|run| run.scope.is_some())
            .count(),
        4,
        "four networks were examined"
    );
}
