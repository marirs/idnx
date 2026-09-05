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

use idnx::engine::orchestrator::{Budget, DiscoveryEngine};
use idnx::providers::{
    DiscoveryContext, DiscoveryProvider, NetworkReachability, ProviderFuture, ProviderOutput,
    ReachabilityState, Vantage, VantageKind,
};
use idnx::topology::evidence::{Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal};
use idnx::topology::realm::Realm;
use idnx::topology::{
    TopologyEvidence,
    graph::{DeviceCategory, NetworkRef, NodeId, Relationship},
};

use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

const VANTAGE: &str = "test0";

fn addr(text: &str) -> IpAddr {
    text.parse().expect("a literal address")
}

fn net(text: &str) -> IpNet {
    text.parse().expect("a literal prefix")
}

/// The key a locally observed network is recorded under: prefix plus observation domain.
fn local(text: &str) -> NetworkRef {
    let prefix = net(text);
    NetworkRef {
        prefix,
        realm: idnx::topology::realm::network_realm(&prefix, &Realm::Local),
    }
}

fn advertised(fact: Fact) -> TopologyEvidence {
    TopologyEvidence::new(fact, EvidenceSource::Snmp, Confidence::Advertised, VANTAGE)
}

fn observed(fact: Fact) -> TopologyEvidence {
    TopologyEvidence::new(
        fact,
        EvidenceSource::KernelRoute,
        Confidence::Observed,
        VANTAGE,
    )
}

fn device_key(text: &str) -> DeviceKey {
    DeviceKey::Address(addr(text))
}

/// What this vantage knows before anything is asked: one attached network, one router on
/// it, and a VLAN seen on the wire whose prefix nothing has stated.
struct ScriptedSeed;

impl DiscoveryProvider for ScriptedSeed {
    fn name(&self) -> &'static str {
        "scripted-seed"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        context.scope.is_none() && context.target.is_none()
    }

    fn discover<'a>(&'a self, _context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            ProviderOutput {
                evidence: vec![
                    observed(Fact::Network {
                        prefix: net("192.0.2.0/24"),
                    }),
                    observed(Fact::DeviceAddress {
                        device: device_key("192.0.2.1"),
                        address: addr("192.0.2.1"),
                    }),
                    observed(Fact::DeviceRoleSignal {
                        device: device_key("192.0.2.1"),
                        signal: RoleSignal::DefaultGateway,
                    }),
                    // A tagged frame was seen. Nothing has said what prefix rides on it,
                    // and the run must not invent one.
                    observed(Fact::Vlan { id: 42 }),
                ],
                notes: vec!["seeded from scripted local state".to_string()],
                attempted: true,
                reachability: Vec::new(),
            }
        })
    }
}

/// One call the engine made into the script.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Scope(IpNet),
    Device(IpAddr),
}

/// The scripted network.
///
/// The alternation matters more than the content. A *device* discloses networks and never
/// the devices on them; a *scope* discovers the devices in it and never the networks beyond
/// them. So the only way the run can reach 203.0.113.9 is: ask 192.0.2.1, learn a subnet,
/// examine that subnet, find the router in it, ask that router, learn a further subnet,
/// examine it, and find the host. Injecting a device from the router that named its network
/// would let the test pass without the engine ever examining a scope.
struct ScriptedNetwork {
    /// What a device discloses when interrogated: networks, never devices.
    disclosures: HashMap<IpAddr, Vec<TopologyEvidence>>,
    /// What examining a network finds in it: devices, never further networks.
    occupants: HashMap<IpNet, Vec<TopologyEvidence>>,
    /// Reachability each scope pass establishes, as state.
    reachability: HashMap<IpNet, NetworkReachability>,
    /// Devices that answer nothing at all, and what the provider says about that.
    silent: HashMap<IpAddr, String>,
    calls: Mutex<Vec<Call>>,
}

impl ScriptedNetwork {
    fn new() -> Self {
        let mut disclosures: HashMap<IpAddr, Vec<TopologyEvidence>> = HashMap::new();
        let mut occupants: HashMap<IpNet, Vec<TopologyEvidence>> = HashMap::new();
        let mut reachability: HashMap<IpNet, NetworkReachability> = HashMap::new();

        // The border router names a subnet nobody here is attached to. It names no device
        // on it: who lives there is only discoverable by examining the subnet.
        disclosures.insert(
            addr("192.0.2.1"),
            vec![
                advertised(Fact::Network {
                    prefix: net("198.51.100.0/24"),
                }),
                advertised(Fact::RoutesTo {
                    device: device_key("192.0.2.1"),
                    network: net("198.51.100.0/24"),
                    next_hop: Some(addr("192.0.2.1")),
                }),
            ],
        );

        // Examining the attached network finds the border router's neighbours -- and one
        // observation that stated a VLAN and the prefix riding on it together.
        occupants.insert(
            net("192.0.2.0/24"),
            vec![
                TopologyEvidence::new(
                    Fact::VlanNetwork {
                        vlan: 77,
                        network: net("192.0.2.0/24"),
                    },
                    EvidenceSource::DhcpLease,
                    Confidence::Observed,
                    VANTAGE,
                )
                .with_detail("client-facing DHCP ACK, tagged, with option 1"),
            ],
        );
        reachability.insert(
            net("192.0.2.0/24"),
            NetworkReachability::probed(
                vec![addr("192.0.2.1")],
                254,
                0,
                vec!["swept the attached network".to_string()],
            )
            .discovered_by("attached to this vantage"),
        );

        // Examining the disclosed subnet finds the device in it: a layer-3 switch, which
        // both bridges and forwards. One box, two kinds of evidence.
        occupants.insert(
            net("198.51.100.0/24"),
            vec![
                advertised(Fact::DeviceAddress {
                    device: device_key("198.51.100.1"),
                    address: addr("198.51.100.1"),
                }),
                advertised(Fact::DeviceRoleSignal {
                    device: device_key("198.51.100.1"),
                    signal: RoleSignal::SpanningTreeBridge,
                }),
                advertised(Fact::DeviceRoleSignal {
                    device: device_key("198.51.100.1"),
                    signal: RoleSignal::SnmpForwarding,
                }),
            ],
        );
        reachability.insert(
            net("198.51.100.0/24"),
            NetworkReachability::probed(
                vec![addr("198.51.100.1")],
                254,
                0,
                vec!["swept the disclosed subnet".to_string()],
            )
            .discovered_by("routed by 192.0.2.1"),
        );

        // That switch routes toward two further networks, and keeps its switching identity
        // while doing it.
        disclosures.insert(
            addr("198.51.100.1"),
            vec![
                advertised(Fact::Network {
                    prefix: net("203.0.113.0/24"),
                }),
                advertised(Fact::RoutesTo {
                    device: device_key("198.51.100.1"),
                    network: net("203.0.113.0/24"),
                    next_hop: Some(addr("198.51.100.1")),
                }),
                advertised(Fact::Network {
                    prefix: net("198.18.0.0/24"),
                }),
                advertised(Fact::RoutesTo {
                    device: device_key("198.51.100.1"),
                    network: net("198.18.0.0/24"),
                    next_hop: Some(addr("198.51.100.1")),
                }),
            ],
        );

        // Examining the second disclosed subnet finds an ordinary host, and something that
        // forwarded traffic without identifying itself.
        occupants.insert(
            net("203.0.113.0/24"),
            vec![
                advertised(Fact::DeviceAddress {
                    device: device_key("203.0.113.9"),
                    address: addr("203.0.113.9"),
                }),
                advertised(Fact::DeviceAddress {
                    device: device_key("203.0.113.254"),
                    address: addr("203.0.113.254"),
                }),
                advertised(Fact::DeviceRoleSignal {
                    device: device_key("203.0.113.254"),
                    signal: RoleSignal::ObservedForwarding,
                }),
            ],
        );
        reachability.insert(
            net("203.0.113.0/24"),
            NetworkReachability::probed(
                vec![addr("203.0.113.9"), addr("203.0.113.254")],
                254,
                0,
                vec!["swept the second subnet".to_string()],
            )
            .discovered_by("routed by 198.51.100.1"),
        );

        // The third network is advertised and nothing in it answers. That is a result, not
        // an absence of one, and it is returned as state.
        reachability.insert(
            net("198.18.0.0/24"),
            NetworkReachability::probed(
                Vec::new(),
                254,
                0,
                vec!["254 address(es) swept; nothing answered".to_string()],
            )
            .discovered_by("advertised by 198.51.100.1"),
        );

        let mut silent = HashMap::new();
        silent.insert(
            addr("203.0.113.9"),
            "203.0.113.9 answered nothing".to_string(),
        );
        silent.insert(
            addr("203.0.113.254"),
            "203.0.113.254 forwarded traffic and disclosed nothing".to_string(),
        );

        Self {
            disclosures,
            occupants,
            reachability,
            silent,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("the call log").clone()
    }
}

impl DiscoveryProvider for ScriptedNetwork {
    fn name(&self) -> &'static str {
        "scripted-network"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        context.scope.is_some() || context.target.is_some()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            if let Some(target) = context.target {
                self.calls
                    .lock()
                    .expect("the call log")
                    .push(Call::Device(target));

                if let Some(evidence) = self.disclosures.get(&target) {
                    return ProviderOutput {
                        evidence: evidence.clone(),
                        notes: vec![format!("{target} disclosed {} fact(s)", evidence.len())],
                        attempted: true,
                        reachability: Vec::new(),
                    };
                }
                let note = self
                    .silent
                    .get(&target)
                    .cloned()
                    .unwrap_or_else(|| format!("{target} answered nothing"));
                return ProviderOutput {
                    evidence: Vec::new(),
                    notes: vec![note],
                    attempted: true,
                    reachability: Vec::new(),
                };
            }

            let scope = context
                .scope
                .expect("applies() admits scope or target only");
            self.calls
                .lock()
                .expect("the call log")
                .push(Call::Scope(scope));

            let evidence = self.occupants.get(&scope).cloned().unwrap_or_default();
            let reachability = self
                .reachability
                .get(&scope)
                .map(|outcome| vec![(scope, outcome.clone())])
                .unwrap_or_default();
            ProviderOutput {
                notes: vec![format!(
                    "{scope} examined; {} occupant fact(s)",
                    evidence.len()
                )],
                evidence,
                attempted: true,
                reachability,
            }
        })
    }
}

/// Runs the engine once over the scripted network and hands back both the report and the
/// script's record of what it was asked.
fn run_scripted() -> (idnx::engine::orchestrator::DiscoveryReport, Vec<Call>) {
    let vantage = Vantage {
        interface: VANTAGE.to_string(),
        kind: VantageKind::Wired,
        index: 0,
        capture_available: false,
    };
    let context = DiscoveryContext::seed(vantage, Duration::from_millis(20), 8);

    // Boxed twice: the engine owns its providers, and the call log has to outlive the run.
    let script = std::sync::Arc::new(ScriptedNetwork::new());
    struct Shared(std::sync::Arc<ScriptedNetwork>);
    impl DiscoveryProvider for Shared {
        fn name(&self) -> &'static str {
            self.0.name()
        }
        fn applies(&self, context: &DiscoveryContext) -> bool {
            self.0.applies(context)
        }
        fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
            self.0.discover(context)
        }
    }

    let engine = DiscoveryEngine::new(
        vec![Box::new(ScriptedSeed)],
        vec![Box::new(Shared(std::sync::Arc::clone(&script)))],
    )
    .with_budget(Budget {
        max_scopes: 16,
        max_iterations: 8,
        max_enumerable_hosts: 4096,
    });

    let report = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(engine.run(context, Some(net("192.0.2.0/24"))));

    let calls = script.calls();
    (report, calls)
}

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
