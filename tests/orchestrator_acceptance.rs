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
    DiscoveryContext, DiscoveryProvider, ProviderFuture, ProviderOutput, Vantage, VantageKind,
};
use idnx::topology::evidence::{Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal};
use idnx::topology::{TopologyEvidence, graph::DeviceCategory};

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

/// The scripted network. Each device discloses what a real one would disclose, and the
/// engine decides what to do about it.
struct ScriptedNetwork {
    disclosures: HashMap<IpAddr, Vec<TopologyEvidence>>,
    /// Devices that answer nothing at all, and what the provider says about that.
    silent: HashMap<IpAddr, String>,
    /// Scopes where no address answers, so the network stays advertised-only.
    unreachable: HashMap<IpNet, String>,
    calls: Mutex<Vec<Call>>,
}

impl ScriptedNetwork {
    fn new() -> Self {
        let mut disclosures: HashMap<IpAddr, Vec<TopologyEvidence>> = HashMap::new();

        // The border router discloses a subnet nobody here is attached to, and the router
        // that lives on it. This is the disclosure the whole cascade hangs from.
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
                advertised(Fact::DeviceAddress {
                    device: device_key("198.51.100.1"),
                    address: addr("198.51.100.1"),
                }),
                advertised(Fact::DeviceRoleSignal {
                    device: device_key("198.51.100.1"),
                    signal: RoleSignal::SnmpForwarding,
                }),
            ],
        );

        // The second router continues the cascade, and adds the two shapes that must
        // survive without being resolved into something they are not.
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
                // An ordinary host on the newly disclosed subnet.
                advertised(Fact::DeviceAddress {
                    device: device_key("203.0.113.9"),
                    address: addr("203.0.113.9"),
                }),
                // A network it says it forwards toward, where nothing will answer.
                advertised(Fact::Network {
                    prefix: net("198.18.0.0/24"),
                }),
                advertised(Fact::RoutesTo {
                    device: device_key("198.51.100.1"),
                    network: net("198.18.0.0/24"),
                    next_hop: Some(addr("198.51.100.1")),
                }),
                // Something forwarded traffic and said nothing about itself. It is a
                // boundary, not a router we can claim to have identified.
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

        let mut silent = HashMap::new();
        silent.insert(
            addr("203.0.113.9"),
            "203.0.113.9 answered nothing".to_string(),
        );
        silent.insert(
            addr("203.0.113.254"),
            "203.0.113.254 forwarded traffic and disclosed nothing".to_string(),
        );

        let mut unreachable = HashMap::new();
        unreachable.insert(
            net("198.18.0.0/24"),
            "advertised by 198.51.100.1; no address in it answered".to_string(),
        );

        Self {
            disclosures,
            silent,
            unreachable,
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
                };
            }

            let scope = context
                .scope
                .expect("applies() admits scope or target only");
            self.calls
                .lock()
                .expect("the call log")
                .push(Call::Scope(scope));

            if let Some(reason) = self.unreachable.get(&scope) {
                return ProviderOutput {
                    evidence: Vec::new(),
                    notes: vec![reason.clone()],
                    attempted: true,
                };
            }
            ProviderOutput {
                evidence: Vec::new(),
                notes: vec![format!("{scope} examined")],
                attempted: true,
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
        .scope_runs
        .iter()
        .find(|run| run.scope == Some(net("198.18.0.0/24")))
        .expect("it was examined like any other network");
    assert!(
        unreachable.runs.iter().any(|run| run
            .note
            .as_deref()
            .is_some_and(|note| note.contains("no address in it answered"))),
        "its failed reachability is stated: {:?}",
        unreachable.runs
    );

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
