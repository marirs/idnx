//! The scripted network the acceptance and the golden outputs both run on.
//!
//! Shared so that the goldens are snapshots of the same run the acceptance asserts about:
//! a second, separately maintained fixture would let the two drift, and the goldens would
//! then be freezing a topology no test reasons about.

#![allow(dead_code)]

use idnx::engine::orchestrator::{Budget, DiscoveryEngine};
use idnx::providers::{
    DiscoveryContext, DiscoveryProvider, NetworkReachability, ProviderFuture, ProviderOutput,
    Vantage, VantageKind,
};
use idnx::topology::evidence::{Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal};
use idnx::topology::realm::Realm;
use idnx::topology::{TopologyEvidence, graph::NetworkRef};

use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

pub const VANTAGE: &str = "test0";

pub fn addr(text: &str) -> IpAddr {
    text.parse().expect("a literal address")
}

pub fn net(text: &str) -> IpNet {
    text.parse().expect("a literal prefix")
}

/// The key a locally observed network is recorded under: prefix plus observation domain.
pub fn local(text: &str) -> NetworkRef {
    let prefix = net(text);
    NetworkRef {
        prefix,
        realm: idnx::topology::realm::network_realm(&prefix, &Realm::Local),
    }
}

/// Every host address in a /24, as the fixture's providers would have probed them.
pub fn every_host(prefix: &str) -> Vec<IpAddr> {
    let IpNet::V4(subnet) = net(prefix) else {
        panic!("the fixture's scopes are IPv4");
    };
    subnet.hosts().map(IpAddr::V4).collect()
}

pub fn advertised(fact: Fact) -> TopologyEvidence {
    TopologyEvidence::new(fact, EvidenceSource::Snmp, Confidence::Advertised, VANTAGE)
}

pub fn observed(fact: Fact) -> TopologyEvidence {
    TopologyEvidence::new(
        fact,
        EvidenceSource::KernelRoute,
        Confidence::Observed,
        VANTAGE,
    )
}

pub fn device_key(text: &str) -> DeviceKey {
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
pub enum Call {
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
                every_host("192.0.2.0/24"),
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
                every_host("198.51.100.0/24"),
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
                every_host("203.0.113.0/24"),
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
                every_host("198.18.0.0/24"),
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
pub fn run_scripted() -> (idnx::engine::orchestrator::DiscoveryReport, Vec<Call>) {
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
