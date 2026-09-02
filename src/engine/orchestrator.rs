//! The automatic discovery engine.
//!
//! One workflow, always. The operator chooses a starting scope; the engine owns provider
//! orchestration, recursion, concurrency, safety limits and completion detection. There is
//! no "deep mode" to enable and no recursion depth to pick.

use std::collections::HashSet;

use ipnet::IpNet;

use std::sync::Arc;

use crate::providers::{
    ContinuousSource, DiscoveryContext, DiscoveryProvider, ProviderRun, Vantage,
};
use crate::topology::TopologyGraph;

/// Safety limits. These bound work; they are not user-facing tuning knobs.
#[derive(Debug, Clone)]
pub struct Budget {
    /// Maximum distinct network scopes processed in one run.
    pub max_scopes: usize,
    /// Maximum fixed-point iterations before declaring convergence regardless.
    pub max_iterations: usize,
    /// Largest network enumerated host-by-host. Kernel tables routinely carry /16s
    /// belonging to VM and container bridges; enumerating one stalls a run for no result.
    pub max_enumerable_hosts: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_scopes: 64,
            max_iterations: 8,
            max_enumerable_hosts: 4096,
        }
    }
}

/// What a single scope's provider pass produced, so nothing fails silently.
#[derive(Debug, Clone)]
pub struct ScopeRun {
    /// The network examined, or `None` for the initial local seed pass.
    pub scope: Option<IpNet>,
    pub runs: Vec<ProviderRun>,
}

/// What this vantage could not observe, stated explicitly.
#[derive(Debug, Clone)]
pub struct VisibilityReport {
    pub vantage: Vantage,
    /// Frame or protocol classes this vantage cannot receive at all.
    pub blind_to: Vec<String>,
    /// Providers that were skipped, and why.
    pub unavailable: Vec<String>,
    /// Frames passively observed, when capture ran. `None` means capture never started.
    ///
    /// Reported so that "the link was quiet" is distinguishable from "nothing was
    /// listening", which produce identical topology otherwise.
    pub observed_frames: Option<u64>,
    /// Topology facts accepted from those frames.
    ///
    /// A frame count alone proves the reader delivered packets and nothing more. Most
    /// traffic on any link is not discovery evidence, so this second number separates "no
    /// discovery protocols on this link" from "the decoding path is broken".
    pub accepted_facts: Option<u64>,
}

/// Result of a complete discovery run.
pub struct DiscoveryReport {
    pub graph: TopologyGraph,
    pub scope_runs: Vec<ScopeRun>,
    /// Per-device interrogation results, so a pivot that disclosed nothing is visible
    /// rather than silently dropped.
    pub pivot_runs: Vec<PivotRun>,
    pub visibility: VisibilityReport,
    /// Scopes discovered but not enumerated because they exceeded the safety budget.
    pub oversized_scopes: Vec<IpNet>,
    pub converged: bool,
}

/// Runs providers to a fixed point over everything discovered.
pub struct DiscoveryEngine {
    seed_providers: Vec<Box<dyn DiscoveryProvider>>,
    scope_providers: Vec<Box<dyn DiscoveryProvider>>,
    /// Observed continuously and drained by the engine, which also owns its shutdown.
    continuous: Option<Arc<dyn ContinuousSource>>,
    budget: Budget,
}

/// What interrogating one infrastructure device produced.
#[derive(Debug, Clone)]
pub struct PivotRun {
    pub address: std::net::IpAddr,
    pub runs: Vec<ProviderRun>,
    /// Networks this pivot disclosed that were not already known.
    pub networks_learned: Vec<IpNet>,
}

impl DiscoveryEngine {
    pub fn new(
        seed_providers: Vec<Box<dyn DiscoveryProvider>>,
        scope_providers: Vec<Box<dyn DiscoveryProvider>>,
    ) -> Self {
        Self {
            seed_providers,
            scope_providers,
            continuous: None,
            budget: Budget::default(),
        }
    }

    /// Attaches a continuously observing source whose lifecycle the engine then owns.
    pub fn with_continuous_source(mut self, source: Arc<dyn ContinuousSource>) -> Self {
        self.continuous = Some(source);
        self
    }

    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// Executes the complete workflow from the given starting context.
    ///
    /// `initial_scope` is the operator's chosen starting point. It is a seed, not a limit:
    /// every network learned along the way receives the same provider pipeline.
    pub async fn run(
        &self,
        context: DiscoveryContext,
        initial_scope: Option<IpNet>,
    ) -> DiscoveryReport {
        let mut graph = TopologyGraph::new();
        let mut scope_runs = Vec::new();
        let mut pivot_runs: Vec<PivotRun> = Vec::new();
        let mut processed: HashSet<IpNet> = HashSet::new();
        let mut interrogated: HashSet<std::net::IpAddr> = HashSet::new();
        let mut oversized = Vec::new();

        // Phase 1: seed from local OS state. This always runs and never depends on any
        // remote device answering.
        let mut seed_runs = Vec::new();
        for provider in &self.seed_providers {
            if !provider.applies(&context) {
                continue;
            }
            let evidence = provider.discover(&context).await;
            seed_runs.push(ProviderRun {
                provider: provider.name(),
                evidence_count: evidence.len(),
                note: if evidence.is_empty() {
                    Some("no evidence from this vantage".to_string())
                } else {
                    None
                },
            });
            for ev in evidence {
                graph.absorb(ev);
            }
        }
        scope_runs.push(ScopeRun {
            scope: None,
            runs: seed_runs,
        });

        // The operator's chosen scope enters the queue like any other network, so it
        // receives exactly the same treatment as one the engine discovered itself.
        let mut queue: Vec<IpNet> = Vec::new();
        if let Some(scope) = initial_scope {
            queue.push(scope);
        }

        // Phase 2: fixed point. Each pass processes every network not yet seen, which may
        // reveal further networks; the loop ends when a pass adds nothing new.
        let mut converged = false;
        // Finishing the continuous source is a one-time transition, tracked so that the
        // final drain happens exactly once and never after the source is already stopped.
        let mut continuous_finished = self.continuous.is_none();

        for _ in 0..self.budget.max_iterations {
            // Poll before anything is decided. Frames that arrived while the previous pass
            // was running would otherwise sit in the buffer until after the convergence
            // check had already concluded there was nothing left to do.
            if let Some(source) = &self.continuous {
                for ev in source.drain() {
                    graph.absorb(ev);
                }
            }

            for net in graph.networks() {
                if !processed.contains(&net) && !queue.contains(&net) {
                    queue.push(net);
                }
            }

            let pending: Vec<IpNet> = queue.drain(..).filter(|n| !processed.contains(n)).collect();

            // Two queues, deliberately.
            //
            // Established pivots have positive routing or bridging evidence. Candidates
            // merely look like they might be network equipment — an unfamiliar appliance,
            // a networking manufacturer, a router-ish name, several addresses. Asking only
            // the first group is circular: a device needs router evidence to be
            // interrogated, and interrogation is how that evidence is obtained, so a silent
            // appliance was never asked anything at all.
            //
            // A candidate hint changes who gets asked and nothing else. Confidence and role
            // still come only from what the answers contain.
            let mut pivots: Vec<std::net::IpAddr> = graph
                .pivot_addresses()
                .into_iter()
                .filter(|a| !interrogated.contains(a))
                .collect();
            for candidate in graph.candidate_addresses() {
                if !interrogated.contains(&candidate) && !pivots.contains(&candidate) {
                    pivots.push(candidate);
                }
            }

            if pending.is_empty() && pivots.is_empty() {
                if !continuous_finished {
                    // Candidate convergence. Stop observing, take everything still
                    // buffered, and only then decide: a frame captured moments ago may
                    // name a network or a router that still needs traversing.
                    continuous_finished = true;
                    if let Some(source) = &self.continuous {
                        let networks_before: HashSet<IpNet> =
                            graph.networks().into_iter().collect();
                        let pivots_before: HashSet<std::net::IpAddr> =
                            graph.pivot_addresses().into_iter().collect();

                        for ev in source.finish() {
                            graph.absorb(ev);
                        }

                        let gained_network = graph
                            .networks()
                            .into_iter()
                            .any(|n| !networks_before.contains(&n));
                        let gained_pivot = graph
                            .pivot_addresses()
                            .into_iter()
                            .any(|a| !pivots_before.contains(&a) && !interrogated.contains(&a));

                        if gained_network || gained_pivot {
                            // The final drain extended the topology, so traversal resumes.
                            continue;
                        }
                    }
                }
                converged = true;
                break;
            }

            for address in pivots {
                interrogated.insert(address);
                let before: HashSet<IpNet> = graph.networks().into_iter().collect();

                let targeted = context.for_target(address);
                let mut runs = Vec::new();
                for provider in &self.scope_providers {
                    if !provider.applies(&targeted) {
                        continue;
                    }
                    let evidence = provider.discover(&targeted).await;
                    runs.push(ProviderRun {
                        provider: provider.name(),
                        evidence_count: evidence.len(),
                        note: if evidence.is_empty() {
                            Some("no response".to_string())
                        } else {
                            None
                        },
                    });
                    for ev in evidence {
                        graph.absorb(ev);
                    }
                }

                let learned: Vec<IpNet> = graph
                    .networks()
                    .into_iter()
                    .filter(|n| !before.contains(n))
                    .collect();

                if !runs.is_empty() {
                    pivot_runs.push(PivotRun {
                        address,
                        runs,
                        networks_learned: learned,
                    });
                }
            }

            for scope in pending {
                if processed.len() >= self.budget.max_scopes {
                    break;
                }
                processed.insert(scope);

                if enumerable_host_count(&scope) > self.budget.max_enumerable_hosts {
                    // Still recorded as a network; simply not swept host by host.
                    oversized.push(scope);
                }

                let scoped = context.for_scope(scope);
                let mut runs = Vec::new();
                for provider in &self.scope_providers {
                    if !provider.applies(&scoped) {
                        continue;
                    }
                    let evidence = provider.discover(&scoped).await;
                    runs.push(ProviderRun {
                        provider: provider.name(),
                        evidence_count: evidence.len(),
                        note: if evidence.is_empty() {
                            Some("no response".to_string())
                        } else {
                            None
                        },
                    });
                    for ev in evidence {
                        graph.absorb(ev);
                    }
                }
                scope_runs.push(ScopeRun {
                    scope: Some(scope),
                    runs,
                });
            }
        }

        // Reaching the iteration ceiling must still stop observation; otherwise the capture
        // thread outlives the run and the frame count is never final.
        if !continuous_finished && let Some(source) = &self.continuous {
            for ev in source.finish() {
                graph.absorb(ev);
            }
        }

        graph.finalize_roles();

        let blind_to = context
            .vantage
            .kind
            .blind_to()
            .iter()
            .map(|s| s.to_string())
            .collect();

        // Left empty on purpose: whether capture actually started is known only to the
        // caller that attempted to open it, and is appended to this list afterwards.
        let unavailable = Vec::new();

        DiscoveryReport {
            graph,
            scope_runs,
            pivot_runs,
            visibility: VisibilityReport {
                vantage: context.vantage.clone(),
                blind_to,
                unavailable,
                observed_frames: None,
                accepted_facts: None,
            },
            oversized_scopes: oversized,
            converged,
        }
    }
}

/// Number of addresses that would be enumerated for a prefix.
///
/// Saturates rather than overflowing on IPv6, where a /64 is not enumerable by any means
/// and must simply compare greater than any budget.
pub fn enumerable_host_count(net: &IpNet) -> usize {
    match net {
        IpNet::V4(v4) => {
            let bits = 32u32.saturating_sub(v4.prefix_len() as u32);
            if bits >= 32 {
                usize::MAX
            } else {
                (1usize << bits).saturating_sub(2)
            }
        }
        // IPv6 host space is never enumerated by sweeping; hosts come from neighbour
        // discovery and other evidence instead.
        IpNet::V6(_) => usize::MAX,
    }
}

/// Interface-name prefixes belonging to virtualisation, containers and tunnels.
///
/// Matching is on the interface a network is reached through, never on the address range:
/// 10.0.0.0/8 is as legitimate for a corporate LAN as for a container bridge, so
/// classifying by prefix would misreport real networks.
const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "utun",
    "tun",
    "tap",
    "ppp",
    "wg",
    "ipsec",
    "gpd",
    "docker",
    "br-",
    "veth",
    "virbr",
    "vmnet",
    "vboxnet",
    "feth",
    "bridge",
    "cni",
    "flannel",
    "kube",
    "zt",
    "tailscale",
    "hyperv",
    "vEthernet",
];

/// True when a network is reached only through virtual, container or tunnel interfaces.
///
/// Such networks stay in the graph; they are simply not presented as cascaded physical
/// topology, because a container bridge is not a discovered subnet of the site.
pub fn is_virtual_network(interfaces: &[&str]) -> bool {
    if interfaces.is_empty() {
        return false;
    }
    interfaces.iter().all(|name| is_virtual_interface(name))
}

/// True when an interface name denotes virtualisation, container or tunnel plumbing.
pub fn is_virtual_interface(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    VIRTUAL_INTERFACE_PREFIXES
        .iter()
        .any(|p| lowered.starts_with(&p.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{Vantage, VantageKind};
    use crate::topology::TopologyEvidence;
    use crate::topology::evidence::{Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal};
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A continuous source that yields evidence only at the very end, standing in for a
    /// frame captured moments before convergence.
    struct LateSource {
        drains: AtomicUsize,
        finishes: AtomicUsize,
        /// Emitted from `finish` only.
        final_evidence: Mutex<Vec<TopologyEvidence>>,
    }

    impl LateSource {
        fn new(final_evidence: Vec<TopologyEvidence>) -> Self {
            Self {
                drains: AtomicUsize::new(0),
                finishes: AtomicUsize::new(0),
                final_evidence: Mutex::new(final_evidence),
            }
        }
    }

    impl ContinuousSource for LateSource {
        fn drain(&self) -> Vec<TopologyEvidence> {
            self.drains.fetch_add(1, Ordering::Relaxed);
            Vec::new()
        }

        fn finish(&self) -> Vec<TopologyEvidence> {
            self.finishes.fetch_add(1, Ordering::Relaxed);
            std::mem::take(&mut *self.final_evidence.lock().unwrap())
        }
    }

    fn context() -> DiscoveryContext {
        DiscoveryContext::seed(
            Vantage {
                interface: "test0".to_string(),
                kind: VantageKind::Wired,
                capture_available: true,
            },
            std::time::Duration::from_millis(1),
            4,
        )
    }

    fn evidence(fact: Fact) -> TopologyEvidence {
        TopologyEvidence::new(fact, EvidenceSource::Stp, Confidence::Observed, "test0")
    }

    #[tokio::test]
    async fn evidence_arriving_just_before_convergence_is_retained() {
        // The buffer is emptied only at finish, so this evidence exists solely in the
        // final drain. Before the fix it was discarded with the capture thread.
        let source = Arc::new(LateSource::new(vec![evidence(Fact::Vlan { id: 77 })]));
        let engine = DiscoveryEngine::new(Vec::new(), Vec::new())
            .with_continuous_source(source.clone() as Arc<dyn ContinuousSource>);

        let report = engine.run(context(), None).await;

        assert!(
            report.graph.vlans_without_prefix().any(|v| v == 77),
            "evidence from the final drain must reach the graph"
        );
        assert!(report.converged);
    }

    #[tokio::test]
    async fn capture_is_polled_before_every_convergence_decision_and_finished_once() {
        let source = Arc::new(LateSource::new(Vec::new()));
        let engine = DiscoveryEngine::new(Vec::new(), Vec::new())
            .with_continuous_source(source.clone() as Arc<dyn ContinuousSource>);

        let _ = engine.run(context(), None).await;

        assert!(
            source.drains.load(Ordering::Relaxed) >= 1,
            "the source must be polled before convergence is decided"
        );
        assert_eq!(
            source.finishes.load(Ordering::Relaxed),
            1,
            "capture must be finished exactly once"
        );
    }

    #[tokio::test]
    async fn a_final_drain_that_adds_topology_resumes_traversal() {
        // A late router observation must be able to extend the run, not merely be recorded
        // after everything has stopped.
        let mac = DeviceKey::mac("00:11:22:33:44:55");
        let source = Arc::new(LateSource::new(vec![
            evidence(Fact::DeviceAddress {
                device: mac.clone(),
                address: "10.9.9.1".parse().unwrap(),
            }),
            evidence(Fact::DeviceRoleSignal {
                device: mac,
                signal: RoleSignal::DefaultGateway,
            }),
            evidence(Fact::Network {
                prefix: IpNet::from_str("10.9.9.0/24").unwrap(),
            }),
        ]));

        let engine = DiscoveryEngine::new(Vec::new(), Vec::new())
            .with_continuous_source(source.clone() as Arc<dyn ContinuousSource>);
        let report = engine.run(context(), None).await;

        assert!(
            report
                .graph
                .networks()
                .contains(&IpNet::from_str("10.9.9.0/24").unwrap()),
            "the late network must be present"
        );
        // The resumed pass must have processed it as a scope like any other network.
        assert!(
            report
                .scope_runs
                .iter()
                .any(|r| r.scope == Some(IpNet::from_str("10.9.9.0/24").unwrap())),
            "traversal must resume so a late network is still examined"
        );
    }

    #[tokio::test]
    async fn a_run_without_a_continuous_source_still_converges() {
        let engine = DiscoveryEngine::new(Vec::new(), Vec::new());
        let report = engine.run(context(), None).await;
        assert!(report.converged);
    }

    #[test]
    fn slash_24_is_enumerable() {
        let net = IpNet::from_str("192.168.1.0/24").unwrap();
        assert_eq!(enumerable_host_count(&net), 254);
    }

    #[test]
    fn slash_16_exceeds_the_default_budget() {
        // A /16 on a container bridge is 65534 addresses; sweeping one stalls a run.
        let net = IpNet::from_str("10.242.0.0/16").unwrap();
        assert!(enumerable_host_count(&net) > Budget::default().max_enumerable_hosts);
    }

    #[test]
    fn ipv6_is_never_treated_as_enumerable() {
        let net = IpNet::from_str("fd00::/64").unwrap();
        assert_eq!(enumerable_host_count(&net), usize::MAX);
    }

    #[test]
    fn virtual_interfaces_are_recognised_by_name() {
        assert!(is_virtual_interface("utun4"));
        assert!(is_virtual_interface("docker0"));
        assert!(is_virtual_interface("feth466"));
        assert!(is_virtual_interface("bridge100"));
        assert!(!is_virtual_interface("en0"));
        assert!(!is_virtual_interface("eth1"));
    }

    #[test]
    fn a_network_on_a_physical_interface_is_not_virtual() {
        // Address range must never decide this: 10/8 is a normal corporate LAN.
        assert!(!is_virtual_network(&["en0"]));
        assert!(is_virtual_network(&["feth466"]));
        // Reached through both a physical and a virtual link, it is real topology.
        assert!(!is_virtual_network(&["en0", "utun3"]));
    }

    #[test]
    fn budget_defaults_are_bounded() {
        let b = Budget::default();
        assert!(b.max_scopes > 0 && b.max_iterations > 0);
    }
}
