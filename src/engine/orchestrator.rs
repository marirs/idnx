//! The automatic discovery engine.
//!
//! One workflow, always. The operator chooses a starting scope; the engine owns provider
//! orchestration, recursion, concurrency, safety limits and completion detection. There is
//! no "deep mode" to enable and no recursion depth to pick.

use std::collections::HashSet;

use ipnet::IpNet;

use crate::topology::evidence::DeviceKey;

use std::sync::Arc;
use std::time::Duration;

use crate::providers::{
    ContinuousSource, DiscoveryContext, DiscoveryProvider, ProviderOutput, ProviderRun, Vantage,
};
use crate::topology::TopologyGraph;

/// How a provider pass is described when it yielded no evidence.
///
/// The distinction this preserves: `silent` (the caller's wording for a link or device that
/// was actually asked) is a claim about the network and may only be made when something was
/// transmitted. A provider that could not run states its own reason, and one that never
/// attempted anything is reported as such rather than borrowing the network's silence.
fn run_note(produced: &ProviderOutput, silent: &str) -> Option<String> {
    if !produced.notes.is_empty() {
        return Some(produced.notes.join("; "));
    }
    if !produced.evidence.is_empty() {
        return None;
    }
    Some(if produced.attempted {
        silent.to_string()
    } else {
        "not attempted".to_string()
    })
}

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
    /// How strictly active probes were tied to the selected interface.
    ///
    /// Reported rather than assumed: source binding constrains egress only as far as the
    /// routing table agrees, which is a weaker guarantee than the kernel pinning the
    /// interface. Claiming the stronger one where only the weaker holds would be dishonest.
    pub binding_mode: crate::net::socket::BindingMode,
    /// Topology facts accepted from those frames.
    ///
    /// A frame count alone proves the reader delivered packets and nothing more. Most
    /// traffic on any link is not discovery evidence, so this second number separates "no
    /// discovery protocols on this link" from "the decoding path is broken".
    pub accepted_facts: Option<u64>,
    /// What passive routing decoding saw on UDP 520/521.
    ///
    /// Reported because RIP silence and RIP never being decoded leave the graph identical,
    /// and only one of them is a fact about the network.
    pub routing_updates: Option<String>,
    /// What passive OSPF and IS-IS decoding saw, reported separately from RIP.
    pub control_plane: Option<String>,
}

/// Result of a complete discovery run.
pub struct DiscoveryReport {
    pub graph: TopologyGraph,
    pub scope_runs: Vec<ScopeRun>,
    /// Per-device interrogation results, so a pivot that disclosed nothing is visible
    /// rather than silently dropped.
    pub pivot_runs: Vec<PivotRun>,
    /// What was attempted against every device and what came back, so that a silent
    /// device is distinguishable from one that was never asked.
    pub coverage: Vec<crate::providers::target::DeviceCoverage>,
    /// Wall-clock time spent interrogating devices, with the sequential equivalent, so the
    /// effect of running them concurrently is measured rather than asserted.
    pub enrichment_elapsed: Duration,
    pub enrichment_sequential_equivalent: Duration,
    pub probes_attempted: usize,
    pub visibility: VisibilityReport,
    /// Scopes discovered but not enumerated because they exceeded the safety budget.
    pub oversized_scopes: Vec<IpNet>,
    pub converged: bool,
}

/// Runs providers to a fixed point over everything discovered.
pub struct DiscoveryEngine {
    seed_providers: Vec<Box<dyn DiscoveryProvider>>,
    /// Shared rather than owned outright: the device queue hands these to concurrent
    /// per-device tasks, which must each hold their own reference.
    scope_providers: Arc<Vec<Box<dyn DiscoveryProvider>>>,
    /// Observed continuously and drained by the engine, which also owns their shutdown.
    ///
    /// More than one, because packet capture and federation both deliver on their own
    /// schedule and both must be polled before the engine decides it has converged. A
    /// bundle arriving from a peer as the last pass finishes can name a whole network, and
    /// treating one of the two as the only such source would lose it.
    continuous: Vec<Arc<dyn ContinuousSource>>,
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
            scope_providers: Arc::new(scope_providers),
            continuous: Vec::new(),
            budget: Budget::default(),
        }
    }

    /// Attaches a continuously observing source whose lifecycle the engine then owns.
    pub fn with_continuous_source(mut self, source: Arc<dyn ContinuousSource>) -> Self {
        self.continuous.push(source);
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
        let mut interrogated: HashSet<DeviceKey> = HashSet::new();
        let mut oversized = Vec::new();
        let mut coverage: Vec<crate::providers::target::DeviceCoverage> = Vec::new();
        let mut enrichment_elapsed = Duration::ZERO;
        let mut enrichment_sequential = Duration::ZERO;
        let mut probes_attempted = 0usize;

        // Phase 1: seed from local OS state. This always runs and never depends on any
        // remote device answering.
        let mut seed_runs = Vec::new();
        for provider in &self.seed_providers {
            if !provider.applies(&context) {
                continue;
            }
            let produced = provider.discover(&context).await;
            seed_runs.push(ProviderRun {
                provider: provider.name(),
                evidence_count: produced.evidence.len(),
                note: run_note(&produced, "no evidence from this vantage"),
            });
            for ev in produced.evidence {
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
        let mut continuous_finished = self.continuous.is_empty();

        for _ in 0..self.budget.max_iterations {
            // Poll before anything is decided. Frames that arrived while the previous pass
            // was running would otherwise sit in the buffer until after the convergence
            // check had already concluded there was nothing left to do.
            for source in &self.continuous {
                for ev in source.drain() {
                    graph.absorb(ev);
                }
            }

            // Only networks this machine observed itself. A peer's network cannot be swept
            // from here: its addresses are not reachable, and a private prefix a peer
            // reported may well name a different network of the same shape -- sweeping it
            // would probe this vantage's own address space and file the result elsewhere.
            for net in graph.local_networks() {
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
            // Everything not yet interrogated, infrastructure first. Every device is
            // enqueued, not only those already believed to be network equipment: asking
            // only devices with routing evidence was circular, since interrogation is how
            // that evidence is obtained. The tier decides how much work a device is worth
            // and nothing else -- role and confidence still come only from the answers.
            let aliases = graph.merge_address_identities();
            apply_aliases(&aliases, &mut interrogated, &mut coverage);
            let outstanding =
                !interrogation_queue(&graph, &interrogated, &context.vantage).is_empty();

            if pending.is_empty() && !outstanding {
                if !continuous_finished {
                    // Candidate convergence. Stop observing, take everything still
                    // buffered, and only then decide: a frame captured moments ago may
                    // name a network or a router that still needs traversing.
                    continuous_finished = true;
                    {
                        let networks_before: HashSet<IpNet> =
                            graph.networks().into_iter().collect();
                        let pivots_before: HashSet<std::net::IpAddr> =
                            graph.pivot_addresses().into_iter().collect();

                        for source in &self.continuous {
                            for ev in source.finish() {
                                graph.absorb(ev);
                            }
                        }

                        let gained_network = graph
                            .networks()
                            .into_iter()
                            .any(|n| !networks_before.contains(&n));
                        let gained_pivot = graph
                            .pivot_addresses()
                            .into_iter()
                            .any(|a| !pivots_before.contains(&a));

                        // A candidate arriving in the final drain must resume traversal
                        // just as a pivot does. Checking only pivots meant a device the
                        // capture revealed at the very end was recorded and never asked
                        // anything, which is the exact failure the two queues exist to
                        // avoid.
                        let gained_device =
                            !interrogation_queue(&graph, &interrogated, &context.vantage)
                                .is_empty();

                        if gained_network || gained_pivot || gained_device {
                            // The final drain extended the topology, so traversal resumes.
                            continue;
                        }
                    }
                }
                converged = true;
                break;
            }

            // Fold address-keyed nodes into their MAC-keyed owners before deciding who to
            // interrogate. A device arrives twice -- by address from a route or lease, by
            // MAC from the neighbour cache -- and an unmerged graph presents those as two
            // devices, so the same machine was probed twice and reported twice.
            let aliases = graph.merge_address_identities();
            apply_aliases(&aliases, &mut interrogated, &mut coverage);
            let queued = interrogation_queue(&graph, &interrogated, &context.vantage);
            for task in &queued {
                interrogated.insert(task.device.clone());
            }
            let networks_before_queue: HashSet<IpNet> = graph.networks().into_iter().collect();

            let run = crate::engine::enrich::enrich_devices(
                queued,
                &context,
                Arc::clone(&self.scope_providers),
            )
            .await;

            enrichment_elapsed += run.elapsed;
            enrichment_sequential += run.sequential_equivalent();
            probes_attempted += run.probes_attempted();
            for ev in run.evidence {
                graph.absorb(ev);
            }

            // Networks learned during a concurrent pass cannot be attributed to one device
            // without serializing the pass again, so they are recorded against the pass.
            let learned: Vec<IpNet> = graph
                .networks()
                .into_iter()
                .filter(|n| !networks_before_queue.contains(n))
                .collect();
            // A PivotRun is kept only for devices with established routing or bridging
            // evidence, because that is the traversal record. Every device -- pivot,
            // candidate and ordinary host -- is accounted for in `coverage` instead.
            for record in &run.coverage {
                if record.tier != crate::providers::target::DeviceTier::EstablishedPivot {
                    continue;
                }
                pivot_runs.push(PivotRun {
                    address: record
                        .primary_endpoint()
                        .and_then(|e| e.split('%').next())
                        .and_then(|e| e.parse().ok())
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                    runs: vec![ProviderRun {
                        provider: "device-enrichment",
                        evidence_count: record.tcp_responsive() + record.protocols_confirmed.len(),
                        note: Some(record.summary()),
                    }],
                    networks_learned: learned.clone(),
                });
            }
            coverage.extend(run.coverage);

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
                for provider in self.scope_providers.iter() {
                    if !provider.applies(&scoped) {
                        continue;
                    }
                    let produced = provider.discover(&scoped).await;
                    runs.push(ProviderRun {
                        provider: provider.name(),
                        evidence_count: produced.evidence.len(),
                        note: run_note(&produced, "no response"),
                    });
                    for ev in produced.evidence {
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
        if !continuous_finished {
            for source in &self.continuous {
                for ev in source.finish() {
                    graph.absorb(ev);
                }
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
            coverage,
            enrichment_elapsed,
            enrichment_sequential_equivalent: enrichment_sequential,
            probes_attempted,
            visibility: VisibilityReport {
                vantage: context.vantage.clone(),
                blind_to,
                unavailable,
                binding_mode: context.binding.mode(&std::net::SocketAddr::new(
                    context
                        .binding
                        .v4_source
                        .map(std::net::IpAddr::V4)
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                    0,
                )),
                observed_frames: None,
                accepted_facts: None,
                routing_updates: None,
                control_plane: None,
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

/// Rewrites interrogation state onto surviving identities after a merge.
///
/// Without this, a device first interrogated under an address key and later merged into a
/// MAC key is absent from the ledger under its new key: it is interrogated a second time
/// and appears twice in coverage. Applied repeatedly because a merge can chain -- an
/// address folds into a scoped address which folds into a MAC.
fn apply_aliases(
    aliases: &[(DeviceKey, DeviceKey)],
    interrogated: &mut HashSet<DeviceKey>,
    coverage: &mut Vec<crate::providers::target::DeviceCoverage>,
) {
    for (absorbed, surviving) in aliases {
        if interrogated.remove(absorbed) {
            interrogated.insert(surviving.clone());
        }
        for record in coverage.iter_mut() {
            if record.device == *absorbed {
                record.device = surviving.clone();
            }
        }
    }

    // A device may have been interrogated under two identities before they merged. Keep
    // the record that learned more rather than an arbitrary one.
    coverage.sort_by(|a, b| {
        a.device
            .to_string()
            .cmp(&b.device.to_string())
            .then(b.tcp_attempted().cmp(&a.tcp_attempted()))
    });
    coverage.dedup_by(|a, b| a.device == b.device);
}

/// Devices still awaiting interrogation, infrastructure first.
fn interrogation_queue(
    graph: &TopologyGraph,
    interrogated: &HashSet<DeviceKey>,
    vantage: &crate::providers::Vantage,
) -> Vec<crate::providers::target::InterrogationTarget> {
    crate::engine::enrich::queue_from_graph(graph, interrogated, &vantage.interface, vantage.index)
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

    #[test]
    fn a_provider_that_never_transmitted_is_not_reported_as_silence() {
        // "no response" is a claim about the network. A provider whose protocol is
        // unimplemented, or whose socket would not bind, produces the same empty vector as
        // a link where nothing answered, and must not inherit that claim.
        let never_ran = ProviderOutput {
            attempted: false,
            ..Default::default()
        };
        assert_eq!(
            run_note(&never_ran, "no response").as_deref(),
            Some("not attempted")
        );

        let asked_and_quiet = ProviderOutput {
            attempted: true,
            ..Default::default()
        };
        assert_eq!(
            run_note(&asked_and_quiet, "no response").as_deref(),
            Some("no response")
        );

        // A provider's own account displaces both, verbatim.
        let stated = ProviderOutput {
            notes: vec!["broadcast:asus unavailable: framing unverified".to_string()],
            ..Default::default()
        };
        assert_eq!(
            run_note(&stated, "no response").as_deref(),
            Some("broadcast:asus unavailable: framing unverified")
        );

        // "Cannot run here" and "nothing here to ask" stay distinguishable, and neither is
        // reported as the network having been asked.
        let cannot = ProviderOutput::unavailable("raw ICMPv6 needs root");
        assert_eq!(
            run_note(&cannot, "no response").as_deref(),
            Some("unavailable: raw ICMPv6 needs root")
        );
        assert!(!cannot.attempted);

        let nothing_to_ask = ProviderOutput::not_applicable("no IPv6 neighbour on this link");
        assert_eq!(
            run_note(&nothing_to_ask, "no response").as_deref(),
            Some("not applicable: no IPv6 neighbour on this link")
        );
        assert!(!nothing_to_ask.attempted);
    }

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
                index: 0,
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
            report.graph.vlans_without_prefix().any(|v| v.id == 77),
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
