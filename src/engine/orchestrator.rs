//! The automatic discovery engine.
//!
//! One workflow, always. The operator chooses a starting scope; the engine owns provider
//! orchestration, recursion, concurrency, safety limits and completion detection. There is
//! no "deep mode" to enable and no recursion depth to pick.

use std::collections::HashSet;

use ipnet::IpNet;

use crate::providers::{DiscoveryContext, DiscoveryProvider, ProviderRun, Vantage};
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
            budget: Budget::default(),
        }
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
        for _ in 0..self.budget.max_iterations {
            for net in graph.networks() {
                if !processed.contains(&net) && !queue.contains(&net) {
                    queue.push(net);
                }
            }

            let pending: Vec<IpNet> = queue.drain(..).filter(|n| !processed.contains(n)).collect();

            // Devices showing infrastructure behaviour are interrogated directly. This is
            // the path that turns a router into new networks, and it never depends on any
            // one provider succeeding.
            let pivots: Vec<std::net::IpAddr> = graph
                .pivot_addresses()
                .into_iter()
                .filter(|a| !interrogated.contains(a))
                .collect();

            if pending.is_empty() && pivots.is_empty() {
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
    use std::str::FromStr;

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
