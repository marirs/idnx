//! The device work queue.
//!
//! One queue enriches every device the graph knows about. Previously two passes competed:
//! a per-subnet sweep probed a fixed port set against every host, and a separate per-device
//! pass probed a wider set against pivots only -- duplicating the overlap, and leaving
//! ordinary hosts with no interrogation at all.
//!
//! Devices are worked concurrently. The engine used to interrogate them one after another,
//! so a run's duration was the sum of every device's timeouts rather than the longest of
//! them. Concurrency here draws on the run-wide probe budget in [`DiscoveryContext`], so
//! device-level and port-level parallelism cannot compose into an unbounded socket count.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinSet;

use crate::providers::target::{DeviceCoverage, DeviceTier, interrogate_device};
use crate::providers::{DiscoveryContext, DiscoveryProvider};
use crate::topology::TopologyEvidence;

/// One device awaiting interrogation.
#[derive(Debug, Clone)]
pub struct DeviceTask {
    pub address: IpAddr,
    pub tier: DeviceTier,
    /// How the device became known, carried through so that a device yielding nothing
    /// still has a complete evidence trail.
    pub discovery_sources: Vec<String>,
}

/// What one pass over the queue produced.
pub struct EnrichmentRun {
    pub evidence: Vec<TopologyEvidence>,
    pub coverage: Vec<DeviceCoverage>,
    /// Wall-clock time for the whole pass, which concurrency makes far shorter than the
    /// sum of the per-device times.
    pub elapsed: Duration,
}

impl EnrichmentRun {
    /// Total time that would have been spent interrogating these devices in sequence.
    ///
    /// Reported alongside `elapsed` so the effect of running them together is visible
    /// rather than asserted.
    pub fn sequential_equivalent(&self) -> Duration {
        self.coverage.iter().map(|c| c.elapsed).sum()
    }

    pub fn probes_attempted(&self) -> usize {
        self.coverage
            .iter()
            .map(|c| c.tcp_attempted + c.udp_attempted.len())
            .sum()
    }
}

/// Interrogates every queued device concurrently.
///
/// `target_providers` are the providers that apply to a specific device (SNMP among them);
/// they run inside the same per-device task so that one device's slow provider does not
/// delay another device entirely.
pub async fn enrich_devices(
    tasks: Vec<DeviceTask>,
    context: &DiscoveryContext,
    target_providers: Arc<Vec<Box<dyn DiscoveryProvider>>>,
) -> EnrichmentRun {
    let started = Instant::now();
    let mut set: JoinSet<(Vec<TopologyEvidence>, DeviceCoverage)> = JoinSet::new();

    for task in tasks {
        let targeted = context.for_target(task.address);
        let providers = Arc::clone(&target_providers);
        set.spawn(async move {
            let (mut evidence, mut coverage) =
                interrogate_device(&targeted, task.tier, task.discovery_sources).await;

            // Target-applicable providers run per device rather than per pass, so that a
            // device that answers SNMP is credited for it in its own coverage record.
            for provider in providers.iter() {
                if !provider.applies(&targeted) {
                    continue;
                }
                let produced = provider.discover(&targeted).await;
                if !produced.is_empty() {
                    coverage
                        .protocols_confirmed
                        .push(provider.name().to_string());
                }
                evidence.extend(produced);
            }

            (evidence, coverage)
        });
    }

    let mut evidence = Vec::new();
    let mut coverage = Vec::new();
    while let Some(joined) = set.join_next().await {
        // A panicking probe must lose that one device, not the whole pass.
        if let Ok((produced, record)) = joined {
            evidence.extend(produced);
            coverage.push(record);
        }
    }
    coverage.sort_by_key(|c| c.address);

    EnrichmentRun {
        evidence,
        coverage,
        elapsed: started.elapsed(),
    }
}

/// Builds the queue from the graph, skipping devices already interrogated.
///
/// Every device is enqueued, not only those that look like infrastructure. The tier decides
/// how much work a device is worth; it never decides what its answers mean.
pub fn queue_from_graph(
    graph: &crate::topology::TopologyGraph,
    interrogated: &HashSet<IpAddr>,
) -> Vec<DeviceTask> {
    let pivots: HashSet<IpAddr> = graph.pivot_addresses().into_iter().collect();
    let candidates: HashSet<IpAddr> = graph.candidate_addresses().into_iter().collect();

    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut queue = Vec::new();

    for node in graph.nodes() {
        for address in node.addresses.iter().copied() {
            if interrogated.contains(&address) || !seen.insert(address) {
                continue;
            }
            if !crate::topology::graph::is_interrogable(&address) {
                continue;
            }
            let tier = if pivots.contains(&address) {
                DeviceTier::EstablishedPivot
            } else if candidates.contains(&address) {
                DeviceTier::Candidate
            } else {
                DeviceTier::Host
            };
            queue.push(DeviceTask {
                address,
                tier,
                discovery_sources: node.evidence_sources(),
            });
        }
    }

    // Infrastructure first: what a pivot discloses may enqueue further networks, and doing
    // that early keeps the fixed-point loop from needing another pass.
    queue.sort_by_key(|task| match task.tier {
        DeviceTier::EstablishedPivot => 0,
        DeviceTier::Candidate => 1,
        DeviceTier::Host => 2,
    });
    queue
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::topology::TopologyGraph;
    use crate::topology::evidence::{
        Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal, TopologyEvidence,
    };

    fn absorb(graph: &mut TopologyGraph, fact: Fact, source: EvidenceSource) {
        graph.absorb(TopologyEvidence::new(
            fact,
            source,
            Confidence::Observed,
            "test0",
        ));
    }

    fn device(graph: &mut TopologyGraph, mac: &str, address: &str) -> DeviceKey {
        let key = DeviceKey::mac(mac);
        absorb(
            graph,
            Fact::DeviceAddress {
                device: key.clone(),
                address: address.parse().unwrap(),
            },
            EvidenceSource::ArpCache,
        );
        key
    }

    #[test]
    fn every_device_is_queued_not_only_infrastructure() {
        // Asking only devices that already look like network equipment is circular:
        // interrogation is how that evidence is obtained in the first place.
        let mut graph = TopologyGraph::new();
        let gateway = device(&mut graph, "02:00:5e:00:00:01", "10.9.0.1");
        device(&mut graph, "02:00:5e:00:00:02", "10.9.0.2");
        device(&mut graph, "02:00:5e:00:00:03", "10.9.0.3");
        absorb(
            &mut graph,
            Fact::DeviceRoleSignal {
                device: gateway,
                signal: RoleSignal::DefaultGateway,
            },
            EvidenceSource::KernelRoute,
        );

        let queue = queue_from_graph(&graph, &HashSet::new());
        let addresses: HashSet<IpAddr> = queue.iter().map(|t| t.address).collect();
        assert_eq!(addresses.len(), 3, "{queue:?}");

        // Infrastructure is worked first, so what it discloses can extend the same pass.
        assert_eq!(queue[0].address, "10.9.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(queue[0].tier, DeviceTier::EstablishedPivot);
        assert!(
            queue[1..]
                .iter()
                .all(|t| t.tier != DeviceTier::EstablishedPivot)
        );
    }

    #[test]
    fn an_already_interrogated_device_is_not_queued_again() {
        let mut graph = TopologyGraph::new();
        device(&mut graph, "02:00:5e:00:00:04", "10.9.0.4");
        device(&mut graph, "02:00:5e:00:00:05", "10.9.0.5");

        let done: HashSet<IpAddr> = ["10.9.0.4".parse().unwrap()].into_iter().collect();
        let queue = queue_from_graph(&graph, &done);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].address, "10.9.0.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn addresses_that_cannot_be_interrogated_are_left_out() {
        // Loopback and link-local addresses are not devices to probe, and queueing them
        // would report coverage for work that means nothing.
        let mut graph = TopologyGraph::new();
        device(&mut graph, "02:00:5e:00:00:06", "127.0.0.1");
        device(&mut graph, "02:00:5e:00:00:07", "169.254.1.9");
        device(&mut graph, "02:00:5e:00:00:08", "10.9.0.8");

        let queue = queue_from_graph(&graph, &HashSet::new());
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].address, "10.9.0.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn a_device_carries_how_it_was_discovered_into_its_coverage() {
        let mut graph = TopologyGraph::new();
        let key = device(&mut graph, "02:00:5e:00:00:09", "10.9.0.9");
        absorb(
            &mut graph,
            Fact::DeviceHostname {
                device: key,
                hostname: "printer".to_string(),
            },
            EvidenceSource::Mdns,
        );

        let queue = queue_from_graph(&graph, &HashSet::new());
        assert_eq!(queue.len(), 1);
        assert!(queue[0].discovery_sources.len() >= 2, "{:?}", queue[0]);
        assert!(
            queue[0]
                .discovery_sources
                .iter()
                .any(|s| s.contains("ARP") || s.contains("mDNS"))
        );
    }
}
