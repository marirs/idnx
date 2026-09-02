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

use crate::net::endpoint::Endpoint;
use crate::providers::target::{
    DeviceCoverage, DeviceTier, InterrogationTarget, interrogate_device,
};
use crate::providers::vendor::DeviceFingerprint;
use crate::providers::{DiscoveryContext, DiscoveryProvider};
use crate::topology::TopologyEvidence;
use crate::topology::evidence::{DeviceKey, EvidenceSource};
use crate::topology::graph::{Node, NodeId, TopologyGraph};

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
            .map(|c| c.tcp_attempted() + c.udp_attempted.len())
            .sum()
    }
}

/// Interrogates every queued device concurrently.
///
/// `target_providers` are the providers that apply to a specific device (SNMP among them);
/// they run inside the same per-device task so that one device's slow provider does not
/// delay another device entirely.
pub async fn enrich_devices(
    tasks: Vec<InterrogationTarget>,
    context: &DiscoveryContext,
    target_providers: Arc<Vec<Box<dyn DiscoveryProvider>>>,
) -> EnrichmentRun {
    let started = Instant::now();
    let mut set: JoinSet<(Vec<TopologyEvidence>, DeviceCoverage)> = JoinSet::new();

    for task in tasks {
        // Providers still address a single IP. The preferred endpoint is the one the full
        // stage set runs against, so it is the one they are pointed at.
        let mut targeted = context.clone();
        targeted.target = task.endpoints.first().map(|e| e.address);
        let providers = Arc::clone(&target_providers);
        set.spawn(async move {
            let (mut evidence, mut coverage) = interrogate_device(&task, &targeted).await;

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
    coverage.sort_by(|a, b| a.addresses.cmp(&b.addresses));

    EnrichmentRun {
        evidence,
        coverage,
        elapsed: started.elapsed(),
    }
}

/// Evidence sources that establish a device is alive.
///
/// A neighbour entry, a captured frame, an ICMP reply or any TCP response all prove the
/// device exists and responds on this link. That is what makes full exploration worthwhile
/// even when the cheap port set is silent.
fn proves_liveness(source: EvidenceSource) -> bool {
    matches!(
        source,
        EvidenceSource::ArpCache
            | EvidenceSource::NdpCache
            | EvidenceSource::IcmpProbe
            | EvidenceSource::TcpProbe
            | EvidenceSource::DhcpLease
            | EvidenceSource::Mdns
            | EvidenceSource::Nbns
            | EvidenceSource::Llmnr
            | EvidenceSource::Ssdp
            | EvidenceSource::Mndp
            | EvidenceSource::Lldp
            | EvidenceSource::Cdp
            | EvidenceSource::Stp
            | EvidenceSource::RouterAdvertisement
            | EvidenceSource::Snmp
            | EvidenceSource::VendorDiscovery
            | EvidenceSource::NatPmp
            | EvidenceSource::AiProtocol
            | EvidenceSource::Mcp
    )
}

/// Orders a device's addresses by how useful they are as a probe destination.
///
/// A routable address is preferred over a link-local one, which needs a zone and only works
/// from the link it was seen on. Within a family the choice is stable so that repeated runs
/// probe the same address and their coverage records line up.
fn preferred_endpoints(node: &Node, vantage: &str) -> Vec<Endpoint> {
    let mut endpoints: Vec<Endpoint> = Vec::new();
    let mut v4: Vec<IpAddr> = Vec::new();
    let mut v6_routable: Vec<IpAddr> = Vec::new();
    let mut v6_link_local: Vec<IpAddr> = Vec::new();

    for address in node.addresses.iter().copied() {
        if !is_probeable(&address) {
            continue;
        }
        match address {
            IpAddr::V4(_) => v4.push(address),
            IpAddr::V6(v6) if crate::net::endpoint::is_link_local(&v6) => {
                v6_link_local.push(address)
            }
            IpAddr::V6(_) => v6_routable.push(address),
        }
    }

    // One endpoint per family. Several addresses in the same family are the same stack on
    // the same device; probing each of them repeats identical work.
    if let Some(address) = v4.first() {
        endpoints.push(Endpoint::global(*address));
    }
    if let Some(address) = v6_routable.first() {
        endpoints.push(Endpoint::global(*address));
    } else if let Some(address) = v6_link_local.first() {
        // The zone is what makes a link-local address reachable at all. It is the link the
        // neighbour was observed on, which is this vantage.
        endpoints.push(Endpoint::new(*address, Some(vantage.to_string())));
    }

    endpoints
}

/// Whether an address can be used as a probe destination.
///
/// Unlike the graph's `is_interrogable`, a link-local IPv6 address qualifies: it is
/// reachable once it carries the zone it was seen on, and for many devices it is the only
/// IPv6 address that exists.
fn is_probeable(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            !v4.is_loopback() && !v4.is_link_local() && !v4.is_multicast() && !v4.is_unspecified()
        }
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_multicast() && !v6.is_unspecified(),
    }
}

/// Builds the queue from the graph, skipping devices already interrogated.
///
/// Every device is enqueued, not only those that look like infrastructure. The tier decides
/// scheduling order; it never decides how much work a device receives or what its answers
/// mean.
///
/// Keyed by device. A dual-stack device is one entry with several endpoints, so it is
/// interrogated once and produces one coverage record, rather than once per address.
pub fn queue_from_graph(
    graph: &TopologyGraph,
    interrogated: &HashSet<DeviceKey>,
    vantage: &str,
) -> Vec<InterrogationTarget> {
    let pivots: HashSet<IpAddr> = graph.pivot_addresses().into_iter().collect();
    let candidates: HashSet<IpAddr> = graph.candidate_addresses().into_iter().collect();

    let mut queue = Vec::new();
    for node in graph.nodes() {
        let NodeId::Device(key) = &node.id else {
            continue;
        };
        if interrogated.contains(key) {
            continue;
        }
        let endpoints = preferred_endpoints(node, vantage);
        if endpoints.is_empty() {
            continue;
        }

        let tier = if node.addresses.iter().any(|a| pivots.contains(a)) {
            DeviceTier::EstablishedPivot
        } else if node.addresses.iter().any(|a| candidates.contains(a)) {
            DeviceTier::Candidate
        } else {
            DeviceTier::Host
        };

        queue.push(InterrogationTarget {
            device: key.clone(),
            tier,
            endpoints,
            known: DeviceFingerprint {
                vendor: node.vendor.clone(),
                open_ports: Vec::new(),
                hostnames: node.hostnames.iter().cloned().collect(),
                descriptions: node.descriptions.iter().cloned().collect(),
            },
            discovery_sources: node.evidence_sources(),
            confirmed_live: node.provenance.iter().any(|p| proves_liveness(p.source)),
        });
    }

    // Infrastructure first: what a pivot discloses may enqueue further networks, and doing
    // that early keeps the fixed-point loop from needing another pass.
    queue.sort_by_key(|task| task.tier.priority());
    queue
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::topology::evidence::{Confidence, Fact, RoleSignal, TopologyEvidence};

    const VANTAGE: &str = "test0";

    fn absorb(graph: &mut TopologyGraph, fact: Fact, source: EvidenceSource) {
        graph.absorb(TopologyEvidence::new(
            fact,
            source,
            Confidence::Observed,
            VANTAGE,
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

    fn addresses_of(task: &InterrogationTarget) -> Vec<String> {
        task.endpoints.iter().map(|e| e.to_string()).collect()
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

        let queue = queue_from_graph(&graph, &HashSet::new(), VANTAGE);
        assert_eq!(queue.len(), 3);

        // Infrastructure is worked first, so what it discloses can extend the same pass.
        assert_eq!(addresses_of(&queue[0]), vec!["10.9.0.1"]);
        assert_eq!(queue[0].tier, DeviceTier::EstablishedPivot);
        assert!(
            queue[1..]
                .iter()
                .all(|t| t.tier != DeviceTier::EstablishedPivot)
        );
    }

    #[test]
    fn a_dual_stack_device_is_one_entry_with_one_endpoint_per_family() {
        // Interrogating each address separately probed the same machine repeatedly and
        // produced several coverage records for one device.
        let mut graph = TopologyGraph::new();
        let key = device(&mut graph, "02:00:5e:00:00:04", "10.9.0.4");
        for address in ["fd00::4", "10.9.0.44"] {
            absorb(
                &mut graph,
                Fact::DeviceAddress {
                    device: key.clone(),
                    address: address.parse().unwrap(),
                },
                EvidenceSource::NdpCache,
            );
        }

        let queue = queue_from_graph(&graph, &HashSet::new(), VANTAGE);
        assert_eq!(queue.len(), 1, "one device, one entry");
        let endpoints = addresses_of(&queue[0]);
        assert_eq!(endpoints.len(), 2, "one per family: {endpoints:?}");
        assert!(endpoints[0].parse::<IpAddr>().unwrap().is_ipv4());
        assert_eq!(endpoints[1], "fd00::4");
    }

    #[test]
    fn a_link_local_neighbour_keeps_the_link_it_was_seen_on() {
        // fe80::1 on one interface and fe80::1 on another are different devices, and the
        // kernel cannot reach either without the zone.
        let mut graph = TopologyGraph::new();
        device(&mut graph, "02:00:5e:00:00:05", "fe80::5");

        let queue = queue_from_graph(&graph, &HashSet::new(), VANTAGE);
        assert_eq!(addresses_of(&queue[0]), vec![format!("fe80::5%{VANTAGE}")]);
    }

    #[test]
    fn a_routable_ipv6_address_is_preferred_over_a_link_local_one() {
        let mut graph = TopologyGraph::new();
        let key = device(&mut graph, "02:00:5e:00:00:06", "fe80::6");
        absorb(
            &mut graph,
            Fact::DeviceAddress {
                device: key,
                address: "fd00::6".parse().unwrap(),
            },
            EvidenceSource::NdpCache,
        );

        let queue = queue_from_graph(&graph, &HashSet::new(), VANTAGE);
        assert_eq!(addresses_of(&queue[0]), vec!["fd00::6"]);
    }

    #[test]
    fn an_ipv6_only_neighbour_is_interrogated_rather_than_skipped() {
        // Previously reported as "enriched from neighbour evidence", which it was not: a
        // neighbour entry is an address, not a service.
        let mut graph = TopologyGraph::new();
        device(&mut graph, "02:00:5e:00:00:07", "fd00::7");

        let queue = queue_from_graph(&graph, &HashSet::new(), VANTAGE);
        assert_eq!(queue.len(), 1);
        assert_eq!(addresses_of(&queue[0]), vec!["fd00::7"]);
    }

    #[test]
    fn an_already_interrogated_device_is_not_queued_again() {
        let mut graph = TopologyGraph::new();
        let done_key = device(&mut graph, "02:00:5e:00:00:08", "10.9.0.8");
        device(&mut graph, "02:00:5e:00:00:09", "10.9.0.9");

        let done: HashSet<DeviceKey> = [done_key].into_iter().collect();
        let queue = queue_from_graph(&graph, &done, VANTAGE);
        assert_eq!(queue.len(), 1);
        assert_eq!(addresses_of(&queue[0]), vec!["10.9.0.9"]);
    }

    #[test]
    fn addresses_that_cannot_be_probed_are_left_out() {
        // Loopback and IPv4 link-local are not probe destinations, and queueing them would
        // report coverage for work that means nothing.
        let mut graph = TopologyGraph::new();
        device(&mut graph, "02:00:5e:00:00:0a", "127.0.0.1");
        device(&mut graph, "02:00:5e:00:00:0b", "169.254.1.9");
        device(&mut graph, "02:00:5e:00:00:0c", "10.9.0.12");

        let queue = queue_from_graph(&graph, &HashSet::new(), VANTAGE);
        assert_eq!(queue.len(), 1);
        assert_eq!(addresses_of(&queue[0]), vec!["10.9.0.12"]);
    }

    #[test]
    fn an_arp_discovered_device_counts_as_confirmed_live() {
        // Liveness is what earns full exploration. A live host whose only service sits on
        // a stage 2 port was otherwise probed on seventeen ports and declared silent.
        let mut graph = TopologyGraph::new();
        device(&mut graph, "02:00:5e:00:00:0d", "10.9.0.13");

        let queue = queue_from_graph(&graph, &HashSet::new(), VANTAGE);
        assert!(queue[0].confirmed_live);
        assert!(proves_liveness(EvidenceSource::NdpCache));
        assert!(proves_liveness(EvidenceSource::IcmpProbe));
        assert!(proves_liveness(EvidenceSource::TcpProbe));
        // A kernel route names a next hop that may not have answered anything.
        assert!(!proves_liveness(EvidenceSource::KernelRoute));
    }

    #[test]
    fn prior_graph_identity_reaches_vendor_selection() {
        // The manufacturer is recorded when the device is first seen, long before
        // interrogation runs. Building the fingerprint from interrogation output alone
        // lost every OUI, so no adapter was ever selected from one.
        let mut graph = TopologyGraph::new();
        let key = device(&mut graph, "02:00:5e:00:00:0e", "10.9.0.14");
        absorb(
            &mut graph,
            Fact::DeviceVendor {
                device: key,
                vendor: "ASUSTek COMPUTER INC.".to_string(),
            },
            EvidenceSource::ArpCache,
        );

        let queue = queue_from_graph(&graph, &HashSet::new(), VANTAGE);
        assert_eq!(
            queue[0].known.vendor.as_deref(),
            Some("ASUSTek COMPUTER INC.")
        );
        assert!(
            crate::providers::vendor::adapters()
                .iter()
                .any(|a| a.applies(&queue[0].known) && a.name() == "vendor:asus")
        );
    }

    #[test]
    fn a_device_carries_how_it_was_discovered_into_its_coverage() {
        let mut graph = TopologyGraph::new();
        let key = device(&mut graph, "02:00:5e:00:00:0f", "10.9.0.15");
        absorb(
            &mut graph,
            Fact::DeviceHostname {
                device: key,
                hostname: "printer".to_string(),
            },
            EvidenceSource::Mdns,
        );

        let queue = queue_from_graph(&graph, &HashSet::new(), VANTAGE);
        assert_eq!(queue.len(), 1);
        assert!(queue[0].discovery_sources.len() >= 2, "{:?}", queue[0]);
    }
}
