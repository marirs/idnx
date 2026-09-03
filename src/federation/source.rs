//! Federation as a continuous source, alongside packet capture.
//!
//! Peer evidence arrives on its own schedule, exactly as captured frames do: a relay hands
//! over what it was holding when the connection succeeds, not when the engine asks. It
//! therefore uses the same [`ContinuousSource`] contract, which the engine polls before
//! every convergence decision and finishes exactly once — so a bundle that lands moments
//! before the run would have ended still enters the graph and can still extend the
//! traversal.
//!
//! That is what makes federated discovery recursive rather than additive. A peer reporting
//! its own prefix is a new network to explore; a peer naming a router is a new pivot. The
//! engine already resumes on either, provided the evidence arrives before it decides it is
//! finished, which is precisely what draining here guarantees.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::identity::PeerId;
use super::ledger::{Accepted, RejectReason};
use crate::providers::ContinuousSource;
use crate::topology::TopologyEvidence;

/// What happened with one peer, for the coverage report.
#[derive(Debug, Clone)]
pub struct PeerOutcome {
    pub peer: PeerId,
    pub vantage: String,
    /// Bundles accepted from this peer during the run.
    pub bundles: usize,
    /// Evidence records accepted.
    pub records: usize,
    /// Why bundles were refused, if any were. Reported rather than hidden: a peer whose
    /// evidence is being discarded looks identical to a peer with nothing to say.
    pub rejected: Vec<String>,
}

/// Evidence accepted from peers, waiting to enter the graph.
///
/// Shared between the transport tasks that fill it and the engine that drains it.
#[derive(Debug, Default)]
pub struct FederationSource {
    pending: Mutex<Vec<TopologyEvidence>>,
    outcomes: Mutex<Vec<PeerOutcome>>,
    accepted_records: AtomicU64,
    stopped: AtomicBool,
}

impl FederationSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds evidence a peer's bundle produced.
    ///
    /// Called from whichever task is talking to that peer. Nothing is absorbed here: the
    /// engine owns the graph, and it takes this at a point where it can act on what
    /// arrives.
    pub fn deliver(&self, accepted: Accepted) {
        let records = accepted.evidence.len();
        if let Ok(mut pending) = self.pending.lock() {
            pending.extend(accepted.evidence);
        }
        self.accepted_records
            .fetch_add(records as u64, Ordering::Relaxed);

        if let Ok(mut outcomes) = self.outcomes.lock() {
            match outcomes
                .iter_mut()
                .find(|o| o.peer == accepted.peer && o.vantage == accepted.vantage)
            {
                Some(existing) => {
                    existing.bundles += 1;
                    existing.records += records;
                }
                None => outcomes.push(PeerOutcome {
                    peer: accepted.peer,
                    vantage: accepted.vantage,
                    bundles: 1,
                    records,
                    rejected: Vec::new(),
                }),
            }
        }
    }

    /// Records a bundle that was refused, and why.
    pub fn reject(&self, peer: Option<PeerId>, vantage: &str, reason: &RejectReason) {
        let Ok(mut outcomes) = self.outcomes.lock() else {
            return;
        };
        let Some(peer) = peer else {
            return;
        };
        match outcomes
            .iter_mut()
            .find(|o| o.peer == peer && o.vantage == vantage)
        {
            Some(existing) => existing.rejected.push(reason.to_string()),
            None => outcomes.push(PeerOutcome {
                peer,
                vantage: vantage.to_string(),
                bundles: 0,
                records: 0,
                rejected: vec![reason.to_string()],
            }),
        }
    }

    /// Everything that happened with peers this run.
    pub fn outcomes(&self) -> Vec<PeerOutcome> {
        self.outcomes.lock().map(|o| o.clone()).unwrap_or_default()
    }

    /// Total records accepted, for the visibility report.
    pub fn accepted_records(&self) -> u64 {
        self.accepted_records.load(Ordering::Relaxed)
    }

    /// Whether any peer contributed anything.
    pub fn had_peers(&self) -> bool {
        self.outcomes.lock().map(|o| !o.is_empty()).unwrap_or(false)
    }
}

impl ContinuousSource for FederationSource {
    fn drain(&self) -> Vec<TopologyEvidence> {
        if self.stopped.load(Ordering::Relaxed) {
            return Vec::new();
        }
        self.pending
            .lock()
            .map(|mut pending| std::mem::take(&mut *pending))
            .unwrap_or_default()
    }

    /// Takes whatever is still queued and stops accepting.
    ///
    /// Called once, at candidate convergence. A bundle that arrived while the last pass was
    /// running is still in here, and it may name a network or a router the engine has not
    /// traversed — which is exactly the case the final drain exists for.
    fn finish(&self) -> Vec<TopologyEvidence> {
        let remaining = self
            .pending
            .lock()
            .map(|mut pending| std::mem::take(&mut *pending))
            .unwrap_or_default();
        self.stopped.store(true, Ordering::Relaxed);
        remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::identity::PeerKey;
    use crate::topology::evidence::{Confidence, EvidenceSource, Fact, PeerOrigin};

    fn accepted(peer: PeerId, count: usize) -> Accepted {
        let origin = PeerOrigin {
            peer: peer.to_hex(),
            vantage: "br0".to_string(),
            sequence: 1,
            published_at: 0,
        };
        Accepted {
            peer,
            vantage: "br0".to_string(),
            sequence: 1,
            evidence: (0..count)
                .map(|i| {
                    TopologyEvidence::new(
                        Fact::Vlan { id: i as u16 },
                        EvidenceSource::UserSupplied,
                        Confidence::Observed,
                        "br0",
                    )
                    .from_peer(origin.clone())
                })
                .collect(),
        }
    }

    #[test]
    fn delivered_evidence_is_drained_exactly_once() {
        let source = FederationSource::new();
        let peer = PeerKey::generate().id();
        source.deliver(accepted(peer, 3));

        assert_eq!(source.drain().len(), 3);
        assert!(source.drain().is_empty(), "draining consumes");
        assert_eq!(source.accepted_records(), 3);
    }

    #[test]
    fn evidence_arriving_late_is_still_taken_by_the_final_drain() {
        // The case this contract exists for: a relay hands over a bundle just as the
        // engine is deciding it has converged, and that bundle may name a whole network.
        let source = FederationSource::new();
        let peer = PeerKey::generate().id();

        assert!(source.drain().is_empty());
        source.deliver(accepted(peer, 2));

        assert_eq!(source.finish().len(), 2);
    }

    #[test]
    fn nothing_is_delivered_after_the_source_is_finished() {
        let source = FederationSource::new();
        let peer = PeerKey::generate().id();
        source.finish();

        source.deliver(accepted(peer, 5));
        assert!(
            source.drain().is_empty(),
            "a stopped source must not extend a run that has already concluded"
        );
    }

    #[test]
    fn peer_outcomes_accumulate_across_bundles() {
        let source = FederationSource::new();
        let peer = PeerKey::generate().id();
        source.deliver(accepted(peer.clone(), 2));
        source.deliver(accepted(peer.clone(), 3));

        let outcomes = source.outcomes();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].bundles, 2);
        assert_eq!(outcomes[0].records, 5);
        assert!(source.had_peers());
    }

    #[test]
    fn a_refused_bundle_is_reported_rather_than_silently_dropped() {
        // A peer whose evidence is being discarded must not look like a peer with nothing
        // to say.
        let source = FederationSource::new();
        let peer = PeerKey::generate().id();
        source.reject(
            Some(peer.clone()),
            "br0",
            &RejectReason::Stale {
                seen: 4,
                offered: 3,
            },
        );

        let outcomes = source.outcomes();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].records, 0);
        assert_eq!(outcomes[0].rejected.len(), 1);
        assert!(outcomes[0].rejected[0].contains("stale"));
    }
}
