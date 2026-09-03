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
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Whether the engine took responsibility for a bundle's evidence.
///
/// Returned to the caller so that an acknowledgement is only sent for evidence that was
/// actually queued. Acknowledging a bundle the engine declined would tell the peer its
/// evidence had landed when it had been dropped, and the peer would never resend it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Queued for the graph.
    Queued,
    /// The run has already concluded. The peer must not be told this was applied.
    Declined,
}

/// The queue and the stopped flag, behind one lock.
///
/// They were separate before, and `finish` took the pending evidence and only then marked
/// itself stopped -- so a bundle arriving in between was enqueued into a queue nothing
/// would ever drain, counted as accepted, and acknowledged to the peer. One lock makes
/// draining and stopping a single decision, and makes delivery either succeed or be told
/// no.
#[derive(Debug, Default)]
struct Queue {
    pending: Vec<TopologyEvidence>,
    stopped: bool,
}

/// Evidence accepted from peers, waiting to enter the graph.
///
/// Shared between the transport tasks that fill it and the engine that drains it.
#[derive(Debug, Default)]
pub struct FederationSource {
    queue: Mutex<Queue>,
    outcomes: Mutex<Vec<PeerOutcome>>,
    accepted_records: AtomicU64,
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
    ///
    /// Returns whether the evidence was queued. The caller must acknowledge the bundle only
    /// on [`Delivery::Queued`]: telling a peer its evidence landed when the run had already
    /// concluded would stop it ever resending, and the evidence would be lost for good.
    #[must_use]
    pub fn deliver(&self, accepted: Accepted) -> Delivery {
        let records = accepted.evidence.len();

        // Enqueueing and the stopped check are one decision under one lock. Split, a
        // bundle could be accepted into a queue that had just been drained for the last
        // time.
        let queued = match self.queue.lock() {
            Ok(mut queue) if !queue.stopped => {
                queue.pending.extend(accepted.evidence);
                true
            }
            _ => false,
        };

        if !queued {
            return Delivery::Declined;
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

        Delivery::Queued
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
        self.queue
            .lock()
            .map(|mut queue| std::mem::take(&mut queue.pending))
            .unwrap_or_default()
    }

    /// Takes whatever is still queued and stops accepting, in one step.
    ///
    /// Called once, at candidate convergence. A bundle that arrived while the last pass was
    /// running is still in here, and it may name a network or a router the engine has not
    /// traversed -- which is exactly the case the final drain exists for. Taking and
    /// stopping under one lock is what guarantees nothing is queued after the last drain
    /// and then silently dropped.
    fn finish(&self) -> Vec<TopologyEvidence> {
        self.queue
            .lock()
            .map(|mut queue| {
                queue.stopped = true;
                std::mem::take(&mut queue.pending)
            })
            .unwrap_or_default()
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
        assert_eq!(source.deliver(accepted(peer, 3)), Delivery::Queued);

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
        assert_eq!(source.deliver(accepted(peer, 2)), Delivery::Queued);

        assert_eq!(source.finish().len(), 2);
    }

    #[test]
    fn a_bundle_arriving_after_the_final_drain_is_declined_not_swallowed() {
        // The race this closes: evidence enqueued between the final drain and the stop was
        // counted as accepted, acknowledged to the peer, and never seen by the engine --
        // so the peer would never resend it and it was lost for good.
        let source = FederationSource::new();
        let peer = PeerKey::generate().id();
        source.finish();

        assert_eq!(
            source.deliver(accepted(peer, 5)),
            Delivery::Declined,
            "the caller must be told, so it does not acknowledge the bundle"
        );
        assert!(source.drain().is_empty());
        assert_eq!(
            source.accepted_records(),
            0,
            "declined evidence must not be counted as accepted"
        );
        assert!(!source.had_peers());
    }

    #[test]
    fn concurrent_delivery_during_finish_is_either_taken_or_declined() {
        // Whichever order the two land in, nothing may be both accepted and dropped.
        use std::sync::Arc;

        for _ in 0..64 {
            let source = Arc::new(FederationSource::new());
            let peer = PeerKey::generate().id();

            let deliverer = {
                let source = Arc::clone(&source);
                let peer = peer.clone();
                std::thread::spawn(move || source.deliver(accepted(peer, 4)))
            };
            let taken = source.finish().len();
            let outcome = deliverer.join().expect("delivery thread");

            let total = taken + source.drain().len();
            match outcome {
                Delivery::Queued => assert_eq!(total, 4, "queued evidence must be drained"),
                Delivery::Declined => assert_eq!(total, 0, "declined evidence must not appear"),
            }
            assert_eq!(source.accepted_records() as usize, total);
        }
    }

    #[test]
    fn peer_outcomes_accumulate_across_bundles() {
        let source = FederationSource::new();
        let peer = PeerKey::generate().id();
        assert_eq!(source.deliver(accepted(peer.clone(), 2)), Delivery::Queued);
        assert_eq!(source.deliver(accepted(peer.clone(), 3)), Delivery::Queued);

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
