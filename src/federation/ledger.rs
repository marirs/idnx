//! Accepting evidence from peers.
//!
//! The ledger is the boundary between what other machines assert and what this one records.
//! Everything crossing it is verified, attributed, and accounted for -- a bundle that is
//! rejected says why, and a record that could not be converted is reported rather than
//! silently dropped, because a peer whose evidence never lands looks identical to a peer
//! with nothing to say.
//!
//! Trust is by public key. A peer this machine has not paired with is refused: verifying a
//! signature proves who signed, not that the signer should be listened to.

use std::collections::HashMap;

use super::bundle::{BundleError, EvidenceBundle};
use super::identity::PeerId;
use crate::topology::TopologyEvidence;
use crate::topology::evidence::PeerOrigin;

/// Why a bundle was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// The signature, identity or schema version did not hold up.
    Unverifiable(BundleError),
    /// Signed by a key this machine has not paired with.
    ///
    /// Distinct from an invalid signature: this bundle is genuine and simply not ours.
    NotPaired(String),
    /// A sequence number at or below one already accepted from this peer -- a replay, or a
    /// bundle arriving out of order behind a newer one.
    Stale { seen: u64, offered: u64 },
    /// Another connection is already midway through applying this peer's bundle.
    ///
    /// Two connections from one peer -- a direct link and a relay, or a reconnect racing a
    /// stale socket -- can otherwise both prepare the same sequence before either commits,
    /// and the evidence is applied twice. The second is told to wait rather than refused
    /// for good.
    Busy { peer: String },
    /// The bundle contains vocabulary this build does not understand.
    ///
    /// Refused whole, and the sequence is not advanced. Taking the readable half would
    /// record a partial view of what the peer said while marking the bundle as consumed,
    /// so a later upgraded build could never make sense of the rest. The peer resends;
    /// resends are idempotent by sequence number.
    Undecodable(Vec<String>),
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectReason::Unverifiable(e) => write!(f, "unverifiable: {e}"),
            RejectReason::NotPaired(peer) => {
                // Truncated by characters, not bytes: this string came off the wire and
                // slicing it at a byte offset would panic inside a multi-byte character.
                let short: String = peer.chars().take(16).collect();
                write!(f, "not paired with peer {short}")
            }
            RejectReason::Stale { seen, offered } => {
                write!(
                    f,
                    "stale: sequence {offered} at or below {seen} already accepted"
                )
            }
            RejectReason::Busy { peer } => {
                let short: String = peer.chars().take(16).collect();
                write!(f, "another transaction for peer {short} is still in flight")
            }
            RejectReason::Undecodable(reasons) => {
                write!(
                    f,
                    "undecodable: {} (this build is older than the peer's)",
                    reasons.join("; ")
                )
            }
        }
    }
}

/// A verified bundle whose evidence is ready, but which the ledger has not yet committed.
///
/// The split exists because acceptance is not one decision. Verifying and decoding is
/// cheap and reversible; advancing the replay cursor is neither. Doing both at once meant a
/// bundle whose evidence the engine then declined -- because the run had already concluded
/// -- was recorded as seen, went unacknowledged, and could never be resent: the peer would
/// retry and be told the sequence was stale, for ever.
///
/// So: prepare, hand the evidence to the engine, persist the cursor, and only then commit.
/// A prepared bundle that is dropped without committing leaves the ledger untouched, and
/// the identical sequence can be offered again.
#[derive(Debug)]
#[must_use = "a prepared bundle must be committed or abandoned"]
pub struct Prepared {
    peer: PeerId,
    vantage: String,
    sequence: u64,
    evidence: Vec<TopologyEvidence>,
    /// Identifies this reservation, so a late-finishing task cannot release a newer one.
    token: u64,
}

impl Prepared {
    pub fn peer(&self) -> &PeerId {
        &self.peer
    }

    pub fn vantage(&self) -> &str {
        &self.vantage
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The reservation this transaction holds.
    pub fn token(&self) -> u64 {
        self.token
    }

    /// Takes the evidence, to hand to whoever owns the graph.
    ///
    /// The token is returned alongside, because committing needs it after the evidence has
    /// been given away.
    pub fn split(self) -> (Accepted, Receipt) {
        let receipt = Receipt {
            peer: self.peer.clone(),
            sequence: self.sequence,
            token: self.token,
        };
        (self.into_accepted(), receipt)
    }

    /// Takes the evidence, to hand to whoever owns the graph.
    pub fn into_accepted(self) -> Accepted {
        Accepted {
            peer: self.peer,
            vantage: self.vantage,
            sequence: self.sequence,
            evidence: self.evidence,
        }
    }
}

/// Proof that a particular transaction is the one being finished.
///
/// Carried through delivery and cursor persistence so that `commit` and `abandon` act on
/// the reservation they belong to. A bare peer identifier was not enough: a task that
/// stalled and finished late would release whichever reservation happened to be current,
/// letting a second connection's transaction be committed or freed by the first's.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a receipt must be committed or abandoned, or the peer stays reserved"]
pub struct Receipt {
    peer: PeerId,
    sequence: u64,
    token: u64,
}

impl Receipt {
    pub fn peer(&self) -> &PeerId {
        &self.peer
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// What accepting one bundle produced.
#[derive(Debug, Clone)]
pub struct Accepted {
    pub peer: PeerId,
    pub vantage: String,
    pub sequence: u64,
    /// Evidence ready to absorb, each record carrying its peer origin.
    pub evidence: Vec<TopologyEvidence>,
}

/// Peers this machine will accept evidence from, and what it has already seen from them.
#[derive(Debug, Default)]
pub struct PeerLedger {
    /// Paired peers, by hex public key.
    trusted: HashMap<String, PeerId>,
    /// Highest sequence accepted per peer, so a replay cannot re-apply old evidence.
    highest_sequence: HashMap<String, u64>,
    /// Reservations currently held, per peer, each with the token that owns it.
    ///
    /// The whole transaction -- prepare, hand to the engine, persist the cursor, commit,
    /// acknowledge -- must be serial per peer. Holding the reservation here makes a second
    /// concurrent prepare for the same peer fail rather than duplicate the work, and the
    /// token means only the transaction that took it can release it.
    in_flight: HashMap<String, u64>,
    /// Monotonic reservation counter.
    next_token: u64,
}

impl PeerLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pairs with a peer: from now on its signed evidence is accepted.
    ///
    /// Pairing is a deliberate act. It is what makes a verified signature meaningful, and
    /// it is the only thing standing between this topology and any machine that can reach
    /// it.
    pub fn pair(&mut self, peer: PeerId) {
        self.trusted.insert(peer.to_hex(), peer);
    }

    pub fn is_paired(&self, peer: &PeerId) -> bool {
        self.trusted.contains_key(&peer.to_hex())
    }

    pub fn paired_peers(&self) -> Vec<&PeerId> {
        let mut peers: Vec<&PeerId> = self.trusted.values().collect();
        peers.sort_by_key(|p| p.to_hex());
        peers
    }

    /// Verifies, authorises and converts a bundle, without recording it as seen.
    ///
    /// Nothing here changes the ledger. The caller commits only once the evidence has an
    /// owner and the cursor is durable; until then the bundle may be offered again.
    pub fn prepare(&mut self, bundle: &EvidenceBundle) -> Result<Prepared, RejectReason> {
        let peer = bundle.verify().map_err(RejectReason::Unverifiable)?;

        if !self.is_paired(&peer) {
            return Err(RejectReason::NotPaired(peer.to_hex()));
        }

        let key = peer.to_hex();
        if let Some(&seen) = self.highest_sequence.get(&key)
            && bundle.sequence <= seen
        {
            return Err(RejectReason::Stale {
                seen,
                offered: bundle.sequence,
            });
        }

        let origin = PeerOrigin {
            peer: key.clone(),
            vantage: bundle.vantage.clone(),
            sequence: bundle.sequence,
            published_at: bundle.published_at,
        };

        // All or nothing. Accepting the readable records and reporting the rest would take
        // a partial view of what the peer said while marking the bundle consumed, so an
        // upgraded build could never recover the remainder.
        let mut evidence = Vec::with_capacity(bundle.records.len());
        let mut undecodable = Vec::new();
        for record in &bundle.records {
            match record.to_evidence() {
                Ok(converted) => evidence.push(converted.from_peer(origin.clone())),
                Err(error) => undecodable.push(error.to_string()),
            }
        }
        if !undecodable.is_empty() {
            undecodable.sort();
            undecodable.dedup();
            return Err(RejectReason::Undecodable(undecodable));
        }

        // Reserved for the duration of the transaction. Released by `commit` or `abandon`,
        // and only by the transaction whose token matches.
        if self.in_flight.contains_key(&key) {
            return Err(RejectReason::Busy { peer: key });
        }
        self.next_token += 1;
        let token = self.next_token;
        self.in_flight.insert(key, token);

        Ok(Prepared {
            peer,
            vantage: bundle.vantage.clone(),
            sequence: bundle.sequence,
            evidence,
            token,
        })
    }

    /// Records a bundle as seen, so it is never applied again.
    ///
    /// Called last: after the evidence has been queued for the graph and after the inbound
    /// cursor has been written to disk. Anything earlier risks a sequence marked consumed
    /// by work that did not happen.
    /// Records a bundle as seen and releases its reservation.
    ///
    /// Ignored unless the receipt owns the current reservation, so a task that stalled and
    /// finished late cannot commit on behalf of a newer transaction.
    pub fn commit(&mut self, receipt: &Receipt) -> bool {
        let key = receipt.peer.to_hex();
        if self.in_flight.get(&key) != Some(&receipt.token) {
            return false;
        }
        let entry = self.highest_sequence.entry(key.clone()).or_default();
        if receipt.sequence > *entry {
            *entry = receipt.sequence;
        }
        self.in_flight.remove(&key);
        true
    }

    /// Releases a reservation without recording the bundle as seen.
    ///
    /// For a transaction that could not finish -- the engine declined the evidence, or the
    /// cursor could not be persisted. The sequence stays offerable, and the peer's next
    /// attempt is not blocked by a reservation nothing will release.
    ///
    /// Ignored unless the receipt owns the current reservation. A stale abandon that freed
    /// whatever was current would let a second connection's transaction be interrupted by
    /// the first's failure.
    pub fn abandon(&mut self, receipt: &Receipt) -> bool {
        let key = receipt.peer.to_hex();
        if self.in_flight.get(&key) != Some(&receipt.token) {
            return false;
        }
        self.in_flight.remove(&key);
        true
    }

    /// Whether a transaction for this peer is in flight.
    pub fn is_busy(&self, peer: &PeerId) -> bool {
        self.in_flight.contains_key(&peer.to_hex())
    }

    /// Seeds the replay cursor from durable state at startup.
    ///
    /// Without this a restart forgets what it accepted, and a captured bundle replayed
    /// afterwards is applied again.
    pub fn restore_cursor(&mut self, peer: &PeerId, sequence: u64) {
        let entry = self.highest_sequence.entry(peer.to_hex()).or_default();
        if sequence > *entry {
            *entry = sequence;
        }
    }

    /// Verifies, converts and commits in one step.
    ///
    /// **Not for runtime use.** It advances the replay cursor before the evidence has an
    /// owner or the cursor is durable, which is exactly the sequence of events that made a
    /// declined bundle unresendable. Runtime code uses `prepare`, hands the evidence over,
    /// persists the cursor, and only then commits.
    ///
    /// Kept public because integration tests are separate crates and cannot reach a
    /// `cfg(test)` item; a guard test fails if anything under `src/` calls it.
    pub fn accept_immediately(
        &mut self,
        bundle: &EvidenceBundle,
    ) -> Result<Accepted, RejectReason> {
        let prepared = self.prepare(bundle)?;
        let (accepted, receipt) = prepared.split();
        self.commit(&receipt);
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::identity::PeerKey;
    use super::super::wire::{SCHEMA_VERSION, WireEvidence};
    use crate::topology::evidence::{Confidence, EvidenceSource, Fact};

    fn evidence() -> Vec<TopologyEvidence> {
        vec![TopologyEvidence::new(
            Fact::Network {
                prefix: "192.168.51.0/24".parse().unwrap(),
            },
            EvidenceSource::InterfaceAddress,
            Confidence::Observed,
            "br0",
        )]
    }

    fn paired() -> (PeerLedger, PeerKey) {
        let key = PeerKey::generate();
        let mut ledger = PeerLedger::new();
        ledger.pair(key.id());
        (ledger, key)
    }

    #[test]
    fn a_paired_peers_evidence_is_accepted_and_attributed() {
        let (mut ledger, key) = paired();
        let bundle = EvidenceBundle::publish(&key, "br0", 1, &evidence());

        let accepted = ledger.accept_immediately(&bundle).expect("accepted");
        assert_eq!(accepted.peer, key.id());
        assert_eq!(accepted.evidence.len(), 1);

        // Attribution survives conversion: the record knows it is not a local observation.
        let origin = accepted.evidence[0].origin.as_ref().expect("attributed");
        assert_eq!(origin.peer, key.id().to_hex());
        assert_eq!(origin.vantage, "br0");
        assert_eq!(origin.sequence, 1);
        assert!(accepted.evidence[0].is_remote());
    }

    #[test]
    fn an_unpaired_peer_is_refused_even_with_a_valid_signature() {
        // Verifying a signature proves who signed, not that the signer should be listened
        // to. Without this, any machine that can reach us can inject topology.
        let stranger = PeerKey::generate();
        let mut ledger = PeerLedger::new();
        let bundle = EvidenceBundle::publish(&stranger, "br0", 1, &evidence());

        assert!(bundle.verify().is_ok(), "the bundle itself is genuine");
        assert_eq!(
            ledger.accept_immediately(&bundle).unwrap_err(),
            RejectReason::NotPaired(stranger.id().to_hex())
        );
    }

    #[test]
    fn a_replayed_bundle_is_rejected() {
        let (mut ledger, key) = paired();
        let bundle = EvidenceBundle::publish(&key, "br0", 4, &evidence());

        assert!(ledger.accept_immediately(&bundle).is_ok());
        assert_eq!(
            ledger.accept_immediately(&bundle).unwrap_err(),
            RejectReason::Stale {
                seen: 4,
                offered: 4
            }
        );
    }

    #[test]
    fn a_bundle_arriving_out_of_order_behind_a_newer_one_is_rejected() {
        let (mut ledger, key) = paired();
        assert!(
            ledger
                .accept_immediately(&EvidenceBundle::publish(&key, "br0", 9, &evidence()))
                .is_ok()
        );
        assert_eq!(
            ledger
                .accept_immediately(&EvidenceBundle::publish(&key, "br0", 8, &evidence()))
                .unwrap_err(),
            RejectReason::Stale {
                seen: 9,
                offered: 8
            }
        );
    }

    #[test]
    fn a_rejected_bundle_does_not_advance_the_sequence() {
        // Otherwise a forged high-sequence bundle would lock the real peer out.
        let (mut ledger, key) = paired();
        let mut forged = EvidenceBundle::publish(&key, "br0", 1000, &evidence());
        forged.vantage = "tampered".to_string();

        assert!(ledger.accept_immediately(&forged).is_err());
        assert!(
            ledger
                .accept_immediately(&EvidenceBundle::publish(&key, "br0", 1, &evidence()))
                .is_ok(),
            "the peer's genuine bundle must still be accepted"
        );
    }

    /// Builds a bundle containing one record this build cannot interpret.
    fn bundle_with_unknown_vocabulary(key: &PeerKey, sequence: u64) -> EvidenceBundle {
        let mut bundle = EvidenceBundle::publish(key, "br0", sequence, &evidence());
        bundle.records.push(WireEvidence {
            fact: super::super::wire::WireFact::Vlan { id: 1 },
            source: "quantum_entanglement".to_string(),
            confidence: "observed".to_string(),
            vantage: "br0".to_string(),
            observed_at: 0,
            detail: None,
        });
        // Re-sign, since editing the records invalidates the original signature.
        EvidenceBundle {
            signature: super::super::identity::encode_hex(&key.sign(
                &super::super::wire::signing_payload(
                    SCHEMA_VERSION,
                    &bundle.peer,
                    &bundle.vantage,
                    bundle.sequence,
                    bundle.published_at,
                    &bundle.records,
                ),
            )),
            ..bundle
        }
    }

    #[test]
    fn a_bundle_this_build_cannot_fully_read_is_refused_whole() {
        // A peer running a newer build sends vocabulary this one lacks. Taking the
        // readable half would record a partial view of what the peer said, and reporting
        // the remainder afterwards does not undo that.
        let (mut ledger, key) = paired();

        let reasons = match ledger.accept_immediately(&bundle_with_unknown_vocabulary(&key, 1)) {
            Err(RejectReason::Undecodable(reasons)) => reasons,
            other => panic!("expected an undecodable rejection, got {other:?}"),
        };
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("quantum_entanglement"), "{reasons:?}");
    }

    #[test]
    fn an_undecodable_bundle_can_still_be_accepted_by_a_later_build() {
        // The sequence must not advance, or the same bundle resent to an upgraded build
        // would be rejected as stale and its evidence lost permanently.
        let (mut ledger, key) = paired();
        assert!(
            ledger
                .accept_immediately(&bundle_with_unknown_vocabulary(&key, 7))
                .is_err()
        );

        // Standing in for the upgraded build: the same sequence, now fully readable.
        let readable = EvidenceBundle::publish(&key, "br0", 7, &evidence());
        assert!(
            ledger.accept_immediately(&readable).is_ok(),
            "a resend at the same sequence must still be accepted"
        );
    }

    #[test]
    fn a_prepared_bundle_that_is_never_committed_can_be_offered_again() {
        // The defect this closes: evidence the engine declined, because the run had
        // already concluded, was still recorded as seen. The peer got no acknowledgement,
        // resent, and was told the sequence was stale -- for ever.
        let (mut ledger, key) = paired();
        let bundle = EvidenceBundle::publish(&key, "br0", 1, &evidence());

        let prepared = ledger.prepare(&bundle).expect("prepared");
        assert_eq!(prepared.sequence(), 1);
        // The delivery is declined, so the bundle is abandoned rather than committed.
        let (_, receipt) = prepared.split();
        assert!(ledger.abandon(&receipt));

        let second = ledger
            .prepare(&bundle)
            .expect("the same sequence is still offerable");
        assert_eq!(second.sequence(), 1);

        // Once committed, it is finished with.
        let (_, receipt) = second.split();
        assert!(ledger.commit(&receipt));
        assert_eq!(
            ledger.prepare(&bundle).unwrap_err(),
            RejectReason::Stale {
                seen: 1,
                offered: 1
            }
        );
    }

    #[test]
    fn preparing_a_bundle_changes_nothing_until_it_is_committed() {
        let (mut ledger, key) = paired();
        for sequence in [5u64, 5, 5] {
            let bundle = EvidenceBundle::publish(&key, "br0", sequence, &evidence());
            let prepared = ledger.prepare(&bundle).expect("no cursor advanced");
            // Release the reservation without committing, as a declined delivery would.
            let (_, receipt) = prepared.split();
            assert!(ledger.abandon(&receipt));
        }
    }

    #[test]
    fn a_restored_cursor_rejects_a_bundle_captured_before_the_restart() {
        // Replay protection must survive a restart, which means seeding the ledger from
        // durable state rather than starting empty.
        let (mut ledger, key) = paired();
        ledger.restore_cursor(&key.id(), 9);

        let replayed = EvidenceBundle::publish(&key, "br0", 9, &evidence());
        assert_eq!(
            ledger.prepare(&replayed).unwrap_err(),
            RejectReason::Stale {
                seen: 9,
                offered: 9
            }
        );
        assert!(
            ledger
                .prepare(&EvidenceBundle::publish(&key, "br0", 10, &evidence()))
                .is_ok()
        );
    }

    #[test]
    fn two_connections_from_one_peer_cannot_apply_the_same_bundle_twice() {
        // A direct link and a relay, or a reconnect racing a stale socket, both offering
        // the same bundle: without a reservation both prepare it before either commits and
        // the evidence lands twice.
        let (mut ledger, key) = paired();
        let bundle = EvidenceBundle::publish(&key, "br0", 1, &evidence());

        let first = ledger.prepare(&bundle).expect("prepared");
        assert!(ledger.is_busy(&key.id()));
        assert_eq!(
            ledger.prepare(&bundle).unwrap_err(),
            RejectReason::Busy {
                peer: key.id().to_hex()
            }
        );

        let (_, receipt) = first.split();
        assert!(ledger.commit(&receipt));
        assert!(!ledger.is_busy(&key.id()));
    }

    #[test]
    fn abandoning_a_transaction_frees_the_peer_for_its_next_attempt() {
        // A reservation nothing releases would block the peer for the life of the process.
        let (mut ledger, key) = paired();
        let bundle = EvidenceBundle::publish(&key, "br0", 1, &evidence());

        let (_, receipt) = ledger.prepare(&bundle).expect("prepared").split();
        assert!(ledger.abandon(&receipt));

        assert!(!ledger.is_busy(&key.id()));
        assert!(
            ledger.prepare(&bundle).is_ok(),
            "the same sequence is offerable again"
        );
    }

    #[test]
    fn a_stale_abandon_cannot_release_a_newer_reservation() {
        // A task that stalls and finishes late must not free -- or commit -- whichever
        // transaction happens to be current by then.
        let (mut ledger, key) = paired();
        let bundle = EvidenceBundle::publish(&key, "br0", 1, &evidence());

        let (_, stale) = ledger.prepare(&bundle).expect("first").split();
        assert!(ledger.abandon(&stale), "the first releases its own");

        let second = ledger.prepare(&bundle).expect("second");
        assert!(ledger.is_busy(&key.id()));

        // The stalled first task finally runs.
        assert!(
            !ledger.abandon(&stale),
            "a stale receipt must not release the reservation it does not own"
        );
        assert!(
            !ledger.commit(&stale),
            "nor commit on behalf of another transaction"
        );
        assert!(ledger.is_busy(&key.id()), "the second still holds it");

        let (_, receipt) = second.split();
        assert!(ledger.commit(&receipt));
        assert!(!ledger.is_busy(&key.id()));
    }

    #[test]
    fn a_forged_bundle_is_reported_as_unverifiable_not_as_unknown() {
        // "we ignored a peer" and "someone sent us something forged" are different
        // operational events and must not read alike.
        let (mut ledger, key) = paired();
        let mut bundle = EvidenceBundle::publish(&key, "br0", 1, &evidence());
        bundle.sequence = 2;

        assert!(matches!(
            ledger.accept_immediately(&bundle),
            Err(RejectReason::Unverifiable(_))
        ));
    }
}
