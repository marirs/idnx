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

    /// Verifies, authorises and converts a bundle.
    pub fn accept(&mut self, bundle: &EvidenceBundle) -> Result<Accepted, RejectReason> {
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

        // Recorded only once the bundle is accepted in full, so a rejected bundle cannot
        // advance the sequence and lock out the peer's later ones -- nor its own resend
        // once this build understands it.
        self.highest_sequence.insert(key, bundle.sequence);

        Ok(Accepted {
            peer,
            vantage: bundle.vantage.clone(),
            sequence: bundle.sequence,
            evidence,
        })
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

        let accepted = ledger.accept(&bundle).expect("accepted");
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
            ledger.accept(&bundle).unwrap_err(),
            RejectReason::NotPaired(stranger.id().to_hex())
        );
    }

    #[test]
    fn a_replayed_bundle_is_rejected() {
        let (mut ledger, key) = paired();
        let bundle = EvidenceBundle::publish(&key, "br0", 4, &evidence());

        assert!(ledger.accept(&bundle).is_ok());
        assert_eq!(
            ledger.accept(&bundle).unwrap_err(),
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
                .accept(&EvidenceBundle::publish(&key, "br0", 9, &evidence()))
                .is_ok()
        );
        assert_eq!(
            ledger
                .accept(&EvidenceBundle::publish(&key, "br0", 8, &evidence()))
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

        assert!(ledger.accept(&forged).is_err());
        assert!(
            ledger
                .accept(&EvidenceBundle::publish(&key, "br0", 1, &evidence()))
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

        let reasons = match ledger.accept(&bundle_with_unknown_vocabulary(&key, 1)) {
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
                .accept(&bundle_with_unknown_vocabulary(&key, 7))
                .is_err()
        );

        // Standing in for the upgraded build: the same sequence, now fully readable.
        let readable = EvidenceBundle::publish(&key, "br0", 7, &evidence());
        assert!(
            ledger.accept(&readable).is_ok(),
            "a resend at the same sequence must still be accepted"
        );
    }

    #[test]
    fn a_forged_bundle_is_reported_as_unverifiable_not_as_unknown() {
        // "we ignored a peer" and "someone sent us something forged" are different
        // operational events and must not read alike.
        let (mut ledger, key) = paired();
        let mut bundle = EvidenceBundle::publish(&key, "br0", 1, &evidence());
        bundle.sequence = 2;

        assert!(matches!(
            ledger.accept(&bundle),
            Err(RejectReason::Unverifiable(_))
        ));
    }
}
