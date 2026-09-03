//! Signed evidence bundles.
//!
//! A bundle is what one peer publishes: the raw evidence it observed, attributed to its
//! identity and vantage, timestamped, sequenced and signed. A receiver can verify who
//! produced it and that nothing was altered, including when it arrived through a relay that
//! neither peer trusts.
//!
//! What a signature does *not* establish is that the evidence is true. A peer can sign a
//! fabrication perfectly well. Verification tells the receiver which peer to attribute the
//! claim to; the merge rules decide what weight it carries.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::identity::{IdentityError, PeerId, PeerKey, decode_hex, encode_hex};
use super::wire::{SCHEMA_VERSION, WireEvidence, signing_payload, unix_seconds};
use crate::topology::TopologyEvidence;

/// A peer's published evidence, signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceBundle {
    /// Wire format version. A receiver refuses what it cannot interpret.
    pub schema_version: u16,
    /// The publishing peer's public key, in hex.
    pub peer: String,
    /// The interface the peer observed from. Its own name for it, not the receiver's.
    pub vantage: String,
    /// Monotonic per peer. Lets a receiver ignore a replayed or reordered bundle.
    pub sequence: u64,
    /// Seconds since the epoch, as the peer's clock reported. Not to be trusted as time,
    /// only as what the peer claimed.
    pub published_at: u64,
    pub records: Vec<WireEvidence>,
    /// Ed25519 signature over [`signing_payload`], in hex.
    pub signature: String,
}

impl EvidenceBundle {
    /// Builds and signs a bundle from evidence this peer observed.
    pub fn publish(
        key: &PeerKey,
        vantage: &str,
        sequence: u64,
        evidence: &[TopologyEvidence],
    ) -> Self {
        // Facts this format version cannot express are left out rather than approximated.
        // A receiver is told what it did get and nothing it did not.
        let records: Vec<WireEvidence> = evidence
            .iter()
            .filter_map(WireEvidence::from_evidence)
            .collect();
        let peer = key.id().to_hex();
        let published_at = unix_seconds(SystemTime::now());
        let signature = key.sign(&signing_payload(
            SCHEMA_VERSION,
            &peer,
            vantage,
            sequence,
            published_at,
            &records,
        ));

        Self {
            schema_version: SCHEMA_VERSION,
            peer,
            vantage: vantage.to_string(),
            sequence,
            published_at,
            records,
            signature: encode_hex(&signature),
        }
    }

    /// Verifies the bundle and returns the peer that signed it.
    ///
    /// Every rejection reason is distinct, because "we ignored a peer" and "a peer sent
    /// something forged" are different operational events.
    pub fn verify(&self) -> Result<PeerId, BundleError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BundleError::UnsupportedSchema(self.schema_version));
        }
        let peer = PeerId::from_hex(&self.peer).map_err(BundleError::Identity)?;
        let signature = decode_hex(&self.signature)
            .ok_or(BundleError::Identity(IdentityError::BadSignature))?;

        peer.verify(
            &signing_payload(
                self.schema_version,
                &self.peer,
                &self.vantage,
                self.sequence,
                self.published_at,
                &self.records,
            ),
            &signature,
        )
        .map_err(BundleError::Identity)?;

        Ok(peer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// A version this build cannot interpret. Refused whole rather than read partially.
    UnsupportedSchema(u16),
    Identity(IdentityError),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::UnsupportedSchema(v) => {
                write!(f, "unsupported federation schema version {v}")
            }
            BundleError::Identity(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BundleError {}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::topology::evidence::{Confidence, EvidenceSource, Fact};

    fn sample() -> Vec<TopologyEvidence> {
        vec![TopologyEvidence::new(
            Fact::Network {
                prefix: "192.168.51.0/24".parse().unwrap(),
            },
            EvidenceSource::InterfaceAddress,
            Confidence::Observed,
            "br0",
        )]
    }

    #[test]
    fn a_published_bundle_verifies_as_its_author() {
        let key = PeerKey::generate();
        let bundle = EvidenceBundle::publish(&key, "br0", 1, &sample());
        assert_eq!(bundle.verify().expect("verifies"), key.id());
        assert_eq!(bundle.vantage, "br0");
        assert_eq!(bundle.records.len(), 1);
    }

    #[test]
    fn a_bundle_survives_a_json_round_trip_through_a_relay() {
        // A relay forwards bytes it cannot read; the signature must still verify after the
        // bundle has been parsed and re-encoded on the way.
        let key = PeerKey::generate();
        let bundle = EvidenceBundle::publish(&key, "br0", 3, &sample());
        let relayed: EvidenceBundle =
            serde_json::from_str(&serde_json::to_string(&bundle).unwrap()).unwrap();
        assert_eq!(relayed.verify().expect("verifies"), key.id());
    }

    #[test]
    fn altering_any_field_invalidates_the_signature() {
        let key = PeerKey::generate();
        let original = EvidenceBundle::publish(&key, "br0", 5, &sample());

        let mut edited = original.clone();
        edited.vantage = "eth9".to_string();
        assert!(edited.verify().is_err(), "vantage");

        let mut edited = original.clone();
        edited.sequence += 1;
        assert!(edited.verify().is_err(), "sequence");

        let mut edited = original.clone();
        edited.published_at += 1;
        assert!(edited.verify().is_err(), "timestamp");

        // The case that matters most: a relay rewriting a prefix to point elsewhere.
        let mut edited = original.clone();
        edited.records[0] = WireEvidence::from_evidence(&TopologyEvidence::new(
            Fact::Network {
                prefix: "10.0.0.0/8".parse().unwrap(),
            },
            EvidenceSource::InterfaceAddress,
            Confidence::Observed,
            "br0",
        ))
        .expect("representable");
        assert!(edited.verify().is_err(), "records");

        let mut edited = original.clone();
        edited.records.clear();
        assert!(edited.verify().is_err(), "record removal");
    }

    #[test]
    fn a_bundle_cannot_be_reattributed_to_another_peer() {
        // Swapping the peer field must not let one peer's evidence be presented as
        // another's, which is how a relay would launder a claim.
        let author = PeerKey::generate();
        let impostor = PeerKey::generate();

        let mut bundle = EvidenceBundle::publish(&author, "br0", 1, &sample());
        bundle.peer = impostor.id().to_hex();
        assert_eq!(
            bundle.verify(),
            Err(BundleError::Identity(IdentityError::BadSignature))
        );
    }

    #[test]
    fn an_unsupported_schema_is_refused_whole() {
        let key = PeerKey::generate();
        let mut bundle = EvidenceBundle::publish(&key, "br0", 1, &sample());
        bundle.schema_version = SCHEMA_VERSION + 1;
        assert_eq!(
            bundle.verify(),
            Err(BundleError::UnsupportedSchema(SCHEMA_VERSION + 1))
        );
    }

    #[test]
    fn hostile_identity_and_signature_text_is_rejected_rather_than_panicking() {
        // Both fields are parsed straight off the wire, before anything is verified. A
        // peer sending multi-byte characters where hex belongs must be refused, not crash
        // the receiver -- which is a denial of service on every peer it can reach.
        let key = PeerKey::generate();
        let base = EvidenceBundle::publish(&key, "br0", 1, &sample());

        let hostile = [
            "🔑".to_string(),
            "🔑".repeat(32),
            "é".repeat(64),
            "\u{0}".repeat(128),
            "ff".repeat(31) + "🔑",
            "ff".repeat(63) + "é",
            "\u{200b}".to_string(),
            String::new(),
            "not hex at all".to_string(),
        ];

        for text in &hostile {
            let mut bundle = base.clone();
            bundle.peer = text.clone();
            assert!(bundle.verify().is_err(), "peer {text:?}");

            let mut bundle = base.clone();
            bundle.signature = text.clone();
            assert!(bundle.verify().is_err(), "signature {text:?}");

            // And a vantage of arbitrary bytes must simply fail verification, since it is
            // covered by the signature.
            let mut bundle = base.clone();
            bundle.vantage = text.clone();
            assert!(bundle.verify().is_err(), "vantage {text:?}");
        }
    }

    #[test]
    fn a_malformed_signature_is_rejected() {
        let key = PeerKey::generate();
        let mut bundle = EvidenceBundle::publish(&key, "br0", 1, &sample());
        bundle.signature = "not hex".to_string();
        assert!(bundle.verify().is_err());

        bundle.signature = encode_hex(&[0u8; 64]);
        assert!(bundle.verify().is_err());
    }
}
