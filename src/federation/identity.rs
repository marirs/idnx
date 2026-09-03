//! Peer identity.
//!
//! A peer is its public key. There is no registry, no naming authority and nothing to
//! configure: the identity travels with every bundle a peer sends, and pairing is the act
//! of deciding to trust one particular key.
//!
//! Ed25519 rather than a shared secret, because the two make different promises. A MAC
//! proves only that someone holding the secret produced the bytes, which means either party
//! could have; a signature attributes a bundle to one key that no verifier can forge. When
//! evidence from another network is merged into a topology and reported as fact, being able
//! to say which peer asserted it -- and to have that survive being relayed through a third
//! party -- is the whole point.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// A peer's public identity: the key others verify its evidence against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerId(VerifyingKey);

impl PeerId {
    /// Parses the 64-character hex form carried on the wire.
    pub fn from_hex(text: &str) -> Result<Self, IdentityError> {
        let bytes = decode_hex(text).ok_or(IdentityError::Malformed)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::Malformed)?;
        VerifyingKey::from_bytes(&bytes)
            .map(PeerId)
            .map_err(|_| IdentityError::Malformed)
    }

    pub fn to_hex(&self) -> String {
        encode_hex(self.0.as_bytes())
    }

    /// Short form for display. Never used for comparison: a truncated key is not identity.
    pub fn short(&self) -> String {
        self.to_hex()[..16].to_string()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), IdentityError> {
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| IdentityError::BadSignature)?;
        self.0
            .verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| IdentityError::BadSignature)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short())
    }
}

/// A peer's own key, used to sign the evidence it publishes.
pub struct PeerKey(SigningKey);

impl PeerKey {
    /// Generates a fresh identity.
    pub fn generate() -> Self {
        PeerKey(SigningKey::generate(&mut rand_core::OsRng))
    }

    /// Restores an identity from its 32-byte seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, IdentityError> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| IdentityError::Malformed)?;
        Ok(PeerKey(SigningKey::from_bytes(&seed)))
    }

    /// The seed, for persisting an identity across runs.
    ///
    /// Secret: anything holding this can publish evidence as this peer.
    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn id(&self) -> PeerId {
        PeerId(self.0.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

impl fmt::Debug for PeerKey {
    /// Never prints the seed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerKey({})", self.id())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// Not a well-formed key or signature.
    Malformed,
    /// The signature does not match this key over these bytes.
    BadSignature,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::Malformed => f.write_str("malformed peer identity"),
            IdentityError::BadSignature => f.write_str("signature does not verify"),
        }
    }
}

impl std::error::Error for IdentityError {}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Decodes hex, over bytes rather than string slices.
///
/// Slicing a `&str` at arbitrary offsets panics when an offset lands inside a multi-byte
/// character, and this parses peer identities and signatures straight off the wire. A peer
/// sending an emoji where a key belongs must be rejected, not terminate the process.
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_round_trips_through_its_wire_form() {
        let key = PeerKey::generate();
        let id = key.id();
        let parsed = PeerId::from_hex(&id.to_hex()).expect("valid identity");
        assert_eq!(parsed, id);
        assert_eq!(id.to_hex().len(), 64);
    }

    #[test]
    fn a_key_restored_from_its_seed_is_the_same_peer() {
        // A peer that restarts must keep its identity, or every restart looks like a new
        // peer and its earlier evidence can no longer be attributed to it.
        let key = PeerKey::generate();
        let restored = PeerKey::from_seed(&key.seed()).expect("valid seed");
        assert_eq!(restored.id(), key.id());
    }

    #[test]
    fn a_signature_verifies_against_the_signing_peer_only() {
        let key = PeerKey::generate();
        let other = PeerKey::generate();
        let message = b"192.168.51.0/24 observed by this peer";

        let signature = key.sign(message);
        assert!(key.id().verify(message, &signature).is_ok());

        // Another peer cannot claim it. This is what a shared secret could not provide.
        assert_eq!(
            other.id().verify(message, &signature),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn altered_evidence_fails_verification() {
        let key = PeerKey::generate();
        let signature = key.sign(b"192.168.51.0/24");
        assert_eq!(
            key.id().verify(b"192.168.52.0/24", &signature),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn a_malformed_identity_is_rejected_rather_than_guessed() {
        assert_eq!(PeerId::from_hex(""), Err(IdentityError::Malformed));
        assert_eq!(PeerId::from_hex("zz"), Err(IdentityError::Malformed));
        assert_eq!(
            PeerId::from_hex(&"ab".repeat(16)),
            Err(IdentityError::Malformed)
        );
    }

    #[test]
    fn untrusted_identity_text_is_rejected_rather_than_panicking() {
        // These arrive straight off the wire. Slicing a &str at byte offsets panics when an
        // offset lands inside a multi-byte character, so a peer field of the right byte
        // length but the wrong content would have terminated the process.
        let hostile = [
            "🔑",                // 4 bytes, one character
            "🔑🔑🔑🔑🔑🔑🔑🔑",  // 32 bytes of emoji
            &"é".repeat(32),     // 64 bytes, 32 characters
            &"\u{0}".repeat(64), // NULs
            "café",
            &"🔒".repeat(16),
            "\u{200b}\u{200b}", // zero-width spaces
            &"ff".repeat(31),   // valid hex, wrong length
            &format!("{}{}", "ff".repeat(31), "🔑"),
        ];

        for text in hostile {
            // Neither may panic; both must simply refuse.
            assert!(decode_hex(text).is_none() || PeerId::from_hex(text).is_err());
            assert!(PeerId::from_hex(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn hex_decoding_accepts_only_hex() {
        assert_eq!(decode_hex("00ff"), Some(vec![0x00, 0xff]));
        assert_eq!(decode_hex("00FF"), Some(vec![0x00, 0xff]));
        assert_eq!(decode_hex(""), Some(Vec::new()));
        assert_eq!(decode_hex("0"), None, "odd length");
        assert_eq!(decode_hex("0g"), None);
        assert_eq!(decode_hex("-1"), None);
        // Round trip over every byte value.
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode_hex(&encode_hex(&all)), Some(all));
    }

    #[test]
    fn a_truncated_signature_is_rejected() {
        let key = PeerKey::generate();
        let signature = key.sign(b"x");
        assert_eq!(
            key.id().verify(b"x", &signature[..32]),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn a_debug_print_never_reveals_the_seed() {
        let key = PeerKey::generate();
        let printed = format!("{key:?}");
        assert!(!printed.contains(&encode_hex(&key.seed())));
        assert!(printed.contains(&key.id().short()));
    }
}
