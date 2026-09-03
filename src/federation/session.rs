//! Authenticated, encrypted sessions between peers.
//!
//! Signatures establish authorship; they do nothing for confidentiality. A bundle carries a
//! network's hostnames, addresses, open ports and management interfaces, and it travels
//! through a relay neither peer controls. Signing it and sending it in clear would hand a
//! complete map of the far network to whoever runs the relay.
//!
//! The handshake is deliberately small. Each side sends an ephemeral X25519 public key
//! **signed by its Ed25519 identity**, which is what binds the encryption to the peer this
//! machine actually paired with -- an unsigned key exchange authenticates nothing and a
//! relay in the middle could substitute its own key for both sides. The shared secret is
//! ephemeral, so a later compromise of an identity key does not decrypt yesterday's
//! traffic.
//!
//! First pairing has nothing to check a key against, so the two ends derive a short
//! authentication code from both identities and the operator compares it out of band. That
//! is the one step no protocol can perform for them.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use super::identity::{IdentityError, PeerId, PeerKey, encode_hex};
use super::limits::{MAX_ENVELOPE_BYTES, check_frame_length};

/// Context string, so keys derived here can never collide with another protocol's.
const HKDF_INFO: &[u8] = b"idnx-federation-session-v1";

/// What one side sends to open a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    /// The sender's long-term identity.
    pub peer: PeerId,
    /// Ephemeral X25519 public key, 32 bytes.
    pub ephemeral: [u8; 32],
    /// Ed25519 signature over the ephemeral key, binding it to the identity.
    pub signature: [u8; 64],
}

impl Handshake {
    /// Verifies that this ephemeral key really was offered by the peer that signed it.
    pub fn verify(&self) -> Result<(), IdentityError> {
        self.peer
            .verify(&signed_ephemeral(&self.ephemeral), &self.signature)
    }
}

/// The bytes signed over an ephemeral key.
///
/// Domain-separated so a signature made here can never be replayed as a signature over an
/// evidence bundle, which is signed with the same identity key.
fn signed_ephemeral(ephemeral: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(HKDF_INFO.len() + 32);
    message.extend_from_slice(b"idnx-ephemeral-v1\n");
    message.extend_from_slice(ephemeral);
    message
}

/// One side of a session, before the peer's handshake has arrived.
pub struct SessionOffer {
    secret: StaticSecret,
    handshake: Handshake,
}

impl SessionOffer {
    /// Creates an ephemeral key and signs it with this peer's identity.
    pub fn new(key: &PeerKey) -> Self {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let ephemeral = PublicKey::from(&secret).to_bytes();
        let signature = key.sign(&signed_ephemeral(&ephemeral));

        Self {
            secret,
            handshake: Handshake {
                peer: key.id(),
                ephemeral,
                signature,
            },
        }
    }

    /// What to send to the other side.
    pub fn handshake(&self) -> &Handshake {
        &self.handshake
    }

    /// Completes the session against the peer's handshake.
    ///
    /// `expected` is the identity this machine paired with. Checking it here is what stops
    /// a relay completing the handshake as itself: without it, a session would be
    /// encrypted, authenticated, and with the wrong party.
    pub fn accept(self, theirs: &Handshake, expected: &PeerId) -> Result<Session, SessionError> {
        theirs.verify().map_err(SessionError::Identity)?;
        if theirs.peer != *expected {
            return Err(SessionError::WrongPeer {
                expected: expected.to_hex(),
                offered: theirs.peer.to_hex(),
            });
        }

        let shared = self
            .secret
            .diffie_hellman(&PublicKey::from(theirs.ephemeral));

        // Both sides must derive the same key, so the two ephemeral keys are ordered
        // rather than taken in send order, which differs between the two ends.
        let (first, second) = if self.handshake.ephemeral <= theirs.ephemeral {
            (self.handshake.ephemeral, theirs.ephemeral)
        } else {
            (theirs.ephemeral, self.handshake.ephemeral)
        };
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(&first);
        salt.extend_from_slice(&second);

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(HKDF_INFO, &mut key)
            .map_err(|_| SessionError::KeyDerivation)?;

        // Directional nonce prefixes, so the two ends never reuse a nonce under the same
        // key. Reuse in ChaCha20-Poly1305 loses both confidentiality and integrity.
        let we_are_first = self.handshake.ephemeral <= theirs.ephemeral;

        Ok(Session {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            peer: theirs.peer.clone(),
            send_prefix: if we_are_first { 0 } else { 1 },
            receive_prefix: if we_are_first { 1 } else { 0 },
            sent: 0,
            authentication_code: authentication_code(&self.handshake.peer, &theirs.peer),
        })
    }
}

/// An established session: an agreed key and the counters that keep nonces unique.
///
/// `Debug` never prints the key material.
pub struct Session {
    cipher: ChaCha20Poly1305,
    peer: PeerId,
    send_prefix: u8,
    receive_prefix: u8,
    sent: u64,
    authentication_code: String,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("peer", &self.peer)
            .field("sent", &self.sent)
            .finish_non_exhaustive()
    }
}

impl Session {
    pub fn peer(&self) -> &PeerId {
        &self.peer
    }

    /// Short code for the operator to compare out of band on first pairing.
    ///
    /// Identical on both ends when, and only when, each is talking to the identity it
    /// believes. Nothing in the protocol can substitute for a human comparing these: on
    /// first contact there is no prior key to check against.
    pub fn authentication_code(&self) -> &str {
        &self.authentication_code
    }

    /// Encrypts one message. Every call uses a fresh nonce.
    pub fn seal(&mut self, plaintext: &[u8], associated: &[u8]) -> Result<Vec<u8>, SessionError> {
        let counter = self.sent;
        self.sent = self
            .sent
            .checked_add(1)
            .ok_or(SessionError::CounterExhausted)?;

        let ciphertext = self
            .cipher
            .encrypt(
                &nonce(self.send_prefix, counter),
                Payload {
                    msg: plaintext,
                    aad: associated,
                },
            )
            .map_err(|_| SessionError::Cipher)?;

        // The counter travels with the message so the receiver can reconstruct the nonce
        // without assuming messages arrive in order.
        let mut framed = counter.to_be_bytes().to_vec();
        framed.extend_from_slice(&ciphertext);
        Ok(framed)
    }

    /// Decrypts one message, checking its size before allocating anything.
    pub fn open(&self, framed: &[u8], associated: &[u8]) -> Result<Vec<u8>, SessionError> {
        check_frame_length(framed.len(), MAX_ENVELOPE_BYTES).map_err(SessionError::Limit)?;
        if framed.len() < 8 {
            return Err(SessionError::Cipher);
        }
        let (counter, ciphertext) = framed.split_at(8);
        let counter = u64::from_be_bytes(counter.try_into().expect("checked above"));

        self.cipher
            .decrypt(
                &nonce(self.receive_prefix, counter),
                Payload {
                    msg: ciphertext,
                    aad: associated,
                },
            )
            .map_err(|_| SessionError::Cipher)
    }
}

/// Builds a nonce from a direction prefix and a counter.
fn nonce(prefix: u8, counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[0] = prefix;
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&bytes)
}

/// A short code derived from both identities, for the operator to compare.
///
/// Order-independent, so both ends show the same digits regardless of who dialled.
fn authentication_code(a: &PeerId, b: &PeerId) -> String {
    use sha2::Digest;

    let (first, second) = if a.to_hex() <= b.to_hex() {
        (a.to_hex(), b.to_hex())
    } else {
        (b.to_hex(), a.to_hex())
    };
    let digest = Sha256::new()
        .chain_update(b"idnx-pairing-code-v1")
        .chain_update(first.as_bytes())
        .chain_update(second.as_bytes())
        .finalize();

    // Six digits, grouped. Short enough to read aloud, long enough that guessing one is
    // not worth attempting against a pairing window a human is watching.
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{:03}-{:03}", value / 1000, value % 1000)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    Identity(IdentityError),
    /// The handshake was valid but belongs to a different peer than the one expected.
    WrongPeer {
        expected: String,
        offered: String,
    },
    KeyDerivation,
    /// Encryption or decryption failed. Deliberately undetailed: distinguishing a bad tag
    /// from bad padding is how padding oracles are built.
    Cipher,
    Limit(super::limits::LimitError),
    /// 2^64 messages on one session. Unreachable in practice; refused rather than wrapped,
    /// because wrapping would reuse a nonce.
    CounterExhausted,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Identity(e) => write!(f, "{e}"),
            SessionError::WrongPeer { expected, offered } => write!(
                f,
                "handshake is from peer {} but {} was expected",
                &offered[..offered.len().min(16)],
                &expected[..expected.len().min(16)]
            ),
            SessionError::KeyDerivation => f.write_str("session key derivation failed"),
            SessionError::Cipher => f.write_str("message could not be decrypted"),
            SessionError::Limit(e) => write!(f, "{e}"),
            SessionError::CounterExhausted => f.write_str("session message counter exhausted"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Hex form of a handshake's ephemeral key, for transport encodings.
pub fn ephemeral_hex(handshake: &Handshake) -> String {
    encode_hex(&handshake.ephemeral)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Session, Session) {
        let a_key = PeerKey::generate();
        let b_key = PeerKey::generate();

        let a = SessionOffer::new(&a_key);
        let b = SessionOffer::new(&b_key);
        let a_handshake = a.handshake().clone();
        let b_handshake = b.handshake().clone();

        (
            a.accept(&b_handshake, &b_key.id()).expect("a completes"),
            b.accept(&a_handshake, &a_key.id()).expect("b completes"),
        )
    }

    #[test]
    fn both_ends_agree_on_a_key_and_can_talk_in_both_directions() {
        let (mut a, mut b) = pair();

        let sealed = a.seal(b"192.168.51.0/24", b"bundle").expect("seals");
        assert_eq!(
            b.open(&sealed, b"bundle").expect("opens"),
            b"192.168.51.0/24"
        );

        let sealed = b.seal(b"ack", b"bundle").expect("seals");
        assert_eq!(a.open(&sealed, b"bundle").expect("opens"), b"ack");
    }

    #[test]
    fn a_relay_cannot_read_what_passes_through_it() {
        // The reason encryption is here at all: a relay forwards these bytes and must not
        // learn the far network's topology from them.
        let (mut a, _b) = pair();
        let secret = b"sensor-09 at 192.168.51.9, ssh open";
        let sealed = a.seal(secret, b"bundle").expect("seals");

        assert!(
            !sealed.windows(secret.len()).any(|w| w == secret),
            "plaintext must not appear in the ciphertext"
        );
        assert!(!sealed.windows(9).any(|w| w == b"sensor-09"));
        assert!(!sealed.windows(12).any(|w| w == b"192.168.51.9"));
    }

    #[test]
    fn a_third_party_cannot_decrypt_the_session() {
        let (mut a, _b) = pair();
        let (_c, d) = pair();
        let sealed = a.seal(b"topology", b"bundle").expect("seals");
        assert_eq!(d.open(&sealed, b"bundle"), Err(SessionError::Cipher));
    }

    #[test]
    fn an_unsigned_or_substituted_ephemeral_key_is_refused() {
        // Without the signature binding the ephemeral key to an identity, a relay in the
        // middle substitutes its own key for both sides and reads everything.
        let a_key = PeerKey::generate();
        let b_key = PeerKey::generate();
        let relay_key = PeerKey::generate();

        let a = SessionOffer::new(&a_key);
        let relay = SessionOffer::new(&relay_key);

        // The relay offers its own handshake while A expects B.
        assert_eq!(
            a.accept(relay.handshake(), &b_key.id()).unwrap_err(),
            SessionError::WrongPeer {
                expected: b_key.id().to_hex(),
                offered: relay_key.id().to_hex(),
            }
        );
    }

    #[test]
    fn a_forged_signature_over_an_ephemeral_key_is_refused() {
        let a_key = PeerKey::generate();
        let b_key = PeerKey::generate();

        let a = SessionOffer::new(&a_key);
        let mut forged = SessionOffer::new(&b_key).handshake().clone();
        forged.ephemeral[0] ^= 0xff;

        assert_eq!(
            a.accept(&forged, &b_key.id()).unwrap_err(),
            SessionError::Identity(IdentityError::BadSignature)
        );
    }

    #[test]
    fn a_tampered_message_or_context_is_refused() {
        let (mut a, b) = pair();
        let sealed = a.seal(b"topology", b"bundle").expect("seals");

        let mut edited = sealed.clone();
        let last = edited.len() - 1;
        edited[last] ^= 0x01;
        assert_eq!(b.open(&edited, b"bundle"), Err(SessionError::Cipher));

        // Associated data is authenticated but not encrypted: changing it must still fail.
        assert_eq!(b.open(&sealed, b"other"), Err(SessionError::Cipher));
    }

    #[test]
    fn every_message_uses_a_fresh_nonce() {
        // Nonce reuse under ChaCha20-Poly1305 loses confidentiality and integrity both.
        let (mut a, b) = pair();
        let first = a.seal(b"same", b"ctx").expect("seals");
        let second = a.seal(b"same", b"ctx").expect("seals");

        assert_ne!(
            first, second,
            "identical plaintext must not produce identical bytes"
        );
        assert_eq!(b.open(&first, b"ctx").expect("opens"), b"same");
        assert_eq!(b.open(&second, b"ctx").expect("opens"), b"same");
    }

    #[test]
    fn the_two_directions_never_share_a_nonce() {
        // Both ends hold the same key, so without direction prefixes their first messages
        // would use the same nonce.
        let (mut a, mut b) = pair();
        let from_a = a.seal(b"x", b"ctx").expect("seals");
        let from_b = b.seal(b"x", b"ctx").expect("seals");
        assert_ne!(from_a, from_b);

        // And a message must not verify when replayed back at its own sender.
        assert_eq!(a.open(&from_a, b"ctx"), Err(SessionError::Cipher));
    }

    #[test]
    fn an_oversized_frame_is_refused_before_decryption() {
        let (_a, b) = pair();
        let huge = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        assert!(matches!(b.open(&huge, b"ctx"), Err(SessionError::Limit(_))));
    }

    #[test]
    fn a_truncated_frame_is_refused() {
        let (_a, b) = pair();
        assert_eq!(b.open(&[], b"ctx"), Err(SessionError::Cipher));
        assert_eq!(b.open(&[0u8; 4], b"ctx"), Err(SessionError::Cipher));
    }

    #[test]
    fn both_ends_show_the_same_authentication_code() {
        // What the operator compares on first pairing, when there is no prior key to check
        // the peer against.
        let (a, b) = pair();
        assert_eq!(a.authentication_code(), b.authentication_code());
        assert_eq!(a.authentication_code().len(), 7, "nnn-nnn");

        // A different pair of identities must show a different code, or comparing it
        // proves nothing.
        let (c, _d) = pair();
        assert_ne!(a.authentication_code(), c.authentication_code());
    }

    #[test]
    fn the_authentication_code_does_not_depend_on_who_dialled() {
        let a = PeerKey::generate().id();
        let b = PeerKey::generate().id();
        assert_eq!(authentication_code(&a, &b), authentication_code(&b, &a));
    }

    #[test]
    fn an_ephemeral_signature_cannot_be_replayed_as_a_bundle_signature() {
        // Both are made with the same identity key, so they must be domain-separated.
        let key = PeerKey::generate();
        let offer = SessionOffer::new(&key);
        let handshake = offer.handshake();

        // The signature verifies over the domain-separated message and nothing else.
        assert!(handshake.verify().is_ok());
        assert!(
            key.id()
                .verify(&handshake.ephemeral, &handshake.signature)
                .is_err(),
            "must not verify over the bare ephemeral key"
        );
    }
}
