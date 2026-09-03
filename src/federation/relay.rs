//! Store-and-forward relay for peers that cannot be reached directly.
//!
//! A peer inside a NAT cannot be dialled. Both ends therefore dial *out* to a relay, which
//! holds envelopes for a mailbox until the other side collects them. That is the whole of
//! its job.
//!
//! The relay is explicitly not trusted. It sees a mailbox name, an envelope size and a
//! delivery time; it cannot read an envelope, because the session key was established
//! between the two peers and the relay was never party to it. It cannot forge one either,
//! since a bundle carries its author's signature. What it *can* do is drop, delay or
//! reorder envelopes -- so the protocol tolerates all three: acknowledgements drive resend,
//! sequence numbers reject replays, and reapplying an already-accepted bundle is harmless.
//!
//! Mailbox names are never sent by a client. A peer proves which identity it holds by
//! signing a challenge, and the relay then computes the mailbox from that identity and the
//! one named as the counterpart. A client that could choose its own mailbox name could read
//! anyone's, which is the difference between a relay that cannot read traffic and one that
//! merely does not.
//!
//! Everything here is bounded: envelopes per mailbox, bytes in total, mailboxes in total,
//! and how long an envelope is held. A relay is reachable by anyone who knows its address,
//! and an unbounded queue reachable by anyone is a way to exhaust it.
//!
//! **This is a service someone has to run.** There is no default rendezvous host, so
//! cross-NAT federation is not automatic: an operator supplies a relay address, or deploys
//! one. Peers on the same link find each other without any of this.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::identity::{PeerId, encode_hex};
use super::limits::{MAX_ENVELOPE_BYTES, check_frame_length};

/// Envelopes held for one mailbox before the oldest is discarded.
pub const MAX_QUEUED_ENVELOPES: usize = 256;

/// Total bytes the relay will hold across every mailbox.
///
/// A relay is reachable by anyone who knows its address. Without a global ceiling, enough
/// mailboxes each under their own limit still add up to whatever memory the host has.
pub const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;

/// Distinct mailboxes held at once.
pub const MAX_MAILBOXES: usize = 4096;

/// How long an envelope is held before it is discarded.
///
/// A peer that has gone for good must not have its mail kept indefinitely, and evidence
/// this old describes a network that has almost certainly changed.
pub const ENVELOPE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// One held envelope.
#[derive(Debug, Clone)]
struct Held {
    bytes: Vec<u8>,
    deposited: Instant,
}

/// Envelopes waiting for collection, per mailbox.
///
/// Bounded four ways: envelopes per mailbox, total bytes, total mailboxes, and age. Each
/// closes a different way for a reachable service to be exhausted.
#[derive(Debug, Default)]
pub struct RelayQueue {
    mailboxes: HashMap<String, Vec<Held>>,
    total_bytes: usize,
}

impl RelayQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts an envelope for a mailbox.
    ///
    /// The contents are never inspected, only measured. Dropping the oldest of a full
    /// mailbox rather than refusing the newest keeps a peer that has been offline from
    /// permanently blocking the one still publishing.
    pub fn deposit(&mut self, mailbox: &str, envelope: Vec<u8>) -> Result<(), RelayError> {
        check_frame_length(envelope.len(), MAX_ENVELOPE_BYTES).map_err(RelayError::Limit)?;
        self.expire();

        if !self.mailboxes.contains_key(mailbox) && self.mailboxes.len() >= MAX_MAILBOXES {
            return Err(RelayError::Full("mailboxes"));
        }

        // Make room globally by discarding the oldest envelopes anywhere, rather than
        // refusing: a relay at capacity should shed history, not stop working.
        while self.total_bytes + envelope.len() > MAX_TOTAL_BYTES {
            if !self.discard_oldest() {
                return Err(RelayError::Full("bytes"));
            }
        }

        let size = envelope.len();
        let queue = self.mailboxes.entry(mailbox.to_string()).or_default();
        if queue.len() >= MAX_QUEUED_ENVELOPES {
            let dropped = queue.remove(0);
            self.total_bytes = self.total_bytes.saturating_sub(dropped.bytes.len());
        }
        queue.push(Held {
            bytes: envelope,
            deposited: Instant::now(),
        });
        self.total_bytes += size;
        Ok(())
    }

    /// Takes everything waiting in a mailbox.
    pub fn collect(&mut self, mailbox: &str) -> Vec<Vec<u8>> {
        self.expire();
        let held = self.mailboxes.remove(mailbox).unwrap_or_default();
        for envelope in &held {
            self.total_bytes = self.total_bytes.saturating_sub(envelope.bytes.len());
        }
        held.into_iter().map(|h| h.bytes).collect()
    }

    /// How many envelopes are waiting, for diagnostics.
    pub fn waiting(&self, mailbox: &str) -> usize {
        self.mailboxes.get(mailbox).map(Vec::len).unwrap_or(0)
    }

    /// Total bytes held, for diagnostics.
    pub fn held_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Discards envelopes older than the time-to-live.
    pub fn expire(&mut self) {
        self.expire_older_than(ENVELOPE_TTL);
    }

    fn expire_older_than(&mut self, ttl: Duration) {
        let now = Instant::now();
        self.mailboxes.retain(|_, queue| {
            queue.retain(|held| now.duration_since(held.deposited) < ttl);
            !queue.is_empty()
        });
        self.total_bytes = self
            .mailboxes
            .values()
            .flat_map(|q| q.iter())
            .map(|h| h.bytes.len())
            .sum();
    }

    /// Removes the single oldest envelope anywhere. False when there is nothing to remove.
    fn discard_oldest(&mut self) -> bool {
        let Some(oldest) = self
            .mailboxes
            .iter()
            .filter_map(|(name, queue)| queue.first().map(|h| (name.clone(), h.deposited)))
            .min_by_key(|(_, deposited)| *deposited)
            .map(|(name, _)| name)
        else {
            return false;
        };

        let Some(queue) = self.mailboxes.get_mut(&oldest) else {
            return false;
        };
        let dropped = queue.remove(0);
        self.total_bytes = self.total_bytes.saturating_sub(dropped.bytes.len());
        if queue.is_empty() {
            self.mailboxes.remove(&oldest);
        }
        true
    }
}

/// A relay queue shared between connections.
pub type SharedRelay = Arc<Mutex<RelayQueue>>;

pub fn shared() -> SharedRelay {
    Arc::new(Mutex::new(RelayQueue::new()))
}

/// The mailbox one peer deposits into for another.
///
/// Directional and derived, not chosen: `mailbox(a, b)` is where A leaves envelopes for B,
/// and only knowing both identities produces it. A peer cannot ask for a mailbox that is
/// not its own, because it never sends a name -- the relay computes it from the identities
/// on the connection.
pub fn mailbox(from: &PeerId, to: &PeerId) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::new()
        .chain_update(b"idnx-relay-mailbox-v1")
        .chain_update(from.to_hex().as_bytes())
        .chain_update(b"->")
        .chain_update(to.to_hex().as_bytes())
        .finalize();
    encode_hex(&digest[..16])
}

/// What a client asks the relay to do, once it has proved who it is.
///
/// No mailbox name appears here. The client names the *counterpart peer*, and the relay
/// derives the mailbox from that and the authenticated identity -- a client that could
/// choose a mailbox name could read anyone's.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum RelayRequest {
    /// Prove which identity this connection holds, by signing the relay's challenge.
    Authenticate { peer: String, signature: String },
    /// Leave a sealed envelope for a peer.
    Deposit { to: String, envelope: String },
    /// Take everything waiting from a peer.
    Collect { from: String },
}

/// What the relay answers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum RelayResponse {
    /// The challenge a client must sign. Sent first, before anything else is accepted.
    Challenge {
        nonce: String,
    },
    Authenticated,
    Accepted,
    Envelopes {
        envelopes: Vec<String>,
    },
    Refused {
        reason: String,
    },
}

/// The bytes a client signs to prove its identity.
///
/// Includes the relay's own nonce, so a signature captured from one connection cannot be
/// replayed onto another, and a domain tag so it can never be mistaken for a signature over
/// an evidence bundle or a session key.
pub fn challenge_payload(nonce: &[u8]) -> Vec<u8> {
    let mut payload = b"idnx-relay-challenge-v1\n".to_vec();
    payload.extend_from_slice(nonce);
    payload
}

/// One client connection's authentication state.
///
/// A connection starts unauthenticated and can do nothing but answer the challenge. That
/// ordering is the point: every later request is attributed to a proven identity.
#[derive(Debug)]
pub struct RelayClient {
    nonce: [u8; 32],
    identity: Option<PeerId>,
}

impl RelayClient {
    /// Starts a connection with a fresh challenge.
    pub fn new() -> Self {
        use rand_core::RngCore;

        let mut nonce = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        Self {
            nonce,
            identity: None,
        }
    }

    /// The challenge to send before anything else.
    pub fn challenge(&self) -> RelayResponse {
        RelayResponse::Challenge {
            nonce: encode_hex(&self.nonce),
        }
    }

    /// The identity this connection proved, if it has.
    pub fn identity(&self) -> Option<&PeerId> {
        self.identity.as_ref()
    }

    /// Handles one request against a queue.
    pub fn handle(&mut self, request: &RelayRequest, queue: &mut RelayQueue) -> RelayResponse {
        match request {
            RelayRequest::Authenticate { peer, signature } => {
                match self.authenticate(peer, signature) {
                    Ok(()) => RelayResponse::Authenticated,
                    Err(e) => RelayResponse::Refused {
                        reason: e.to_string(),
                    },
                }
            }
            RelayRequest::Deposit { to, envelope } => {
                let Some(identity) = self.identity.clone() else {
                    return refused(RelayError::Unauthenticated);
                };
                let (Ok(to), Some(bytes)) =
                    (PeerId::from_hex(to), super::identity::decode_hex(envelope))
                else {
                    return refused(RelayError::Unauthenticated);
                };
                // Derived here, from the proven identity. The client never names a mailbox.
                match queue.deposit(&mailbox(&identity, &to), bytes) {
                    Ok(()) => RelayResponse::Accepted,
                    Err(e) => refused(e),
                }
            }
            RelayRequest::Collect { from } => {
                let Some(identity) = self.identity.clone() else {
                    return refused(RelayError::Unauthenticated);
                };
                let Ok(from) = PeerId::from_hex(from) else {
                    return refused(RelayError::Unauthenticated);
                };
                RelayResponse::Envelopes {
                    envelopes: queue
                        .collect(&mailbox(&from, &identity))
                        .iter()
                        .map(|e| encode_hex(e))
                        .collect(),
                }
            }
        }
    }

    fn authenticate(&mut self, peer: &str, signature: &str) -> Result<(), RelayError> {
        let peer = PeerId::from_hex(peer).map_err(|_| RelayError::Unauthenticated)?;
        let signature =
            super::identity::decode_hex(signature).ok_or(RelayError::Unauthenticated)?;
        peer.verify(&challenge_payload(&self.nonce), &signature)
            .map_err(|_| RelayError::Unauthenticated)?;
        self.identity = Some(peer);
        Ok(())
    }
}

impl Default for RelayClient {
    fn default() -> Self {
        Self::new()
    }
}

fn refused(error: RelayError) -> RelayResponse {
    RelayResponse::Refused {
        reason: error.to_string(),
    }
}

/// How long a connection may stay silent before the relay closes it.
///
/// A relay is reachable by anyone; connections that open and then say nothing are how a
/// service runs out of file descriptors.
pub const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long one read may take.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    Limit(super::limits::LimitError),
    /// A global ceiling was reached. Names which one, so an operator can tell a relay that
    /// is genuinely busy from one being exhausted deliberately.
    Full(&'static str),
    /// The client did not prove it holds the identity it claimed.
    Unauthenticated,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Limit(e) => write!(f, "{e}"),
            RelayError::Full(what) => write!(f, "relay is at its {what} limit"),
            RelayError::Unauthenticated => {
                f.write_str("client did not prove it holds the identity it claimed")
            }
        }
    }
}

impl std::error::Error for RelayError {}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::identity::PeerKey;

    #[test]
    fn an_envelope_deposited_for_a_peer_is_collected_once() {
        let a = PeerKey::generate().id();
        let b = PeerKey::generate().id();
        let box_ab = mailbox(&a, &b);

        let mut relay = RelayQueue::new();
        relay.deposit(&box_ab, b"sealed".to_vec()).expect("accepts");
        assert_eq!(relay.waiting(&box_ab), 1);

        assert_eq!(relay.collect(&box_ab), vec![b"sealed".to_vec()]);
        assert_eq!(relay.waiting(&box_ab), 0);
        assert!(relay.collect(&box_ab).is_empty(), "collected only once");
    }

    #[test]
    fn mailboxes_are_directional_and_specific_to_a_pair() {
        // A peer must not be able to read what was left for someone else, and the reverse
        // direction is a different mailbox.
        let a = PeerKey::generate().id();
        let b = PeerKey::generate().id();
        let c = PeerKey::generate().id();

        assert_ne!(mailbox(&a, &b), mailbox(&b, &a), "directional");
        assert_ne!(mailbox(&a, &b), mailbox(&a, &c), "pair-specific");
        assert_eq!(mailbox(&a, &b), mailbox(&a, &b), "stable");
    }

    #[test]
    fn a_mailbox_name_reveals_neither_identity() {
        // The relay learns that two parties talk, not who they are.
        let a = PeerKey::generate().id();
        let b = PeerKey::generate().id();
        let name = mailbox(&a, &b);

        assert!(!name.contains(&a.to_hex()));
        assert!(!name.contains(&b.to_hex()));
        assert!(!a.to_hex().contains(&name));
    }

    #[test]
    fn an_oversized_envelope_is_refused() {
        let mut relay = RelayQueue::new();
        assert!(matches!(
            relay.deposit("box", vec![0u8; MAX_ENVELOPE_BYTES + 1]),
            Err(RelayError::Limit(_))
        ));
    }

    #[test]
    fn a_peer_that_never_collects_cannot_grow_the_relay_without_end() {
        let mut relay = RelayQueue::new();
        for i in 0..(MAX_QUEUED_ENVELOPES * 2) {
            relay
                .deposit("box", i.to_be_bytes().to_vec())
                .expect("accepts");
        }
        assert_eq!(relay.waiting("box"), MAX_QUEUED_ENVELOPES);

        // The oldest are dropped, so the peer still publishing is not blocked by one that
        // has been offline.
        let held = relay.collect("box");
        assert_eq!(held.len(), MAX_QUEUED_ENVELOPES);
        assert_eq!(
            held[held.len() - 1],
            (MAX_QUEUED_ENVELOPES * 2 - 1).to_be_bytes().to_vec()
        );
    }

    /// Authenticates a client the way a real connection does.
    fn authenticated(key: &PeerKey) -> RelayClient {
        let mut client = RelayClient::new();
        let RelayResponse::Challenge { nonce } = client.challenge() else {
            panic!("expected a challenge");
        };
        let nonce = super::super::identity::decode_hex(&nonce).expect("hex");
        let signature = key.sign(&challenge_payload(&nonce));

        let mut queue = RelayQueue::new();
        assert_eq!(
            client.handle(
                &RelayRequest::Authenticate {
                    peer: key.id().to_hex(),
                    signature: encode_hex(&signature),
                },
                &mut queue,
            ),
            RelayResponse::Authenticated
        );
        client
    }

    #[test]
    fn a_client_cannot_act_before_proving_who_it_is() {
        // Every request is attributed to a proven identity, or refused. Without this, the
        // mailbox a request touches would be whatever the client claimed.
        let mut queue = RelayQueue::new();
        let mut client = RelayClient::new();
        let other = PeerKey::generate().id().to_hex();

        assert!(matches!(
            client.handle(
                &RelayRequest::Deposit {
                    to: other.clone(),
                    envelope: encode_hex(b"sealed"),
                },
                &mut queue,
            ),
            RelayResponse::Refused { .. }
        ));
        assert!(matches!(
            client.handle(&RelayRequest::Collect { from: other }, &mut queue),
            RelayResponse::Refused { .. }
        ));
        assert!(client.identity().is_none());
    }

    #[test]
    fn a_signature_from_the_wrong_key_does_not_authenticate() {
        let mut queue = RelayQueue::new();
        let mut client = RelayClient::new();
        let RelayResponse::Challenge { nonce } = client.challenge() else {
            panic!("expected a challenge");
        };
        let nonce = super::super::identity::decode_hex(&nonce).expect("hex");

        // Signed by one key, claimed as another.
        let signer = PeerKey::generate();
        let claimed = PeerKey::generate();
        let signature = signer.sign(&challenge_payload(&nonce));

        assert!(matches!(
            client.handle(
                &RelayRequest::Authenticate {
                    peer: claimed.id().to_hex(),
                    signature: encode_hex(&signature),
                },
                &mut queue,
            ),
            RelayResponse::Refused { .. }
        ));
        assert!(client.identity().is_none());
    }

    #[test]
    fn a_challenge_signature_cannot_be_replayed_onto_another_connection() {
        // Each connection issues its own nonce, so a captured proof is worthless elsewhere.
        let key = PeerKey::generate();
        let first = RelayClient::new();
        let RelayResponse::Challenge { nonce } = first.challenge() else {
            panic!("expected a challenge");
        };
        let nonce = super::super::identity::decode_hex(&nonce).expect("hex");
        let signature = key.sign(&challenge_payload(&nonce));

        let mut second = RelayClient::new();
        let mut queue = RelayQueue::new();
        assert!(matches!(
            second.handle(
                &RelayRequest::Authenticate {
                    peer: key.id().to_hex(),
                    signature: encode_hex(&signature),
                },
                &mut queue,
            ),
            RelayResponse::Refused { .. }
        ));
    }

    #[test]
    fn a_client_cannot_read_a_mailbox_that_is_not_addressed_to_it() {
        // The whole reason mailbox names are derived rather than sent: B leaves mail for A,
        // and an eavesdropper who knows both identities still cannot ask for it.
        let a = PeerKey::generate();
        let b = PeerKey::generate();
        let intruder = PeerKey::generate();
        let mut queue = RelayQueue::new();

        let mut b_client = authenticated(&b);
        assert_eq!(
            b_client.handle(
                &RelayRequest::Deposit {
                    to: a.id().to_hex(),
                    envelope: encode_hex(b"sealed for A"),
                },
                &mut queue,
            ),
            RelayResponse::Accepted
        );

        // The intruder asks for exactly the same conversation.
        let mut intruder_client = authenticated(&intruder);
        assert_eq!(
            intruder_client.handle(
                &RelayRequest::Collect {
                    from: b.id().to_hex()
                },
                &mut queue
            ),
            RelayResponse::Envelopes { envelopes: vec![] }
        );

        // A collects it, because the relay derived the mailbox from A's proven identity.
        let mut a_client = authenticated(&a);
        assert_eq!(
            a_client.handle(
                &RelayRequest::Collect {
                    from: b.id().to_hex()
                },
                &mut queue
            ),
            RelayResponse::Envelopes {
                envelopes: vec![encode_hex(b"sealed for A")]
            }
        );
    }

    #[test]
    fn total_bytes_are_bounded_across_every_mailbox() {
        // Per-mailbox limits alone still add up to the whole host.
        let mut queue = RelayQueue::new();
        let envelope = vec![0u8; MAX_ENVELOPE_BYTES];

        for i in 0..((MAX_TOTAL_BYTES / MAX_ENVELOPE_BYTES) + 8) {
            let _ = queue.deposit(&format!("box-{i}"), envelope.clone());
        }
        assert!(
            queue.held_bytes() <= MAX_TOTAL_BYTES,
            "{} bytes held",
            queue.held_bytes()
        );
    }

    #[test]
    fn the_number_of_mailboxes_is_bounded() {
        let mut queue = RelayQueue::new();
        for i in 0..(MAX_MAILBOXES + 16) {
            let _ = queue.deposit(&format!("box-{i}"), vec![0u8; 8]);
        }
        assert!(matches!(
            queue.deposit("one-more", vec![0u8; 8]),
            Err(RelayError::Full("mailboxes"))
        ));
    }

    #[test]
    fn envelopes_expire_rather_than_being_held_for_ever() {
        // A peer that has gone for good must not have its mail kept indefinitely, and
        // evidence this old describes a network that has changed.
        let mut queue = RelayQueue::new();
        queue.deposit("box", b"old".to_vec()).expect("accepts");
        assert_eq!(queue.waiting("box"), 1);

        queue.expire_older_than(Duration::ZERO);
        assert_eq!(queue.waiting("box"), 0);
        assert_eq!(queue.held_bytes(), 0);
    }

    #[test]
    fn envelopes_are_stored_verbatim_and_never_inspected() {
        // The relay's only legitimate operations are measure, hold and hand back.
        let mut relay = RelayQueue::new();
        let sealed = vec![0xde, 0xad, 0xbe, 0xef];
        relay.deposit("box", sealed.clone()).expect("accepts");
        assert_eq!(relay.collect("box"), vec![sealed]);
    }
}
