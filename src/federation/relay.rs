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
//! reorder envelopes — so the protocol tolerates all three: acknowledgements drive resend,
//! sequence numbers reject replays, and reapplying an already-accepted bundle is harmless.
//!
//! Mailbox names are derived from the two peer identities rather than chosen, so a peer
//! cannot claim someone else's mailbox by asking for it.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use super::identity::{PeerId, encode_hex};
use super::limits::{MAX_ENVELOPE_BYTES, check_frame_length};

/// Envelopes waiting for collection, per mailbox.
///
/// Bounded in both directions: a mailbox holds a limited number of envelopes and drops the
/// oldest when full, so a peer that never collects cannot make the relay grow without end.
#[derive(Debug, Default)]
pub struct RelayQueue {
    mailboxes: HashMap<String, Vec<Vec<u8>>>,
}

/// Envelopes held for one mailbox before the oldest is discarded.
pub const MAX_QUEUED_ENVELOPES: usize = 256;

impl RelayQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts an envelope for a mailbox.
    ///
    /// The contents are never inspected, only measured. Dropping the oldest rather than
    /// refusing the newest keeps a peer that has been offline from permanently blocking
    /// the one still publishing.
    pub fn deposit(&mut self, mailbox: &str, envelope: Vec<u8>) -> Result<(), RelayError> {
        check_frame_length(envelope.len(), MAX_ENVELOPE_BYTES).map_err(RelayError::Limit)?;

        let queue = self.mailboxes.entry(mailbox.to_string()).or_default();
        if queue.len() >= MAX_QUEUED_ENVELOPES {
            queue.remove(0);
        }
        queue.push(envelope);
        Ok(())
    }

    /// Takes everything waiting in a mailbox.
    pub fn collect(&mut self, mailbox: &str) -> Vec<Vec<u8>> {
        self.mailboxes.remove(mailbox).unwrap_or_default()
    }

    /// How many envelopes are waiting, for diagnostics.
    pub fn waiting(&self, mailbox: &str) -> usize {
        self.mailboxes.get(mailbox).map(Vec::len).unwrap_or(0)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    Limit(super::limits::LimitError),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Limit(e) => write!(f, "{e}"),
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

    #[test]
    fn envelopes_are_stored_verbatim_and_never_inspected() {
        // The relay's only legitimate operations are measure, hold and hand back.
        let mut relay = RelayQueue::new();
        let sealed = vec![0xde, 0xad, 0xbe, 0xef];
        relay.deposit("box", sealed.clone()).expect("accepts");
        assert_eq!(relay.collect("box"), vec![sealed]);
    }
}
