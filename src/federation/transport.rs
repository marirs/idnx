//! The peer-to-peer protocol, over any byte stream.
//!
//! Deliberately generic over the stream rather than tied to TCP. A peer inside a NAT dials
//! out to a relay and a peer on the same link is reached directly, and both are the same
//! conversation; making the protocol depend on how the bytes arrive would mean two
//! implementations and two sets of bugs.
//!
//! Framing is a 4-byte big-endian length followed by that many bytes. The length is checked
//! against the limit *before* a buffer is reserved, so a peer claiming four gigabytes costs
//! one comparison rather than four gigabytes.
//!
//! Exactly one message crosses in the clear: the handshake, which cannot be encrypted
//! because it is what establishes the key. Everything after it -- every bundle, every
//! acknowledgement -- is sealed, so a relay forwarding the frames learns nothing but their
//! size and timing.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::bundle::EvidenceBundle;
use super::identity::{PeerId, PeerKey, decode_hex, encode_hex};
use super::limits::{
    LimitError, MAX_ENVELOPE_BYTES, MAX_RECORDS, MAX_TEXT_BYTES, MAX_VANTAGE_BYTES,
    check_frame_length, check_record_count, check_text,
};
use super::session::{Handshake, Session, SessionError, SessionOffer};

/// Associated data on every sealed frame, so a frame from one protocol version or purpose
/// cannot be replayed into another.
const FRAME_CONTEXT: &[u8] = b"idnx-federation-frame-v1";

/// The cleartext handshake, in wire form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireHandshake {
    pub peer: String,
    pub ephemeral: String,
    pub signature: String,
}

impl WireHandshake {
    fn from_handshake(handshake: &Handshake) -> Self {
        Self {
            peer: handshake.peer.to_hex(),
            ephemeral: encode_hex(&handshake.ephemeral),
            signature: encode_hex(&handshake.signature),
        }
    }

    fn to_handshake(&self) -> Result<Handshake, TransportError> {
        let peer = PeerId::from_hex(&self.peer).map_err(|_| TransportError::Malformed("peer"))?;
        let ephemeral: [u8; 32] = decode_hex(&self.ephemeral)
            .and_then(|b| b.try_into().ok())
            .ok_or(TransportError::Malformed("ephemeral key"))?;
        let signature: [u8; 64] = decode_hex(&self.signature)
            .and_then(|b| b.try_into().ok())
            .ok_or(TransportError::Malformed("signature"))?;

        Ok(Handshake {
            peer,
            ephemeral,
            signature,
        })
    }
}

/// What peers say to each other once the session is up. Always sealed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "message", rename_all = "snake_case")]
pub enum Message {
    /// Evidence one peer observed.
    Bundle { bundle: EvidenceBundle },
    /// Confirms a bundle was accepted, by sequence and digest.
    ///
    /// The digest is what makes resend idempotent in the sender's own bookkeeping: a
    /// sequence alone cannot distinguish the bundle that was acknowledged from a different
    /// one published under the same number after a crash.
    Ack { sequence: u64, digest: String },
    /// Rejects a bundle, with the reason. Sent rather than staying silent, so a peer whose
    /// evidence is being discarded finds out why instead of resending forever.
    Reject { sequence: u64, reason: String },
    /// Nothing further to send for now.
    Idle,
}

/// A digest of a bundle, for acknowledgements.
pub fn bundle_digest(bundle: &EvidenceBundle) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(bundle.schema_version.to_be_bytes());
    hasher.update(bundle.peer.as_bytes());
    hasher.update(bundle.sequence.to_be_bytes());
    // The signature already covers every record, so hashing it covers them transitively
    // while keeping the digest cheap.
    hasher.update(bundle.signature.as_bytes());
    encode_hex(&hasher.finalize()[..16])
}

/// Reads one length-prefixed frame, refusing the length before allocating.
pub async fn read_frame<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Vec<u8>, TransportError> {
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;

    let claimed = u32::from_be_bytes(length) as usize;
    // Before the allocation, not after. This is the whole point of the check.
    check_frame_length(claimed, MAX_ENVELOPE_BYTES).map_err(TransportError::Limit)?;

    let mut payload = vec![0u8; claimed];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    Ok(payload)
}

/// Writes one length-prefixed frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    stream: &mut W,
    payload: &[u8],
) -> Result<(), TransportError> {
    check_frame_length(payload.len(), MAX_ENVELOPE_BYTES).map_err(TransportError::Limit)?;
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| TransportError::Io(e.to_string()))
}

/// Performs the handshake and returns the established session.
///
/// `expected` is the identity this machine paired with, when it knows one. Passing `None`
/// is first contact: the session is still encrypted and still bound to whoever answered,
/// but which peer that is has not been established, so the caller must confirm the
/// authentication code before trusting anything it sends.
pub async fn handshake<S>(
    stream: &mut S,
    key: &PeerKey,
    expected: Option<&PeerId>,
) -> Result<Session, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let offer = SessionOffer::new(key);
    let ours = serde_json::to_vec(&WireHandshake::from_handshake(offer.handshake()))
        .map_err(|_| TransportError::Malformed("handshake"))?;
    write_frame(stream, &ours).await?;

    let theirs = read_frame(stream).await?;
    let theirs: WireHandshake =
        serde_json::from_slice(&theirs).map_err(|_| TransportError::Malformed("handshake"))?;
    let theirs = theirs.to_handshake()?;

    // With no expectation, the peer authenticates itself to its own key: the session is
    // confidential and bound, but the operator has not yet said this is the right peer.
    let expected = expected.cloned().unwrap_or_else(|| theirs.peer.clone());
    offer
        .accept(&theirs, &expected)
        .map_err(TransportError::Session)
}

/// Sends one message, sealed.
pub async fn send<S>(
    stream: &mut S,
    session: &mut Session,
    message: &Message,
) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    let plaintext =
        serde_json::to_vec(message).map_err(|_| TransportError::Malformed("message"))?;
    let sealed = session
        .seal(&plaintext, FRAME_CONTEXT)
        .map_err(TransportError::Session)?;
    write_frame(stream, &sealed).await
}

/// Receives one message, checking its bounds before it becomes structured data.
pub async fn receive<S>(stream: &mut S, session: &Session) -> Result<Message, TransportError>
where
    S: AsyncRead + Unpin,
{
    let sealed = read_frame(stream).await?;
    let plaintext = session
        .open(&sealed, FRAME_CONTEXT)
        .map_err(TransportError::Session)?;

    let message: Message =
        serde_json::from_slice(&plaintext).map_err(|_| TransportError::Malformed("message"))?;
    check_message(&message)?;
    Ok(message)
}

/// Bounds every peer-controlled field before the message is acted on.
///
/// To be precise about when: the *frame length* is the only limit enforced before
/// allocation. Record counts and individual strings are checked here, after serde has
/// produced a value, because serde must see the bytes to produce one. That is sound only
/// because the frame cap already bounds the whole message at a megabyte -- so the worst a
/// peer can make this allocate is a megabyte, and these checks then reject anything that
/// fits inside it while still being unreasonable.
///
/// Every string in every fact is checked, not a chosen few. Hostnames, vendors,
/// descriptions, interface names, bridge identifiers, capability details and service
/// details are all peer-controlled and all end up in the graph.
fn check_message(message: &Message) -> Result<(), TransportError> {
    let Message::Bundle { bundle } = message else {
        return Ok(());
    };

    check_record_count(bundle.records.len()).map_err(TransportError::Limit)?;
    check_text("vantage", &bundle.vantage, MAX_VANTAGE_BYTES).map_err(TransportError::Limit)?;
    check_text("peer", &bundle.peer, MAX_TEXT_BYTES).map_err(TransportError::Limit)?;
    check_text("signature", &bundle.signature, MAX_TEXT_BYTES).map_err(TransportError::Limit)?;

    for record in &bundle.records {
        for (field, value) in record.text_fields() {
            // The vantage has a tighter bound than free text: it names an interface.
            let limit = if field.contains("vantage") {
                MAX_VANTAGE_BYTES
            } else {
                MAX_TEXT_BYTES
            };
            check_text(field, value, limit).map_err(TransportError::Limit)?;
        }
    }
    Ok(())
}

/// How long to wait before dialling again, growing with consecutive failures.
///
/// Capped, so a peer that is simply switched off is retried at a steady low rate rather
/// than never. The growth exists so a relay that is down does not receive a connection
/// attempt every second from every peer that wants it.
pub fn reconnect_delay(consecutive_failures: u32) -> std::time::Duration {
    const BASE_MS: u64 = 500;
    const CEILING_MS: u64 = 60_000;

    let exponent = consecutive_failures.min(8);
    let millis = BASE_MS.saturating_mul(1u64 << exponent).min(CEILING_MS);
    std::time::Duration::from_millis(millis)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Io(String),
    /// A field could not be parsed. Names the field, never the contents, which are
    /// attacker-controlled and would end up in a log.
    Malformed(&'static str),
    Limit(LimitError),
    Session(SessionError),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "{e}"),
            TransportError::Malformed(what) => write!(f, "malformed {what}"),
            TransportError::Limit(e) => write!(f, "{e}"),
            TransportError::Session(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// The record count limit, re-exported for callers building bundles.
pub const RECORD_LIMIT: usize = MAX_RECORDS;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::topology::TopologyEvidence;
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

    /// Runs both ends of a handshake over an in-memory duplex.
    async fn connected() -> (
        (tokio::io::DuplexStream, Session, PeerKey),
        (tokio::io::DuplexStream, Session, PeerKey),
    ) {
        let a_key = PeerKey::generate();
        let b_key = PeerKey::generate();
        let (mut a_stream, mut b_stream) = tokio::io::duplex(1 << 20);

        let a_id = a_key.id();
        let b_id = b_key.id();
        let a_task = {
            let a_key = PeerKey::from_seed(&a_key.seed()).unwrap();
            tokio::spawn(async move {
                let session = handshake(&mut a_stream, &a_key, Some(&b_id)).await;
                (a_stream, session)
            })
        };
        let session_b = handshake(&mut b_stream, &b_key, Some(&a_id)).await;
        let (a_stream, session_a) = a_task.await.expect("a completes");

        (
            (a_stream, session_a.expect("a session"), a_key),
            (b_stream, session_b.expect("b session"), b_key),
        )
    }

    #[tokio::test]
    async fn two_peers_exchange_a_bundle_and_an_acknowledgement() {
        let ((mut a_stream, mut a_session, a_key), (mut b_stream, mut b_session, _)) =
            connected().await;

        let bundle = EvidenceBundle::publish(&a_key, "br0", 1, &evidence());
        let digest = bundle_digest(&bundle);
        send(
            &mut a_stream,
            &mut a_session,
            &Message::Bundle {
                bundle: bundle.clone(),
            },
        )
        .await
        .expect("sends");

        let Message::Bundle { bundle: received } =
            receive(&mut b_stream, &b_session).await.expect("receives")
        else {
            panic!("expected a bundle");
        };
        assert_eq!(received, bundle);
        assert_eq!(received.verify().expect("verifies"), a_key.id());

        send(
            &mut b_stream,
            &mut b_session,
            &Message::Ack {
                sequence: 1,
                digest: digest.clone(),
            },
        )
        .await
        .expect("sends");

        assert_eq!(
            receive(&mut a_stream, &a_session).await.expect("receives"),
            Message::Ack {
                sequence: 1,
                digest
            }
        );
    }

    #[tokio::test]
    async fn a_relay_watching_the_stream_sees_no_topology() {
        // The frames are what a relay forwards. Everything after the handshake must be
        // opaque to it.
        let a_key = PeerKey::generate();
        let b_key = PeerKey::generate();
        let (mut a_stream, mut b_stream) = tokio::io::duplex(1 << 20);

        let b_id = b_key.id();
        let a_id = a_key.id();
        let seed = a_key.seed();
        let a_task = tokio::spawn(async move {
            let key = PeerKey::from_seed(&seed).unwrap();
            let mut session = handshake(&mut a_stream, &key, Some(&b_id))
                .await
                .expect("a session");
            let bundle = EvidenceBundle::publish(&key, "br0", 1, &evidence());
            send(&mut a_stream, &mut session, &Message::Bundle { bundle })
                .await
                .expect("sends");
            a_stream
        });

        // B performs its side of the handshake, then reads the raw sealed frame.
        let _session = handshake(&mut b_stream, &b_key, Some(&a_id))
            .await
            .expect("b session");
        let sealed = read_frame(&mut b_stream).await.expect("frame");
        let _ = a_task.await;

        for needle in [b"192.168.51.0/24".as_slice(), b"br0".as_slice()] {
            assert!(
                !sealed.windows(needle.len()).any(|w| w == needle),
                "topology leaked into a frame a relay can read"
            );
        }
    }

    #[tokio::test]
    async fn a_handshake_from_the_wrong_peer_is_refused() {
        // A relay that answers in place of the paired peer must not establish a session.
        let a_key = PeerKey::generate();
        let relay_key = PeerKey::generate();
        let expected = PeerKey::generate().id();
        let (mut a_stream, mut relay_stream) = tokio::io::duplex(1 << 16);

        let relay_task = tokio::spawn(async move {
            let _ = handshake(&mut relay_stream, &relay_key, None).await;
        });
        let result = handshake(&mut a_stream, &a_key, Some(&expected)).await;
        let _ = relay_task.await;

        assert!(matches!(
            result,
            Err(TransportError::Session(SessionError::WrongPeer { .. }))
        ));
    }

    #[tokio::test]
    async fn an_absurd_frame_length_is_refused_without_allocating_it() {
        // Four gigabytes claimed, nothing sent. The read must fail on the length alone.
        let (mut writer, mut reader) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = writer.write_all(&u32::MAX.to_be_bytes()).await;
        });

        assert!(matches!(
            read_frame(&mut reader).await,
            Err(TransportError::Limit(LimitError::TooLarge { .. }))
        ));
    }

    #[tokio::test]
    async fn a_frame_that_is_not_from_this_session_is_refused() {
        let ((mut a_stream, mut a_session, _), (mut b_stream, _, _)) = connected().await;
        let ((_, _, _), (_, other_session, _)) = connected().await;

        send(&mut a_stream, &mut a_session, &Message::Idle)
            .await
            .expect("sends");
        assert!(matches!(
            receive(&mut b_stream, &other_session).await,
            Err(TransportError::Session(SessionError::Cipher))
        ));
    }

    #[test]
    fn a_bundle_declaring_too_many_records_is_refused() {
        let key = PeerKey::generate();
        let mut bundle = EvidenceBundle::publish(&key, "br0", 1, &evidence());
        let record = bundle.records[0].clone();
        bundle.records = vec![record; MAX_RECORDS + 1];

        assert!(matches!(
            check_message(&Message::Bundle { bundle }),
            Err(TransportError::Limit(LimitError::TooManyRecords { .. }))
        ));
    }

    #[test]
    fn a_bundle_with_an_overlong_field_is_refused() {
        let key = PeerKey::generate();
        let mut bundle = EvidenceBundle::publish(&key, "br0", 1, &evidence());
        bundle.vantage = "x".repeat(MAX_VANTAGE_BYTES + 1);

        assert!(matches!(
            check_message(&Message::Bundle { bundle }),
            Err(TransportError::Limit(LimitError::TextTooLong { .. }))
        ));
    }

    #[test]
    fn every_string_inside_a_fact_is_bounded_not_just_the_obvious_ones() {
        // Hostnames, vendors, descriptions, interface names, bridge identifiers and
        // capability details are all peer-controlled and all reach the graph. Checking
        // only the vantage and the detail left every one of them unbounded.
        use crate::topology::evidence::{Capability, DeviceKey};

        let device = DeviceKey::mac("02:00:5e:00:00:01");
        let overlong = "x".repeat(MAX_TEXT_BYTES + 1);
        let key = PeerKey::generate();

        let facts = [
            Fact::DeviceHostname {
                device: device.clone(),
                hostname: overlong.clone(),
            },
            Fact::DeviceVendor {
                device: device.clone(),
                vendor: overlong.clone(),
            },
            Fact::DeviceDescription {
                device: device.clone(),
                text: overlong.clone(),
            },
            Fact::InterfaceNetwork {
                interface: overlong.clone(),
                prefix: "10.0.0.0/8".parse().unwrap(),
            },
            Fact::BridgeLink {
                bridge_id: overlong.clone(),
                root_id: "root".to_string(),
                port: None,
            },
            Fact::DeviceCapability {
                device: device.clone(),
                capability: Capability::NatGateway,
                detail: Some(overlong.clone()),
            },
            Fact::Service {
                address: "10.0.0.1".parse().unwrap(),
                port: 80,
                protocol: "tcp",
                detail: Some(overlong.clone()),
            },
            Fact::OpaqueBoundary {
                device,
                why: overlong.clone(),
            },
            Fact::ResolvedAs {
                name: overlong,
                address: "10.0.0.1".parse().unwrap(),
            },
        ];

        for fact in facts {
            let record = TopologyEvidence::new(
                fact.clone(),
                EvidenceSource::ArpCache,
                Confidence::Observed,
                "br0",
            );
            let bundle = EvidenceBundle::publish(&key, "br0", 1, &[record]);
            assert!(
                matches!(
                    check_message(&Message::Bundle { bundle }),
                    Err(TransportError::Limit(LimitError::TextTooLong { .. }))
                ),
                "unbounded string in {fact:?}"
            );
        }
    }

    #[test]
    fn a_digest_identifies_one_bundle_and_not_another() {
        // A sequence number alone cannot tell the acknowledged bundle from a different one
        // published under the same number after a crash.
        let key = PeerKey::generate();
        let first = EvidenceBundle::publish(&key, "br0", 1, &evidence());
        let same = first.clone();
        let different = EvidenceBundle::publish(&key, "br0", 1, &[]);

        assert_eq!(bundle_digest(&first), bundle_digest(&same));
        assert_ne!(bundle_digest(&first), bundle_digest(&different));
    }

    #[test]
    fn reconnect_backoff_grows_and_then_holds() {
        // Growth so a relay that is down is not hammered; a ceiling so a peer that comes
        // back is noticed within a minute rather than never.
        let first = reconnect_delay(0);
        let later = reconnect_delay(4);
        assert!(later > first);
        assert_eq!(reconnect_delay(20), reconnect_delay(60));
        assert!(reconnect_delay(60) <= std::time::Duration::from_secs(60));
    }
}
