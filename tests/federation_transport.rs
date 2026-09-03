//! Requires the `federation` feature, which is off by default: the subsystem is
//! unapproved and is not part of the shipped build.
#![cfg(feature = "federation")]

//! End-to-end federation across a relay, with the failures a real deployment produces.
//!
//! Peer A is on 192.168.1.0/24 and cannot see past the NAT. Peer B runs inside
//! 192.168.51.0/24 and observes it directly, plus a further subnet routed behind another
//! router there. Neither can dial the other, so both dial the relay, which holds sealed
//! envelopes it cannot read.
//!
//! The scenario is exercised through restart, replay, a dropped acknowledgement and a relay
//! reconnection, because each of those happens routinely and each has a different failure
//! mode: losing an identity, applying evidence twice, resending forever, and losing what
//! was in flight.

use std::collections::HashSet;
use std::path::PathBuf;

use idnx::federation::bundle::EvidenceBundle;
use idnx::federation::identity::PeerKey;
use idnx::federation::ledger::{PeerLedger, RejectReason};
use idnx::federation::relay::{RelayQueue, mailbox};
use idnx::federation::session::{Session, SessionOffer};
use idnx::federation::source::{Delivery, FederationSource};
use idnx::federation::store::FederationStore;
use idnx::federation::transport::{Message, bundle_digest};
use idnx::providers::ContinuousSource;
use idnx::topology::TopologyGraph;
use idnx::topology::evidence::{
    Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal, TopologyEvidence,
};
use idnx::topology::graph::DeviceCategory;

const B_VANTAGE: &str = "br0";

fn observed(fact: Fact, source: EvidenceSource) -> TopologyEvidence {
    TopologyEvidence::new(fact, source, Confidence::Observed, B_VANTAGE)
}

/// What A sees from its own side of the NAT: one network and a boundary.
fn what_a_observes() -> Vec<TopologyEvidence> {
    let boundary = DeviceKey::Mac("a0:ad:9f:e6:38:00".to_string());
    vec![
        TopologyEvidence::new(
            Fact::Network {
                prefix: "192.168.1.0/24".parse().unwrap(),
            },
            EvidenceSource::InterfaceAddress,
            Confidence::Observed,
            "en0",
        ),
        TopologyEvidence::new(
            Fact::DeviceAddress {
                device: boundary.clone(),
                address: "192.168.1.53".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
            "en0",
        ),
        TopologyEvidence::new(
            Fact::OpaqueBoundary {
                device: boundary,
                why: "performs NAT; nothing behind it is observable from this vantage".to_string(),
            },
            EvidenceSource::NatPmp,
            Confidence::Observed,
            "en0",
        ),
    ]
}

/// What B observes inside .51, including the subnet routed behind it.
fn what_b_observes() -> Vec<TopologyEvidence> {
    let router = DeviceKey::Mac("a0:ad:9f:e6:38:01".to_string());
    let inner = DeviceKey::Mac("60:cf:84:37:1b:70".to_string());
    let lan = "192.168.51.0/24".parse().unwrap();
    let behind = "10.77.0.0/24".parse().unwrap();

    vec![
        observed(
            Fact::Network { prefix: lan },
            EvidenceSource::InterfaceAddress,
        ),
        observed(
            Fact::InterfaceNetwork {
                interface: B_VANTAGE.to_string(),
                prefix: lan,
            },
            EvidenceSource::InterfaceAddress,
        ),
        observed(
            Fact::DeviceAddress {
                device: router.clone(),
                address: "192.168.51.1".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
        ),
        observed(
            Fact::DeviceRoleSignal {
                device: router,
                signal: RoleSignal::DefaultGateway,
            },
            EvidenceSource::DefaultGateway,
        ),
        observed(
            Fact::DeviceAddress {
                device: DeviceKey::Mac("02:00:5e:51:00:09".to_string()),
                address: "192.168.51.9".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
        ),
        observed(
            Fact::Network { prefix: behind },
            EvidenceSource::KernelRoute,
        ),
        observed(
            Fact::RoutesTo {
                device: inner.clone(),
                network: behind,
                next_hop: None,
            },
            EvidenceSource::KernelRoute,
        ),
        observed(
            Fact::DeviceRoleSignal {
                device: inner,
                signal: RoleSignal::KernelNextHop,
            },
            EvidenceSource::KernelRoute,
        ),
    ]
}

/// A unique state file per test, removed afterwards.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir()
            .join("idnx-federation-tests")
            .join(format!("{name}-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }

    fn path(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("tmp"));
    }
}

/// Establishes a session between two peers, as the transport handshake does.
fn session_pair(a: &PeerKey, b: &PeerKey) -> (Session, Session) {
    let a_offer = SessionOffer::new(a);
    let b_offer = SessionOffer::new(b);
    let a_handshake = a_offer.handshake().clone();
    let b_handshake = b_offer.handshake().clone();

    (
        a_offer.accept(&b_handshake, &b.id()).expect("a completes"),
        b_offer.accept(&a_handshake, &a.id()).expect("b completes"),
    )
}

/// B publishes a bundle and leaves it, sealed, in the relay mailbox for A.
fn publish_through_relay(
    relay: &mut RelayQueue,
    b_key: &PeerKey,
    b_session: &mut Session,
    a_key: &PeerKey,
    sequence: u64,
    evidence: &[TopologyEvidence],
) -> EvidenceBundle {
    let bundle = EvidenceBundle::publish(b_key, B_VANTAGE, sequence, evidence);
    let message = Message::Bundle {
        bundle: bundle.clone(),
    };
    let sealed = b_session
        .seal(&serde_json::to_vec(&message).unwrap(), b"frame")
        .expect("seals");
    relay
        .deposit(&mailbox(&b_key.id(), &a_key.id()), sealed)
        .expect("relay accepts");
    bundle
}

/// A collects from the relay, opens what it finds, and offers it to its ledger.
fn collect_at_a(
    relay: &mut RelayQueue,
    a_session: &Session,
    a_key: &PeerKey,
    b_key: &PeerKey,
    ledger: &mut PeerLedger,
    source: &FederationSource,
) -> Vec<Result<u64, RejectReason>> {
    let mut outcomes = Vec::new();
    for sealed in relay.collect(&mailbox(&b_key.id(), &a_key.id())) {
        let plaintext = a_session.open(&sealed, b"frame").expect("opens");
        let Message::Bundle { bundle } = serde_json::from_slice(&plaintext).expect("parses") else {
            continue;
        };
        match ledger.accept_immediately(&bundle) {
            Ok(accepted) => {
                let sequence = accepted.sequence;
                // Acknowledged only if the engine took it. Acknowledging evidence the run
                // declined would tell the peer it landed and stop it ever resending.
                match source.deliver(accepted) {
                    Delivery::Queued => outcomes.push(Ok(sequence)),
                    Delivery::Declined => outcomes.push(Err(RejectReason::Undecodable(vec![
                        "the run had already concluded".to_string(),
                    ]))),
                }
            }
            Err(reason) => {
                source.reject(bundle.verify().ok(), &bundle.vantage, &reason);
                outcomes.push(Err(reason));
            }
        }
    }
    outcomes
}

fn networks(graph: &TopologyGraph) -> HashSet<String> {
    graph.networks().iter().map(|n| n.to_string()).collect()
}

#[test]
fn a_peer_behind_a_nat_reaches_the_parent_through_a_relay() {
    let a_key = PeerKey::generate();
    let b_key = PeerKey::generate();
    let mut relay = RelayQueue::new();
    let (a_session, mut b_session) = session_pair(&a_key, &b_key);

    let mut ledger = PeerLedger::new();
    ledger.pair(b_key.id());
    let source = FederationSource::new();

    publish_through_relay(
        &mut relay,
        &b_key,
        &mut b_session,
        &a_key,
        1,
        &what_b_observes(),
    );

    let outcomes = collect_at_a(&mut relay, &a_session, &a_key, &b_key, &mut ledger, &source);
    assert_eq!(outcomes, vec![Ok(1)]);

    // A's graph: its own side, plus everything B could see.
    let mut graph = TopologyGraph::new();
    for record in what_a_observes() {
        graph.absorb(record);
    }
    for record in source.drain() {
        graph.absorb(record);
    }
    graph.finalize_roles();

    assert_eq!(
        networks(&graph),
        HashSet::from([
            "192.168.1.0/24".to_string(),
            "192.168.51.0/24".to_string(),
            "10.77.0.0/24".to_string(),
        ])
    );
    // And the boundary is still where A's own sight ends.
    assert_eq!(graph.devices_in(DeviceCategory::OpaqueBoundary).len(), 1);
}

#[test]
fn the_relay_cannot_read_what_it_forwards() {
    // The relay is not trusted. It holds bytes, measures them, and hands them back.
    let a_key = PeerKey::generate();
    let b_key = PeerKey::generate();
    let mut relay = RelayQueue::new();
    let (_a_session, mut b_session) = session_pair(&a_key, &b_key);

    publish_through_relay(
        &mut relay,
        &b_key,
        &mut b_session,
        &a_key,
        1,
        &what_b_observes(),
    );

    let box_name = mailbox(&b_key.id(), &a_key.id());
    let held = relay.collect(&box_name);
    assert_eq!(held.len(), 1);

    for needle in [
        b"192.168.51.0/24".as_slice(),
        b"10.77.0.0".as_slice(),
        b"192.168.51.9".as_slice(),
        B_VANTAGE.as_bytes(),
        b"default_gateway".as_slice(),
    ] {
        assert!(
            !held[0].windows(needle.len()).any(|w| w == needle),
            "the relay can read {:?}",
            String::from_utf8_lossy(needle)
        );
    }

    // Nor does the mailbox name give the peers away.
    assert!(!box_name.contains(&a_key.id().to_hex()));
    assert!(!box_name.contains(&b_key.id().to_hex()));
}

#[test]
fn a_replayed_envelope_is_rejected_rather_than_applied_twice() {
    // A relay can hand the same envelope over more than once, and an observer can capture
    // and re-deposit one. Applying it twice would double-count evidence.
    let a_key = PeerKey::generate();
    let b_key = PeerKey::generate();
    let mut relay = RelayQueue::new();
    let (a_session, mut b_session) = session_pair(&a_key, &b_key);

    let mut ledger = PeerLedger::new();
    ledger.pair(b_key.id());
    let source = FederationSource::new();

    let bundle = publish_through_relay(
        &mut relay,
        &b_key,
        &mut b_session,
        &a_key,
        1,
        &what_b_observes(),
    );
    assert_eq!(
        collect_at_a(&mut relay, &a_session, &a_key, &b_key, &mut ledger, &source),
        vec![Ok(1)]
    );

    // The same bundle, sealed again and re-deposited.
    let message = Message::Bundle { bundle };
    let sealed = b_session
        .seal(&serde_json::to_vec(&message).unwrap(), b"frame")
        .expect("seals");
    relay
        .deposit(&mailbox(&b_key.id(), &a_key.id()), sealed)
        .expect("accepts");

    let outcomes = collect_at_a(&mut relay, &a_session, &a_key, &b_key, &mut ledger, &source);
    assert_eq!(
        outcomes,
        vec![Err(RejectReason::Stale {
            seen: 1,
            offered: 1
        })]
    );

    // Reported, not silently discarded.
    let peer_outcomes = source.outcomes();
    assert_eq!(peer_outcomes.len(), 1);
    assert_eq!(peer_outcomes[0].bundles, 1);
    assert_eq!(peer_outcomes[0].rejected.len(), 1);
}

#[test]
fn identities_and_replay_protection_survive_a_restart_of_both_peers() {
    // A peer that forgets its identity looks like a new peer; one that forgets its cursor
    // accepts yesterday's captured bundle again.
    let a_state = Scratch::new("restart-a");
    let b_state = Scratch::new("restart-b");

    let (a_id, b_id, first_sequence) = {
        let a = FederationStore::open(a_state.path()).expect("opens");
        let mut b = FederationStore::open(b_state.path()).expect("opens");
        let sequence = b.next_sequence().expect("claims");
        (a.peer_id(), b.peer_id(), sequence)
    };
    assert_eq!(first_sequence, 1);

    // Both processes restart.
    let mut a = FederationStore::open(a_state.path()).expect("reopens");
    let mut b = FederationStore::open(b_state.path()).expect("reopens");

    assert_eq!(a.peer_id(), a_id, "A is the same peer after a restart");
    assert_eq!(b.peer_id(), b_id, "B is the same peer after a restart");
    assert_eq!(
        b.next_sequence().expect("claims"),
        2,
        "sequence must not repeat across a restart"
    );

    // A remembers what it already accepted, so a captured bundle cannot be replayed at it.
    a.pair(&b_id, "the sensor network").expect("pairs");
    a.record_inbound(&b_id, 1).expect("records");
    drop(a);

    let a = FederationStore::open(a_state.path()).expect("reopens");
    assert!(a.is_paired(&b_id));
    assert_eq!(a.inbound_cursor(&b_id), Some(1));
}

#[test]
fn a_dropped_acknowledgement_causes_a_resend_that_is_harmless() {
    // The acknowledgement is lost, so B cannot know A accepted the bundle and resends it.
    // The receiver must neither double-count it nor treat the resend as an attack.
    let a_key = PeerKey::generate();
    let b_key = PeerKey::generate();
    let mut relay = RelayQueue::new();
    let (a_session, mut b_session) = session_pair(&a_key, &b_key);

    let mut ledger = PeerLedger::new();
    ledger.pair(b_key.id());
    let source = FederationSource::new();

    let bundle = publish_through_relay(
        &mut relay,
        &b_key,
        &mut b_session,
        &a_key,
        1,
        &what_b_observes(),
    );
    let digest = bundle_digest(&bundle);
    assert_eq!(
        collect_at_a(&mut relay, &a_session, &a_key, &b_key, &mut ledger, &source),
        vec![Ok(1)]
    );

    // A acknowledges; the relay loses it. B still holds the bundle as unacknowledged.
    let _lost_ack = Message::Ack {
        sequence: 1,
        digest: digest.clone(),
    };

    // B resends the identical bundle at the same sequence.
    let message = Message::Bundle {
        bundle: bundle.clone(),
    };
    let sealed = b_session
        .seal(&serde_json::to_vec(&message).unwrap(), b"frame")
        .expect("seals");
    relay
        .deposit(&mailbox(&b_key.id(), &a_key.id()), sealed)
        .expect("accepts");

    let outcomes = collect_at_a(&mut relay, &a_session, &a_key, &b_key, &mut ledger, &source);
    assert_eq!(
        outcomes,
        vec![Err(RejectReason::Stale {
            seen: 1,
            offered: 1
        })],
        "the resend is refused as already applied, not applied twice"
    );

    // The digest lets B recognise the acknowledgement when it finally arrives, so the
    // resend loop terminates rather than continuing forever.
    assert_eq!(bundle_digest(&bundle), digest);

    // Exactly one application of the evidence.
    assert_eq!(source.outcomes()[0].bundles, 1);
}

#[test]
fn a_relay_reconnection_delivers_what_was_held_while_it_was_down() {
    // B keeps publishing while A cannot reach the relay. Nothing is lost, and the whole
    // backlog is applied in order when the connection returns.
    let a_key = PeerKey::generate();
    let b_key = PeerKey::generate();
    let mut relay = RelayQueue::new();
    let (a_session, mut b_session) = session_pair(&a_key, &b_key);

    let mut ledger = PeerLedger::new();
    ledger.pair(b_key.id());
    let source = FederationSource::new();

    // Three bundles published while A is offline.
    for (sequence, evidence) in [
        (1u64, what_b_observes()),
        (2, what_b_observes()),
        (3, what_b_observes()),
    ] {
        publish_through_relay(
            &mut relay,
            &b_key,
            &mut b_session,
            &a_key,
            sequence,
            &evidence,
        );
    }
    assert_eq!(relay.waiting(&mailbox(&b_key.id(), &a_key.id())), 3);

    // A reconnects and collects the backlog.
    let outcomes = collect_at_a(&mut relay, &a_session, &a_key, &b_key, &mut ledger, &source);
    assert_eq!(outcomes, vec![Ok(1), Ok(2), Ok(3)]);
    assert_eq!(source.outcomes()[0].bundles, 3);
}

#[test]
fn peer_evidence_arriving_late_still_extends_the_topology() {
    // Federation is a continuous source for the same reason capture is: a relay hands over
    // what it was holding when the connection succeeds, not when the engine asks. Evidence
    // landing as the run concludes must still be taken.
    let a_key = PeerKey::generate();
    let b_key = PeerKey::generate();
    let mut relay = RelayQueue::new();
    let (a_session, mut b_session) = session_pair(&a_key, &b_key);

    let mut ledger = PeerLedger::new();
    ledger.pair(b_key.id());
    let source = FederationSource::new();

    // The engine polls, finds nothing, and is about to converge.
    assert!(source.drain().is_empty());

    publish_through_relay(
        &mut relay,
        &b_key,
        &mut b_session,
        &a_key,
        1,
        &what_b_observes(),
    );
    collect_at_a(&mut relay, &a_session, &a_key, &b_key, &mut ledger, &source);

    // The final drain takes it, and it names two networks the engine has never traversed.
    let mut graph = TopologyGraph::new();
    for record in what_a_observes() {
        graph.absorb(record);
    }
    let late = source.finish();
    assert!(!late.is_empty());
    for record in late {
        graph.absorb(record);
    }
    graph.finalize_roles();

    assert!(networks(&graph).contains("192.168.51.0/24"));
    assert!(networks(&graph).contains("10.77.0.0/24"));
}

#[test]
fn an_unpaired_peer_reaching_the_relay_contributes_nothing() {
    // Anything can deposit into a mailbox it can name. Pairing, not reachability, is what
    // makes evidence count.
    let a_key = PeerKey::generate();
    let stranger = PeerKey::generate();
    let mut relay = RelayQueue::new();
    let (a_session, mut stranger_session) = session_pair(&a_key, &stranger);

    // A has paired with nobody.
    let mut ledger = PeerLedger::new();
    let source = FederationSource::new();

    publish_through_relay(
        &mut relay,
        &stranger,
        &mut stranger_session,
        &a_key,
        1,
        &what_b_observes(),
    );

    let outcomes = collect_at_a(
        &mut relay,
        &a_session,
        &a_key,
        &stranger,
        &mut ledger,
        &source,
    );
    assert_eq!(
        outcomes,
        vec![Err(RejectReason::NotPaired(stranger.id().to_hex()))]
    );
    assert!(source.drain().is_empty(), "nothing reaches the graph");
}
