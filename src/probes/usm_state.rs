//! Per-engine timeliness state, and the checks a response passes before it means anything.
//!
//! Two ideas run through this module.
//!
//! **Nothing counts until it is authenticated.** Engine boots and engine time arrive in the
//! clear, in a message anyone can send. Believing them before the digest verifies would let
//! an off-path attacker move a manager's clock estimate arbitrarily -- forward, so genuine
//! replies fall outside the window and the run reports a silent device; or backward, so
//! replayed messages become acceptable again. So the window is checked against state that
//! only authenticated messages have ever changed, and the state is updated only after a
//! complete response has validated.
//!
//! **Time in a run is measured, not read from a clock.** The estimate of an agent's engine
//! time is the value it last reported plus the monotonic time elapsed since. Using the wall
//! clock would make the window depend on NTP steps and daylight saving, which is exactly the
//! kind of failure that appears once a year and is indistinguishable from a wrong key.
//!
//! No sockets here: this is what the lifecycle consults, so each rule can be tested on its
//! own rather than through an exchange.

use std::net::SocketAddrV4;
use std::time::Instant;

use crate::probes::snmp::Oid;
use crate::probes::snmp_v3::{DecodedMessage, ProvisionalEngine, ReportReason};
use crate::probes::usm::SaltSource;

/// The window either side of an agent's clock in which a message is timely (RFC 3414 §3.2).
pub const TIME_WINDOW_SECONDS: i64 = 150;

/// The largest value engine boots may take before the engine must be re-keyed (RFC 3414).
pub const BOOTS_CEILING: u32 = 2_147_483_647;

/// What the timeliness rules make of one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timeliness {
    /// Inside the window, and not older than anything already accepted.
    InWindow,
    /// Outside the window: stale, replayed, or from an engine whose clock has moved. One
    /// resynchronisation is warranted; a loop of them is not.
    Outside,
    /// The engine has restarted, or reports a boots counter at its ceiling. RFC 3414 treats
    /// the ceiling as an engine that must be re-keyed rather than resynchronised.
    Unusable,
}

/// What this run knows about one authoritative engine.
///
/// Created from a discovery exchange, which is unauthenticated, and therefore starts
/// *unconfirmed*: the counters are a starting point for the first authenticated request and
/// nothing more. The first verified response confirms them, and only confirmed state is used
/// to reject anything.
pub struct EngineState {
    engine_id: Vec<u8>,
    boots: u32,
    /// The engine time reported at the last accepted synchronisation.
    synchronised_time: u32,
    /// When that value was recorded, by the monotonic clock.
    recorded_at: Instant,
    /// The highest engine time any accepted message has carried, which is what a replay has
    /// to beat.
    highest_time: u32,
    /// Whether an authenticated message has ever confirmed this state.
    confirmed: bool,
    salts: SaltSource,
}

impl EngineState {
    /// Takes the counters from a discovery exchange as a starting point.
    ///
    /// Unconfirmed by construction: `ProvisionalEngine` is what an unauthenticated exchange
    /// produced, and this type records that distinction rather than erasing it at the
    /// boundary.
    pub fn from_discovery(engine: &ProvisionalEngine) -> Result<Self, String> {
        Ok(Self {
            engine_id: engine.engine_id.clone(),
            boots: engine.boots,
            synchronised_time: engine.time,
            recorded_at: Instant::now(),
            highest_time: engine.time,
            confirmed: false,
            salts: SaltSource::new()?,
        })
    }

    pub fn engine_id(&self) -> &[u8] {
        &self.engine_id
    }

    pub fn boots(&self) -> u32 {
        self.boots
    }

    pub fn confirmed(&self) -> bool {
        self.confirmed
    }

    /// The engine's time as this run estimates it now.
    ///
    /// The last reported value plus the monotonic time since it was reported. Saturates
    /// rather than wrapping: a run long enough to overflow the counter has bigger problems
    /// than an inaccurate estimate, and wrapping would silently make old messages timely.
    pub fn estimated_time(&self) -> u32 {
        let elapsed = self.recorded_at.elapsed().as_secs();
        u32::try_from(u64::from(self.synchronised_time).saturating_add(elapsed))
            .unwrap_or(BOOTS_CEILING)
            .min(BOOTS_CEILING)
    }

    /// The next privacy salt for this engine.
    pub fn next_salt(&mut self) -> Result<[u8; 8], String> {
        self.salts.take_salt()
    }

    /// Whether a message's counters place it inside the window (RFC 3414 §3.2.7).
    ///
    /// Consulted only for messages that have already authenticated. An unauthenticated
    /// message's counters are an assertion by whoever sent it.
    pub fn timeliness(&self, message_boots: u32, message_time: u32) -> Timeliness {
        if message_boots == BOOTS_CEILING || self.boots == BOOTS_CEILING {
            return Timeliness::Unusable;
        }
        if message_boots < self.boots {
            // An engine's boot counter never goes backwards, so this is a replay from before
            // a restart, or another engine answering.
            return Timeliness::Outside;
        }
        if message_boots > self.boots {
            // A restart. Legitimate, and the counters must be resynchronised before anything
            // is accepted against them.
            return Timeliness::Outside;
        }
        let estimate = i64::from(self.estimated_time());
        let reported = i64::from(message_time);
        if reported < estimate - TIME_WINDOW_SECONDS {
            return Timeliness::Outside;
        }
        // A message from further ahead than the window is equally untimely: the agent's clock
        // and this estimate disagree by more than the protocol allows either way.
        if reported > estimate + TIME_WINDOW_SECONDS {
            return Timeliness::Outside;
        }
        Timeliness::InWindow
    }

    /// Records the counters of a message that has authenticated and validated completely.
    ///
    /// The only path that changes timeliness state. Advancing on anything less -- a Report
    /// that failed to verify, a response that authenticated but did not correlate -- would
    /// let an attacker who can send datagrams drag the window wherever they liked.
    pub fn absorb_authenticated(&mut self, message_boots: u32, message_time: u32) {
        if message_boots < self.boots {
            // An engine's boot counter never goes backwards. Something older than what is
            // already accepted cannot advance anything.
            return;
        }
        if message_boots > self.boots {
            // A restart: the time counter began again, so the previous high-water mark says
            // nothing about what is current.
            self.boots = message_boots;
            self.synchronised_time = message_time;
            self.recorded_at = Instant::now();
            self.highest_time = message_time;
        } else if message_time > self.highest_time {
            self.synchronised_time = message_time;
            self.recorded_at = Instant::now();
            self.highest_time = message_time;
        }
        self.confirmed = true;
    }
}

impl std::fmt::Debug for EngineState {
    /// Counters and shapes; no salt state and no key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineState")
            .field(
                "engine_id",
                &self
                    .engine_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
            .field("boots", &self.boots)
            .field("estimated_time", &self.estimated_time())
            .field("highest_time", &self.highest_time)
            .field("confirmed", &self.confirmed)
            .finish()
    }
}

/// Everything one exchange expects of the answer to it.
///
/// Held together rather than checked in pieces at call sites, because every one of these is
/// load-bearing and a missed check does not fail visibly: it accepts an answer to a
/// different question, from a different party, or from a different engine.
#[derive(Debug, Clone)]
pub struct Expectation {
    pub source: SocketAddrV4,
    pub engine_id: Vec<u8>,
    pub message_id: i32,
    pub request_id: i32,
    /// The PDU type an answer must carry. A Report is accepted separately, by the caller
    /// that knows whether one is expected here.
    pub pdu_type: u8,
    /// The OID a GET must answer about. `None` for GETNEXT, whose answer names the next one.
    pub oid: Option<Oid>,
}

/// Why a response was refused before anything in it was believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    WrongSource,
    WrongEngine,
    WrongMessageId,
    WrongRequestId,
    WrongPduType,
    WrongVarbind,
    NotAuthenticated,
    DigestFailed,
    Untimely,
    Malformed(String),
}

impl Refusal {
    /// What an operator is told. Never names a user, a key, or a passphrase.
    pub fn describe(&self) -> String {
        match self {
            Refusal::WrongSource => "the answer came from a different address".to_string(),
            Refusal::WrongEngine => {
                "the answer came from a different authoritative engine".to_string()
            }
            Refusal::WrongMessageId => "the answer did not carry the message id sent".to_string(),
            Refusal::WrongRequestId => "the answer did not carry the request id sent".to_string(),
            Refusal::WrongPduType => "the answer was not the PDU type expected".to_string(),
            Refusal::WrongVarbind => "the answer was about a different object".to_string(),
            Refusal::NotAuthenticated => {
                "the answer was not authenticated where authentication was required".to_string()
            }
            Refusal::DigestFailed => "the answer's digest did not verify".to_string(),
            Refusal::Untimely => "the answer fell outside the engine's time window".to_string(),
            Refusal::Malformed(why) => format!("the answer could not be read: {why}"),
        }
    }
}

/// Checks a decoded message against what was sent, before its contents mean anything.
///
/// Deliberately ordered cheapest-first, and deliberately complete: the digest is verified
/// only for a message that already claims to be the answer to this request, and the contents
/// are read only after that. Every step refuses rather than adjusts.
pub fn correlate(
    message: &DecodedMessage<'_>,
    from: SocketAddrV4,
    expectation: &Expectation,
) -> Result<(), Refusal> {
    if from != expectation.source {
        return Err(Refusal::WrongSource);
    }
    if message.message_id != expectation.message_id {
        return Err(Refusal::WrongMessageId);
    }
    if message.usm.engine_id != expectation.engine_id {
        return Err(Refusal::WrongEngine);
    }
    Ok(())
}

/// Checks the scoped PDU of an answer against what was asked.
///
/// Separate from [`correlate`] because it happens later: for an authPriv exchange these
/// fields do not exist until the message has authenticated and been decrypted, and reading
/// them earlier would mean trusting ciphertext.
pub fn correlate_scoped(
    scoped: &crate::probes::snmp_v3::ScopedPdu,
    engine_id: &[u8],
    expectation: &Expectation,
) -> Result<(), Refusal> {
    // The context an answer applies to must be the engine that answered. An answer scoped to
    // some other context describes a different agent's objects.
    if !scoped.context_engine_id.is_empty() && scoped.context_engine_id != engine_id {
        return Err(Refusal::WrongEngine);
    }
    if scoped.pdu.pdu_type != expectation.pdu_type {
        return Err(Refusal::WrongPduType);
    }
    if scoped.pdu.request_id != expectation.request_id {
        return Err(Refusal::WrongRequestId);
    }
    if let Some(expected) = &expectation.oid {
        // Exactly one varbind, about exactly the object asked for. The same rule the v2c
        // path applies: a value filed under a different OID answers a question nobody asked.
        if scoped.pdu.error_status == 0 {
            match scoped.pdu.varbinds.as_slice() {
                [(found, _)] if found == expected => {}
                _ => return Err(Refusal::WrongVarbind),
            }
        }
    }
    Ok(())
}

/// Checks that a Report is the single-varbind answer discovery asked for.
///
/// A Report carrying several varbinds, or one about anything other than
/// `usmStatsUnknownEngineIDs.0`, is not the discovery answer -- and its engine identifier
/// must not be taken as though it were.
pub fn discovery_report_reason(
    scoped: &crate::probes::snmp_v3::ScopedPdu,
    expectation: &Expectation,
) -> Result<ReportReason, Refusal> {
    if scoped.pdu.pdu_type != crate::probes::snmp_v3::PDU_REPORT {
        return Err(Refusal::WrongPduType);
    }
    if scoped.pdu.request_id != expectation.request_id {
        return Err(Refusal::WrongRequestId);
    }
    let [(oid, _)] = scoped.pdu.varbinds.as_slice() else {
        return Err(Refusal::WrongVarbind);
    };
    let reason = ReportReason::from_oid(oid);
    if !is_discovery_report(reason) {
        return Err(Refusal::WrongVarbind);
    }
    Ok(reason)
}

/// How many times an exchange may resynchronise before it is abandoned.
///
/// Exactly one. A `notInTimeWindow` Report is an ordinary event -- an agent restarts, a run
/// is long -- so one resynchronisation and one resend is right. A loop is not: an agent that
/// keeps reporting untimeliness after being resynchronised is either misbehaving or being
/// impersonated, and retrying against it turns one bad answer into unbounded traffic and an
/// unbounded number of chances to guess.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResyncBudget {
    spent: bool,
}

impl ResyncBudget {
    /// Consumes the single allowance, if it is still there.
    pub fn spend(&mut self) -> bool {
        if self.spent {
            return false;
        }
        self.spent = true;
        true
    }

    pub fn spent(&self) -> bool {
        self.spent
    }
}

/// Whether a Report is the one discovery asked for.
///
/// Discovery accepts exactly one answer: a correlated Report whose single varbind is
/// `usmStatsUnknownEngineIDs.0`. Any other Report -- unknown user, wrong digest, unsupported
/// level -- means the agent understood the message as something other than discovery, and
/// its engine identifier must not be taken from it as though it had.
pub fn is_discovery_report(reason: ReportReason) -> bool {
    matches!(reason, ReportReason::UnknownEngineId)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::snmp::{BerValue, PDU_GET_RESPONSE, SnmpPdu};
    use crate::probes::snmp_v3::ScopedPdu;

    const ENGINE: &[u8] = b"\x80\x00\x1f\x88\x80\x01";

    fn provisional(boots: u32, time: u32) -> ProvisionalEngine {
        ProvisionalEngine {
            engine_id: ENGINE.to_vec(),
            boots,
            time,
            reason: Some(ReportReason::UnknownEngineId),
        }
    }

    fn state(boots: u32, time: u32) -> EngineState {
        EngineState::from_discovery(&provisional(boots, time)).expect("randomness is available")
    }

    fn expectation() -> Expectation {
        Expectation {
            source: "192.0.2.1:161".parse().expect("a literal endpoint"),
            engine_id: ENGINE.to_vec(),
            message_id: 4242,
            request_id: 99,
            pdu_type: PDU_GET_RESPONSE,
            oid: Some(Oid::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0])),
        }
    }

    fn scoped(pdu_type: u8, request_id: i32, oids: Vec<Oid>) -> ScopedPdu {
        ScopedPdu {
            context_engine_id: ENGINE.to_vec(),
            context_name: Vec::new(),
            pdu: SnmpPdu {
                pdu_type,
                request_id,
                error_status: 0,
                error_index: 0,
                varbinds: oids
                    .into_iter()
                    .map(|oid| (oid, BerValue::Integer(1)))
                    .collect(),
            },
        }
    }

    #[test]
    fn discovery_state_starts_unconfirmed() {
        // What discovery returns is an unauthenticated assertion. It is a starting point for
        // the first authenticated request and is not permitted to reject anything until a
        // verified message has confirmed it.
        let state = state(3, 900);
        assert!(!state.confirmed());
        assert_eq!(state.boots(), 3);
        assert_eq!(state.engine_id(), ENGINE);
    }

    #[test]
    fn the_window_is_one_hundred_and_fifty_seconds_either_side() {
        let mut state = state(3, 1000);
        state.absorb_authenticated(3, 1000);
        assert!(state.confirmed());

        assert_eq!(state.timeliness(3, 1000), Timeliness::InWindow);
        assert_eq!(state.timeliness(3, 1000 + 150), Timeliness::InWindow);
        assert_eq!(state.timeliness(3, 1000 - 150), Timeliness::InWindow);
        // Beyond it in either direction: a message from too far in the past is a replay, and
        // one from too far ahead means the estimate and the agent disagree by more than the
        // protocol allows.
        assert_eq!(state.timeliness(3, 1000 + 151), Timeliness::Outside);
        assert_eq!(state.timeliness(3, 1000 - 151), Timeliness::Outside);
    }

    #[test]
    fn a_boot_counter_that_moves_is_never_silently_accepted() {
        let mut state = state(5, 1000);
        state.absorb_authenticated(5, 1000);

        // Backwards: a replay from before a restart, or another engine answering.
        assert_eq!(state.timeliness(4, 1000), Timeliness::Outside);
        // Forwards: a genuine restart, which still has to be resynchronised before anything
        // is accepted against it.
        assert_eq!(state.timeliness(6, 10), Timeliness::Outside);
        // At the ceiling: RFC 3414 says such an engine must be re-keyed, not resynchronised.
        assert_eq!(state.timeliness(BOOTS_CEILING, 10), Timeliness::Unusable);
    }

    #[test]
    fn only_an_authenticated_message_moves_the_window() {
        // The attack this closes: an off-path sender who can move a manager's estimate can
        // push it forward until real replies look stale, or back until old ones look fresh.
        // `timeliness` never writes, and `absorb_authenticated` is the only writer.
        let mut state = state(3, 1000);
        let before = state.estimated_time();
        for _ in 0..10 {
            let _ = state.timeliness(3, 5000);
        }
        assert_eq!(state.estimated_time(), before, "asking changed nothing");

        state.absorb_authenticated(3, 5000);
        assert!(
            state.estimated_time() >= 5000,
            "an authenticated answer did"
        );
    }

    #[test]
    fn a_replayed_time_does_not_lower_the_high_water_mark() {
        let mut state = state(3, 1000);
        state.absorb_authenticated(3, 2000);
        let after = state.estimated_time();
        // Replaying an older authenticated message must not drag the estimate backwards,
        // which would widen the window around messages that are already stale.
        state.absorb_authenticated(3, 1500);
        assert!(state.estimated_time() >= after);
        assert_eq!(state.timeliness(3, 1500), Timeliness::Outside);
    }

    #[test]
    fn a_restart_resets_the_high_water_mark_rather_than_keeping_it() {
        // After a restart the engine's time counter begins again, so the previous mark says
        // nothing about what is current -- keeping it would reject every message the
        // restarted engine sends until it had run for as long as the old one.
        let mut state = state(3, 90_000);
        state.absorb_authenticated(3, 90_000);
        state.absorb_authenticated(4, 12);
        assert_eq!(state.boots(), 4);
        assert_eq!(state.timeliness(4, 12), Timeliness::InWindow);
    }

    #[test]
    fn the_time_estimate_advances_with_the_monotonic_clock() {
        // Not the wall clock: an NTP step or a daylight-saving change would otherwise move
        // the window, producing a failure that appears twice a year and reads as a wrong key.
        let mut state = state(3, 1000);
        state.absorb_authenticated(3, 1000);
        let first = state.estimated_time();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(
            state.estimated_time() > first,
            "the estimate follows elapsed time"
        );
    }

    #[test]
    fn correlation_refuses_an_answer_to_a_different_question() {
        let expectation = expectation();

        // The scoped checks, which happen after authentication and decryption.
        let good = scoped(
            PDU_GET_RESPONSE,
            99,
            vec![Oid::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0])],
        );
        assert!(correlate_scoped(&good, ENGINE, &expectation).is_ok());

        let wrong_request = scoped(
            PDU_GET_RESPONSE,
            100,
            vec![Oid::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0])],
        );
        assert_eq!(
            correlate_scoped(&wrong_request, ENGINE, &expectation),
            Err(Refusal::WrongRequestId)
        );

        let wrong_type = scoped(0xA0, 99, vec![Oid::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0])]);
        assert_eq!(
            correlate_scoped(&wrong_type, ENGINE, &expectation),
            Err(Refusal::WrongPduType)
        );

        let wrong_object = scoped(
            PDU_GET_RESPONSE,
            99,
            vec![Oid::new(vec![1, 3, 6, 1, 2, 1, 1, 5, 0])],
        );
        assert_eq!(
            correlate_scoped(&wrong_object, ENGINE, &expectation),
            Err(Refusal::WrongVarbind)
        );

        // Two varbinds where one object was asked about.
        let two = scoped(
            PDU_GET_RESPONSE,
            99,
            vec![
                Oid::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]),
                Oid::new(vec![1, 3, 6, 1, 2, 1, 1, 5, 0]),
            ],
        );
        assert_eq!(
            correlate_scoped(&two, ENGINE, &expectation),
            Err(Refusal::WrongVarbind)
        );

        // A context belonging to another engine.
        let elsewhere = ScopedPdu {
            context_engine_id: b"\x80\x00\x1f\x88\x80\x09".to_vec(),
            ..good
        };
        assert_eq!(
            correlate_scoped(&elsewhere, ENGINE, &expectation),
            Err(Refusal::WrongEngine)
        );
    }

    #[test]
    fn discovery_accepts_only_the_unknown_engine_report() {
        let expectation = expectation();
        let unknown_engine = Oid::new(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0]);

        let report = scoped(crate::probes::snmp_v3::PDU_REPORT, 99, vec![unknown_engine]);
        assert_eq!(
            discovery_report_reason(&report, &expectation),
            Ok(ReportReason::UnknownEngineId)
        );

        // Every other Report means the agent read the message as something other than
        // discovery, so its engine identifier must not be taken from it.
        for counter in [1u32, 2, 3, 5, 6] {
            let other = scoped(
                crate::probes::snmp_v3::PDU_REPORT,
                99,
                vec![Oid::new(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, counter, 0])],
            );
            assert_eq!(
                discovery_report_reason(&other, &expectation),
                Err(Refusal::WrongVarbind),
                "counter {counter} is not the discovery answer"
            );
        }

        // A response instead of a Report, an uncorrelated Report, and a Report carrying more
        // than one varbind.
        assert_eq!(
            discovery_report_reason(
                &scoped(
                    PDU_GET_RESPONSE,
                    99,
                    vec![Oid::new(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0])]
                ),
                &expectation
            ),
            Err(Refusal::WrongPduType)
        );
        assert_eq!(
            discovery_report_reason(
                &scoped(
                    crate::probes::snmp_v3::PDU_REPORT,
                    7,
                    vec![Oid::new(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0])]
                ),
                &expectation
            ),
            Err(Refusal::WrongRequestId)
        );
        assert_eq!(
            discovery_report_reason(
                &scoped(
                    crate::probes::snmp_v3::PDU_REPORT,
                    99,
                    vec![
                        Oid::new(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0]),
                        Oid::new(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0]),
                    ]
                ),
                &expectation
            ),
            Err(Refusal::WrongVarbind)
        );
    }

    #[test]
    fn resynchronisation_is_allowed_once_and_never_becomes_a_loop() {
        // An agent that keeps reporting untimeliness after being resynchronised is either
        // misbehaving or being impersonated. Retrying turns one bad answer into unbounded
        // traffic and unbounded chances to guess.
        let mut budget = ResyncBudget::default();
        assert!(budget.spend(), "the first resynchronisation is allowed");
        assert!(budget.spent());
        for _ in 0..5 {
            assert!(!budget.spend(), "and there is never a second");
        }
    }

    #[test]
    fn a_refusal_explains_itself_without_naming_a_credential() {
        for refusal in [
            Refusal::WrongSource,
            Refusal::WrongEngine,
            Refusal::WrongMessageId,
            Refusal::WrongRequestId,
            Refusal::WrongPduType,
            Refusal::WrongVarbind,
            Refusal::NotAuthenticated,
            Refusal::DigestFailed,
            Refusal::Untimely,
            Refusal::Malformed("a truncated varbind".to_string()),
        ] {
            let text = refusal.describe();
            assert!(!text.is_empty());
            for forbidden in ["passphrase", "password", "key material", "user name is"] {
                assert!(!text.contains(forbidden), "{refusal:?}: {text}");
            }
        }
    }

    #[test]
    fn engine_state_formats_without_revealing_its_salt_stream() {
        let state = state(3, 1000);
        let rendered = format!("{state:?}");
        assert!(rendered.contains("boots: 3"), "{rendered}");
        assert!(rendered.contains("confirmed: false"), "{rendered}");
        assert!(!rendered.contains("salt"), "{rendered}");
    }
}
