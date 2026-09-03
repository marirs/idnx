//! What running one probe amounted to.
//!
//! Five states, because collapsing them loses the distinctions an operator needs. A
//! protocol whose framing has never been verified is not the same as one that was sent and
//! ignored; a socket that could not be opened is not the same as a device that stayed
//! quiet; and bytes that arrived but failed validation are a finding in their own right.
//!
//! Only [`AttemptOutcome::Answered`] carries a result, so a probe that cannot show a
//! validated reply has no way to report one. Silence means "not confirmed" and never
//! "offline": the four other states are all consistent with a device that is present.

/// The outcome of one probe attempt, carrying `T` only when a reply survived validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome<T> {
    /// Nothing was sent: the protocol, platform support or privilege is missing.
    Unavailable { reason: String },
    /// Transmission failed locally: no socket, no binding, no packet on the wire.
    NotSent { reason: String },
    /// A verified request went out and nothing came back.
    NoResponse { sent: String },
    /// Bytes arrived and did not survive validation.
    InvalidResponse { sent: String, rejected: usize },
    /// A correlated, structurally valid reply.
    Answered { sent: String, result: T },
}

impl<T> AttemptOutcome<T> {
    pub fn unavailable(reason: impl Into<String>) -> Self {
        AttemptOutcome::Unavailable {
            reason: reason.into(),
        }
    }

    pub fn not_sent(reason: impl Into<String>) -> Self {
        AttemptOutcome::NotSent {
            reason: reason.into(),
        }
    }

    /// Whether a request actually reached the wire.
    ///
    /// This is what separates "nothing answered" from "nothing was asked". Only the former
    /// is a fact about the network.
    pub fn transmitted(&self) -> bool {
        matches!(
            self,
            AttemptOutcome::NoResponse { .. }
                | AttemptOutcome::InvalidResponse { .. }
                | AttemptOutcome::Answered { .. }
        )
    }

    /// The validated reply, if there was one. Every other state yields `None` by
    /// construction rather than by convention.
    pub fn result(self) -> Option<T> {
        match self {
            AttemptOutcome::Answered { result, .. } => Some(result),
            _ => None,
        }
    }

    /// One line naming the probe and what became of it. Distinct per state, so the five
    /// cases stay distinguishable in output as well as in the type.
    pub fn describe(&self, probe: &str) -> String {
        match self {
            AttemptOutcome::Unavailable { reason } => format!("{probe} unavailable: {reason}"),
            AttemptOutcome::NotSent { reason } => format!("{probe} not sent: {reason}"),
            AttemptOutcome::NoResponse { sent } => format!("{probe} no response ({sent})"),
            AttemptOutcome::InvalidResponse { sent, rejected } => {
                format!("{probe} {rejected} reply/replies failed validation ({sent})")
            }
            AttemptOutcome::Answered { sent, .. } => format!("{probe} answered ({sent})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_state_is_distinguishable_and_only_an_answer_carries_a_result() {
        let sent = "UDP 9999".to_string();
        let cases: Vec<AttemptOutcome<u8>> = vec![
            AttemptOutcome::unavailable("framing unverified"),
            AttemptOutcome::not_sent("no IPv4 source address"),
            AttemptOutcome::NoResponse { sent: sent.clone() },
            AttemptOutcome::InvalidResponse {
                sent: sent.clone(),
                rejected: 2,
            },
            AttemptOutcome::Answered { sent, result: 7 },
        ];

        let described: Vec<String> = cases.iter().map(|c| c.describe("probe:test")).collect();
        for (index, text) in described.iter().enumerate() {
            for (other, previous) in described.iter().enumerate() {
                assert!(index == other || text != previous, "{text} is ambiguous");
            }
        }
        assert!(described[0].contains("unavailable"));
        assert!(described[1].contains("not sent"));
        assert!(described[2].contains("no response"));
        assert!(described[3].contains("failed validation"));
        assert!(described[4].contains("answered"));

        // Only the two states that put a request on the wire may be read as the network
        // having been asked.
        let transmitted: Vec<bool> = cases.iter().map(|c| c.transmitted()).collect();
        assert_eq!(transmitted, vec![false, false, true, true, true]);

        for case in cases {
            let answered = matches!(case, AttemptOutcome::Answered { .. });
            assert_eq!(case.result().is_some(), answered);
        }
    }
}
