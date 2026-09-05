//! Discovery providers.
//!
//! Every source of topology knowledge — the kernel routing table, a DHCP lease, an LLDP
//! frame, an SNMP walk, a vendor's proprietary broadcast — implements the same trait and
//! returns the same evidence type. No provider is privileged, and none can report a result
//! any way other than by emitting evidence into the graph.

pub mod ai;
pub mod local;
pub mod network;
pub mod passive;
pub mod target;
pub mod vendor;

use std::collections::BTreeSet;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use ipnet::IpNet;

use crate::topology::TopologyEvidence;

/// Future returned by a provider.
///
/// Written out by hand rather than pulling in `async-trait`: the trait must be
/// dyn-compatible so providers can live in one heterogeneous registry, and this keeps the
/// dependency surface as lean as the rest of the crate (the SNMP BER codec is hand-rolled
/// for the same reason).
pub type ProviderFuture<'a> = Pin<Box<dyn Future<Output = ProviderOutput> + Send + 'a>>;

/// What one provider pass produced.
///
/// Evidence remains the only channel into the graph. This adds a second, strictly
/// non-graph channel for what the provider *attempted*, because the engine cannot infer it:
/// an empty result previously became the note "no response", which is a claim about the
/// network. It is only true when something was actually sent. A provider whose protocol is
/// unimplemented, whose socket would not bind, or whose vantage cannot carry the traffic
/// returns the same empty vector and must not borrow that claim.
/// What a probe pass established about one network's reachability.
///
/// First-class state rather than a sentence in a note. A note is written for a person and
/// cannot be consumed: an export could not tell "nothing answered" from "we never asked"
/// without matching on prose, and every renderer would have to agree on the wording. The
/// engine aggregates these across providers and passes; the human sentence is rendered
/// from the result, never treated as the result.
///
/// A network being unreachable is not a reason to drop it. A prefix nothing answers on is
/// a real finding -- it is what some device claims -- and it stays on the map carrying the
/// reason it could not be confirmed. How the network came to be known is kept in
/// `discovery` and never inferred from the probe result: reachability says what answered,
/// not what the network is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkReachability {
    /// Addresses that answered *during this run*: a TCP response or refusal, a correlated
    /// ICMP reply, a fresh ARP or NDP answer, or a validated protocol reply.
    ///
    /// Never a neighbour-cache entry. The kernel remembers stations long after they are
    /// gone, and counting a memory as an answer made empty networks reachable.
    pub responders: Vec<IpAddr>,
    /// The addresses at least one probe actually left this machine for.
    ///
    /// A set, not a count. Counts cannot be merged truthfully: two passes that each probed
    /// 127 addresses may have probed 254 distinct ones or the same 127 twice, and neither
    /// summing nor taking the larger can tell those apart. The union can.
    pub probed: BTreeSet<IpAddr>,
    /// Probes that never left: a socket that would not bind, a source address the vantage
    /// does not hold. Kept apart from silence, which is a fact about the network.
    pub not_sent: usize,
    /// Each prober's account of what it tried and what came back.
    pub reasons: Vec<String>,
    /// How the network came to be known -- advertised by a router, attached to this
    /// vantage, supplied by the operator. Held separately because probing does not
    /// establish it and a failed probe must not overwrite it.
    pub discovery: Vec<String>,
}

/// The discriminant a consumer reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityState {
    /// Something in it answered during this run.
    Reachable,
    /// Probes reached the wire and nothing answered. Says nothing about how the network
    /// was discovered: attached, routed, advertised and operator-supplied networks all
    /// arrive here identically.
    ProbedUnreachable,
    /// Nothing was probed at all -- too large to enumerate, or every socket refused to
    /// send. An absence of answers that nobody asked for is not silence.
    NotEnumerated,
}

impl ReachabilityState {
    pub fn wire(&self) -> &'static str {
        match self {
            ReachabilityState::Reachable => "reachable",
            ReachabilityState::ProbedUnreachable => "probed_unreachable",
            ReachabilityState::NotEnumerated => "not_enumerated",
        }
    }
}

impl NetworkReachability {
    /// A completed sweep: what answered, which addresses were actually probed, and how
    /// many probes never left.
    ///
    /// Responders are folded into the probed set: an address that answered was necessarily
    /// asked, so a caller cannot report an answer from an address it did not probe.
    pub fn probed(
        responders: Vec<IpAddr>,
        probed: impl IntoIterator<Item = IpAddr>,
        not_sent: usize,
        reasons: Vec<String>,
    ) -> Self {
        let mut addresses: BTreeSet<IpAddr> = probed.into_iter().collect();
        addresses.extend(responders.iter().copied());
        Self {
            responders,
            probed: addresses,
            not_sent,
            reasons,
            discovery: Vec::new(),
        }
    }

    /// How many distinct addresses were actually probed.
    pub fn attempted(&self) -> usize {
        self.probed.len()
    }

    /// Nothing was probed, and why.
    pub fn not_enumerated(reason: impl Into<String>) -> Self {
        Self {
            reasons: vec![reason.into()],
            ..Self::default()
        }
    }

    /// Records how the network came to be known, which probing never establishes.
    pub fn discovered_by(mut self, how: impl Into<String>) -> Self {
        self.discovery.push(how.into());
        self
    }

    /// The state, derived from the evidence rather than asserted alongside it.
    ///
    /// Derived so the two can never disagree: a responder means reachable, probes with no
    /// responder mean silence, and no probe at all means the question was never put --
    /// including the case where every socket refused to send, which used to be reported as
    /// a silent network.
    pub fn state(&self) -> ReachabilityState {
        if !self.responders.is_empty() {
            ReachabilityState::Reachable
        } else if !self.probed.is_empty() {
            ReachabilityState::ProbedUnreachable
        } else {
            ReachabilityState::NotEnumerated
        }
    }

    /// Folds another pass's account of the same network into this one.
    ///
    /// Responders and accounts accumulate: an earlier design kept only the strongest state,
    /// so one responder among 254 attempts erased the 253 that answered nothing, and the
    /// coverage of the sweep -- most of what the result is worth -- went with it.
    ///
    /// Coverage is the union of the addresses each pass probed. Adding the counts claimed
    /// 508 addresses probed in a network holding 254; taking the larger count reported 127
    /// when two partially overlapping passes had between them covered 254. Only the
    /// addresses themselves answer the question, so the addresses are what is kept.
    ///
    /// `not_sent` is a count of probes rather than of addresses, so it does add: two passes
    /// that each failed to send is two probes that never left.
    pub fn merge(&mut self, other: NetworkReachability) {
        self.responders.extend(other.responders);
        self.responders.sort();
        self.responders.dedup();
        self.probed.extend(other.probed);
        self.not_sent += other.not_sent;
        self.reasons.extend(other.reasons);
        self.reasons.dedup();
        self.discovery.extend(other.discovery);
        self.discovery.dedup();
    }

    /// The sentence a person reads. Rendered from the state; never the state itself.
    pub fn describe(&self) -> String {
        let detail = if self.reasons.is_empty() {
            String::new()
        } else {
            format!(" ({})", self.reasons.join("; "))
        };
        match self.state() {
            ReachabilityState::Reachable => format!(
                "reachable; {} of {} address(es) probed answered{detail}",
                self.responders.len(),
                self.attempted()
            ),
            ReachabilityState::ProbedUnreachable => format!(
                "{} address(es) probed, none answered{detail}",
                self.attempted()
            ),
            ReachabilityState::NotEnumerated => {
                let unsent = if self.not_sent > 0 {
                    format!("; {} probe(s) never left this machine", self.not_sent)
                } else {
                    String::new()
                };
                format!("not enumerated{detail}{unsent}")
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct ProviderOutput {
    pub evidence: Vec<TopologyEvidence>,
    /// What was attempted and what came back, in the provider's own words. Reported
    /// verbatim; the engine never rewrites these.
    pub notes: Vec<String>,
    /// Whether any request reached the wire (or any local source was actually read).
    ///
    /// False turns "no response" into "not attempted" wherever the run is reported.
    pub attempted: bool,
    /// What this pass established about the reachability of specific networks.
    ///
    /// Separate from evidence because it is not a topology fact: whether an address
    /// answered says nothing about what the network *is*, and folding the two together is
    /// how "nothing answered" became "no such network".
    pub reachability: Vec<(IpNet, NetworkReachability)>,
}

impl ProviderOutput {
    /// Nothing was attempted because the provider could not run here.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            evidence: Vec::new(),
            notes: vec![format!("unavailable: {}", reason.into())],
            attempted: false,
            reachability: Vec::new(),
        }
    }

    /// Nothing was attempted because there was nothing here to ask.
    ///
    /// Kept apart from `unavailable`, which says the provider cannot run on this machine.
    /// "No cached IPv6 neighbour to solicit" is a statement about the link and must not be
    /// rendered as neighbour discovery being unusable.
    pub fn not_applicable(reason: impl Into<String>) -> Self {
        Self {
            evidence: Vec::new(),
            notes: vec![format!("not applicable: {}", reason.into())],
            attempted: false,
            reachability: Vec::new(),
        }
    }
}

/// Providers that simply return evidence keep doing so; the conversion marks the pass as
/// attempted, which is correct for every provider that got as far as producing a vector.
impl From<Vec<TopologyEvidence>> for ProviderOutput {
    fn from(evidence: Vec<TopologyEvidence>) -> Self {
        Self {
            evidence,
            notes: Vec::new(),
            attempted: true,
            reachability: Vec::new(),
        }
    }
}

/// Adapts a provider body that yields plain evidence into a [`ProviderOutput`].
///
/// Providers that have nothing extra to report keep returning a vector; wrapping here marks
/// the pass as attempted without every provider restating it.
pub async fn attempted<F>(body: F) -> ProviderOutput
where
    F: Future<Output = Vec<TopologyEvidence>>,
{
    body.await.into()
}

/// How the selected interface connects, which determines what it can observe.
///
/// This is not cosmetic: a wireless station cannot receive wired spanning-tree or LLDP
/// frames, and reporting "no switches found" from such a vantage would be misleading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VantageKind {
    Wired,
    Wireless,
    Virtual,
    Loopback,
    Unknown,
}

impl VantageKind {
    pub fn label(&self) -> &'static str {
        match self {
            VantageKind::Wired => "wired",
            VantageKind::Wireless => "wireless station",
            VantageKind::Virtual => "virtual/VPN",
            VantageKind::Loopback => "loopback",
            VantageKind::Unknown => "unknown",
        }
    }

    /// Frame types this vantage cannot receive, stated so an empty capture is never
    /// mistaken for an empty network.
    pub fn blind_to(&self) -> &'static [&'static str] {
        match self {
            VantageKind::Wireless => &[
                "wired STP/BPDU",
                "LLDP/CDP from wired switches",
                "trunk VLAN tags",
                "switched unicast between other hosts",
            ],
            VantageKind::Virtual => &["physical link-layer frames", "STP/BPDU", "LLDP/CDP"],
            VantageKind::Wired => &["switched unicast between other hosts (without a mirror port)"],
            VantageKind::Loopback => &["everything off-host"],
            VantageKind::Unknown => &[],
        }
    }
}

/// The vantage point discovery is running from.
#[derive(Debug, Clone)]
pub struct Vantage {
    pub interface: String,
    pub kind: VantageKind,
    /// Kernel scope index for this interface.
    ///
    /// Carried rather than derived from the name at the point of use. On Windows an IPv6
    /// zone is a numeric index and there is no name to resolve, so parsing the friendly
    /// name as an integer yielded scope 0 and an address the kernel could not route.
    pub index: u32,
    /// Whether raw link-layer capture is possible here (privileges plus platform support).
    pub capture_available: bool,
}

impl Vantage {
    pub fn label(&self) -> String {
        format!("{} ({})", self.interface, self.kind.label())
    }
}

/// What a provider is being asked to examine.
///
/// A provider may be invoked with no scope (seeding from the local machine), with a
/// network scope (examining a discovered subnet), or with a specific target device
/// (interrogating a pivot).
#[derive(Debug, Clone)]
pub struct DiscoveryContext {
    pub vantage: Vantage,
    /// Network currently under examination, if any.
    pub scope: Option<IpNet>,
    /// Specific device being interrogated, if any.
    pub target: Option<IpAddr>,
    pub timeout: Duration,
    pub concurrency: usize,
    /// Local addresses every active probe originates from.
    ///
    /// Naming an interface must constrain the traffic, not only the target list: an
    /// unbound socket follows ordinary OS routing and can leave through a different
    /// interface entirely, producing evidence attributed to a vantage that never carried
    /// it.
    pub binding: Arc<crate::net::socket::SocketBinding>,
    /// One shared budget for every network probe in the run.
    ///
    /// Device-level and port-level parallelism draw on the same permits, so interrogating
    /// many devices at once cannot multiply into `devices x ports` simultaneous sockets.
    /// Without this the two concurrency limits compose, and the total is whatever the two
    /// happen to multiply to.
    pub probe_permits: Arc<Semaphore>,
    /// SNMP communities the operator supplied. Empty means the anonymous default only.
    pub snmp_communities: Vec<String>,
    pub privileged: bool,
}

impl DiscoveryContext {
    pub fn seed(vantage: Vantage, timeout: Duration, concurrency: usize) -> Self {
        let interface = vantage.interface.clone();
        let index = vantage.index;
        Self {
            vantage,
            scope: None,
            target: None,
            timeout,
            concurrency,
            binding: Arc::new(crate::net::socket::SocketBinding::for_interface(
                &interface,
                &crate::net::interface::list_socket_sources(),
                index,
            )),
            probe_permits: Arc::new(Semaphore::new(concurrency.max(1))),
            snmp_communities: Vec::new(),
            privileged: false,
        }
    }

    /// The binding and probe budget as one value, for paths that need both.
    pub fn probe_channel(&self) -> crate::net::socket::ProbeChannel {
        crate::net::socket::ProbeChannel {
            binding: Arc::clone(&self.binding),
            permits: Arc::clone(&self.probe_permits),
        }
    }

    pub fn for_scope(&self, scope: IpNet) -> Self {
        Self {
            scope: Some(scope),
            target: None,
            ..self.clone()
        }
    }

    pub fn for_target(&self, target: IpAddr) -> Self {
        Self {
            target: Some(target),
            ..self.clone()
        }
    }
}

/// Outcome of running one provider, so that failures are reported rather than dropped.
#[derive(Debug, Clone)]
pub struct ProviderRun {
    pub provider: &'static str,
    pub evidence_count: usize,
    /// Why the provider produced nothing, when it produced nothing.
    pub note: Option<String>,
}

/// A source that observes continuously rather than when asked.
///
/// Packet capture does not fit the request/response shape of a provider: frames arrive on
/// their own schedule, including after the last scope has been processed. The engine polls
/// this before every convergence decision and finishes it exactly once, so evidence that
/// lands moments before the end is still absorbed and can still extend the traversal.
pub trait ContinuousSource: Send + Sync {
    /// Evidence accumulated since the previous call. Must be cheap and non-blocking.
    fn drain(&self) -> Vec<TopologyEvidence>;

    /// Stops observing and returns whatever remained buffered.
    ///
    /// Called once, at candidate convergence. After this the source yields nothing further.
    fn finish(&self) -> Vec<TopologyEvidence>;
}

/// A source of topology evidence.
pub trait DiscoveryProvider: Send + Sync {
    /// Stable name used in diagnostics.
    fn name(&self) -> &'static str;

    /// Whether this provider can contribute anything in the given context. Used to skip
    /// work rather than to hide failures: a provider that applies but finds nothing still
    /// reports that it ran.
    fn applies(&self, _context: &DiscoveryContext) -> bool {
        true
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a>;
}

#[cfg(test)]
mod reachability_tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("a literal address")
    }

    #[test]
    fn one_responder_among_many_attempts_keeps_both() {
        // The defect this replaced: a rank-based merge kept only the strongest state, so a
        // single answer erased the 253 addresses that answered nothing. "1 of 254" and
        // "1 of 1" are different results, and only the coverage tells them apart.
        let whole_subnet =
            || (1..=254u8).map(|host| IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, host)));
        let mut held = NetworkReachability::probed(
            Vec::new(),
            whole_subnet(),
            0,
            vec!["254 swept by the port sweep; silent".to_string()],
        );
        held.merge(NetworkReachability::probed(
            vec![ip("192.0.2.5")],
            whole_subnet(),
            0,
            vec!["254 asked by the ARP sweep; one answered".to_string()],
        ));

        assert_eq!(held.state(), ReachabilityState::Reachable);
        assert_eq!(held.responders, vec![ip("192.0.2.5")]);
        assert_eq!(
            held.attempted(),
            254,
            "the sweep's coverage survives, and two passes over the same /24 are not 508"
        );
        assert_eq!(held.reasons.len(), 2, "both accounts are kept");
        assert!(held.describe().contains("1 of 254"));
    }

    #[test]
    fn probes_that_never_left_are_not_silence() {
        // Every socket refused to bind, so nothing was asked. Reporting that as a network
        // that stayed silent turned a local fault into a finding about someone else's
        // network.
        let nothing_sent = NetworkReachability::probed(
            Vec::new(),
            Vec::new(),
            254,
            vec!["no usable source address on this vantage".to_string()],
        );
        assert_eq!(nothing_sent.state(), ReachabilityState::NotEnumerated);
        assert!(nothing_sent.describe().contains("never left this machine"));

        // One probe that did leave makes the silence real, for that one address.
        let one_sent =
            NetworkReachability::probed(Vec::new(), vec![ip("192.0.2.1")], 253, Vec::new());
        assert_eq!(one_sent.state(), ReachabilityState::ProbedUnreachable);
    }

    #[test]
    fn how_a_network_was_discovered_survives_a_failed_sweep() {
        // Probing establishes what answered. It never establishes what the network is, so
        // a silent sweep must not overwrite the provenance that put it on the map.
        let mut held = NetworkReachability::probed(
            Vec::new(),
            (1..=254u8).map(|host| IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, host))),
            0,
            Vec::new(),
        )
        .discovered_by("advertised by 198.51.100.1");
        held.merge(NetworkReachability::probed(
            Vec::new(),
            Vec::new(),
            0,
            Vec::new(),
        ));

        assert_eq!(held.state(), ReachabilityState::ProbedUnreachable);
        assert_eq!(
            held.discovery,
            vec!["advertised by 198.51.100.1".to_string()]
        );
    }

    #[test]
    fn responders_accumulate_once_each() {
        let mut held =
            NetworkReachability::probed(vec![ip("192.0.2.5")], Vec::new(), 0, Vec::new());
        held.merge(NetworkReachability::probed(
            vec![ip("192.0.2.9"), ip("192.0.2.5")],
            Vec::new(),
            0,
            Vec::new(),
        ));
        assert_eq!(held.responders, vec![ip("192.0.2.5"), ip("192.0.2.9")]);
        assert_eq!(
            held.attempted(),
            2,
            "an address that answered was necessarily probed"
        );
    }

    #[test]
    fn partially_overlapping_passes_union_their_coverage() {
        // Counts cannot merge truthfully. Two passes that each probed 127 addresses may
        // have covered 254 distinct ones or the same 127 twice; summing claims 254 for
        // both, and taking the larger claims 127 for both. Only the addresses know.
        let lower = || (1..=127u8).map(|host| IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, host)));
        let upper =
            || (100..=226u8).map(|host| IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, host)));

        let mut held = NetworkReachability::probed(Vec::new(), lower(), 0, Vec::new());
        held.merge(NetworkReachability::probed(
            Vec::new(),
            upper(),
            0,
            Vec::new(),
        ));

        // 1..=127 and 100..=226 overlap on 28 addresses: 127 + 127 - 28 = 226.
        assert_eq!(
            held.attempted(),
            226,
            "the union, not the sum and not the larger"
        );

        // The same pass twice adds nothing.
        let mut twice = NetworkReachability::probed(Vec::new(), lower(), 0, Vec::new());
        twice.merge(NetworkReachability::probed(
            Vec::new(),
            lower(),
            0,
            Vec::new(),
        ));
        assert_eq!(
            twice.attempted(),
            127,
            "probing the same addresses twice is not 254"
        );
    }

    #[test]
    fn silence_and_never_having_asked_read_differently() {
        // The whole reason this is state rather than prose: both produce an identical
        // absence of hosts, and only one is a statement about the network.
        let silent = NetworkReachability::probed(
            Vec::new(),
            (1..=254u8).map(|host| IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, host))),
            0,
            Vec::new(),
        );
        let unasked = NetworkReachability::not_enumerated("65534 addresses exceeds the budget");
        assert_ne!(silent.state(), unasked.state());
        assert!(silent.describe().contains("none answered"));
        assert!(unasked.describe().starts_with("not enumerated"));
    }
}
