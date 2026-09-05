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
/// A network being unreachable is not a reason to drop it. An advertised prefix nothing
/// answers on is a real finding -- it is what a router claims -- and it stays on the map
/// carrying the reason it could not be confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkOutcome {
    /// Something in the network answered, and this is what answered.
    Reachable { responders: Vec<IpAddr> },
    /// The network is claimed by some device, addresses in it were probed, and none
    /// answered. `reasons` carries each provider's account of what it tried.
    AdvertisedUnreachable {
        attempted: usize,
        reasons: Vec<String>,
    },
    /// No address in it was probed at all, and why -- too large to enumerate, out of
    /// scope for this vantage, or a protocol that never ran.
    NotEnumerated { reason: String },
}

impl NetworkOutcome {
    /// How strong a statement this is, for merging. A confirmed responder outranks a
    /// failed sweep, which outranks never having asked: the strongest claim any pass
    /// established is the one that survives.
    fn rank(&self) -> u8 {
        match self {
            NetworkOutcome::Reachable { .. } => 2,
            NetworkOutcome::AdvertisedUnreachable { .. } => 1,
            NetworkOutcome::NotEnumerated { .. } => 0,
        }
    }

    /// Folds another pass's outcome for the same network into this one.
    pub fn merge(&mut self, other: NetworkOutcome) {
        match (&mut *self, other) {
            (
                NetworkOutcome::Reachable { responders },
                NetworkOutcome::Reachable { responders: more },
            ) => {
                responders.extend(more);
                responders.sort();
                responders.dedup();
            }
            (
                NetworkOutcome::AdvertisedUnreachable { attempted, reasons },
                NetworkOutcome::AdvertisedUnreachable {
                    attempted: more,
                    reasons: also,
                },
            ) => {
                *attempted += more;
                reasons.extend(also);
                reasons.dedup();
            }
            (current, other) => {
                if other.rank() > current.rank() {
                    *current = other;
                }
            }
        }
    }

    /// The sentence a person reads. Rendered from the state; never the state itself.
    pub fn describe(&self) -> String {
        match self {
            NetworkOutcome::Reachable { responders } => match responders.len() {
                0 => "reachable".to_string(),
                1 => format!("reachable; {} answered", responders[0]),
                n => format!("reachable; {n} address(es) answered"),
            },
            NetworkOutcome::AdvertisedUnreachable { attempted, reasons } => {
                let detail = if reasons.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", reasons.join("; "))
                };
                format!("advertised; {attempted} address(es) probed, none answered{detail}")
            }
            NetworkOutcome::NotEnumerated { reason } => format!("not enumerated: {reason}"),
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
    pub reachability: Vec<(IpNet, NetworkOutcome)>,
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
    fn a_responder_outranks_a_failed_sweep_and_a_sweep_that_never_ran() {
        // Passes disagree legitimately: one provider sweeps a network and hears nothing
        // while another reaches a device in it. The strongest thing anyone established is
        // the truth about the network; the weaker accounts must not overwrite it whichever
        // order they arrive in.
        let responder = NetworkOutcome::Reachable {
            responders: vec![ip("192.0.2.5")],
        };
        let silence = NetworkOutcome::AdvertisedUnreachable {
            attempted: 254,
            reasons: vec!["swept, nothing answered".to_string()],
        };
        let never = NetworkOutcome::NotEnumerated {
            reason: "too large".to_string(),
        };

        let mut forwards = responder.clone();
        forwards.merge(silence.clone());
        forwards.merge(never.clone());
        assert_eq!(forwards, responder);

        let mut backwards = never;
        backwards.merge(silence);
        backwards.merge(responder.clone());
        assert_eq!(backwards, responder);
    }

    #[test]
    fn two_sweeps_of_the_same_network_accumulate_rather_than_replace() {
        let mut held = NetworkOutcome::Reachable {
            responders: vec![ip("192.0.2.5")],
        };
        held.merge(NetworkOutcome::Reachable {
            responders: vec![ip("192.0.2.9"), ip("192.0.2.5")],
        });
        assert_eq!(
            held,
            NetworkOutcome::Reachable {
                responders: vec![ip("192.0.2.5"), ip("192.0.2.9")]
            },
            "every responder is kept, once each"
        );

        let mut failed = NetworkOutcome::AdvertisedUnreachable {
            attempted: 10,
            reasons: vec!["ICMP".to_string()],
        };
        failed.merge(NetworkOutcome::AdvertisedUnreachable {
            attempted: 4,
            reasons: vec!["TCP".to_string()],
        });
        assert_eq!(
            failed,
            NetworkOutcome::AdvertisedUnreachable {
                attempted: 14,
                reasons: vec!["ICMP".to_string(), "TCP".to_string()]
            },
            "the total probed is the sum, and each account is kept"
        );
    }

    #[test]
    fn silence_and_never_having_asked_read_differently() {
        // The whole reason this is state rather than prose: these two produce an identical
        // absence of hosts, and only one of them is a statement about the network.
        let silent = NetworkOutcome::AdvertisedUnreachable {
            attempted: 254,
            reasons: vec!["swept".to_string()],
        };
        let unasked = NetworkOutcome::NotEnumerated {
            reason: "65534 addresses exceeds the 4096 this run enumerates".to_string(),
        };
        assert!(silent.describe().contains("none answered"));
        assert!(unasked.describe().starts_with("not enumerated"));
        assert_ne!(silent, unasked);
    }
}
