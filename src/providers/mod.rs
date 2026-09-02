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
pub type ProviderFuture<'a> = Pin<Box<dyn Future<Output = Vec<TopologyEvidence>> + Send + 'a>>;

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
                &crate::net::interface::list_interface_addresses(),
                index,
            )),
            probe_permits: Arc::new(Semaphore::new(concurrency.max(1))),
            snmp_communities: Vec::new(),
            privileged: false,
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
