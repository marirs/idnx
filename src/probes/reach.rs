//! Bounded reachability probing for router interfaces nobody disclosed.
//!
//! Every other source in this crate waits to be told. When no router advertises a route, no
//! DHCP server carries option 121 and no routing protocol is heard, the map stops at the
//! attached link even though the forwarding boundaries are visible and answering. This asks
//! directly, and it asks a deliberately small, ordered set of addresses.
//!
//! Three constraints keep it from becoming a scan.
//!
//! Gateway candidates only. The first and last usable address of a /24 is where a router
//! interface lives when there is one; probing the other 252 would be sweeping address space
//! on the chance of a hit, which is what this crate exists not to do.
//!
//! The exact target must answer. A Time Exceeded from an intermediate hop proves that hop
//! forwards, not that the address we asked about exists -- so only an Echo Reply whose
//! source is the target, carrying our identifier and sequence, creates a device.
//!
//! And a responding address is an address. It becomes a network only when something states
//! a prefix: an address mask reply, a route, or an interrogation of the interface itself. A
//! /24 drawn around a responding address would be exactly the invention this refuses.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// Addresses within a /24 where a router interface is conventionally configured.
const GATEWAY_HOSTS: [u8; 2] = [1, 254];

/// The TCP ports asked of a candidate that ignored ICMP.
///
/// Deliberately small, and chosen for what infrastructure answers rather than for coverage:
/// a router that suppresses ICMP commonly still has a management interface, SSH, telnet or
/// a resolver. The full 62-port interrogation belongs to the per-device pipeline and runs
/// only after something has established the device exists.
pub const INFRASTRUCTURE_TCP_PORTS: [u16; 5] = [53, 80, 443, 22, 8080];

/// What answered for a candidate.
///
/// Named rather than collapsed into a boolean because the report has to say what was tried:
/// "silent" is only meaningful when the reader knows which questions were asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseSignal {
    /// An echo reply from the address itself.
    Icmp,
    /// A TCP handshake completed on this port.
    TcpOpen(u16),
    /// A TCP reset: the port is closed and the host is answering.
    TcpRefused(u16),
    /// A correlated DNS response.
    Dns,
    /// A NAT-PMP gateway response.
    NatPmp,
}

impl ResponseSignal {
    pub fn label(&self) -> String {
        match self {
            ResponseSignal::Icmp => "ICMP echo reply".to_string(),
            ResponseSignal::TcpOpen(port) => format!("TCP {port} accepted"),
            ResponseSignal::TcpRefused(port) => format!("TCP {port} refused"),
            ResponseSignal::Dns => "DNS response".to_string(),
            ResponseSignal::NatPmp => "NAT-PMP response".to_string(),
        }
    }
}

/// One line naming every question a candidate is asked, for the coverage report.
pub fn probes_attempted() -> String {
    format!(
        "ICMP echo, TCP {}, UDP DNS 53, NAT-PMP 5351",
        INFRASTRUCTURE_TCP_PORTS
            .iter()
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join("/")
    )
}

/// The private blocks a candidate may come from (RFC 1918).
///
/// Bounded to these deliberately: probing outside them would put traffic onto addresses the
/// operator does not hold, which is neither useful nor ours to do.
fn private_blocks() -> [Ipv4Net; 3] {
    [
        "10.0.0.0/8".parse().expect("a literal prefix"),
        "172.16.0.0/12".parse().expect("a literal prefix"),
        "192.168.0.0/16".parse().expect("a literal prefix"),
    ]
}

/// The private block containing an address, if any.
pub fn enclosing_private_block(address: Ipv4Addr) -> Option<Ipv4Net> {
    private_blocks()
        .into_iter()
        .find(|block| block.contains(&address))
}

/// The ordered candidate list for one run.
///
/// Deterministic, so two runs on an unchanged network probe the same addresses in the same
/// order and their reports can be compared. Priority follows how likely an address is to be
/// a router interface we have reason to look for:
///
///   1. The neighbourhoods around addresses already observed -- the /24s adjacent to what
///      this vantage has actually seen, where a cascaded network most often sits.
///   2. The rest of the enclosing private block, in address order.
///
/// `known` addresses are excluded: they have been established by something already, and
/// re-establishing them by reachability adds nothing.
pub fn candidates(
    observed: &[Ipv4Addr],
    known: &BTreeSet<Ipv4Addr>,
    limit: usize,
) -> Vec<Ipv4Addr> {
    candidates_with_coverage(observed, known, limit).0
}

/// The ordered candidate list, with how much of the space it covers.
///
/// The budget is spread rather than spent front-to-back. Taking the first N /24s of a block
/// examined 10.0.0.0/8's lowest quarter-percent and reported the rest as though it had been
/// asked; a stride covers the whole block at the same cost, and the coverage figure says
/// what fraction that was.
pub fn candidates_with_coverage(
    observed: &[Ipv4Addr],
    known: &BTreeSet<Ipv4Addr>,
    limit: usize,
) -> (Vec<Ipv4Addr>, Coverage) {
    let mut ordered: Vec<Ipv4Addr> = Vec::new();
    let mut seen: BTreeSet<Ipv4Addr> = BTreeSet::new();
    let mut subnets: BTreeSet<Ipv4Addr> = BTreeSet::new();

    let take = |subnet: Ipv4Net,
                ordered: &mut Vec<Ipv4Addr>,
                seen: &mut BTreeSet<Ipv4Addr>,
                subnets: &mut BTreeSet<Ipv4Addr>|
     -> bool {
        subnets.insert(subnet.network());
        for host in GATEWAY_HOSTS {
            let address = host_in(subnet, host);
            if known.contains(&address) || !seen.insert(address) {
                continue;
            }
            ordered.push(address);
            if ordered.len() >= limit {
                return true;
            }
        }
        false
    };

    // Neighbourhoods first, in the order the observations were given: the /24s nearest to
    // what this vantage has actually seen, including the forwarding hops it found.
    let mut blocks: Vec<Ipv4Net> = Vec::new();
    for address in observed {
        let Some(block) = enclosing_private_block(*address) else {
            continue;
        };
        if !blocks.contains(&block) {
            blocks.push(block);
        }
        for neighbourhood in neighbourhoods(*address, block) {
            if take(neighbourhood, &mut ordered, &mut seen, &mut subnets) {
                return (ordered, coverage(&subnets, &blocks));
            }
        }
    }
    blocks.sort_by_key(|block| block.network());

    // Then the rest of each block, strided so the sample spans it evenly. A /16 is covered
    // exactly; a /8 is sampled, and the report says so rather than implying it was swept.
    let remaining = limit.saturating_sub(ordered.len());
    if remaining == 0 {
        return (ordered, coverage(&subnets, &blocks));
    }
    for block in &blocks {
        let all: Vec<Ipv4Net> = block.subnets(24).into_iter().flatten().collect();
        let want = (remaining / GATEWAY_HOSTS.len()).max(1);
        // Floor, not ceiling: with a budget of 246 subnets and 256 to cover, rounding up
        // gave a stride of 2 and sampled half a block the budget could have covered
        // outright.
        let stride = (all.len() / want.max(1)).max(1);
        for subnet in all.into_iter().step_by(stride) {
            if take(subnet, &mut ordered, &mut seen, &mut subnets) {
                return (ordered, coverage(&subnets, &blocks));
            }
        }
    }

    (ordered, coverage(&subnets, &blocks))
}

/// How many /24s were sampled against how many the blocks hold.
fn coverage(sampled: &BTreeSet<Ipv4Addr>, blocks: &[Ipv4Net]) -> Coverage {
    let total = blocks
        .iter()
        .map(|block| 1usize << (24 - block.prefix_len().min(24)) as usize)
        .sum();
    Coverage {
        sampled_subnets: sampled.len(),
        total_subnets: total,
    }
}

/// The /24s to add once an address answers.
///
/// A positive response is the best evidence available about where the next one will be:
/// networks are provisioned in runs, and the /24s beside a live router interface are worth
/// asking about before the far end of the block.
pub fn expand_around(address: Ipv4Addr) -> Vec<Ipv4Addr> {
    let Some(block) = enclosing_private_block(address) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for subnet in neighbourhoods(address, block) {
        for host in GATEWAY_HOSTS {
            let candidate = host_in(subnet, host);
            if candidate != address {
                out.push(candidate);
            }
        }
    }
    out
}

/// The /24s immediately around an observed address, inside its private block.
///
/// "Around" is bounded to a small window on purpose: a second network provisioned beside
/// the one we are standing on is the case worth trying, and the rest of the block is
/// covered by the ordered pass that follows.
fn neighbourhoods(address: Ipv4Addr, block: Ipv4Net) -> Vec<Ipv4Net> {
    const WINDOW: i32 = 8;
    let octets = address.octets();
    let mut out = Vec::new();

    for offset in -WINDOW..=WINDOW {
        let third = octets[2] as i32 + offset;
        if !(0..=255).contains(&third) {
            continue;
        }
        let candidate = Ipv4Addr::new(octets[0], octets[1], third as u8, 0);
        if !block.contains(&candidate) {
            continue;
        }
        if let Ok(subnet) = Ipv4Net::new(candidate, 24) {
            out.push(subnet.trunc());
        }
    }
    out
}

/// A specific host address inside a /24.
fn host_in(subnet: Ipv4Net, host: u8) -> Ipv4Addr {
    let mut octets = subnet.network().octets();
    octets[3] = host;
    Ipv4Addr::from(octets)
}

/// How much of the candidate space the budget actually covered.
///
/// Reported because "510 silent" means something different across 256 subnets than across
/// 65,536: on a /8 the budget can only sample, and a sample that found nothing has not
/// examined the block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Coverage {
    /// /24s a candidate was generated for.
    pub sampled_subnets: usize,
    /// /24s the enclosing private blocks hold in total.
    pub total_subnets: usize,
}

impl Coverage {
    pub fn describe(&self) -> String {
        if self.sampled_subnets >= self.total_subnets {
            return format!("all {} /24(s) in the enclosing block", self.total_subnets);
        }
        format!(
            "{} of {} /24(s) sampled across the enclosing block",
            self.sampled_subnets, self.total_subnets
        )
    }
}

/// What one bounded pass asked and what answered.
#[derive(Debug, Clone, Default)]
pub struct ReachabilitySweep {
    /// Every address asked, in the order they were asked.
    pub asked: Vec<Ipv4Addr>,
    /// Addresses that answered as themselves.
    pub responded: Vec<Ipv4Addr>,
    /// Whether the candidate list was cut short by the budget rather than exhausted.
    pub budget_exhausted: bool,
}

impl ReachabilitySweep {
    /// Candidates that did not answer. Not "absent": an address that ignores ICMP and one
    /// that does not exist are indistinguishable from here.
    pub fn silent(&self) -> usize {
        self.asked.len() - self.responded.len()
    }
}

/// Whether a datagram is the Echo Reply belonging to one specific probe.
///
/// The rule that keeps this honest: the source must be the address that was asked. A Time
/// Exceeded from an intermediate router proves that router forwards our traffic -- which is
/// worth knowing and is what the egress-path provider records -- but it says nothing about
/// whether the address we asked about exists at all. Accepting one here would create a
/// device for an address nobody answered for.
pub fn is_exact_reply(
    datagram: &[u8],
    identifier: u16,
    sequence: u16,
    from: Ipv4Addr,
    target: Ipv4Addr,
) -> bool {
    if from != target {
        return false;
    }
    let Some(icmp) = crate::probes::path::icmp_message(datagram) else {
        return false;
    };
    // Type 0 is Echo Reply. Type 11 (Time Exceeded) and type 3 (Destination Unreachable)
    // are answers from somewhere else about the target, not answers from the target.
    if icmp.len() < 8 || icmp[0] != 0 || icmp[1] != 0 {
        return false;
    }
    u16::from_be_bytes([icmp[4], icmp[5]]) == identifier
        && u16::from_be_bytes([icmp[6], icmp[7]]) == sequence
}

/// What one echo established: unavailable, not sent, silent, or answered.
pub type EchoOutcome = crate::probes::attempt::AttemptOutcome<Ipv4Addr>;

/// Asks one address to answer for itself, over the interface-bound correlated ICMP path.
///
/// Returns what actually happened rather than a bare bool. The distinction is the whole
/// point: a socket that would not open, a send that failed and an address that stayed
/// silent are three different findings, and collapsing them into `false` let a run report
/// a quiet network when nothing had left this machine.
#[cfg(unix)]
pub async fn echo(
    target: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    binding: &crate::net::socket::SocketBinding,
    budget: std::time::Duration,
) -> EchoOutcome {
    let sent = format!("ICMP echo request to {target}");
    let Some(socket) = crate::probes::path::icmp_socket() else {
        return EchoOutcome::unavailable(
            "an ICMP datagram socket could not be opened on this host".to_string(),
        );
    };
    // Bound to the selected interface, like every other active probe. An unbound socket
    // follows ordinary routing and can leave through an interface the operator did not
    // choose, which attributes the answer to a vantage that never carried it.
    if binding.bind_icmp(&socket).is_err() {
        return EchoOutcome::not_sent(
            "the ICMP socket could not be bound to the selected interface".to_string(),
        );
    }
    let destination = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(target, 0));
    if socket
        .send_to(
            &crate::probes::path::echo_request(identifier, sequence),
            destination,
        )
        .await
        .is_err()
    {
        return EchoOutcome::not_sent(format!("the echo request to {target} could not be sent"));
    }

    let deadline = tokio::time::Instant::now() + budget;
    let mut buffer = [0u8; 1500];
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Ok(Ok((length, from))) =
            tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await
        else {
            continue;
        };
        let std::net::IpAddr::V4(from) = from.ip() else {
            continue;
        };
        if is_exact_reply(&buffer[..length], identifier, sequence, from, target) {
            return EchoOutcome::Answered {
                sent,
                result: target,
            };
        }
    }
    EchoOutcome::NoResponse { sent }
}

/// Where raw ICMP cannot be opened at all.
#[cfg(not(unix))]
pub async fn echo(
    target: Ipv4Addr,
    _identifier: u16,
    _sequence: u16,
    _binding: &crate::net::socket::SocketBinding,
    _budget: std::time::Duration,
) -> EchoOutcome {
    let _ = target;
    EchoOutcome::unavailable("raw ICMP is not available on this platform".to_string())
}

/// Probes one candidate and reports whether that exact address answered.
#[cfg(unix)]
pub async fn probe(
    target: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    binding: &crate::net::socket::SocketBinding,
    budget: std::time::Duration,
) -> bool {
    echo(target, identifier, sequence, binding, budget)
        .await
        .result()
        .is_some()
}

/// Asks one candidate every cheap question and keeps every answer.
///
/// Deliberately not first-answer-wins. Stopping early made the set of signals a function of
/// which probe finished first, so a device that answers ICMP and TCP could be attributed to
/// either depending on timing -- and the report claimed seven probes were attempted when
/// four of them never ran. Every question is asked, every answer is retained, and the order
/// is fixed, so two runs against an unchanged device produce the same attribution.
///
/// The set stays small: five TCP ports and two UDP protocols per candidate. The full
/// interrogation is the per-device pipeline's work and runs only after this finds something.
pub async fn probe_signals(
    target: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    channel: &crate::net::socket::ProbeChannel,
    budget: std::time::Duration,
) -> Vec<ResponseSignal> {
    let mut answers = Vec::new();

    if probe(target, identifier, sequence, &channel.binding, budget).await {
        answers.push(ResponseSignal::Icmp);
    }

    // A completed handshake and a reset are equally answers: one says the port is open, the
    // other says the host is there and the port is closed.
    for port in INFRASTRUCTURE_TCP_PORTS {
        let destination = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(target, port));
        match channel.binding.tcp_connect(destination, budget).await {
            Ok(_) => answers.push(ResponseSignal::TcpOpen(port)),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                answers.push(ResponseSignal::TcpRefused(port));
            }
            Err(_) => {}
        }
    }

    // UDP, for the interfaces that answer a protocol and nothing else. Any correlated
    // answer counts, identity or not: speaking DNS at all is the target answering for
    // itself.
    let endpoint = crate::net::endpoint::Endpoint::global(std::net::IpAddr::V4(target));
    if crate::probes::dns::identify(&endpoint, "version.bind", &channel.binding, budget)
        .await
        .is_some()
    {
        answers.push(ResponseSignal::Dns);
    }
    if crate::probes::natpmp::probe_nat_gateway(target, &channel.binding, budget)
        .await
        .is_some()
    {
        answers.push(ResponseSignal::NatPmp);
    }

    answers
}

/// Which source a set of signals is attributed to.
///
/// Fixed precedence, never arrival order: the same device answering the same way must be
/// attributed the same way on every run.
pub fn attribution(signals: &[ResponseSignal]) -> Option<&ResponseSignal> {
    const ORDER: [u8; 5] = [0, 1, 2, 3, 4];
    let rank = |signal: &ResponseSignal| match signal {
        ResponseSignal::Icmp => ORDER[0],
        ResponseSignal::TcpOpen(_) => ORDER[1],
        ResponseSignal::TcpRefused(_) => ORDER[2],
        ResponseSignal::Dns => ORDER[3],
        ResponseSignal::NatPmp => ORDER[4],
    };
    signals.iter().min_by_key(|signal| rank(signal))
}

/// Where raw ICMP cannot be opened, nothing is asked and nothing answers.
#[cfg(not(unix))]
pub async fn probe(
    _target: Ipv4Addr,
    _identifier: u16,
    _sequence: u16,
    _binding: &crate::net::socket::SocketBinding,
    _budget: std::time::Duration,
) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known() -> BTreeSet<Ipv4Addr> {
        BTreeSet::new()
    }

    #[test]
    fn candidates_are_gateway_addresses_and_never_whole_subnets() {
        // The constraint that keeps this from being a scan: two addresses per /24, not 254.
        let list = candidates(&[Ipv4Addr::new(192, 168, 1, 119)], &known(), 64);
        assert!(!list.is_empty());
        for address in &list {
            let last = address.octets()[3];
            assert!(
                GATEWAY_HOSTS.contains(&last),
                "{address} is not a gateway candidate"
            );
        }
    }

    #[test]
    fn the_order_is_deterministic_and_starts_at_the_observed_neighbourhood() {
        let observed = [Ipv4Addr::new(192, 168, 1, 119)];
        let first = candidates(&observed, &known(), 40);
        let second = candidates(&observed, &known(), 40);
        assert_eq!(first, second, "two runs must probe the same addresses");

        // The window is eight /24s either side of what was seen, so the first twenty
        // candidates are all near 192.168.1.x, before the ordered pass over the block.
        assert!(
            first
                .iter()
                .take(20)
                .all(|address| address.octets()[2] <= 9),
            "the neighbourhood comes first: {first:?}"
        );
        assert_eq!(first[0], Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(first[1], Ipv4Addr::new(192, 168, 0, 254));
    }

    #[test]
    fn a_cascaded_network_in_the_same_block_is_reachable_in_the_ordered_pass() {
        // 192.168.51.1 is not in the neighbourhood window around 192.168.1.119, so it must
        // still be reached by the ordered pass over the enclosing /16.
        let list = candidates(&[Ipv4Addr::new(192, 168, 1, 119)], &known(), 4096);
        assert!(list.contains(&Ipv4Addr::new(192, 168, 51, 1)));
        assert!(list.contains(&Ipv4Addr::new(192, 168, 51, 254)));
    }

    #[test]
    fn the_limit_bounds_the_work_and_is_reported() {
        let list = candidates(&[Ipv4Addr::new(10, 1, 2, 3)], &known(), 16);
        assert_eq!(list.len(), 16, "the budget is a hard bound, not a target");

        // 10.0.0.0/8 holds 65536 /24s; without the bound this would be 131072 probes.
        let unbounded = candidates(&[Ipv4Addr::new(10, 1, 2, 3)], &known(), 200);
        assert_eq!(unbounded.len(), 200);
    }

    #[test]
    fn a_large_block_is_sampled_across_its_whole_range_not_its_first_corner() {
        // Taking the first N /24s of a /8 examined its lowest quarter-percent and left the
        // rest unasked while the report read as though the block had been covered.
        let (list, coverage) =
            candidates_with_coverage(&[Ipv4Addr::new(10, 1, 2, 3)], &known(), 512);
        assert_eq!(list.len(), 512);
        assert_eq!(coverage.total_subnets, 65536);
        assert!(coverage.sampled_subnets <= 512);
        assert!(
            coverage.describe().contains("of 65536"),
            "the report must say it sampled: {}",
            coverage.describe()
        );

        // The sample reaches the far end of the block, not merely 10.0.x and 10.1.x.
        let highest = list
            .iter()
            .map(|address| address.octets()[1])
            .max()
            .expect("candidates exist");
        assert!(
            highest > 200,
            "the stride must span the /8, saw up to 10.{highest}.x.x"
        );

        // A /16 fits inside the budget exactly, so it is covered rather than sampled.
        let (_, covered) =
            candidates_with_coverage(&[Ipv4Addr::new(192, 168, 1, 119)], &known(), 512);
        assert_eq!(covered.total_subnets, 256);
        assert_eq!(covered.sampled_subnets, 256);
        assert!(covered.describe().starts_with("all 256"));
    }

    #[test]
    fn a_positive_response_expands_the_search_around_it() {
        // Networks are provisioned in runs: the /24s beside a live router interface are
        // worth asking about before the far end of the block.
        let around = expand_around(Ipv4Addr::new(192, 168, 51, 1));
        assert!(around.contains(&Ipv4Addr::new(192, 168, 52, 1)));
        assert!(around.contains(&Ipv4Addr::new(192, 168, 50, 254)));
        assert!(
            !around.contains(&Ipv4Addr::new(192, 168, 51, 1)),
            "the address that answered is not re-asked"
        );
        for address in &around {
            assert!(enclosing_private_block(*address).is_some());
        }
        assert!(expand_around(Ipv4Addr::new(8, 8, 8, 8)).is_empty());
    }

    #[test]
    fn attribution_is_by_fixed_precedence_and_never_by_arrival() {
        // Evidence attribution must not depend on which probe finished first: the same
        // device answering the same way is attributed the same way on every run.
        let both = [
            ResponseSignal::TcpOpen(80),
            ResponseSignal::Icmp,
            ResponseSignal::Dns,
        ];
        assert_eq!(attribution(&both), Some(&ResponseSignal::Icmp));

        let reversed = [
            ResponseSignal::Dns,
            ResponseSignal::Icmp,
            ResponseSignal::TcpOpen(80),
        ];
        assert_eq!(
            attribution(&both),
            attribution(&reversed),
            "order of discovery must not change attribution"
        );

        // An open port outranks a reset, which outranks the UDP protocols.
        assert_eq!(
            attribution(&[ResponseSignal::TcpRefused(22), ResponseSignal::TcpOpen(443)]),
            Some(&ResponseSignal::TcpOpen(443))
        );
        assert_eq!(
            attribution(&[ResponseSignal::NatPmp, ResponseSignal::TcpRefused(22)]),
            Some(&ResponseSignal::TcpRefused(22))
        );
        assert_eq!(attribution(&[]), None);
    }

    #[test]
    fn every_signal_a_candidate_can_answer_with_is_named() {
        // "Silent" is only meaningful when the reader knows what was asked. A router that
        // suppresses ICMP but answers TCP or DNS is not silent, and the previous pass
        // recorded it as such.
        let attempted = probes_attempted();
        assert!(attempted.contains("ICMP echo"));
        assert!(attempted.contains("TCP 53/80/443/22/8080"));
        assert!(attempted.contains("UDP DNS 53"));
        assert!(attempted.contains("NAT-PMP 5351"));

        assert_eq!(ResponseSignal::Icmp.label(), "ICMP echo reply");
        assert_eq!(ResponseSignal::TcpOpen(443).label(), "TCP 443 accepted");
        // A reset is an answer: the port is closed and the host is there.
        assert_eq!(ResponseSignal::TcpRefused(22).label(), "TCP 22 refused");
        assert_eq!(ResponseSignal::Dns.label(), "DNS response");
        assert_eq!(ResponseSignal::NatPmp.label(), "NAT-PMP response");
    }

    #[test]
    fn addresses_already_established_are_not_probed_again() {
        let mut known = BTreeSet::new();
        known.insert(Ipv4Addr::new(192, 168, 1, 1));
        let list = candidates(&[Ipv4Addr::new(192, 168, 1, 119)], &known, 64);
        assert!(
            !list.contains(&Ipv4Addr::new(192, 168, 1, 1)),
            "something already established this address"
        );
    }

    #[test]
    fn only_private_space_is_probed() {
        // A public address is not the operator's to probe on a guess.
        assert!(candidates(&[Ipv4Addr::new(8, 8, 8, 8)], &known(), 64).is_empty());
        assert_eq!(
            enclosing_private_block(Ipv4Addr::new(172, 20, 5, 5)),
            Some("172.16.0.0/12".parse().unwrap())
        );
        assert_eq!(enclosing_private_block(Ipv4Addr::new(203, 0, 113, 1)), None);

        for address in candidates(&[Ipv4Addr::new(172, 20, 5, 5)], &known(), 64) {
            assert!(enclosing_private_block(address).is_some());
        }
    }

    #[test]
    fn only_the_target_answering_for_itself_counts() {
        // A Time Exceeded proves an intermediate router forwards; it does not prove the
        // address we asked about exists, and creating a device from one would put an
        // address on the map that nobody answered for.
        let target = Ipv4Addr::new(192, 168, 51, 1);
        let mut echo_reply = vec![0u8, 0, 0, 0];
        echo_reply.extend_from_slice(&0x2b1du16.to_be_bytes());
        echo_reply.extend_from_slice(&7u16.to_be_bytes());
        assert!(is_exact_reply(&echo_reply, 0x2b1d, 7, target, target));

        // From a different address: an answer about the target, not from it.
        let hop = Ipv4Addr::new(192, 168, 1, 1);
        assert!(!is_exact_reply(&echo_reply, 0x2b1d, 7, hop, target));

        // Time Exceeded, even from the target's own address, is not an echo reply.
        let mut expired = echo_reply.clone();
        expired[0] = 11;
        assert!(!is_exact_reply(&expired, 0x2b1d, 7, target, target));

        // Destination Unreachable, likewise.
        let mut unreachable = echo_reply.clone();
        unreachable[0] = 3;
        assert!(!is_exact_reply(&unreachable, 0x2b1d, 7, target, target));

        // Another program's exchange.
        assert!(!is_exact_reply(&echo_reply, 0x1111, 7, target, target));
        assert!(!is_exact_reply(&echo_reply, 0x2b1d, 8, target, target));
    }

    #[test]
    fn silence_is_counted_and_never_called_absence() {
        let sweep = ReachabilitySweep {
            asked: vec![
                Ipv4Addr::new(192, 168, 51, 1),
                Ipv4Addr::new(192, 168, 52, 1),
            ],
            responded: vec![Ipv4Addr::new(192, 168, 51, 1)],
            budget_exhausted: false,
        };
        assert_eq!(sweep.silent(), 1);
    }
}
