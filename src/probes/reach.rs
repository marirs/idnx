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
    let mut ordered: Vec<Ipv4Addr> = Vec::new();
    let mut seen: BTreeSet<Ipv4Addr> = BTreeSet::new();

    let push = |address: Ipv4Addr, ordered: &mut Vec<Ipv4Addr>, seen: &mut BTreeSet<Ipv4Addr>| {
        if known.contains(&address) || !seen.insert(address) {
            return;
        }
        ordered.push(address);
    };

    // Neighbourhoods first, in the order the observations were given, so the addresses
    // nearest to what this vantage has actually seen are probed before the wider block.
    for address in observed {
        let Some(block) = enclosing_private_block(*address) else {
            continue;
        };
        for neighbourhood in neighbourhoods(*address, block) {
            for host in GATEWAY_HOSTS {
                push(host_in(neighbourhood, host), &mut ordered, &mut seen);
                if ordered.len() >= limit {
                    ordered.truncate(limit);
                    return ordered;
                }
            }
        }
    }

    // Then the rest of each enclosing block, in address order.
    let mut blocks: Vec<Ipv4Net> = observed
        .iter()
        .filter_map(|address| enclosing_private_block(*address))
        .collect();
    blocks.sort_by_key(|block| block.network());
    blocks.dedup();

    for block in blocks {
        for subnet in block.subnets(24).into_iter().flatten() {
            for host in GATEWAY_HOSTS {
                push(host_in(subnet, host), &mut ordered, &mut seen);
                if ordered.len() >= limit {
                    ordered.truncate(limit);
                    return ordered;
                }
            }
        }
    }

    ordered.truncate(limit);
    ordered
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

/// Probes one candidate and reports whether that exact address answered.
///
/// Unix only, like every raw-ICMP path in this crate: elsewhere there is no socket to open,
/// and the provider reports the probe as unavailable rather than reporting silence.
#[cfg(unix)]
pub async fn probe(
    target: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    binding: &crate::net::socket::SocketBinding,
    budget: std::time::Duration,
) -> bool {
    let Some(socket) = crate::probes::path::icmp_socket() else {
        return false;
    };
    if binding.bind_icmp(&socket).is_err() {
        return false;
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
        return false;
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
            return true;
        }
    }
    false
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
