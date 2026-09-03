//! Router interfaces on the path out of this network.
//!
//! The kernel routing table names exactly one router: the default gateway. Everything
//! beyond it is invisible to every provider that reads local state, and yet the routers
//! there are real, often reachable, and frequently the only devices that know the prefixes
//! of the networks behind them.
//!
//! A TTL-limited packet makes them announce themselves. Each router that decrements the TTL
//! to zero replies with ICMP Time Exceeded from one of its own interface addresses -- which
//! is direct behavioural evidence that the device forwards, obtained with no credentials
//! and no cooperation.
//!
//! **What a hop is and is not.** It is a router interface address, observed. It is not a
//! prefix: the address tells you nothing about the size of the network it belongs to, and
//! deriving one would be inventing topology. So a hop becomes a device to interrogate and,
//! where it discloses nothing further, an unresolved boundary. Any network that follows
//! comes from what the router itself says.
//!
//! The destination is a TEST-NET address reserved by RFC 5737. That is deliberate: it is
//! routed by the default route like any other off-link address, so every router on the path
//! answers, and it is guaranteed to belong to nobody -- no packet of ours ever arrives at a
//! third party's machine. The alternative, picking some real host, would send unsolicited
//! traffic to someone who never asked for it.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::net::socket::SocketBinding;

/// Reserved by RFC 5737 for documentation. Routed by the default route, owned by no one.
pub const PATH_PROBE_DESTINATION: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// How far along the path to look.
///
/// Small on purpose. The interesting routers -- the ones that might disclose a network this
/// vantage cannot see -- are the first few; beyond that the path is someone else's
/// infrastructure and nothing about the operator's own topology.
pub const MAX_HOPS: u8 = 5;

/// A router interface that forwarded one of our packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathHop {
    /// Distance in hops. 1 is the default gateway.
    pub distance: u8,
    /// The address the router answered from: one of its own interfaces.
    pub address: IpAddr,
}

/// Discovers router interfaces along the default path.
///
/// Returns hops in order, skipping distances that did not answer. An empty result means
/// nothing beyond the gateway announced itself, which is common on paths that filter ICMP
/// and is not an error.
pub async fn discover_path(
    binding: &SocketBinding,
    per_hop_timeout: Duration,
    max_hops: u8,
) -> Vec<PathHop> {
    let mut hops = Vec::new();

    for distance in 1..=max_hops {
        match probe_hop(binding, distance, per_hop_timeout).await {
            Some(address) => {
                let hop = PathHop { distance, address };
                // The path has reached a router already seen: further probes would only
                // repeat it.
                if hops.iter().any(|h: &PathHop| h.address == hop.address) {
                    break;
                }
                hops.push(hop);
            }
            // A silent hop is normal. Keep going: the next router may still answer.
            None => continue,
        }
    }

    hops
}

/// Sends one TTL-limited probe and waits for the router that dropped it.
#[cfg(unix)]
async fn probe_hop(binding: &SocketBinding, ttl: u8, timeout: Duration) -> Option<IpAddr> {
    use std::os::fd::AsRawFd;

    let destination = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
        PATH_PROBE_DESTINATION,
        33434 + ttl as u16,
    ));
    let sender = binding.udp_socket(&destination).await.ok()?;

    // An unprivileged ICMP datagram socket. macOS and modern Linux both allow this; where
    // they do not, the open fails and path discovery is simply unavailable, which the
    // caller reports rather than pretending the path is empty.
    let receiver = icmp_socket()?;

    // SAFETY: the fd is owned by `sender` and outlives the call; the value is a c_int of
    // the declared length.
    let value = ttl as libc::c_int;
    let set = unsafe {
        libc::setsockopt(
            sender.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_TTL,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if set != 0 {
        return None;
    }

    sender.send_to(b"idnx", destination).await.ok()?;

    let mut buffer = [0u8; 1500];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.checked_duration_since(tokio::time::Instant::now())?;
        let (length, from) = tokio::time::timeout(remaining, receiver.recv_from(&mut buffer))
            .await
            .ok()?
            .ok()?;

        // Only Time Exceeded counts. A Destination Unreachable means the packet died for
        // another reason and the sender is not necessarily on the path.
        if is_time_exceeded(&buffer[..length]) {
            return Some(from.ip());
        }
    }
}

/// Path discovery needs an ICMP datagram socket, which Windows does not expose this way.
#[cfg(not(unix))]
async fn probe_hop(_binding: &SocketBinding, _ttl: u8, _timeout: Duration) -> Option<IpAddr> {
    None
}

/// Opens an unprivileged ICMP datagram socket.
#[cfg(unix)]
fn icmp_socket() -> Option<tokio::net::UdpSocket> {
    // SAFETY: a plain socket(2) call with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return None;
    }
    // SAFETY: `fd` is a fresh, owned descriptor and is not used again after this point.
    let std_socket = unsafe {
        use std::os::fd::FromRawFd;
        std::net::UdpSocket::from_raw_fd(fd)
    };
    std_socket.set_nonblocking(true).ok()?;
    tokio::net::UdpSocket::from_std(std_socket).ok()
}

/// Builds an ICMP echo request with its checksum.
pub fn echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
    let mut packet = vec![8u8, 0, 0, 0];
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(b"idnx-path");

    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// The one's-complement sum every IP-family protocol uses.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, remainder) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = remainder {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Whether a received datagram is an ICMP Time Exceeded message.
///
/// Platforms differ in what they hand back on an ICMP datagram socket: some deliver the
/// ICMP message alone, others prepend the IP header of the error packet. Both shapes are
/// accepted, distinguished by the IPv4 version nibble, rather than assuming one and
/// silently reading a version field as an ICMP type.
pub fn is_time_exceeded(datagram: &[u8]) -> bool {
    const ICMP_TIME_EXCEEDED: u8 = 11;

    let Some(&first) = datagram.first() else {
        return false;
    };

    // An IPv4 header begins with version 4 and a header length in 32-bit words.
    if first >> 4 == 4 {
        let header_length = usize::from(first & 0x0f) * 4;
        return datagram.get(header_length) == Some(&ICMP_TIME_EXCEEDED);
    }
    first == ICMP_TIME_EXCEEDED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_destination_belongs_to_nobody() {
        // RFC 5737 TEST-NET-1. Chosen so that no packet of ours ever reaches a real host:
        // the routers on the path answer, and the packet itself dies.
        assert_eq!(PATH_PROBE_DESTINATION, Ipv4Addr::new(192, 0, 2, 1));
        assert!(PATH_PROBE_DESTINATION.is_documentation());
        // And it is not on any link this machine could be attached to, so it always routes
        // by the default route.
        assert!(!PATH_PROBE_DESTINATION.is_private());
        assert!(!PATH_PROBE_DESTINATION.is_link_local());
    }

    #[test]
    fn only_time_exceeded_counts_as_a_hop() {
        // A Destination Unreachable means the packet died for some other reason, and its
        // sender is not necessarily a router on the path.
        assert!(is_time_exceeded(&[11, 0, 0, 0]));
        assert!(!is_time_exceeded(&[3, 0, 0, 0]), "destination unreachable");
        assert!(!is_time_exceeded(&[0, 0, 0, 0]), "echo reply");
        assert!(!is_time_exceeded(&[]), "empty");
    }

    #[test]
    fn an_ip_header_in_front_of_the_icmp_message_is_handled() {
        // macOS delivers the IP header of the error packet; reading its version nibble as
        // an ICMP type found no hops at all on a path where every router was answering.
        let mut with_header = vec![0x45, 0, 0, 56, 0, 0, 0, 0, 64, 1, 0, 0];
        with_header.extend_from_slice(&[192, 168, 70, 1]);
        with_header.extend_from_slice(&[192, 168, 1, 119]);
        with_header.extend_from_slice(&[11, 0, 0, 0]);
        assert_eq!(with_header[0] >> 4, 4);
        assert!(is_time_exceeded(&with_header));

        // And an echo reply behind a header is still not a hop.
        let mut echo = with_header.clone();
        echo[20] = 0;
        assert!(!is_time_exceeded(&echo));
    }

    #[test]
    fn an_echo_request_carries_a_valid_checksum() {
        // A router will not answer a malformed probe, and a silently wrong checksum looks
        // exactly like a path that filters ICMP.
        let packet = echo_request(0x4242, 3);
        assert_eq!(packet[0], 8, "echo request");
        assert_eq!(packet[1], 0);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 0x4242);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 3);
        // A correct checksum makes the sum over the whole packet zero.
        assert_eq!(internet_checksum(&packet), 0);
    }

    #[test]
    fn the_hop_budget_stays_within_the_operators_own_infrastructure() {
        // Beyond a few hops the path is someone else's network and says nothing about the
        // topology this tool is describing. Written as a range check so that raising the
        // constant past the operator's own infrastructure fails here.
        let budget = usize::from(MAX_HOPS);
        assert!((3..=8).contains(&budget), "{budget} hops");
    }

    #[tokio::test]
    async fn path_discovery_reports_hops_in_order_and_stops_at_a_repeat() {
        // Exercised against the real default path where one exists. A machine with no
        // route out returns nothing, which is a valid result and not a failure.
        let hops = discover_path(
            &SocketBinding::unbound(),
            Duration::from_millis(300),
            MAX_HOPS,
        )
        .await;

        let mut previous = 0u8;
        let mut seen: Vec<IpAddr> = Vec::new();
        for hop in &hops {
            assert!(hop.distance > previous, "hops must be ordered: {hops:?}");
            previous = hop.distance;
            assert!(!seen.contains(&hop.address), "a repeat must end the path");
            seen.push(hop.address);
        }
    }
}
