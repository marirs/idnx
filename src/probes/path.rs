//! Router interfaces on the default egress path.
//!
//! The kernel routing table names exactly one router: the default gateway. The routers
//! beyond it are invisible to every provider that reads local state, and yet they are real
//! and frequently reachable.
//!
//! A TTL-limited ICMP echo makes them announce themselves. Each router that decrements the
//! hop count to zero replies with Time Exceeded from one of its own interface addresses,
//! which is behavioural evidence that the interface forwards IPv4 -- obtained with no
//! credentials and no cooperation.
//!
//! **What a hop proves, exactly.** That an interface at that address forwarded one packet,
//! at that distance, toward one destination, from this vantage. It proves nothing else. Not
//! a prefix: the address says nothing about the size of the network it belongs to. Not
//! opacity: a router that forwards is not thereby hiding anything. Not NAT. Not ownership:
//! hop count is not administrative boundary, and a router four hops out is as likely to
//! belong to a carrier as to the operator. Everything beyond "this interface forwards" has
//! to come from interrogating the device itself.
//!
//! The destination is a TEST-NET address reserved by RFC 5737. It routes by the default
//! route like any other off-link address, so the routers on the path answer. It is not a
//! guarantee of containment -- a router with a default route of its own will forward it
//! onward until something drops it -- but it is addressed to a block nobody is permitted to
//! use for real hosts, so it cannot arrive at a service anyone is running.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::net::socket::SocketBinding;

/// Reserved by RFC 5737 for documentation, so no real host holds it.
pub const PATH_PROBE_DESTINATION: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// ICMP message types used here.
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;

/// How far along the path to look.
///
/// A budget, not a boundary. Hop count says nothing about who owns a router, and this
/// number does not mark the edge of the operator's network -- it only bounds how many
/// probes one run sends.
pub const MAX_HOPS: u8 = 5;

/// A router interface that forwarded one of our probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathHop {
    /// Distance in hops. 1 is the default gateway.
    pub distance: u8,
    /// The address the router answered from: one of its own interfaces.
    pub address: IpAddr,
    /// Where the probe was headed. Part of the finding: an interface forwards *toward*
    /// something, and a different destination may take a different path.
    pub toward: IpAddr,
    /// The previous responding hop, when there was one. What makes the path a path.
    pub previous: Option<IpAddr>,
}

/// What a probe was, so its errors can be recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeIdentity {
    /// Per-run value, so another process's traceroute is not mistaken for ours.
    pub identifier: u16,
    /// The hop distance this probe was sent at.
    pub sequence: u16,
    pub destination: Ipv4Addr,
}

/// Discovers router interfaces along the default egress path.
///
/// An empty result means nothing answered, which is common where ICMP is filtered and is
/// not an error.
pub async fn discover_path(
    binding: &SocketBinding,
    per_hop_timeout: Duration,
    max_hops: u8,
) -> Vec<PathHop> {
    let identifier = probe_identifier();
    let mut hops: Vec<PathHop> = Vec::new();
    let mut previous: Option<IpAddr> = None;

    for distance in 1..=max_hops {
        let identity = ProbeIdentity {
            identifier,
            sequence: u16::from(distance),
            destination: PATH_PROBE_DESTINATION,
        };

        match probe_hop(binding, distance, identity, per_hop_timeout).await {
            Some(address) => {
                // The path has reached a router already seen: further probes only repeat it.
                if hops.iter().any(|h| h.address == address) {
                    break;
                }
                hops.push(PathHop {
                    distance,
                    address,
                    toward: IpAddr::V4(PATH_PROBE_DESTINATION),
                    previous,
                });
                previous = Some(address);
            }
            // A silent hop is normal. Keep going: the next router may still answer, and the
            // gap is preserved by the distance rather than by position.
            None => continue,
        }
    }

    hops
}

/// A per-run probe identifier.
///
/// Distinguishes our echoes from any other program's on the same machine, so an unrelated
/// traceroute's Time Exceeded is not read as one of our hops.
fn probe_identifier() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(0);

    let ordinal = COUNTER.fetch_add(1, Ordering::Relaxed);
    (std::process::id() as u16) ^ ordinal.rotate_left(8) ^ 0x9e37
}

/// Sends one TTL-limited ICMP echo and waits for the router that dropped it.
///
/// One socket, so the echo and its error share a kernel association; an unprivileged ICMP
/// datagram socket only receives errors belonging to its own messages, and a probe sent on
/// a different socket produces errors nothing here can see.
#[cfg(unix)]
async fn probe_hop(
    binding: &SocketBinding,
    ttl: u8,
    identity: ProbeIdentity,
    timeout: Duration,
) -> Option<IpAddr> {
    use std::os::fd::AsRawFd;

    let destination =
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(identity.destination, 0));
    let socket = icmp_socket()?;

    // Both directions on this one socket, so the path discovered is the path out of the
    // selected interface rather than whichever the routing table would otherwise prefer.
    binding.bind_icmp(&socket).ok()?;
    if let Some(local) = binding.local_address_for(&destination) {
        // Binding the source address as well, for the platforms where the interface option
        // is unavailable or was refused.
        let _ = bind_source(&socket, local);
    }

    // SAFETY: the fd is owned by `socket` and outlives the call; the value is a c_int of
    // the declared length.
    let value = ttl as libc::c_int;
    let set = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_TTL,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if set != 0 {
        return None;
    }

    socket
        .send_to(
            &echo_request(identity.identifier, identity.sequence),
            destination,
        )
        .await
        .ok()?;

    let mut buffer = [0u8; 1500];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.checked_duration_since(tokio::time::Instant::now())?;
        let (length, from) = tokio::time::timeout(remaining, socket.recv_from(&mut buffer))
            .await
            .ok()?
            .ok()?;

        // Correlated, not merely typed. Any unrelated Time Exceeded arriving inside the
        // window would otherwise be recorded as a hop on our path.
        if matches_probe(&buffer[..length], identity) {
            return Some(from.ip());
        }
    }
}

/// Path discovery needs an ICMP datagram socket, which Windows does not expose this way.
#[cfg(not(unix))]
async fn probe_hop(
    _binding: &SocketBinding,
    _ttl: u8,
    _identity: ProbeIdentity,
    _timeout: Duration,
) -> Option<IpAddr> {
    None
}

/// Binds a socket to a source address.
#[cfg(unix)]
fn bind_source(socket: &tokio::net::UdpSocket, local: std::net::SocketAddr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let std::net::SocketAddr::V4(v4) = local else {
        return Ok(());
    };
    let address = libc::sockaddr_in {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(v4.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: the fd is owned by `socket`, and the address is a well-formed sockaddr_in of
    // the length declared.
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            std::ptr::addr_of!(address).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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
    let mut packet = vec![ICMP_ECHO_REQUEST, 0, 0, 0];
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

/// Whether a received datagram is the Time Exceeded belonging to one specific probe.
///
/// An ICMP error carries the head of the packet that caused it, and that copy is what makes
/// correlation possible: the embedded destination, protocol, message type, identifier and
/// sequence must all match the probe that was sent. Checking only the outer type would
/// accept any Time Exceeded that happened to arrive -- another program's traceroute, or a
/// stale error from a probe several hops ago -- and record it as a hop on this path.
pub fn matches_probe(datagram: &[u8], identity: ProbeIdentity) -> bool {
    let Some(icmp) = icmp_message(datagram) else {
        return false;
    };
    if icmp.first() != Some(&ICMP_TIME_EXCEEDED) {
        return false;
    }

    // Type, code and the four unused bytes, then the offending packet.
    let embedded = icmp.get(8..).unwrap_or_default();
    let Some(&first) = embedded.first() else {
        return false;
    };
    if first >> 4 != 4 {
        return false;
    }
    let header_length = usize::from(first & 0x0f) * 4;
    if header_length < 20 || embedded.len() < header_length + 8 {
        return false;
    }

    // The embedded packet must be the ICMP echo we sent, to the destination we chose.
    if embedded.get(9) != Some(&(libc_icmp_protocol())) {
        return false;
    }
    let Some(destination) = embedded.get(16..20) else {
        return false;
    };
    if destination != identity.destination.octets() {
        return false;
    }

    let inner = &embedded[header_length..];
    if inner.first() != Some(&ICMP_ECHO_REQUEST) {
        return false;
    }
    let (Some(id), Some(sequence)) = (inner.get(4..6), inner.get(6..8)) else {
        return false;
    };

    u16::from_be_bytes([id[0], id[1]]) == identity.identifier
        && u16::from_be_bytes([sequence[0], sequence[1]]) == identity.sequence
}

/// The IPv4 protocol number for ICMP.
const fn libc_icmp_protocol() -> u8 {
    1
}

/// Strips the IP header some platforms prepend to an ICMP datagram.
///
/// macOS delivers the IP header of the error packet; Linux delivers the ICMP message alone.
/// Assuming one shape read a version nibble as a message type and found no hops at all on a
/// path where every router was answering.
fn icmp_message(datagram: &[u8]) -> Option<&[u8]> {
    let &first = datagram.first()?;
    if first >> 4 == 4 {
        let header_length = usize::from(first & 0x0f) * 4;
        return datagram.get(header_length..);
    }
    Some(datagram)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUR_ADDRESS: [u8; 4] = [192, 168, 1, 119];

    fn identity() -> ProbeIdentity {
        ProbeIdentity {
            identifier: 0xbeef,
            sequence: 2,
            destination: PATH_PROBE_DESTINATION,
        }
    }

    /// Builds an ICMP Time Exceeded carrying the head of a probe.
    ///
    /// Modelled on a real reply captured from the router at hop 2, so the fixtures exercise
    /// the layout the parser actually meets rather than an idealised one.
    fn time_exceeded(
        outer_header: bool,
        destination: [u8; 4],
        protocol: u8,
        inner_type: u8,
        identifier: u16,
        sequence: u16,
    ) -> Vec<u8> {
        let mut embedded = vec![0x45, 0, 0, 37, 0x1f, 0x59, 0, 0, 1, protocol, 0, 0];
        embedded.extend_from_slice(&OUR_ADDRESS);
        embedded.extend_from_slice(&destination);
        embedded.push(inner_type);
        embedded.extend_from_slice(&[0, 0, 0]);
        embedded.extend_from_slice(&identifier.to_be_bytes());
        embedded.extend_from_slice(&sequence.to_be_bytes());

        let mut icmp = vec![ICMP_TIME_EXCEEDED, 0, 0xf4, 0xff, 0, 0, 0, 0];
        icmp.extend_from_slice(&embedded);

        if !outer_header {
            return icmp;
        }
        let mut packet = vec![0x45, 0xc0, 0, 45, 0x32, 0x5b, 0, 0, 0x3f, 1, 0, 0];
        packet.extend_from_slice(&[192, 168, 70, 1]);
        packet.extend_from_slice(&OUR_ADDRESS);
        packet.extend_from_slice(&icmp);
        packet
    }

    fn matching_reply(outer_header: bool) -> Vec<u8> {
        time_exceeded(
            outer_header,
            PATH_PROBE_DESTINATION.octets(),
            1,
            ICMP_ECHO_REQUEST,
            0xbeef,
            2,
        )
    }

    #[test]
    fn a_correlated_reply_is_accepted_in_both_platform_shapes() {
        // macOS prepends the IP header of the error packet; Linux does not.
        assert!(matches_probe(&matching_reply(true), identity()));
        assert!(matches_probe(&matching_reply(false), identity()));
    }

    #[test]
    fn an_unrelated_time_exceeded_is_ignored() {
        // Another program's traceroute, running at the same moment on the same machine.
        let other_identifier = time_exceeded(
            true,
            PATH_PROBE_DESTINATION.octets(),
            1,
            ICMP_ECHO_REQUEST,
            0x1234,
            2,
        );
        assert!(!matches_probe(&other_identifier, identity()));

        // Our own probe, but from a different hop: a late error must not be attributed to
        // the distance currently being measured.
        let other_sequence = time_exceeded(
            true,
            PATH_PROBE_DESTINATION.octets(),
            1,
            ICMP_ECHO_REQUEST,
            0xbeef,
            4,
        );
        assert!(!matches_probe(&other_sequence, identity()));

        // Headed somewhere else entirely.
        let other_destination = time_exceeded(true, [8, 8, 8, 8], 1, ICMP_ECHO_REQUEST, 0xbeef, 2);
        assert!(!matches_probe(&other_destination, identity()));

        // A UDP traceroute's error, which carries no ICMP identifier at all.
        let udp_probe = time_exceeded(
            true,
            PATH_PROBE_DESTINATION.octets(),
            17,
            ICMP_ECHO_REQUEST,
            0xbeef,
            2,
        );
        assert!(!matches_probe(&udp_probe, identity()));
    }

    #[test]
    fn other_icmp_messages_are_not_hops() {
        // Destination Unreachable means the packet died for another reason, and its sender
        // is not necessarily a router on the path. Echo Reply means it arrived.
        let mut unreachable = matching_reply(true);
        unreachable[20] = 3;
        assert!(!matches_probe(&unreachable, identity()));

        let mut echo_reply = matching_reply(true);
        echo_reply[20] = 0;
        assert!(!matches_probe(&echo_reply, identity()));
    }

    #[test]
    fn a_malformed_embedded_packet_is_rejected_without_panicking() {
        // Appliance ICMP implementations truncate and mangle these routinely, and the
        // bytes come from whatever answered.
        let full = matching_reply(true);
        for length in 0..full.len() {
            let _ = matches_probe(&full[..length], identity());
        }

        // An embedded header claiming a length that is not there.
        let mut bad_ihl = full.clone();
        bad_ihl[28] = 0x4f;
        assert!(!matches_probe(&bad_ihl, identity()));

        // An embedded header shorter than the minimum.
        let mut short_ihl = full.clone();
        short_ihl[28] = 0x41;
        assert!(!matches_probe(&short_ihl, identity()));

        // Not IPv4 at all.
        let mut not_ipv4 = full;
        not_ipv4[28] = 0x60;
        assert!(!matches_probe(&not_ipv4, identity()));

        assert!(!matches_probe(&[], identity()));
        assert!(!matches_probe(&[11], identity()));
    }

    #[test]
    fn an_echo_request_carries_a_valid_checksum() {
        // A router will not answer a malformed probe, and a wrong checksum looks exactly
        // like a path that filters ICMP.
        let packet = echo_request(0x4242, 3);
        assert_eq!(packet[0], ICMP_ECHO_REQUEST);
        assert_eq!(packet[1], 0);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 0x4242);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 3);
        // A correct checksum makes the sum over the whole packet zero.
        assert_eq!(internet_checksum(&packet), 0);
    }

    #[test]
    fn the_transmitted_packet_is_the_one_the_parser_expects() {
        // The defect this guards: an earlier version generated an echo request, never sent
        // it, and transmitted a UDP payload instead -- so the probe and the correlation
        // were describing two different protocols.
        let sent = echo_request(0xbeef, 2);
        let reply = time_exceeded(
            true,
            PATH_PROBE_DESTINATION.octets(),
            1,
            sent[0],
            u16::from_be_bytes([sent[4], sent[5]]),
            u16::from_be_bytes([sent[6], sent[7]]),
        );
        assert!(matches_probe(&reply, identity()));
    }

    #[test]
    fn each_run_uses_a_distinct_probe_identifier() {
        // So two runs, or two vantages in one process, cannot read each other's errors.
        let first = probe_identifier();
        let second = probe_identifier();
        assert_ne!(first, second);
    }

    #[test]
    fn the_probe_destination_is_a_reserved_block() {
        // RFC 5737 TEST-NET-1: nobody is permitted to run a real host there, so the probe
        // cannot arrive at anyone's service. It is not a containment guarantee -- a router
        // with a default route will forward it onward until something drops it.
        assert!(PATH_PROBE_DESTINATION.is_documentation());
        assert!(!PATH_PROBE_DESTINATION.is_private());
    }
}
