//! Interface-bound socket creation.
//!
//! Target selection was scoped to the chosen interface, but every socket was created with
//! ordinary OS routing. `idnx eth1` could therefore probe a device through en0, attribute
//! the answer to eth1, and report a vantage that never saw it. On a multi-homed host that
//! is not a small inaccuracy: the whole point of naming an interface is to describe what is
//! visible from that link.
//!
//! Every active probe -- TCP, UDP, broadcast and multicast alike -- goes through this type,
//! which binds the local end to an address configured on the selected interface. Binding
//! the source address is portable and needs no privileges, unlike `SO_BINDTODEVICE`; it
//! constrains egress wherever the routing table has a route out of that interface for the
//! destination, which is the case discovery cares about. Where no suitable source address
//! exists, that is reported rather than silently falling back to default routing.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

#[cfg(unix)]
use std::os::fd::AsFd;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::net::interface::InterfaceAddress;

/// How strictly a socket is tied to the selected interface.
///
/// Reported rather than assumed. Source-address binding constrains egress wherever the
/// routing table has a route out of that interface, which is the case discovery cares
/// about, but it is not the same guarantee as asking the kernel to use one interface.
/// Claiming the stronger property where only the weaker holds would be dishonest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingMode {
    /// No interface was selected; ordinary routing applies.
    Unbound,
    /// The local end is bound to a source address on the interface.
    SourceAddress,
    /// The kernel was told which interface to use (`IP_BOUND_IF` on macOS,
    /// `SO_BINDTODEVICE` on Linux) in addition to the source address.
    NativeInterface,
}

impl BindingMode {
    pub fn label(&self) -> &'static str {
        match self {
            BindingMode::Unbound => "unbound (ordinary routing)",
            BindingMode::SourceAddress => "source-address bound",
            BindingMode::NativeInterface => "interface bound",
        }
    }
}

/// Local addresses to bind probes to, for one interface.
#[derive(Debug, Clone, Default)]
pub struct SocketBinding {
    /// The interface these addresses belong to. Empty means unbound.
    pub interface: String,
    /// Whether an interface was explicitly selected.
    ///
    /// Tracked separately from whether a usable source address was found. Deriving
    /// "constrained" from "has a source address" meant an interface with no address in the
    /// needed family silently reverted to ordinary routing -- exactly the case where
    /// constraining matters most.
    pub selected: bool,
    /// Kernel scope index for the interface, used for link-local IPv6.
    ///
    /// Carried rather than derived at the socket, because on Windows a zone is a numeric
    /// index and there is no name to look up: parsing a friendly name as an integer
    /// silently produced scope 0 and an unroutable address.
    pub index: u32,
    /// Source address for IPv4 probes.
    pub v4_source: Option<Ipv4Addr>,
    /// Source address for routable IPv6 probes.
    pub v6_source: Option<Ipv6Addr>,
    /// Source address for link-local IPv6 probes, which need a source on the same link.
    pub v6_link_local_source: Option<Ipv6Addr>,
    /// Whether asking the kernel to pin this interface actually succeeded.
    ///
    /// Established by trying it, not by asking whether the platform has the option.
    /// `SO_BINDTODEVICE` needs `CAP_NET_RAW`, so on an unprivileged Linux run the call is
    /// refused -- and reporting "interface bound" on the strength of the platform alone
    /// claimed a guarantee that was never obtained.
    native_binding: bool,
}

impl SocketBinding {
    /// A binding that constrains nothing, for contexts with no chosen interface.
    pub fn unbound() -> Self {
        Self::default()
    }

    /// Whether an interface was explicitly selected, regardless of what addresses it has.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// The strongest guarantee this binding can make for a destination.
    ///
    /// Reports what was achieved, not what the platform advertises.
    pub fn mode(&self, destination: &SocketAddr) -> BindingMode {
        if !self.selected {
            return BindingMode::Unbound;
        }
        if self.native_binding {
            return BindingMode::NativeInterface;
        }
        if self.local_address_for(destination).is_some() {
            BindingMode::SourceAddress
        } else {
            BindingMode::Unbound
        }
    }

    /// Collects the source addresses configured on one interface.
    pub fn for_interface(interface: &str, addresses: &[InterfaceAddress], index: u32) -> Self {
        let mut binding = Self {
            interface: interface.to_string(),
            // Selection is a fact about the operator's request, not about what the
            // interface happens to be configured with.
            selected: !interface.is_empty(),
            index,
            ..Default::default()
        };

        for address in addresses {
            if address.interface_name != interface {
                continue;
            }
            match address.ip {
                IpAddr::V4(v4) => {
                    // Deterministic: the numerically lowest address, so repeated runs bind
                    // the same source and their results are comparable.
                    if binding.v4_source.is_none_or(|current| v4 < current) {
                        binding.v4_source = Some(v4);
                    }
                }
                IpAddr::V6(v6) if crate::net::endpoint::is_link_local(&v6) => {
                    if binding
                        .v6_link_local_source
                        .is_none_or(|current| v6 < current)
                    {
                        binding.v6_link_local_source = Some(v6);
                    }
                }
                IpAddr::V6(v6) => {
                    if binding.v6_source.is_none_or(|current| v6 < current) {
                        binding.v6_source = Some(v6);
                    }
                }
            }
        }

        // Establish the guarantee by attempting it once, rather than inferring it from the
        // target platform. The scratch socket is discarded; only the outcome is kept.
        binding.native_binding = binding.index != 0 && probe_native_binding(&binding);

        binding
    }

    /// Whether this binding constrains anything at all.
    pub fn is_bound(&self) -> bool {
        self.selected
    }

    /// The local address a probe to `destination` should originate from.
    ///
    /// `None` means either that nothing is being constrained, or that this interface has no
    /// address in the destination's family -- in which case the probe cannot honestly be
    /// attributed to this vantage. [`SocketBinding::can_reach`] is the check that
    /// distinguishes those.
    pub fn local_address_for(&self, destination: &SocketAddr) -> Option<SocketAddr> {
        match destination {
            SocketAddr::V4(_) => self
                .v4_source
                .map(|v4| SocketAddr::V4(SocketAddrV4::new(v4, 0))),
            SocketAddr::V6(v6) => {
                let link_local = crate::net::endpoint::is_link_local(v6.ip());
                let source = if link_local {
                    self.v6_link_local_source.or(self.v6_source)
                } else {
                    self.v6_source.or(self.v6_link_local_source)
                }?;
                let scope = if crate::net::endpoint::is_link_local(&source) {
                    self.index
                } else {
                    0
                };
                Some(SocketAddr::V6(SocketAddrV6::new(source, 0, 0, scope)))
            }
        }
    }

    /// Whether a probe to this destination can be attributed to this vantage.
    ///
    /// A selected interface with no address in the destination's family cannot reach it as
    /// itself. Probing anyway would produce evidence labelled with a vantage that never
    /// carried the traffic, so the probe fails instead.
    pub fn can_reach(&self, destination: &SocketAddr) -> bool {
        if !self.selected {
            return true;
        }
        self.local_address_for(destination).is_some()
    }

    /// Error for a destination this interface cannot originate traffic to.
    fn unreachable(&self, destination: &SocketAddr) -> io::Error {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!(
                "{} has no {} source address to reach {destination}",
                if self.interface.is_empty() {
                    "the selected interface"
                } else {
                    &self.interface
                },
                if destination.is_ipv4() {
                    "IPv4"
                } else {
                    "IPv6"
                }
            ),
        )
    }

    /// Opens a TCP connection from this interface.
    pub async fn tcp_connect(
        &self,
        destination: SocketAddr,
        timeout_duration: Duration,
    ) -> io::Result<TcpStream> {
        if !self.can_reach(&destination) {
            return Err(self.unreachable(&destination));
        }

        let socket = match destination {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
        // Ask the kernel to use this interface where the platform allows it. Source
        // binding alone constrains egress only as far as the routing table agrees, which
        // on a multi-homed host with overlapping routes is not a guarantee.
        self.bind_to_interface(&socket, destination.is_ipv4())?;
        if let Some(local) = self.local_address_for(&destination) {
            socket.bind(local)?;
        }

        timeout(timeout_duration, socket.connect(destination))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))?
    }

    /// Opens a UDP socket for talking to `destination` from this interface.
    pub async fn udp_socket(&self, destination: &SocketAddr) -> io::Result<UdpSocket> {
        if !self.can_reach(destination) {
            return Err(self.unreachable(destination));
        }

        let local = self
            .local_address_for(destination)
            .unwrap_or(match destination {
                SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::V6(_) => {
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
                }
            });
        let socket = UdpSocket::bind(local).await?;
        self.bind_to_interface(&socket, destination.is_ipv4())?;
        Ok(socket)
    }

    /// Opens a UDP socket for an IPv4 broadcast from this interface.
    ///
    /// Broadcast is the case interface selection matters most: a broadcast sent from the
    /// wrong interface reaches an entirely different link, and every answer would be
    /// attributed to the vantage that did not send it.
    pub async fn udp_broadcast(&self) -> io::Result<UdpSocket> {
        let socket = self.udp_bound_v4(0).await?;
        socket.set_broadcast(true)?;
        Ok(socket)
    }

    /// Opens an IPv4 UDP socket for multicast, with the egress interface set explicitly.
    ///
    /// `IP_MULTICAST_IF` is what actually decides where a multicast datagram leaves. Source
    /// binding alone does not: on a multi-homed host the kernel picks the multicast
    /// interface from its own routing state, so an SSDP or mDNS query could be answered by
    /// devices on a link this vantage never claimed to see.
    pub async fn udp_multicast_v4(&self, port: u16) -> io::Result<UdpSocket> {
        let socket = self.udp_bound_v4(port).await?;
        socket.set_broadcast(true)?;
        if let Some(source) = self.v4_source {
            set_multicast_interface_v4(&socket, source)?;
        }
        Ok(socket)
    }

    /// Opens an IPv6 UDP socket for multicast, with the egress interface set explicitly.
    pub async fn udp_multicast_v6(&self, port: u16) -> io::Result<UdpSocket> {
        if self.selected && self.index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "{} has no scope index, so IPv6 multicast cannot be aimed at it",
                    self.interface
                ),
            ));
        }
        let socket = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            port,
            0,
            0,
        )))
        .await?;
        if self.index != 0 {
            set_multicast_interface_v6(&socket, self.index)?;
        }
        Ok(socket)
    }

    /// Opens an IPv4 UDP socket on a specific local port, bound to this interface.
    ///
    /// Used by protocols that must listen on a fixed port (MNDP on 5678) and as the base
    /// for broadcast and multicast senders.
    pub async fn udp_bound_v4(&self, port: u16) -> io::Result<UdpSocket> {
        if self.selected && self.v4_source.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("{} has no IPv4 source address", self.interface),
            ));
        }
        let local = SocketAddrV4::new(self.v4_source.unwrap_or(Ipv4Addr::UNSPECIFIED), port);
        let socket = UdpSocket::bind(SocketAddr::V4(local)).await?;
        self.bind_to_interface(&socket, true)?;
        Ok(socket)
    }

    /// Asks the kernel to send this socket's traffic out of the selected interface.
    ///
    /// Non-fatal where the call is refused: on Linux `SO_BINDTODEVICE` needs `CAP_NET_RAW`,
    /// which an unprivileged run does not have. Source binding remains in force either way,
    /// and [`SocketBinding::mode`] reports which guarantee actually applies rather than
    /// claiming the stronger one.
    #[cfg(unix)]
    fn bind_to_interface<S: AsFd>(&self, socket: &S, ipv4: bool) -> io::Result<()> {
        if !self.selected || self.index == 0 {
            return Ok(());
        }
        // A refusal is not fatal: source binding still applies, and `mode` already reports
        // that the weaker guarantee is the one in force.
        let _ = bind_socket_to_interface(socket, &self.interface, self.index, ipv4);
        Ok(())
    }

    /// Windows exposes no libc equivalent here; source binding is the guarantee, and
    /// [`SocketBinding::mode`] says so.
    #[cfg(not(unix))]
    fn bind_to_interface<S>(&self, _socket: &S, _ipv4: bool) -> io::Result<()> {
        Ok(())
    }
}

/// A binding paired with the run-wide probe budget.
///
/// Passed as one value so a discovery path cannot take the interface constraint without
/// also taking the concurrency limit. The legacy subnet scanner previously did exactly
/// that: it opened unbound sockets and created a semaphore of its own, so neither the
/// vantage nor the probe budget applied to any of its traffic.
#[derive(Clone)]
pub struct ProbeChannel {
    pub binding: std::sync::Arc<SocketBinding>,
    pub permits: std::sync::Arc<tokio::sync::Semaphore>,
}

impl ProbeChannel {
    /// A channel constraining nothing, for tests and for callers with no vantage.
    pub fn unbound(concurrency: usize) -> Self {
        Self {
            binding: std::sync::Arc::new(SocketBinding::unbound()),
            permits: std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1))),
        }
    }
}

/// Whether the platform offers a way to pin a socket to an interface.
///
/// Support is necessary but not sufficient: the call can still be refused at runtime, which
/// is why [`probe_native_binding`] tries it rather than trusting this.
pub fn native_binding_supported() -> bool {
    cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux"
    ))
}

/// Tries the native interface bind once and reports whether the kernel accepted it.
#[cfg(unix)]
fn probe_native_binding(binding: &SocketBinding) -> bool {
    if !native_binding_supported() {
        return false;
    }
    // A scratch socket, never sent on. Binding to port 0 on the wildcard address always
    // succeeds, so a failure below is the interface option being refused and nothing else.
    let Ok(scratch) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
        return false;
    };
    bind_socket_to_interface(&scratch, &binding.interface, binding.index, true).is_ok()
}

/// Windows exposes no libc equivalent, so the native bind is never attempted there.
#[cfg(not(unix))]
fn probe_native_binding(_binding: &SocketBinding) -> bool {
    false
}

/// macOS: `IP_BOUND_IF` / `IPV6_BOUND_IF`. Works without privileges, which makes it the
/// strongest guarantee available to an ordinary run.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn bind_socket_to_interface<S: AsFd>(
    socket: &S,
    _name: &str,
    index: u32,
    ipv4: bool,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    const IP_BOUND_IF: libc::c_int = 25;
    const IPV6_BOUND_IF: libc::c_int = 125;

    let (level, option) = if ipv4 {
        (libc::IPPROTO_IP, IP_BOUND_IF)
    } else {
        (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
    };
    let value = index as libc::c_uint;
    // SAFETY: the fd is owned by `socket` and outlives the call; the value is a c_uint of
    // the length declared.
    let result = unsafe {
        libc::setsockopt(
            socket.as_fd().as_raw_fd(),
            level,
            option,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Linux: `SO_BINDTODEVICE`. Needs `CAP_NET_RAW`, so an unprivileged run falls back to
/// source binding, which [`SocketBinding::mode`] reports honestly.
#[cfg(target_os = "linux")]
fn bind_socket_to_interface<S: AsFd>(
    socket: &S,
    name: &str,
    _index: u32,
    _ipv4: bool,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let cname = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name"))?;
    // SAFETY: the fd is owned by `socket`, and the name is a NUL-terminated string that
    // outlives the call. EPERM without CAP_NET_RAW is expected; the caller reports the
    // weaker guarantee rather than failing.
    let result = unsafe {
        libc::setsockopt(
            socket.as_fd().as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            cname.as_ptr().cast(),
            cname.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Other Unix platforms offer no portable equivalent; source binding stands alone.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "linux"))
))]
fn bind_socket_to_interface<S: AsFd>(_socket: &S, _name: &str, _index: u32, _ipv4: bool) {}

/// Sets the IPv4 multicast egress interface by source address.
///
/// This, not the bound source address, is what decides where a multicast datagram leaves.
#[cfg(unix)]
fn set_multicast_interface_v4<S: AsFd>(socket: &S, source: Ipv4Addr) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let request = libc::in_addr {
        s_addr: u32::from_ne_bytes(source.octets()),
    };
    // SAFETY: the fd is owned by `socket`; the value is an in_addr of the declared length.
    let result = unsafe {
        libc::setsockopt(
            socket.as_fd().as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            std::ptr::addr_of!(request).cast(),
            std::mem::size_of::<libc::in_addr>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Sets the IPv6 multicast egress interface by scope index.
#[cfg(unix)]
fn set_multicast_interface_v6<S: AsFd>(socket: &S, index: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let value = index as libc::c_uint;
    // SAFETY: the fd is owned by `socket`; the value is a c_uint of the declared length.
    let result = unsafe {
        libc::setsockopt(
            socket.as_fd().as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_IF,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Windows exposes these options through winsock rather than libc, which this project does
/// not link. Source binding applies and [`SocketBinding::mode`] reports it as such, rather
/// than claiming an interface guarantee that was never established.
#[cfg(not(unix))]
fn set_multicast_interface_v4<S>(_socket: &S, _source: Ipv4Addr) -> io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_multicast_interface_v6<S>(_socket: &S, _index: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(interface: &str, ip: &str, prefix: u8) -> InterfaceAddress {
        let ip: IpAddr = ip.parse().unwrap();
        InterfaceAddress {
            interface_name: interface.to_string(),
            ip,
            cidr: ipnet::IpNet::new(ip, prefix).unwrap(),
        }
    }

    fn binding() -> SocketBinding {
        SocketBinding::for_interface(
            "eth1",
            &[
                address("eth1", "10.0.0.5", 24),
                address("eth1", "fd00::5", 64),
                address("eth1", "fe80::5", 64),
                // Another interface entirely. Binding to this is the bug being prevented.
                address("en0", "192.168.1.5", 24),
                address("en0", "fd00:99::5", 64),
            ],
            7,
        )
    }

    #[test]
    fn only_addresses_on_the_selected_interface_are_used() {
        let binding = binding();
        assert_eq!(binding.v4_source, Some("10.0.0.5".parse().unwrap()));
        assert_eq!(binding.v6_source, Some("fd00::5".parse().unwrap()));
        assert_eq!(
            binding.v6_link_local_source,
            Some("fe80::5".parse().unwrap())
        );
        assert!(binding.is_bound());
    }

    #[test]
    fn source_selection_is_deterministic() {
        // Interface addresses arrive from a hash-ordered source, so picking the first one
        // seen made repeated runs bind different sources and produce different results.
        let addresses = [
            address("eth1", "10.0.0.9", 24),
            address("eth1", "10.0.0.2", 24),
            address("eth1", "10.0.0.5", 24),
        ];
        let forward = SocketBinding::for_interface("eth1", &addresses, 1);
        let mut reversed = addresses.to_vec();
        reversed.reverse();
        let backward = SocketBinding::for_interface("eth1", &reversed, 1);
        assert_eq!(forward.v4_source, backward.v4_source);
        assert_eq!(forward.v4_source, Some("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn a_probe_originates_from_the_selected_interface() {
        let binding = binding();
        let local = binding
            .local_address_for(&"10.0.0.200:80".parse().unwrap())
            .expect("a source address");
        assert_eq!(local.ip(), IpAddr::V4("10.0.0.5".parse().unwrap()));
        assert_eq!(local.port(), 0, "the kernel chooses the source port");
    }

    #[test]
    fn a_link_local_destination_gets_a_link_local_source_and_the_interface_index() {
        let binding = binding();
        let SocketAddr::V6(local) = binding
            .local_address_for(&"[fe80::200]:80".parse().unwrap())
            .expect("a source address")
        else {
            panic!("expected IPv6");
        };
        assert_eq!(*local.ip(), "fe80::5".parse::<Ipv6Addr>().unwrap());
        // The index comes from the vantage, not from parsing an interface name -- which is
        // what broke scoped IPv6 on Windows, where a zone is numeric and has no name.
        assert_eq!(local.scope_id(), 7);
    }

    #[test]
    fn a_routable_destination_prefers_a_routable_source() {
        let binding = binding();
        let local = binding
            .local_address_for(&"[fd00::200]:80".parse().unwrap())
            .expect("a source address");
        assert_eq!(local.ip(), IpAddr::V6("fd00::5".parse().unwrap()));
    }

    #[test]
    fn an_interface_without_the_family_cannot_reach_it() {
        // Probing anyway would attribute the answer to a vantage that never carried it.
        let v4_only = SocketBinding::for_interface("eth1", &[address("eth1", "10.0.0.5", 24)], 1);
        assert!(v4_only.can_reach(&"10.0.0.1:80".parse().unwrap()));
        assert!(!v4_only.can_reach(&"[fd00::1]:80".parse().unwrap()));
    }

    #[test]
    fn an_unbound_binding_constrains_nothing() {
        let unbound = SocketBinding::unbound();
        assert!(!unbound.is_bound());
        assert!(unbound.can_reach(&"10.0.0.1:80".parse().unwrap()));
        assert!(unbound.can_reach(&"[fd00::1]:80".parse().unwrap()));
        assert!(
            unbound
                .local_address_for(&"10.0.0.1:80".parse().unwrap())
                .is_none()
        );
    }

    #[tokio::test]
    async fn connecting_through_an_interface_that_cannot_reach_it_fails_rather_than_rerouting() {
        let v4_only = SocketBinding::for_interface("eth1", &[address("eth1", "10.0.0.5", 24)], 1);
        let error = v4_only
            .tcp_connect("[fd00::1]:80".parse().unwrap(), Duration::from_millis(50))
            .await
            .expect_err("must not fall back to default routing");
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    }

    #[test]
    fn the_reported_mode_is_what_was_achieved_not_what_the_platform_offers() {
        // A fabricated interface index cannot be bound to on any platform, so the native
        // bind must fail and the reported mode must fall back rather than claim it.
        // Reporting NativeInterface from `cfg!` alone would have said "interface bound" on
        // an unprivileged Linux run where SO_BINDTODEVICE was refused.
        let unbindable = SocketBinding::for_interface(
            "eth1",
            &[address("eth1", "10.0.0.5", 24)],
            // An index no interface has.
            0x7fff_ffff,
        );
        assert!(!unbindable.native_binding);
        assert_eq!(
            unbindable.mode(&"10.0.0.1:80".parse().unwrap()),
            BindingMode::SourceAddress
        );

        // And with no source address either, nothing is constrained and it says so.
        let nothing = SocketBinding::for_interface("eth9", &[], 0x7fff_ffff);
        assert!(nothing.is_selected());
        assert_eq!(
            nothing.mode(&"10.0.0.1:80".parse().unwrap()),
            BindingMode::Unbound
        );
    }

    #[tokio::test]
    async fn a_loopback_connection_still_works_when_unbound() {
        // Guards against the binding path breaking ordinary connections.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let unbound = SocketBinding::unbound();
        assert!(
            unbound
                .tcp_connect(address, Duration::from_millis(500))
                .await
                .is_ok()
        );
    }
}
