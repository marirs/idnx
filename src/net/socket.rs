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

use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::net::interface::InterfaceAddress;

/// Local addresses to bind probes to, for one interface.
#[derive(Debug, Clone, Default)]
pub struct SocketBinding {
    /// The interface these addresses belong to. Empty means unbound.
    pub interface: String,
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
}

impl SocketBinding {
    /// A binding that constrains nothing, for contexts with no chosen interface.
    pub fn unbound() -> Self {
        Self::default()
    }

    /// Collects the source addresses configured on one interface.
    pub fn for_interface(interface: &str, addresses: &[InterfaceAddress], index: u32) -> Self {
        let mut binding = Self {
            interface: interface.to_string(),
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

        binding
    }

    /// Whether this binding constrains anything at all.
    pub fn is_bound(&self) -> bool {
        !self.interface.is_empty()
            && (self.v4_source.is_some()
                || self.v6_source.is_some()
                || self.v6_link_local_source.is_some())
    }

    /// The local address a probe to `destination` should originate from.
    ///
    /// `None` means either that nothing is being constrained, or that this interface has no
    /// address in the destination's family -- in which case the probe cannot honestly be
    /// attributed to this vantage, and [`local_address_for`] returning `None` alongside
    /// [`is_bound`] returning `true` is how the caller tells the two apart.
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
    /// A bound interface with no address in the destination's family cannot reach it as
    /// itself. Probing anyway would produce evidence labelled with a vantage that never
    /// carried the traffic.
    pub fn can_reach(&self, destination: &SocketAddr) -> bool {
        !self.is_bound() || self.local_address_for(destination).is_some()
    }

    /// Opens a TCP connection from this interface.
    pub async fn tcp_connect(
        &self,
        destination: SocketAddr,
        timeout_duration: Duration,
    ) -> io::Result<TcpStream> {
        if !self.can_reach(&destination) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "{} has no address able to reach {destination}",
                    self.interface
                ),
            ));
        }

        let socket = match destination {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
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
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "{} has no address able to reach {destination}",
                    self.interface
                ),
            ));
        }

        let local = self
            .local_address_for(destination)
            .unwrap_or(match destination {
                SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::V6(_) => {
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
                }
            });
        UdpSocket::bind(local).await
    }

    /// Opens a UDP socket for an IPv4 broadcast from this interface.
    ///
    /// Broadcast is the case source binding matters most: a broadcast sent from the wrong
    /// interface reaches an entirely different link, and every answer would be attributed
    /// to the vantage that did not send it.
    pub async fn udp_broadcast(&self) -> io::Result<UdpSocket> {
        let local = SocketAddr::V4(SocketAddrV4::new(
            self.v4_source.unwrap_or(Ipv4Addr::UNSPECIFIED),
            0,
        ));
        let socket = UdpSocket::bind(local).await?;
        socket.set_broadcast(true)?;
        Ok(socket)
    }

    /// Opens an IPv4 UDP socket on a specific local port, bound to this interface.
    ///
    /// Used by protocols that must listen on a fixed port (MNDP on 5678) and by multicast
    /// senders, where the bound source address is what selects the outgoing interface.
    pub async fn udp_bound_v4(&self, port: u16) -> io::Result<UdpSocket> {
        let local = SocketAddrV4::new(self.v4_source.unwrap_or(Ipv4Addr::UNSPECIFIED), port);
        UdpSocket::bind(SocketAddr::V4(local)).await
    }
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
