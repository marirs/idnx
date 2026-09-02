//! Addressing a device without assuming an address family.
//!
//! Probes originally took an `Ipv4Addr`, which made IPv6 devices unreachable and forced the
//! engine to skip them with a note claiming they were "enriched from neighbour evidence"
//! instead. They were not: a neighbour entry is an address, not a service.
//!
//! An IPv6 link-local address is only meaningful together with the link it was seen on.
//! `fe80::1` on one interface and `fe80::1` on another are different devices, and the
//! kernel cannot route to either without a scope. This type carries that zone from
//! discovery through to the socket.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

/// A reachable address, with the link it must be reached over when that matters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub address: IpAddr,
    /// Interface name for a link-local address. `None` for anything globally routed.
    pub zone: Option<String>,
}

impl Endpoint {
    pub fn new(address: IpAddr, zone: Option<String>) -> Self {
        // A zone on a routable address is meaningless and would only be noise in output.
        let zone = zone.filter(|_| requires_zone(&address));
        Self { address, zone }
    }

    /// Address with no link qualification.
    pub fn global(address: IpAddr) -> Self {
        Self {
            address,
            zone: None,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    /// Builds a connectable socket address.
    ///
    /// For a link-local IPv6 address this resolves the interface name to the kernel's scope
    /// index. Without it `connect` fails with "no route to host" no matter what is listening.
    pub fn socket_addr(&self, port: u16) -> SocketAddr {
        match self.address {
            IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), port),
            IpAddr::V6(v6) => {
                let scope = self.zone.as_deref().map(scope_index).unwrap_or(0);
                SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope))
            }
        }
    }

    /// How the address should appear in a URL or a `Host:` header.
    ///
    /// IPv6 literals need brackets, and a zone must not leak into a header a server will
    /// try to parse.
    pub fn host_literal(&self) -> String {
        match self.address {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.zone {
            Some(zone) => write!(f, "{}%{}", self.address, zone),
            None => write!(f, "{}", self.address),
        }
    }
}

/// Whether an address is meaningless without knowing which link it was seen on.
pub fn requires_zone(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => is_link_local(v6),
    }
}

/// `Ipv6Addr::is_unicast_link_local` is still unstable, so fe80::/10 is written out.
pub fn is_link_local(address: &Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

/// Resolves an interface name to the kernel's scope index.
#[cfg(unix)]
fn scope_index(name: &str) -> u32 {
    let Ok(cstr) = std::ffi::CString::new(name) else {
        return 0;
    };
    // SAFETY: the pointer is a valid NUL-terminated string that outlives the call.
    unsafe { libc::if_nametoindex(cstr.as_ptr()) }
}

/// On Windows a zone is written as the numeric index directly, so there is nothing to look
/// up; an unparseable zone yields 0, which fails the connection rather than reaching the
/// wrong link.
#[cfg(not(unix))]
fn scope_index(name: &str) -> u32 {
    name.parse().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zone_is_kept_only_where_it_changes_the_destination() {
        let link_local = Endpoint::new("fe80::1".parse().unwrap(), Some("en0".to_string()));
        assert_eq!(link_local.zone.as_deref(), Some("en0"));

        // A zone on a routable address would be noise, and worse, would appear in output as
        // though the address were link-scoped.
        let global = Endpoint::new("2001:db8::1".parse().unwrap(), Some("en0".to_string()));
        assert!(global.zone.is_none());

        let v4 = Endpoint::new("10.0.0.1".parse().unwrap(), Some("en0".to_string()));
        assert!(v4.zone.is_none());
    }

    #[test]
    fn a_link_local_socket_carries_a_scope_index() {
        // Which index depends on the host, but a named loopback interface always exists and
        // must resolve to something non-zero; without it the connection cannot be routed.
        let name = if cfg!(target_os = "linux") {
            "lo"
        } else {
            "lo0"
        };
        let endpoint = Endpoint::new("fe80::1".parse().unwrap(), Some(name.to_string()));
        let SocketAddr::V6(v6) = endpoint.socket_addr(80) else {
            panic!("expected an IPv6 socket address");
        };
        assert_eq!(v6.port(), 80);
        assert_ne!(v6.scope_id(), 0, "{name} did not resolve to a scope index");
    }

    #[test]
    fn an_unknown_zone_fails_rather_than_reaching_the_wrong_link() {
        let endpoint = Endpoint::new(
            "fe80::1".parse().unwrap(),
            Some("definitely-not-an-interface".to_string()),
        );
        let SocketAddr::V6(v6) = endpoint.socket_addr(80) else {
            panic!("expected an IPv6 socket address");
        };
        assert_eq!(v6.scope_id(), 0);
    }

    #[test]
    fn ipv6_literals_are_bracketed_for_headers_and_urls() {
        assert_eq!(
            Endpoint::global("fd00::5".parse().unwrap()).host_literal(),
            "[fd00::5]"
        );
        assert_eq!(
            Endpoint::global("10.0.0.5".parse().unwrap()).host_literal(),
            "10.0.0.5"
        );
    }

    #[test]
    fn display_shows_the_link_for_a_scoped_address() {
        let scoped = Endpoint::new("fe80::9".parse().unwrap(), Some("eth1".to_string()));
        assert_eq!(scoped.to_string(), "fe80::9%eth1");
        assert_eq!(
            Endpoint::global("10.0.0.9".parse().unwrap()).to_string(),
            "10.0.0.9"
        );
    }
}
