//! One raw ICMPv6 socket, shared by every probe that speaks it.
//!
//! Neighbour discovery and router discovery need exactly the same thing: a socket pinned to
//! the selected interface, transmitting with hop limit 255, and reporting the hop limit,
//! destination address and arrival interface of what it receives. Those three facts come
//! from the kernel's ancillary data rather than from the message body, which is what makes
//! them worth anything -- an attacker controls every byte of the payload and none of the
//! header the kernel reports.
//!
//! Kept in one place deliberately. Two subtly different readers of the same protocol is how
//! a defect survives in one of them, which is precisely what happened to the link-layer
//! reader in this crate.

use std::net::Ipv6Addr;
use std::time::Duration;

/// RFC 4861 §11.2: neighbour and router discovery messages must be sent and received with
/// hop limit 255. Anything less has crossed a router and cannot describe this link.
pub const REQUIRED_HOP_LIMIT: u8 = 255;

/// One ICMPv6 message with the header facts the kernel reports alongside it.
pub struct ReceivedMessage {
    pub message: Vec<u8>,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub hop_limit: u8,
    /// Interface the message arrived on, from `IPV6_PKTINFO`.
    ///
    /// A raw ICMPv6 socket is not bound to one link, so this is the only thing that says
    /// the answer describes the link we asked on.
    pub interface_index: u32,
}

/// A raw ICMPv6 socket pinned to one interface.
/// The descriptor is read only by the unix implementation; elsewhere `open` refuses first.
#[cfg_attr(not(unix), allow(dead_code))]
pub struct IcmpV6Socket {
    fd: libc::c_int,
}

#[cfg(unix)]
impl Drop for IcmpV6Socket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Unix only: a raw ICMPv6 socket is not reachable on Windows without a driver, and the
/// non-unix `open` below refuses rather than letting a caller believe it listened.
#[cfg(unix)]
impl IcmpV6Socket {
    /// Opens the socket and asks the kernel for the two header fields validation needs.
    pub fn open(scope_index: u32) -> Result<Self, String> {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                // Shared by neighbour and router discovery, so the reason names neither.
                Some(libc::EPERM) | Some(libc::EACCES) => {
                    "raw ICMPv6 socket denied: needs root".to_string()
                }
                _ => format!("raw ICMPv6 socket could not be opened: {error}"),
            });
        }
        let socket = IcmpV6Socket { fd };

        let enable: libc::c_int = 1;
        // Without these the hop limit and destination address are unavailable, and the two
        // checks that make an advertisement trustworthy could not be made at all.
        socket.set_option(libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, &enable)?;
        socket.set_option(libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, &enable)?;

        // Solicitations must leave with hop limit 255, since that is what the receiver
        // checks, and must leave through the selected interface.
        let hops: libc::c_int = REQUIRED_HOP_LIMIT as libc::c_int;
        socket.set_option(libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, &hops)?;
        socket.set_option(libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, &hops)?;
        let index = scope_index as libc::c_int;
        socket.set_option(libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, &index)?;

        let flags = unsafe { libc::fcntl(socket.fd, libc::F_GETFL, 0) };
        unsafe { libc::fcntl(socket.fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        Ok(socket)
    }

    fn set_option<T>(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: &T,
    ) -> Result<(), String> {
        let set = unsafe {
            libc::setsockopt(
                self.fd,
                level,
                name,
                value as *const T as *const libc::c_void,
                std::mem::size_of::<T>() as libc::socklen_t,
            )
        };
        if set < 0 {
            return Err(format!(
                "ICMPv6 socket option {name} could not be set: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub fn send_to(&self, message: &[u8], destination: Ipv6Addr, scope: u32) -> Result<(), String> {
        let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        address.sin6_addr.s6_addr = destination.octets();
        address.sin6_scope_id = scope;

        let sent = unsafe {
            libc::sendto(
                self.fd,
                message.as_ptr() as *const libc::c_void,
                message.len(),
                0,
                &address as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(format!(
                "the solicitation could not be transmitted: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// Waits up to `limit` for one message, returning it with its hop limit and
    /// destination address.
    pub fn recv(&self, limit: Duration) -> Option<ReceivedMessage> {
        let mut poller = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = limit.as_millis().min(200) as libc::c_int;
        if unsafe { libc::poll(&mut poller, 1, millis) } <= 0 {
            return None;
        }

        let mut payload = [0u8; 1500];
        let mut control = [0u8; 256];
        let mut from: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_name = &mut from as *mut _ as *mut libc::c_void;
        header.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        header.msg_iov = &mut iov;
        header.msg_iovlen = 1;
        header.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        header.msg_controllen = control.len() as _;

        let read = unsafe { libc::recvmsg(self.fd, &mut header, 0) };
        if read <= 0 {
            return None;
        }

        let mut hop_limit = None;
        let mut destination = None;
        let mut arrived_on = None;
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&header) };
        while !cmsg.is_null() {
            let entry = unsafe { &*cmsg };
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            if entry.cmsg_level == libc::IPPROTO_IPV6 {
                if entry.cmsg_type == libc::IPV6_HOPLIMIT {
                    let value = unsafe { std::ptr::read_unaligned(data as *const libc::c_int) };
                    hop_limit = u8::try_from(value).ok();
                } else if entry.cmsg_type == libc::IPV6_PKTINFO {
                    let info =
                        unsafe { std::ptr::read_unaligned(data as *const libc::in6_pktinfo) };
                    destination = Some(Ipv6Addr::from(info.ipi6_addr.s6_addr));
                    arrived_on = Some(info.ipi6_ifindex);
                }
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&header, cmsg) };
        }

        // Both are required. Without them the message cannot be validated, and an
        // unvalidated message is not an answer.
        Some(ReceivedMessage {
            message: payload[..read as usize].to_vec(),
            source: Ipv6Addr::from(from.sin6_addr.s6_addr),
            destination: destination?,
            hop_limit: hop_limit?,
            interface_index: arrived_on?,
        })
    }
}

/// The same surface where raw ICMPv6 cannot be opened at all.
#[cfg(not(unix))]
impl IcmpV6Socket {
    pub fn open(_scope_index: u32) -> Result<Self, String> {
        Err("raw ICMPv6 access is not implemented on this platform".to_string())
    }

    pub fn send_to(
        &self,
        _message: &[u8],
        _destination: Ipv6Addr,
        _scope: u32,
    ) -> Result<(), String> {
        Err("raw ICMPv6 access is not implemented on this platform".to_string())
    }

    pub fn recv(&self, _limit: Duration) -> Option<ReceivedMessage> {
        None
    }
}
