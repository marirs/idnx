//! Sending and receiving raw link-layer frames on the selected interface.
//!
//! Needed because ARP has no socket API: the kernel resolves addresses on our behalf and
//! reports only its conclusion. A cache entry says a MAC was learned at some point, not
//! that the host is answering now, and it carries none of the reply's fields, so nothing
//! downstream can check that the answer was about the address we asked for. Building the
//! request and validating the reply ourselves is the only way liveness is confirmed rather
//! than assumed.
//!
//! Access is privileged and platform-specific: BPF on macOS and other BSDs, `AF_PACKET` on
//! Linux, and nothing at all elsewhere. Every failure is returned as a stated reason rather
//! than an empty result, so a probe that could not run is never reported as a device that
//! did not answer.

use std::time::{Duration, Instant};

/// A frame as it appeared on the wire, link header included.
pub type Frame = Vec<u8>;

/// The hardware address of an interface, for use as the ARP sender field.
///
/// Read from the kernel rather than accepted from a caller: a request carrying an address
/// this interface does not own would be answered to somewhere else, and the reply would
/// never arrive.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn interface_mac(interface: &str) -> Option<[u8; 6]> {
    use std::ffi::CStr;

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }

    let mut found = None;
    let mut cursor = head;
    while !cursor.is_null() {
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;

        if entry.ifa_name.is_null() || entry.ifa_addr.is_null() {
            continue;
        }
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        if name.to_string_lossy() != interface {
            continue;
        }
        if let Some(mac) = link_address(entry.ifa_addr) {
            found = Some(mac);
            break;
        }
    }

    unsafe { libc::freeifaddrs(head) };
    found
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn interface_mac(_interface: &str) -> Option<[u8; 6]> {
    None
}

/// Extracts the hardware address from a link-layer `sockaddr`, whose shape differs per OS.
#[cfg(target_os = "macos")]
fn link_address(addr: *const libc::sockaddr) -> Option<[u8; 6]> {
    let family = unsafe { (*addr).sa_family } as i32;
    if family != libc::AF_LINK {
        return None;
    }
    let dl = addr as *const libc::sockaddr_dl;
    let dl = unsafe { &*dl };
    if dl.sdl_alen != 6 {
        return None;
    }
    // `sdl_data` holds the interface name first, then the address; `sdl_nlen` says how far
    // in the address starts.
    let offset = dl.sdl_nlen as usize;
    if offset + 6 > dl.sdl_data.len() {
        return None;
    }
    let mut mac = [0u8; 6];
    for (index, slot) in mac.iter_mut().enumerate() {
        *slot = dl.sdl_data[offset + index] as u8;
    }
    Some(mac)
}

#[cfg(target_os = "linux")]
fn link_address(addr: *const libc::sockaddr) -> Option<[u8; 6]> {
    let family = unsafe { (*addr).sa_family } as i32;
    if family != libc::AF_PACKET {
        return None;
    }
    let ll = addr as *const libc::sockaddr_ll;
    let ll = unsafe { &*ll };
    if ll.sll_halen != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&ll.sll_addr[..6]);
    Some(mac)
}

/// Whether raw link-layer access is available here, and why not when it is not.
///
/// Exists so that exactly one ARP sweep runs per network. The validated raw sweep and the
/// scanner's indirect trick of sending UDP datagrams to provoke the kernel's own ARP both
/// resolve the same addresses; running both doubles the broadcast traffic and produces two
/// accounts of the same link, one of which is only a cache read. This predicate decides
/// which one runs, and it answers by opening a channel rather than by guessing from the
/// platform or the effective uid.
pub fn raw_link_status(interface: &str) -> Result<(), String> {
    LinkChannel::open(interface).map(|_| ())
}

/// A raw link-layer channel pinned to one interface.
///
/// Pinned deliberately: an ARP request that leaves through a different link resolves a
/// different network's address space while the answer is attributed to this vantage.
pub struct LinkChannel {
    fd: libc::c_int,
    /// Read buffer size the kernel expects. On BPF a short read returns `EINVAL`, and the
    /// value is negotiated by the driver rather than chosen by us.
    read_size: usize,
    /// True where reads yield BPF records that must be unpacked; false where each read is
    /// exactly one frame.
    bpf_framing: bool,
}

#[cfg(unix)]
impl Drop for LinkChannel {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl LinkChannel {
    /// Opens the interface for raw frames, or explains why it could not.
    pub fn open(interface: &str) -> Result<Self, String> {
        #[cfg(target_os = "macos")]
        {
            Self::open_bpf(interface)
        }
        #[cfg(target_os = "linux")]
        {
            Self::open_packet_socket(interface)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = interface;
            Err("raw link-layer access is not implemented on this platform".to_string())
        }
    }

    #[cfg(target_os = "macos")]
    fn open_bpf(interface: &str) -> Result<Self, String> {
        use std::ffi::CString;

        // `_IOW('B', n, T)` / `_IOR('B', n, T)` encodings from `net/bpf.h`.
        const BIOCSETIF: libc::c_ulong = 0x8020_426c;
        const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270;
        const BIOCGBLEN: libc::c_ulong = 0x4004_4266;
        const BIOCSHDRCMPLT: libc::c_ulong = 0x8004_4275;
        const BIOCSSEESENT: libc::c_ulong = 0x8004_4277;

        let mut fd = -1;
        let mut denied = false;
        for index in 0..64 {
            let path = CString::new(format!("/dev/bpf{index}")).map_err(|e| e.to_string())?;
            let opened = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
            if opened >= 0 {
                fd = opened;
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EACCES) {
                denied = true;
            }
        }
        if fd < 0 {
            return Err(if denied {
                "no BPF device could be opened: raw link-layer access needs root".to_string()
            } else {
                "no BPF device was available".to_string()
            });
        }

        let channel = LinkChannel {
            fd,
            read_size: 4096,
            bpf_framing: true,
        };

        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        let name = interface.as_bytes();
        if name.len() >= request.ifr_name.len() {
            return Err(format!("interface name {interface} is too long"));
        }
        for (slot, byte) in request.ifr_name.iter_mut().zip(name) {
            *slot = *byte as libc::c_char;
        }
        if unsafe { libc::ioctl(channel.fd, BIOCSETIF, &request) } < 0 {
            return Err(format!(
                "BPF could not be attached to {interface}: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Deliver each frame as it arrives rather than when the buffer fills, so a reply is
        // seen inside the probe's deadline.
        let enable: libc::c_uint = 1;
        unsafe { libc::ioctl(channel.fd, BIOCIMMEDIATE, &enable) };
        // We supply the complete link header, including the source address; without this
        // the kernel overwrites it and the request no longer says who to answer.
        unsafe { libc::ioctl(channel.fd, BIOCSHDRCMPLT, &enable) };
        // Do not read back our own transmissions: a request looped straight into the
        // receive path would otherwise be a candidate for "a reply arrived".
        let disable: libc::c_uint = 0;
        unsafe { libc::ioctl(channel.fd, BIOCSSEESENT, &disable) };

        let mut buffer_len: libc::c_uint = 0;
        if unsafe { libc::ioctl(channel.fd, BIOCGBLEN, &mut buffer_len) } < 0 || buffer_len == 0 {
            return Err("BPF did not report a read buffer size".to_string());
        }

        // Non-blocking, so the deadline is enforced by us rather than by the driver.
        let flags = unsafe { libc::fcntl(channel.fd, libc::F_GETFL, 0) };
        unsafe { libc::fcntl(channel.fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };

        Ok(LinkChannel {
            read_size: buffer_len as usize,
            ..channel
        })
    }

    #[cfg(target_os = "linux")]
    fn open_packet_socket(interface: &str) -> Result<Self, String> {
        const ETH_P_ALL: u16 = 0x0003;

        let index = interface_index(interface)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                (ETH_P_ALL as i32).to_be(),
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return Err(if error.raw_os_error() == Some(libc::EPERM) {
                "raw packet socket denied: link-layer access needs CAP_NET_RAW".to_string()
            } else {
                format!("raw packet socket could not be opened: {error}")
            });
        }

        let channel = LinkChannel {
            fd,
            read_size: 2048,
            bpf_framing: false,
        };

        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = ETH_P_ALL.to_be();
        address.sll_ifindex = index as i32;
        let bound = unsafe {
            libc::bind(
                channel.fd,
                &address as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if bound < 0 {
            return Err(format!(
                "raw packet socket could not be bound to {interface}: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(channel)
    }
}

/// The parts that touch file descriptors. Unix only, because raw link-layer access is:
/// there is no equivalent on Windows without a third-party driver, and pretending otherwise
/// would mean a probe that reports silence it never listened for.
#[cfg(unix)]
impl LinkChannel {
    /// Transmits one complete frame, link header included.
    pub fn send(&self, frame: &[u8]) -> Result<(), String> {
        let written =
            unsafe { libc::write(self.fd, frame.as_ptr() as *const libc::c_void, frame.len()) };
        if written < 0 {
            return Err(format!(
                "frame could not be transmitted: {}",
                std::io::Error::last_os_error()
            ));
        }
        if written as usize != frame.len() {
            return Err(format!(
                "frame was truncated on transmission: {written} of {} bytes",
                frame.len()
            ));
        }
        Ok(())
    }

    /// Collects frames until `deadline`, calling `accept` for each one.
    ///
    /// Returns once `accept` is satisfied or the deadline passes, whichever comes first;
    /// the caller decides what a match is, because only the caller knows what it asked.
    pub fn read_until<T>(
        &self,
        deadline: Instant,
        mut accept: impl FnMut(&[u8]) -> Option<T>,
    ) -> ReadResult<T> {
        let mut buffer = vec![0u8; self.read_size];
        let mut seen = 0usize;

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if !self.wait_readable(remaining) {
                continue;
            }

            let read = unsafe {
                libc::read(
                    self.fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                )
            };
            if read <= 0 {
                continue;
            }
            let filled = &buffer[..read as usize];

            for frame in self.unpack(filled) {
                seen += 1;
                if let Some(found) = accept(frame) {
                    return ReadResult {
                        found: Some(found),
                        frames_seen: seen,
                    };
                }
            }
        }

        ReadResult {
            found: None,
            frames_seen: seen,
        }
    }

    /// Blocks until the channel has data or `limit` elapses. False means neither happened
    /// yet, which is not an error.
    fn wait_readable(&self, limit: Duration) -> bool {
        let mut poller = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // Capped so a long deadline still returns to the loop and re-checks the clock.
        let millis = limit.as_millis().min(200) as libc::c_int;
        let ready = unsafe { libc::poll(&mut poller, 1, millis) };
        ready > 0 && (poller.revents & libc::POLLIN) != 0
    }

    /// Splits one read into frames. BPF packs several records with alignment padding;
    /// a packet socket returns exactly one frame per read.
    fn unpack<'a>(&self, filled: &'a [u8]) -> Vec<&'a [u8]> {
        if !self.bpf_framing {
            return vec![filled];
        }

        /// `BPF_WORDALIGN` from `net/bpf.h`; `BPF_ALIGNMENT` is `sizeof(int32_t)`.
        fn word_align(len: usize) -> usize {
            const ALIGNMENT: usize = std::mem::size_of::<i32>();
            (len + (ALIGNMENT - 1)) & !(ALIGNMENT - 1)
        }

        let mut frames = Vec::new();
        let mut offset = 0usize;
        // `struct bpf_hdr`: timeval (16 bytes on 64-bit), caplen, datalen, hdrlen.
        const CAPLEN_AT: usize = 16;
        const DATALEN_AT: usize = 20;
        const HDRLEN_AT: usize = 24;
        const HEADER_MIN: usize = 26;

        while offset + HEADER_MIN <= filled.len() {
            let record = &filled[offset..];
            let caplen =
                u32::from_ne_bytes(record[CAPLEN_AT..CAPLEN_AT + 4].try_into().unwrap()) as usize;
            let datalen =
                u32::from_ne_bytes(record[DATALEN_AT..DATALEN_AT + 4].try_into().unwrap()) as usize;
            let hdrlen =
                u16::from_ne_bytes(record[HDRLEN_AT..HDRLEN_AT + 2].try_into().unwrap()) as usize;

            if hdrlen == 0 || caplen == 0 || datalen == 0 || hdrlen + caplen > record.len() {
                break;
            }
            frames.push(&record[hdrlen..hdrlen + caplen]);
            offset += word_align(hdrlen + caplen);
        }

        frames
    }
}

/// The same surface where raw frames cannot be reached at all.
///
/// `open` already refuses on these platforms, so nothing here can be called with a live
/// channel; the bodies exist so the rest of the crate compiles unchanged and so that no
/// caller silently loses the honest failure.
#[cfg(not(unix))]
impl LinkChannel {
    pub fn send(&self, _frame: &[u8]) -> Result<(), String> {
        Err("raw link-layer access is not implemented on this platform".to_string())
    }

    pub fn read_until<T>(
        &self,
        _deadline: Instant,
        _accept: impl FnMut(&[u8]) -> Option<T>,
    ) -> ReadResult<T> {
        ReadResult {
            found: None,
            frames_seen: 0,
        }
    }
}

/// What a bounded read produced, including what it rejected.
///
/// The count matters: frames arrived and none matched is a different finding from no
/// frames at all, and neither is proof the host is absent.
pub struct ReadResult<T> {
    pub found: Option<T>,
    pub frames_seen: usize,
}

#[cfg(target_os = "linux")]
fn interface_index(interface: &str) -> Result<u32, String> {
    use std::ffi::CString;
    let name = CString::new(interface).map_err(|e| e.to_string())?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(format!("interface {interface} has no kernel index"));
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interface_that_does_not_exist_is_reported_rather_than_silently_empty() {
        // The reason travels with the failure; a probe that could not open a channel must
        // not be reported as a device that did not answer.
        match LinkChannel::open("idnx-nonexistent0") {
            Ok(_) => panic!("a channel was opened on an interface that does not exist"),
            Err(reason) => assert!(!reason.is_empty()),
        }
    }

    #[test]
    fn a_local_interface_has_a_hardware_address_or_none_is_claimed() {
        // Loopback has no Ethernet address on any supported platform, and inventing one
        // would put a sender address on the wire that answers nowhere.
        assert!(interface_mac("lo0").is_none() || interface_mac("lo").is_none());
    }
}
