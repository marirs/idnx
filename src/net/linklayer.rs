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

use std::time::Instant;
// The owned-descriptor types exist only on unix, which is also the only place a channel
// can be opened.
#[cfg(unix)]
use std::os::fd::FromRawFd;
// Only the polling read path takes a wait limit, and that path is unix-only.
#[cfg(unix)]
use std::time::Duration;

/// What one poll established about the channel.
#[cfg(unix)]
enum Readiness {
    /// Data is waiting.
    Ready,
    /// Nothing yet, which is the ordinary case and not a fault.
    NotYet,
    /// The descriptor is in a state the network cannot explain.
    Fault(String),
}

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

/// A raw link-layer channel pinned to one interface.
///
/// Pinned deliberately: an ARP request that leaves through a different link resolves a
/// different network's address space while the answer is attributed to this vantage.
///
/// The descriptor is an [`OwnedFd`], which is what makes the ownership single and explicit.
/// It was a bare `c_int` with a hand-written `Drop`, and the open path finished with a
/// struct update -- `LinkChannel { read_size, ..channel }` -- which copied the integer into
/// the new value and then dropped the old one, closing the descriptor both now referred to.
/// Every send afterwards failed with `EBADF`, so the sweep reported a silent link it had
/// never transmitted on. A `c_int` is `Copy` and a file descriptor is not; using a type that
/// says so is what prevents the same mistake returning.
#[cfg(unix)]
pub struct LinkChannel {
    fd: std::os::fd::OwnedFd,
    /// Read buffer size the kernel expects. On BPF a short read returns `EINVAL`, and the
    /// value is negotiated by the driver rather than chosen by us.
    read_size: usize,
    /// True where reads yield BPF records that must be unpacked; false where each read is
    /// exactly one frame.
    bpf_framing: bool,
}

/// Where raw frames cannot be reached at all, the type carries nothing: `open` refuses
/// before an instance can exist.
#[cfg(not(unix))]
pub struct LinkChannel {
    _unreachable: (),
}

/// Whether a channel should also deliver the frames this process sends.
///
/// Off for a probe, so its own request cannot be read back as a reply. On for an observer,
/// which exists precisely to check that a request reached the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeeSent {
    Exclude,
    Include,
}

impl LinkChannel {
    /// Opens the interface for raw frames, or explains why it could not.
    pub fn open(interface: &str) -> Result<Self, String> {
        Self::open_with(interface, SeeSent::Exclude)
    }

    /// Opens a channel that also reports this process's own transmissions.
    ///
    /// Used to check what a `write` actually produced. A successful `write` to a BPF device
    /// means the kernel accepted the bytes and nothing more -- not that a frame left the
    /// interface -- and on some links, macOS Wi-Fi among them, the two differ.
    pub fn open_observer(interface: &str) -> Result<Self, String> {
        Self::open_with(interface, SeeSent::Include)
    }

    fn open_with(interface: &str, see_sent: SeeSent) -> Result<Self, String> {
        #[cfg(target_os = "macos")]
        {
            Self::open_bpf(interface, see_sent)
        }
        #[cfg(target_os = "linux")]
        {
            let _ = see_sent;
            Self::open_packet_socket(interface)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (interface, see_sent);
            Err("raw link-layer access is not implemented on this platform".to_string())
        }
    }

    #[cfg(target_os = "macos")]
    fn open_bpf(interface: &str, see_sent: SeeSent) -> Result<Self, String> {
        use std::ffi::CString;

        // `_IOW('B', n, T)` / `_IOR('B', n, T)` encodings from `net/bpf.h`.
        const BIOCSETIF: libc::c_ulong = 0x8020_426c;
        const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270;
        const BIOCGBLEN: libc::c_ulong = 0x4004_4266;
        // _IOR('B', 106, u_int): 0x40000000 | (4 << 16) | ('B' << 8) | 106, and 106 is 0x6a.
        const BIOCGDLT: libc::c_ulong = 0x4004_426a;
        const BIOCSHDRCMPLT: libc::c_ulong = 0x8004_4275;
        const BIOCSSEESENT: libc::c_ulong = 0x8004_4277;

        /// `DLT_EN10MB` from `net/bpf.h`: Ethernet framing, which is what an ARP request
        /// built here assumes. Any other link type takes a different header, and writing
        /// an Ethernet frame to it produces bytes the driver has no reason to accept.
        const DLT_EN10MB: libc::c_uint = 1;

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

        // Ownership moves here and stays here. Everything below reads the descriptor
        // through `as_raw_fd`, and the single owner closes it exactly once.
        let mut channel = LinkChannel {
            fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
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
        if unsafe { libc::ioctl(channel.fd(), BIOCSETIF, &request) } < 0 {
            return Err(format!(
                "BPF could not be attached to {interface}: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Every setting below is checked. They were fire-and-forget, so a driver that
        // refused one left the channel quietly configured differently from what the probe
        // assumed -- and the probe then reported the link's silence rather than its own.
        let setting =
            |name: libc::c_ulong, value: libc::c_uint, what: &str| -> Result<(), String> {
                if unsafe { libc::ioctl(channel.fd(), name, &value) } < 0 {
                    return Err(format!(
                        "BPF refused {what} on {interface}: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                Ok(())
            };

        // Deliver each frame as it arrives rather than when the buffer fills, so a reply is
        // seen inside the probe's deadline.
        setting(BIOCIMMEDIATE, 1, "immediate mode")?;
        // We supply the complete link header, including the source address; without this
        // the kernel overwrites it and the request no longer says who to answer.
        setting(BIOCSHDRCMPLT, 1, "complete-header mode")?;
        // A probe must not read back its own transmissions, or its request becomes a
        // candidate for "a reply arrived"; an observer exists to see exactly that.
        setting(
            BIOCSSEESENT,
            match see_sent {
                SeeSent::Exclude => 0,
                SeeSent::Include => 1,
            },
            "see-sent mode",
        )?;

        // The framing the driver will actually use. Building Ethernet ARP frames for a
        // link that is not Ethernet-framed produces bytes with the wrong header entirely.
        let mut link_type: libc::c_uint = 0;
        if unsafe { libc::ioctl(channel.fd(), BIOCGDLT, &mut link_type) } < 0 {
            return Err(format!(
                "BPF did not report a link type for {interface}: {}",
                std::io::Error::last_os_error()
            ));
        }
        if link_type != DLT_EN10MB {
            return Err(format!(
                "{interface} uses BPF link type {link_type}, not Ethernet (DLT_EN10MB); \
                 Ethernet ARP frames cannot be framed for it"
            ));
        }

        let mut buffer_len: libc::c_uint = 0;
        if unsafe { libc::ioctl(channel.fd(), BIOCGBLEN, &mut buffer_len) } < 0 || buffer_len == 0 {
            return Err(format!(
                "BPF did not report a read buffer size for {interface}: {}",
                std::io::Error::last_os_error()
            ));
        }
        channel.read_size = buffer_len as usize;

        // Non-blocking, so the deadline is enforced by us rather than by the driver.
        let flags = unsafe { libc::fcntl(channel.fd(), libc::F_GETFL, 0) };
        if flags < 0 {
            return Err(format!(
                "BPF descriptor flags could not be read for {interface}: {}",
                std::io::Error::last_os_error()
            ));
        }
        if unsafe { libc::fcntl(channel.fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(format!(
                "BPF descriptor could not be made non-blocking for {interface}: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(channel)
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
            fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
            read_size: 2048,
            bpf_framing: false,
        };

        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = ETH_P_ALL.to_be();
        address.sll_ifindex = index as i32;
        let bound = unsafe {
            libc::bind(
                channel.fd(),
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
        let written = unsafe {
            libc::write(
                self.fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
            )
        };
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
        let mut fault = None;

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.wait_readable(remaining) {
                Readiness::Ready => {}
                Readiness::NotYet => continue,
                Readiness::Fault(reason) => {
                    fault = Some(reason);
                    break;
                }
            }

            let read = unsafe {
                libc::read(
                    self.fd(),
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                )
            };
            if read < 0 {
                let error = std::io::Error::last_os_error();
                // Nothing buffered, or a signal interrupted the call: neither is a fault.
                // EAGAIN is EWOULDBLOCK on every platform this builds for.
                if matches!(error.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
                    continue;
                }
                fault = Some(format!("read failed: {error}"));
                break;
            }
            if read == 0 {
                continue;
            }
            let filled = &buffer[..read as usize];

            for frame in self.unpack(filled) {
                seen += 1;
                if let Some(found) = accept(frame) {
                    return ReadResult {
                        found: Some(found),
                        frames_seen: seen,
                        fault,
                    };
                }
            }
        }

        ReadResult {
            found: None,
            frames_seen: seen,
            fault,
        }
    }

    /// Blocks until the channel has data or `limit` elapses.
    ///
    /// Three outcomes, not two. Treating everything that is not readable as "nothing yet"
    /// meant a descriptor the kernel had marked as errored, hung up or invalid was polled
    /// to the deadline and then reported as a quiet link.
    fn wait_readable(&self, limit: Duration) -> Readiness {
        let mut poller = libc::pollfd {
            fd: self.fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Capped so a long deadline still returns to the loop and re-checks the clock.
        let millis = limit.as_millis().min(200) as libc::c_int;
        let ready = unsafe { libc::poll(&mut poller, 1, millis) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                return Readiness::NotYet;
            }
            return Readiness::Fault(format!("poll failed: {error}"));
        }

        // These say something about the descriptor, not about the network.
        if poller.revents & libc::POLLNVAL != 0 {
            return Readiness::Fault("the channel descriptor is not valid".to_string());
        }
        if poller.revents & libc::POLLERR != 0 {
            return Readiness::Fault("the channel reported an error condition".to_string());
        }
        if poller.revents & libc::POLLHUP != 0 {
            return Readiness::Fault("the channel hung up".to_string());
        }

        if poller.revents & libc::POLLIN != 0 {
            Readiness::Ready
        } else {
            Readiness::NotYet
        }
    }

    /// The descriptor for a syscall, borrowed rather than surrendered.
    fn fd(&self) -> libc::c_int {
        use std::os::fd::AsRawFd;
        self.fd.as_raw_fd()
    }

    /// Splits one read into frames.
    ///
    /// Delegates to the capture reader's unpacker rather than carrying a second copy. The
    /// copy that used to live here read Darwin's `bpf_hdr` as though its timestamp were a
    /// 64-bit `timeval`, so it took the captured length from offset 16 instead of 8, got a
    /// nonsense value, and stopped at the first record. That is why this channel reported
    /// zero frames on a link where the capture reader was delivering thousands -- and why
    /// no ARP reply was ever seen. Two subtly different readers of one format is how a
    /// defect survives in only one of them.
    fn unpack<'a>(&self, filled: &'a [u8]) -> Vec<&'a [u8]> {
        if !self.bpf_framing {
            return vec![filled];
        }
        #[cfg(target_os = "macos")]
        {
            crate::net::capture::bpf_frames(filled)
        }
        #[cfg(not(target_os = "macos"))]
        {
            vec![filled]
        }
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
            fault: Some("raw link-layer access is not implemented on this platform".to_string()),
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
    /// A fault on this channel, when one occurred.
    ///
    /// Reported because a failing read and a quiet link produced identical results: `read`
    /// returning an error was collapsed into "nothing yet", so a channel that was broken
    /// reported the network as silent. `EAGAIN` is not a fault -- it is the ordinary answer
    /// on a non-blocking descriptor with nothing buffered.
    pub fault: Option<String>,
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

    /// The test that would have caught the defect this module carried.
    ///
    /// Two readers on one interface disagreeing completely is a fault in the one that sees
    /// nothing, not a property of the medium: any link carrying traffic delivers frames to
    /// both. It compares them directly rather than asserting an absolute count, so it holds
    /// on a quiet link as well as a busy one.
    // The capture reader it compares against is macOS-only, as is the defect it guards.
    #[test]
    #[ignore = "needs root and an interface carrying traffic"]
    #[cfg(target_os = "macos")]
    fn ambient_frames_reach_both_readers() {
        let interface = std::env::var("IDNX_ARP_INTERFACE").expect("IDNX_ARP_INTERFACE");
        let window = std::time::Duration::from_millis(1500);

        let counted = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let sink = std::sync::Arc::clone(&counted);
        let session = crate::net::capture::start(&interface, move |_frame| {
            sink.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        })
        .expect("the capture reader opens");

        let channel = LinkChannel::open_observer(&interface).expect("the link channel opens");
        let read = channel.read_until(Instant::now() + window, |_frame| -> Option<()> { None });

        let mut session = session;
        session.stop();
        let by_capture = counted.load(std::sync::atomic::Ordering::Relaxed);

        println!(
            "capture saw {by_capture} frame(s), link channel saw {} (fault: {:?})",
            read.frames_seen, read.fault
        );
        assert!(
            read.fault.is_none(),
            "the channel faulted: {:?}",
            read.fault
        );
        if by_capture > 0 {
            assert!(
                read.frames_seen > 0,
                "capture read {by_capture} frames while the link channel read none: the \
                 receive path is defective"
            );
        }
    }

    #[test]
    fn a_local_interface_has_a_hardware_address_or_none_is_claimed() {
        // Loopback has no Ethernet address on any supported platform, and inventing one
        // would put a sender address on the wire that answers nowhere.
        assert!(interface_mac("lo0").is_none() || interface_mac("lo").is_none());
    }
}
