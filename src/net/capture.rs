//! Raw link-layer frame capture.
//!
//! Capture is opportunistic. It opens if privileges and the platform allow, runs alongside
//! everything else, and its failure changes nothing about the rest of discovery. No caller
//! waits on it and no result depends on it.
//!
//! Reads are blocking syscalls, so each capture runs on its own dedicated OS thread rather
//! than a runtime worker: a busy link must never starve the async providers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;

/// Why capture could not be started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// Elevated privileges are required to open a raw capture device.
    PermissionDenied,
    /// The platform or interface does not support raw capture.
    Unsupported(String),
}

impl CaptureError {
    pub fn explain(&self) -> String {
        match self {
            CaptureError::PermissionDenied => {
                "raw link-layer capture requires elevated privileges".to_string()
            }
            CaptureError::Unsupported(why) => format!("raw link-layer capture unavailable: {why}"),
        }
    }
}

/// A running capture, stopped by dropping it or calling [`CaptureSession::stop`].
pub struct CaptureSession {
    stop: Arc<AtomicBool>,
    frames_seen: Arc<AtomicU64>,
    handle: Option<JoinHandle<()>>,
}

impl CaptureSession {
    /// Total frames handed to the decoder so far.
    ///
    /// Reported so an operator can tell "the link was silent" from "capture never ran",
    /// which look identical in the topology otherwise.
    pub fn frames_seen(&self) -> u64 {
        self.frames_seen.load(Ordering::Relaxed)
    }

    /// Signals the reader to finish and waits briefly for it.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // The reader polls the stop flag between short non-blocking reads, so it exits
        // promptly; joining here keeps the thread from outliving the session.
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Starts capturing on an interface, invoking `on_frame` for each frame received.
///
/// The callback runs on the capture thread and must be cheap; decoding is, and anything
/// expensive belongs behind a channel.
pub fn start<F>(interface: &str, on_frame: F) -> Result<CaptureSession, CaptureError>
where
    F: FnMut(&[u8]) + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let frames_seen = Arc::new(AtomicU64::new(0));

    let handle = spawn_reader(
        interface,
        on_frame,
        Arc::clone(&stop),
        Arc::clone(&frames_seen),
    )?;

    Ok(CaptureSession {
        stop,
        frames_seen,
        handle: Some(handle),
    })
}

#[cfg(target_os = "macos")]
fn spawn_reader<F>(
    interface: &str,
    mut on_frame: F,
    stop: Arc<AtomicBool>,
    frames_seen: Arc<AtomicU64>,
) -> Result<JoinHandle<()>, CaptureError>
where
    F: FnMut(&[u8]) + Send + 'static,
{
    use std::ffi::CString;
    use std::os::unix::io::FromRawFd;

    let mut fd = -1;
    let mut permission_denied = false;
    for i in 0..32 {
        let path = format!("/dev/bpf{}\0", i);
        // Safe: the path is NUL-terminated and the flags are constants.
        let opened = unsafe {
            libc::open(
                path.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_NONBLOCK,
            )
        };
        if opened >= 0 {
            fd = opened;
            break;
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES) {
            permission_denied = true;
        }
    }

    if fd < 0 {
        return Err(if permission_denied {
            CaptureError::PermissionDenied
        } else {
            CaptureError::Unsupported("no BPF device available".to_string())
        });
    }

    let Ok(if_name) = CString::new(interface) else {
        unsafe { libc::close(fd) };
        return Err(CaptureError::Unsupported("invalid interface name".into()));
    };

    #[repr(C)]
    struct Ifreq {
        ifr_name: [libc::c_char; 16],
        _padding: [u8; 16],
    }

    // Safe: zeroed is a valid Ifreq, and the name is copied within bounds below.
    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    let bytes = if_name.as_bytes_with_nul();
    for (slot, byte) in ifr.ifr_name.iter_mut().zip(bytes.iter().take(16)) {
        *slot = *byte as libc::c_char;
    }

    const BIOCSETIF: libc::c_ulong = 0x8020426c;
    const BIOCIMMEDIATE: libc::c_ulong = 0x80044270;
    const BIOCPROMISC: libc::c_ulong = 0x20002069;
    const BIOCGBLEN: libc::c_ulong = 0x40044266;

    if unsafe { libc::ioctl(fd, BIOCSETIF, &ifr) } < 0 {
        unsafe { libc::close(fd) };
        return Err(CaptureError::Unsupported(format!(
            "cannot bind BPF to {interface}"
        )));
    }

    let enable: libc::c_uint = 1;
    unsafe {
        libc::ioctl(fd, BIOCIMMEDIATE, &enable);
        // Promiscuous mode is what makes traffic between other hosts visible. Without a
        // mirror port a switch still will not forward most of it, which the visibility
        // report states rather than implying otherwise.
        libc::ioctl(fd, BIOCPROMISC);
    }

    let mut buffer_len: libc::c_uint = 0;
    if unsafe { libc::ioctl(fd, BIOCGBLEN, &mut buffer_len) } < 0 || buffer_len == 0 {
        buffer_len = 4096;
    }

    let handle = std::thread::Builder::new()
        .name(format!("idnx-capture-{interface}"))
        .spawn(move || {
            use std::io::Read;
            // Safe: fd is owned here and not used elsewhere after this point.
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            let mut buffer = vec![0u8; buffer_len as usize];

            while !stop.load(Ordering::Relaxed) {
                match file.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        for frame in bpf_frames(&buffer[..n]) {
                            frames_seen.fetch_add(1, Ordering::Relaxed);
                            on_frame(frame);
                        }
                    }
                    // Non-blocking device with nothing queued.
                    _ => std::thread::sleep(std::time::Duration::from_millis(20)),
                }
            }
        })
        .map_err(|e| CaptureError::Unsupported(e.to_string()))?;

    Ok(handle)
}

/// Splits a BPF read buffer into individual frames.
///
/// Records are padded to a `BPF_ALIGNMENT` boundary and each carries its own captured
/// length, so a fixed stride would skip packets and mis-slice the rest.
#[cfg(any(target_os = "macos", test))]
pub fn bpf_frames(buffer: &[u8]) -> Vec<&[u8]> {
    const BPF_HDR_MIN_LEN: usize = 18;
    fn word_align(len: usize) -> usize {
        const ALIGNMENT: usize = std::mem::size_of::<i32>();
        (len + (ALIGNMENT - 1)) & !(ALIGNMENT - 1)
    }

    let mut frames = Vec::new();
    let mut offset = 0;

    while offset + BPF_HDR_MIN_LEN <= buffer.len() {
        // Darwin bpf_hdr: tstamp(8) caplen(4) datalen(4) hdrlen(2)
        let caplen = u32::from_le_bytes([
            buffer[offset + 8],
            buffer[offset + 9],
            buffer[offset + 10],
            buffer[offset + 11],
        ]) as usize;
        let hdrlen = u16::from_le_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;

        if hdrlen < BPF_HDR_MIN_LEN || caplen == 0 {
            break;
        }
        let start = offset + hdrlen;
        let end = start + caplen;
        if end > buffer.len() {
            break;
        }
        frames.push(&buffer[start..end]);

        let advance = word_align(hdrlen + caplen);
        if advance == 0 {
            break;
        }
        offset += advance;
    }

    frames
}

#[cfg(target_os = "linux")]
fn spawn_reader<F>(
    interface: &str,
    mut on_frame: F,
    stop: Arc<AtomicBool>,
    frames_seen: Arc<AtomicU64>,
) -> Result<JoinHandle<()>, CaptureError>
where
    F: FnMut(&[u8]) + Send + 'static,
{
    use std::ffi::CString;

    // ETH_P_ALL: passive discovery needs STP, ARP, DHCP and RA as well as LLDP, so the
    // socket cannot be bound to a single EtherType. CDP in particular is LLC/SNAP and
    // carries no distinguishing EtherType at all.
    const ETH_P_ALL: u16 = 0x0003;

    // Safe: constants only; the returned fd is checked below.
    let sock = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ALL.to_be() as i32) };
    if sock < 0 {
        let err = std::io::Error::last_os_error().raw_os_error();
        return Err(if err == Some(libc::EPERM) || err == Some(libc::EACCES) {
            CaptureError::PermissionDenied
        } else {
            CaptureError::Unsupported("cannot create a raw packet socket".to_string())
        });
    }

    let Ok(if_name) = CString::new(interface) else {
        unsafe { libc::close(sock) };
        return Err(CaptureError::Unsupported("invalid interface name".into()));
    };

    // Safe: if_name is a valid NUL-terminated string.
    let if_index = unsafe { libc::if_nametoindex(if_name.as_ptr()) };
    if if_index == 0 {
        unsafe { libc::close(sock) };
        return Err(CaptureError::Unsupported(format!(
            "unknown interface {interface}"
        )));
    }

    // Safe: zeroed sockaddr_ll is valid; fields are set before use.
    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as u16;
    sa.sll_protocol = ETH_P_ALL.to_be();
    sa.sll_ifindex = if_index as i32;

    let bound = unsafe {
        libc::bind(
            sock,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if bound < 0 {
        unsafe { libc::close(sock) };
        return Err(CaptureError::Unsupported(format!(
            "cannot bind to {interface}"
        )));
    }

    // Promiscuous mode, so frames not addressed to this host are delivered where the
    // switch forwards them at all.
    let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
    mreq.mr_ifindex = if_index as i32;
    mreq.mr_type = libc::PACKET_MR_PROMISC as u16;
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            &mreq as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
        );
    }

    // Non-blocking, so the reader can observe the stop flag between reads.
    unsafe {
        let flags = libc::fcntl(sock, libc::F_GETFL, 0);
        libc::fcntl(sock, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let handle = std::thread::Builder::new()
        .name(format!("idnx-capture-{interface}"))
        .spawn(move || {
            let mut buf = vec![0u8; 65536];
            while !stop.load(Ordering::Relaxed) {
                // Safe: buf is owned and its length is passed correctly.
                let n = unsafe {
                    libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                };
                if n > 14 {
                    frames_seen.fetch_add(1, Ordering::Relaxed);
                    on_frame(&buf[..n as usize]);
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
            unsafe { libc::close(sock) };
        })
        .map_err(|e| CaptureError::Unsupported(e.to_string()))?;

    Ok(handle)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn spawn_reader<F>(
    _interface: &str,
    _on_frame: F,
    _stop: Arc<AtomicBool>,
    _frames_seen: Arc<AtomicU64>,
) -> Result<JoinHandle<()>, CaptureError>
where
    F: FnMut(&[u8]) + Send + 'static,
{
    Err(CaptureError::Unsupported(
        "raw capture is not implemented on this platform".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a Darwin BPF record: header then payload, padded to a 4-byte boundary.
    fn bpf_record(payload: &[u8]) -> Vec<u8> {
        let hdrlen: u16 = 18;
        let mut rec = Vec::new();
        rec.extend_from_slice(&[0u8; 8]); // timestamp
        rec.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // caplen
        rec.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // datalen
        rec.extend_from_slice(&hdrlen.to_le_bytes());
        rec.extend_from_slice(payload);
        while rec.len() % 4 != 0 {
            rec.push(0);
        }
        rec
    }

    #[test]
    fn multiple_frames_in_one_buffer_are_all_returned() {
        // A fixed stride would have returned only the first of these.
        let mut buffer = bpf_record(&[1u8; 60]);
        buffer.extend_from_slice(&bpf_record(&[2u8; 42]));
        buffer.extend_from_slice(&bpf_record(&[3u8; 100]));

        let frames = bpf_frames(&buffer);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].len(), 60);
        assert_eq!(frames[1].len(), 42);
        assert_eq!(frames[2].len(), 100);
        assert!(frames[1].iter().all(|b| *b == 2));
    }

    #[test]
    fn a_truncated_record_is_dropped_rather_than_mis_sliced() {
        let mut buffer = bpf_record(&[7u8; 40]);
        // Header claiming more payload than the buffer holds.
        buffer.extend_from_slice(&[0u8; 8]);
        buffer.extend_from_slice(&9999u32.to_le_bytes());
        buffer.extend_from_slice(&9999u32.to_le_bytes());
        buffer.extend_from_slice(&18u16.to_le_bytes());

        let frames = bpf_frames(&buffer);
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn an_empty_buffer_yields_nothing() {
        assert!(bpf_frames(&[]).is_empty());
        assert!(bpf_frames(&[0u8; 10]).is_empty());
    }

    #[test]
    fn capture_errors_explain_themselves() {
        assert!(
            CaptureError::PermissionDenied
                .explain()
                .contains("privileges")
        );
        assert!(
            CaptureError::Unsupported("no device".into())
                .explain()
                .contains("no device")
        );
    }
}
