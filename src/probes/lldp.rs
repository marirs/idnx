use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct LldpNeighbor {
    pub chassis_id: String,
    pub port_id: String,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    #[allow(dead_code)]
    pub management_ip: Option<Ipv4Addr>,
    #[allow(dead_code)]
    pub capabilities: Vec<String>,
}

/// Parses a raw LLDP Ethernet frame (EtherType 0x88CC)
/// Each TLV is encoded as:
/// Bits 15-9 (7 bits): TLV Type
/// Bits 8-0 (9 bits): TLV Length
pub fn parse_lldp_frame(payload: &[u8]) -> Option<LldpNeighbor> {
    if payload.len() < 14 {
        return None;
    }

    // Check if frame is Cisco Discovery Protocol (CDP: dest MAC 01:00:0c:cc:cc:cc)
    if payload.len() >= 22
        && payload[0..6] == CDP_MULTICAST_MAC
        && let Some(cdp) = crate::probes::cdp::parse_cdp_frame(payload)
    {
        let desc = match (cdp.platform, cdp.software_version) {
            (Some(p), Some(v)) => Some(format!("{} - {}", p, v)),
            (Some(p), None) => Some(p),
            (None, Some(v)) => Some(v),
            (None, None) => None,
        };
        return Some(LldpNeighbor {
            chassis_id: cdp.device_id.clone(),
            port_id: cdp.port_id,
            system_name: Some(cdp.device_id),
            system_description: desc,
            management_ip: cdp.management_ip,
            capabilities: cdp.capabilities,
        });
    }

    // Skip Ethernet header (14 bytes: 6 dest MAC + 6 src MAC + 2 EtherType)
    let mut offset = 14;

    let mut chassis_id = None;
    let mut port_id = None;
    let mut system_name = None;
    let mut system_description = None;
    let mut management_ip = None;
    let mut capabilities = Vec::new();

    while offset + 2 <= payload.len() {
        let header = ((payload[offset] as u16) << 8) | (payload[offset + 1] as u16);
        let tlv_type = (header >> 9) as u8;
        let tlv_len = (header & 0x01FF) as usize;
        offset += 2;

        if offset + tlv_len > payload.len() {
            break;
        }

        let value = &payload[offset..offset + tlv_len];
        offset += tlv_len;

        match tlv_type {
            0 => {
                // End of LLDPDU
                break;
            }
            1 => {
                // Chassis ID
                if !value.is_empty() {
                    let subtype = value[0];
                    if subtype == 4 && value.len() == 7 {
                        // MAC address subtype
                        chassis_id = Some(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            value[1], value[2], value[3], value[4], value[5], value[6]
                        ));
                    } else {
                        chassis_id = Some(String::from_utf8_lossy(&value[1..]).to_string());
                    }
                }
            }
            2 => {
                // Port ID
                if !value.is_empty() {
                    port_id = Some(String::from_utf8_lossy(&value[1..]).to_string());
                }
            }
            3 => {} // TTL
            4 => {} // Port Description
            5 => {
                // System Name (e.g. "RT-BE58-GO", "UGREEN-Switch")
                system_name = Some(String::from_utf8_lossy(value).trim().to_string());
            }
            6 => {
                // System Description (Firmware, model details)
                system_description = Some(String::from_utf8_lossy(value).trim().to_string());
            }
            7 => {
                // System Capabilities
                if value.len() >= 4 {
                    let caps = ((value[0] as u16) << 8) | (value[1] as u16);
                    if caps & 0x0004 != 0 {
                        capabilities.push("Bridge/Switch".to_string());
                    }
                    if caps & 0x0008 != 0 {
                        capabilities.push("WLAN Access Point".to_string());
                    }
                    if caps & 0x0010 != 0 {
                        capabilities.push("Router".to_string());
                    }
                    if caps & 0x0020 != 0 {
                        capabilities.push("Telephone".to_string());
                    }
                }
            }
            8
                // Management Address
                if value.len() >= 6 && value[0] == 5 && value[1] == 1 => {
                    // IPv4 management address
                    management_ip = Some(Ipv4Addr::new(value[2], value[3], value[4], value[5]));
                }
            _ => {}
        }
    }

    if let (Some(chassis), Some(port)) = (chassis_id, port_id) {
        Some(LldpNeighbor {
            chassis_id: chassis,
            port_id: port,
            system_name,
            system_description,
            management_ip,
            capabilities,
        })
    } else {
        None
    }
}

/// CDP frames are sent to this reserved Cisco multicast address. CDP is LLC/SNAP
/// encapsulated, so it carries no distinguishing EtherType and must be matched on the
/// destination MAC instead.
const CDP_MULTICAST_MAC: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];

/// Minimum size of Darwin's `struct bpf_hdr`.
#[cfg(target_os = "macos")]
const BPF_HDR_MIN_LEN: usize = 18;

/// `BPF_WORDALIGN` from `net/bpf.h`; on Darwin `BPF_ALIGNMENT` is `sizeof(int32_t)`.
#[cfg(target_os = "macos")]
fn bpf_word_align(len: usize) -> usize {
    const BPF_ALIGNMENT: usize = std::mem::size_of::<i32>();
    (len + (BPF_ALIGNMENT - 1)) & !(BPF_ALIGNMENT - 1)
}

/// Result of attempting an LLDP capture
#[derive(Debug)]
#[allow(dead_code)]
pub enum LldpCaptureResult {
    Success(Vec<LldpNeighbor>),
    PermissionDenied,
    NotSupported(String),
}

/// Cross-platform Layer 2 LLDP frame capture (macOS BPF + Linux raw socket)
pub async fn capture_lldp_neighbors(interface: &str, duration: Duration) -> LldpCaptureResult {
    #[cfg(target_os = "macos")]
    {
        capture_macos_bpf(interface, duration)
    }

    #[cfg(target_os = "linux")]
    {
        capture_linux_raw_socket(interface, duration)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (interface, duration);
        LldpCaptureResult::NotSupported("LLDP raw capture not supported on this OS".to_string())
    }
}

#[cfg(target_os = "macos")]
fn capture_macos_bpf(interface: &str, duration: Duration) -> LldpCaptureResult {
    use std::ffi::CString;
    use std::os::unix::io::FromRawFd;
    use std::os::unix::io::IntoRawFd;

    // Try opening an available /dev/bpf device
    let mut bpf_fd = -1;
    let mut permission_denied = false;

    for i in 0..16 {
        let path = format!("/dev/bpf{}\0", i);
        let fd = unsafe {
            libc::open(
                path.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_NONBLOCK,
            )
        };
        if fd >= 0 {
            bpf_fd = fd;
            break;
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EACCES) {
                permission_denied = true;
            }
        }
    }

    if bpf_fd < 0 {
        if permission_denied {
            return LldpCaptureResult::PermissionDenied;
        }
        return LldpCaptureResult::NotSupported("Could not allocate a BPF device".to_string());
    }

    // Attach to requested interface: ioctl(bpf_fd, BIOCSETIF, &ifreq)
    let if_name = match CString::new(interface) {
        Ok(c) => c,
        Err(_) => {
            unsafe { libc::close(bpf_fd) };
            return LldpCaptureResult::NotSupported("Invalid interface name".to_string());
        }
    };

    #[repr(C)]
    struct Ifreq {
        ifr_name: [libc::c_char; 16],
        _padding: [u8; 16],
    }

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    let bytes = if_name.as_bytes_with_nul();
    let len = bytes.len().min(16);
    for (i, &b) in bytes[..len].iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    const BIOCSETIF: libc::c_ulong = 0x8020426c; // macOS Darwin BIOCSETIF
    const BIOCIMMEDIATE: libc::c_ulong = 0x80044270; // macOS Darwin BIOCIMMEDIATE

    if unsafe { libc::ioctl(bpf_fd, BIOCSETIF, &ifr) } < 0 {
        unsafe { libc::close(bpf_fd) };
        return LldpCaptureResult::NotSupported(format!("Failed to bind BPF to {}", interface));
    }

    let enable: libc::c_uint = 1;
    unsafe {
        libc::ioctl(bpf_fd, BIOCIMMEDIATE, &enable);
    }

    let mut file = unsafe { std::fs::File::from_raw_fd(bpf_fd) };
    let mut buffer = [0u8; 4096];
    let start = std::time::Instant::now();
    let mut neighbors = Vec::new();

    while start.elapsed() < duration {
        use std::io::Read;
        match file.read(&mut buffer) {
            Ok(n) if n > 14 => {
                // Process BPF buffer (contains bpf_hdr + packet)
                let mut read_offset = 0;
                while read_offset + BPF_HDR_MIN_LEN <= n {
                    // Darwin `struct bpf_hdr` on 64-bit:
                    //   0..8   bh_tstamp (two u32)
                    //   8..12  bh_caplen
                    //   12..16 bh_datalen
                    //   16..18 bh_hdrlen
                    let bh_caplen = u32::from_le_bytes([
                        buffer[read_offset + 8],
                        buffer[read_offset + 9],
                        buffer[read_offset + 10],
                        buffer[read_offset + 11],
                    ]) as usize;
                    let bh_hdrlen =
                        u16::from_le_bytes([buffer[read_offset + 16], buffer[read_offset + 17]])
                            as usize;

                    if bh_hdrlen < BPF_HDR_MIN_LEN || bh_caplen == 0 {
                        break;
                    }

                    let pkt_start = read_offset + bh_hdrlen;
                    let pkt_end = pkt_start + bh_caplen;
                    if pkt_end > n || pkt_start + 14 > n {
                        break;
                    }

                    // Bound the frame by its own captured length. Passing the remainder of
                    // the buffer let the TLV walker run past the end of one packet and into
                    // the next, producing garbage neighbours on a busy link.
                    let frame = &buffer[pkt_start..pkt_end];

                    // EtherType at offset 12 (LLDP 0x88CC), or the CDP multicast
                    // destination MAC, since CDP is LLC/SNAP and carries a length there.
                    let ethertype = ((frame[12] as u16) << 8) | (frame[13] as u16);
                    let is_cdp = frame[0..6] == CDP_MULTICAST_MAC;

                    if (ethertype == 0x88CC || is_cdp)
                        && let Some(neighbor) = parse_lldp_frame(frame)
                    {
                        neighbors.push(neighbor);
                    }

                    // Each record is padded to a BPF_ALIGNMENT boundary. Advancing by a
                    // fixed 2048 instead skipped every packet after the first in a buffer,
                    // and mis-set the offset whenever a record was smaller than that.
                    let advance = bpf_word_align(bh_hdrlen + bh_caplen);
                    if advance == 0 {
                        break;
                    }
                    read_offset += advance;
                }
            }
            _ => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    let _ = file.into_raw_fd(); // Release ownership safely
    LldpCaptureResult::Success(neighbors)
}

#[cfg(target_os = "linux")]
fn capture_linux_raw_socket(interface: &str, duration: Duration) -> LldpCaptureResult {
    use std::ffi::CString;

    // Bind to ETH_P_ALL rather than ETH_P_LLDP.
    //
    // CDP is LLC/SNAP encapsulated: the 802.3 length/type field holds a frame length, not
    // 0x88CC, so a socket bound to ETH_P_LLDP never receives a single CDP frame. Binding
    // to ETH_P_ALL and narrowing with a kernel packet filter is what actually makes the
    // CDP parser reachable on Linux; matching macOS, which sees both.
    const ETH_P_ALL: u16 = 0x0003;
    let sock = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ALL.to_be() as i32) };

    if sock < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) || err.raw_os_error() == Some(libc::EACCES) {
            return LldpCaptureResult::PermissionDenied;
        }
        return LldpCaptureResult::NotSupported("Could not create raw packet socket".to_string());
    }

    let if_name = match CString::new(interface) {
        Ok(c) => c,
        Err(_) => {
            unsafe { libc::close(sock) };
            return LldpCaptureResult::NotSupported("Invalid interface name".to_string());
        }
    };

    let if_index = unsafe { libc::if_nametoindex(if_name.as_ptr()) };
    if if_index == 0 {
        unsafe { libc::close(sock) };
        return LldpCaptureResult::NotSupported("Failed to get interface index".to_string());
    }

    // Bind socket to interface
    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as u16;
    sa.sll_protocol = ETH_P_ALL.to_be();
    sa.sll_ifindex = if_index as i32;

    if unsafe {
        libc::bind(
            sock,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    } < 0
    {
        unsafe { libc::close(sock) };
        return LldpCaptureResult::NotSupported(
            "Failed to bind raw socket to interface".to_string(),
        );
    }

    // Narrow ETH_P_ALL down in the kernel so the userspace loop is not handed every frame
    // on the link. Without this the discovery window is spent copying unrelated traffic and
    // the few LLDP/CDP advertisements in it are missed.
    attach_lldp_cdp_filter(sock);

    let mut buf = [0u8; 2048];
    let start = std::time::Instant::now();
    let mut neighbors = Vec::new();

    // Set non-blocking
    unsafe {
        let flags = libc::fcntl(sock, libc::F_GETFL, 0);
        libc::fcntl(sock, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    while start.elapsed() < duration {
        let n = unsafe { libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n > 14 {
            if let Some(neighbor) = parse_lldp_frame(&buf[..n as usize]) {
                neighbors.push(neighbor);
            }
            // A frame was available, so drain the queue instead of sleeping. Sleeping after
            // every successful read let bursts of advertisements expire unread.
            continue;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    unsafe { libc::close(sock) };
    LldpCaptureResult::Success(neighbors)
}

/// Attaches a classic BPF filter accepting only LLDP (EtherType 0x88CC) and CDP
/// (destination MAC 01:00:0c:cc:cc:cc) frames.
///
/// Failure is deliberately non-fatal: without the filter the socket still delivers the
/// frames we want, just alongside everything else, so capture degrades rather than breaks.
#[cfg(target_os = "linux")]
fn attach_lldp_cdp_filter(sock: i32) {
    // Offsets are into the Ethernet header.
    //   0: ldh  [12]                 ; EtherType / 802.3 length
    //   1: jeq  #0x88CC -> accept    ; LLDP
    //   2: ld   [0]                  ; first 4 octets of the destination MAC
    //   3: jeq  #0x01000CCC          ; CDP multicast, high half
    //   4: ldh  [4]                  ; last 2 octets of the destination MAC
    //   5: jeq  #0xCCCC -> accept    ; CDP multicast, low half
    //   6: ret  #262144              ; accept (snap length)
    //   7: ret  #0                   ; reject
    const BPF_LD: u16 = 0x00;
    const BPF_H: u16 = 0x08;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    let prog: [libc::sock_filter; 8] = [
        libc::sock_filter {
            code: BPF_LD | BPF_H | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 12,
        },
        libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 4,
            jf: 0,
            k: 0x0000_88CC,
        },
        libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 3,
            k: 0x0100_0CCC,
        },
        libc::sock_filter {
            code: BPF_LD | BPF_H | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: 0x0000_CCCC,
        },
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: 262_144,
        },
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];

    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };

    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lldp_frame() {
        let frame = vec![
            // Ethernet Header (Dest, Src, EtherType 0x88CC)
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0xa0, 0xad, 0x9f, 0xe6, 0x38, 0x00, 0x88, 0xcc,
            // TLV 1: Chassis ID (Type=1, Len=7 -> header 0x0207), Subtype 4 (MAC)
            0x02, 0x07, 0x04, 0xa0, 0xad, 0x9f, 0xe6, 0x38, 0x00,
            // TLV 2: Port ID (Type=2, Len=5 -> header 0x0405), Subtype 5, "eth0"
            0x04, 0x05, 0x05, b'e', b't', b'h', b'0',
            // TLV 5: System Name (Type=5, Len=10 -> header 0x0a0a), "RT-BE58-GO"
            0x0a, 0x0a, b'R', b'T', b'-', b'B', b'E', b'5', b'8', b'-', b'G', b'O',
            // TLV 0: End of LLDPDU (header 0x0000)
            0x00, 0x00,
        ];

        let neighbor = parse_lldp_frame(&frame).expect("Failed to parse LLDP frame");
        assert_eq!(neighbor.chassis_id, "a0:ad:9f:e6:38:00");
        assert_eq!(neighbor.port_id, "eth0");
        assert_eq!(neighbor.system_name.as_deref(), Some("RT-BE58-GO"));
    }
}
