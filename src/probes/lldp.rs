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
            8 => {
                // Management Address
                if value.len() >= 6 && value[0] == 5 && value[1] == 1 {
                    // IPv4 management address
                    management_ip = Some(Ipv4Addr::new(value[2], value[3], value[4], value[5]));
                }
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
                while read_offset + 18 <= n {
                    // In 64-bit Darwin, bpf_hdr has bh_hdrlen at byte 16
                    let bh_hdrlen = ((buffer[read_offset + 16] as usize)
                        | ((buffer[read_offset + 17] as usize) << 8))
                        .max(18);
                    let pkt_start = read_offset + bh_hdrlen;
                    if pkt_start + 14 > n {
                        break;
                    }

                    // Check EtherType at offset 12 in the Ethernet header
                    let ethertype =
                        ((buffer[pkt_start + 12] as u16) << 8) | (buffer[pkt_start + 13] as u16);
                    if ethertype == 0x88CC {
                        if let Some(neighbor) = parse_lldp_frame(&buffer[pkt_start..n]) {
                            neighbors.push(neighbor);
                        }
                    }

                    // Move to next packet
                    read_offset += 2048; // Advance frame
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

    // ETH_P_LLDP = 0x88CC
    const ETH_P_LLDP: u16 = 0x88CC;
    let sock = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (ETH_P_LLDP as u16).to_be() as i32,
        )
    };

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
    sa.sll_protocol = (ETH_P_LLDP as u16).to_be();
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
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    unsafe { libc::close(sock) };
    LldpCaptureResult::Success(neighbors)
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
