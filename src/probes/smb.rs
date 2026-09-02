//! Pure-Rust, zero-dependency SMB2 Negotiate Protocol probe.
//!
//! Connects to Microsoft-DS / SMB (ports 445 / 139) and transmits an SMB2 NEGOTIATE
//! request. Parses the server's NTLMSSP security buffer to extract NetBIOS Computer Name,
//! Workgroup/Domain Name, and DNS hostnames without external dependencies.

use crate::net::endpoint::Endpoint;
use crate::net::socket::SocketBinding;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Host identity extracted from SMB2 negotiation
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmbInfo {
    pub computer_name: Option<String>,
    pub domain_name: Option<String>,
    pub dns_computer_name: Option<String>,
    pub dns_domain_name: Option<String>,
    pub dialect: Option<String>,
}

/// Builds an SMB2 NEGOTIATE request packet with NetBIOS framing
pub fn build_smb2_negotiate_request() -> Vec<u8> {
    let mut smb = Vec::new();

    // SMB2 Header (64 bytes)
    smb.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // Protocol ID: "\xFESMB"
    smb.extend_from_slice(&64u16.to_le_bytes()); // StructureSize = 64
    smb.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge = 0
    smb.extend_from_slice(&0u32.to_le_bytes()); // Status = 0
    smb.extend_from_slice(&0x0000u16.to_le_bytes()); // Command: NEGOTIATE (0)
    smb.extend_from_slice(&0u16.to_le_bytes()); // CreditsRequested = 0
    smb.extend_from_slice(&0u32.to_le_bytes()); // Flags = 0
    smb.extend_from_slice(&0u32.to_le_bytes()); // NextCommand = 0
    smb.extend_from_slice(&1u64.to_le_bytes()); // MessageId = 1
    smb.extend_from_slice(&0u32.to_le_bytes()); // ProcessId = 0
    smb.extend_from_slice(&0u32.to_le_bytes()); // TreeId = 0
    smb.extend_from_slice(&0u64.to_le_bytes()); // SessionId = 0
    smb.extend_from_slice(&[0u8; 16]); // Signature = 16 zeros

    // SMB2 Negotiate Request Body (36 bytes + dialects)
    smb.extend_from_slice(&36u16.to_le_bytes()); // StructureSize = 36
    smb.extend_from_slice(&2u16.to_le_bytes()); // DialectCount = 2
    smb.extend_from_slice(&0x01u16.to_le_bytes()); // SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
    smb.extend_from_slice(&0u16.to_le_bytes()); // Reserved = 0
    smb.extend_from_slice(&0x0000007Fu32.to_le_bytes()); // Capabilities = 0x7F
    smb.extend_from_slice(&[0x11; 16]); // ClientGUID: 16 bytes
    smb.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime = 0

    // Dialects: SMB 2.0.2 (0x0202) and SMB 2.1 (0x0210)
    smb.extend_from_slice(&0x0202u16.to_le_bytes());
    smb.extend_from_slice(&0x0210u16.to_le_bytes());

    // NetBIOS framing (4 bytes)
    let smb_len = smb.len();
    let mut packet = Vec::with_capacity(4 + smb_len);
    packet.push(0x00); // Session message
    packet.push((smb_len >> 16) as u8);
    packet.push((smb_len >> 8) as u8);
    packet.push((smb_len & 0xFF) as u8);
    packet.extend_from_slice(&smb);

    packet
}

/// Helper to decode UTF-16LE bytes into String
fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let (chunks, _) = bytes.as_chunks::<2>();
    let u16s: Vec<u16> = chunks
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&u16s).ok()
}

/// Parses NTLMSSP Target Info AV_PAIRs to extract host computer name and domain
pub fn parse_ntlmssp_av_pairs(data: &[u8]) -> SmbInfo {
    let mut info = SmbInfo::default();

    // Look for "NTLMSSP\0" signature
    let sig = b"NTLMSSP\0";
    let ntlm_pos = match data.windows(sig.len()).position(|w| w == sig) {
        Some(p) => p,
        None => return info,
    };

    let ntlm = &data[ntlm_pos..];
    // NTLM Challenge Message: type = 0x00000002 at offset 8
    if ntlm.len() < 48 {
        return info;
    }

    // Target Info Field: Length (2 bytes), Allocated (2 bytes), Offset (4 bytes) at offset 40
    let target_info_len = u16::from_le_bytes([ntlm[40], ntlm[41]]) as usize;
    let target_info_offset = u32::from_le_bytes([ntlm[44], ntlm[45], ntlm[46], ntlm[47]]) as usize;

    if target_info_offset + target_info_len > ntlm.len() {
        return info;
    }

    let av_data = &ntlm[target_info_offset..target_info_offset + target_info_len];
    let mut offset = 0;

    // Iterate through AV_PAIR list: [Id (2 bytes), Len (2 bytes), Value]
    while offset + 4 <= av_data.len() {
        let av_id = u16::from_le_bytes([av_data[offset], av_data[offset + 1]]);
        let av_len = u16::from_le_bytes([av_data[offset + 2], av_data[offset + 3]]) as usize;
        offset += 4;

        if av_id == 0 {
            // MsvAvEOL (end of list)
            break;
        }

        if offset + av_len > av_data.len() {
            break;
        }

        let val_bytes = &av_data[offset..offset + av_len];
        match av_id {
            1 => {
                // MsvAvNbComputerName
                info.computer_name = decode_utf16le(val_bytes);
            }
            2 => {
                // MsvAvNbDomainName
                info.domain_name = decode_utf16le(val_bytes);
            }
            3 => {
                // MsvAvDnsComputerName
                info.dns_computer_name = decode_utf16le(val_bytes);
            }
            4 => {
                // MsvAvDnsDomainName
                info.dns_domain_name = decode_utf16le(val_bytes);
            }
            _ => {}
        }
        offset += av_len;
    }

    info
}

/// Parses an SMB2 Negotiate Response
pub fn parse_smb2_response(buf: &[u8]) -> Option<SmbInfo> {
    if buf.len() < 68 {
        return None;
    }

    // NetBIOS header is 4 bytes, SMB2 starts at offset 4
    let smb_start = if buf[4..8] == [0xFE, b'S', b'M', b'B'] {
        4
    } else if buf[0..4] == [0xFE, b'S', b'M', b'B'] {
        0
    } else {
        return None;
    };

    let smb = &buf[smb_start..];
    if smb.len() < 68 {
        return None;
    }

    // Dialect is at SMB header + 68 bytes (offset 4 in negotiate response body)
    let dialect_code = if smb.len() >= 72 {
        u16::from_le_bytes([smb[68], smb[69]])
    } else {
        0
    };

    let dialect_str = match dialect_code {
        0x0202 => "SMB 2.0.2",
        0x0210 => "SMB 2.1",
        0x0300 => "SMB 3.0",
        0x0302 => "SMB 3.0.2",
        0x0311 => "SMB 3.1.1",
        _ => "SMB2",
    };

    // Parse NTLMSSP payload embedded in security buffer
    let mut info = parse_ntlmssp_av_pairs(smb);
    info.dialect = Some(dialect_str.to_string());

    if info.computer_name.is_some() || info.domain_name.is_some() {
        Some(info)
    } else {
        None
    }
}

/// Asynchronously probes target IP on port 445/139 for SMB host identity
pub async fn probe_smb(
    target: &Endpoint,
    port: u16,
    binding: &SocketBinding,
    timeout_duration: Duration,
) -> Option<SmbInfo> {
    let connect_fut = binding.tcp_connect(target.socket_addr(port), timeout_duration);
    let mut stream = timeout(timeout_duration, connect_fut).await.ok()?.ok()?;

    let req = build_smb2_negotiate_request();
    stream.write_all(&req).await.ok()?;

    let mut buf = vec![0u8; 4096];
    let read_fut = stream.read(&mut buf);
    let bytes_read = timeout(timeout_duration, read_fut).await.ok()?.ok()?;

    if bytes_read > 0 {
        parse_smb2_response(&buf[..bytes_read])
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// UNIT TESTS
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb2_negotiate_request_wire_format() {
        let req = build_smb2_negotiate_request();
        assert!(req.len() >= 68);
        assert_eq!(req[0], 0x00); // NetBIOS session message
        assert_eq!(&req[4..8], &[0xFE, b'S', b'M', b'B']); // SMB2 header
    }

    #[test]
    fn test_parse_ntlmssp_synthetic() {
        // Construct a synthetic NTLMSSP challenge message
        let mut ntlm = Vec::new();
        ntlm.extend_from_slice(b"NTLMSSP\0");
        ntlm.extend_from_slice(&2u32.to_le_bytes()); // Type 2 Challenge
        ntlm.extend_from_slice(&[0u8; 28]); // Dummy fields

        // AV_PAIRs
        let mut av_pairs = Vec::new();
        // MsvAvNbComputerName (Id: 1) = "WIN-SERVER"
        av_pairs.extend_from_slice(&1u16.to_le_bytes());
        let comp_utf16: Vec<u8> = "WIN-SERVER"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        av_pairs.extend_from_slice(&(comp_utf16.len() as u16).to_le_bytes());
        av_pairs.extend_from_slice(&comp_utf16);

        // MsvAvNbDomainName (Id: 2) = "WORKGROUP"
        av_pairs.extend_from_slice(&2u16.to_le_bytes());
        let domain_utf16: Vec<u8> = "WORKGROUP"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        av_pairs.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        av_pairs.extend_from_slice(&domain_utf16);

        // MsvAvEOL (Id: 0)
        av_pairs.extend_from_slice(&0u16.to_le_bytes());
        av_pairs.extend_from_slice(&0u16.to_le_bytes());

        // Target Info header at offset 40: Len (2), Allocated (2), Offset (4)
        let target_info_offset = 48u32;
        ntlm.extend_from_slice(&(av_pairs.len() as u16).to_le_bytes());
        ntlm.extend_from_slice(&(av_pairs.len() as u16).to_le_bytes());
        ntlm.extend_from_slice(&target_info_offset.to_le_bytes());
        ntlm.extend_from_slice(&av_pairs);

        let info = parse_ntlmssp_av_pairs(&ntlm);
        assert_eq!(info.computer_name.as_deref(), Some("WIN-SERVER"));
        assert_eq!(info.domain_name.as_deref(), Some("WORKGROUP"));
    }
}
