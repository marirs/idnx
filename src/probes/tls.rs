//! Pure-Rust, zero-dependency TLS 1.2/1.3 handshake probe and X.509 certificate extractor.
//!
//! Connects to HTTPS / TLS services (ports 443, 8443, etc.) and transmits a minimal
//! TLS `ClientHello` message. Parses the resulting `Certificate` handshake message
//! to extract Subject Common Name (CN), Subject Alternative Names (SANs), and Issuer
//! without any OpenSSL or C library dependencies.

use crate::net::endpoint::Endpoint;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Extracted TLS Certificate metadata
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsCertificateInfo {
    pub common_name: Option<String>,
    pub alt_names: Vec<String>,
    pub issuer_cn: Option<String>,
}

// OID byte sequences for X.509 fields
// 2.5.4.3 = id-at-commonName (encoded: 55 04 03)
const OID_COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];
// 2.5.29.17 = id-ce-subjectAltName (encoded: 55 1d 11)
const OID_SUBJECT_ALT_NAME: [u8; 3] = [0x55, 0x1D, 0x11];

/// Constructs a standard, minimal TLS 1.2/1.3 ClientHello message
pub fn build_client_hello() -> Vec<u8> {
    let mut hello_body = Vec::new();

    // ProtocolVersion: TLS 1.2 (0x0303)
    hello_body.extend_from_slice(&[0x03, 0x03]);

    // Random: 32 bytes (Unix timestamp + 28 bytes)
    hello_body.extend_from_slice(&[0x42; 32]);

    // Session ID: 0 bytes length
    hello_body.push(0x00);

    // CipherSuites: 6 standard suites (12 bytes)
    // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)
    // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
    // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)
    // TLS_AES_128_GCM_SHA256 (0x1301)
    // TLS_AES_256_GCM_SHA384 (0x1302)
    // TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)
    let ciphers = [
        0xC0, 0x2B, 0xC0, 0x2F, 0xC0, 0x30, 0x13, 0x01, 0x13, 0x02, 0x00, 0x2F,
    ];
    hello_body.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(&ciphers);

    // CompressionMethods: 1 byte length, null (0x00)
    hello_body.extend_from_slice(&[0x01, 0x00]);

    // Extensions: supported_groups (elliptic curves)
    let supported_groups = [0x00, 0x1D, 0x00, 0x17, 0x00, 0x18]; // x25519, secp256r1, secp384r1
    let mut ext_body = Vec::new();
    ext_body.extend_from_slice(&0x000Au16.to_be_bytes()); // extension type 10 (supported_groups)
    ext_body.extend_from_slice(&((supported_groups.len() + 2) as u16).to_be_bytes());
    ext_body.extend_from_slice(&(supported_groups.len() as u16).to_be_bytes());
    ext_body.extend_from_slice(&supported_groups);

    // Extensions total length
    hello_body.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(&ext_body);

    // Handshake Layer: Type 1 (ClientHello) + 3-byte length + body
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let body_len = hello_body.len();
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push((body_len & 0xFF) as u8);
    handshake.extend_from_slice(&hello_body);

    // TLS Record Layer: Type 22 (Handshake), Version 0x0301 (TLS 1.0), Length
    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Parses ASN.1 string (UTF8String, PrintableString, IA5String, etc.)
fn parse_asn1_string(data: &[u8], offset: &mut usize) -> Option<String> {
    if *offset >= data.len() {
        return None;
    }
    let tag = data[*offset];
    *offset += 1;

    // Supported ASN.1 string tags:
    // 0x0C = UTF8String, 0x13 = PrintableString, 0x14 = TeletexString, 0x16 = IA5String
    if tag != 0x0C && tag != 0x13 && tag != 0x14 && tag != 0x16 {
        return None;
    }

    if *offset >= data.len() {
        return None;
    }

    let mut len = data[*offset] as usize;
    *offset += 1;
    if (len & 0x80) != 0 {
        let num_bytes = len & 0x7F;
        len = 0;
        for _ in 0..num_bytes {
            if *offset >= data.len() {
                return None;
            }
            len = (len << 8) | (data[*offset] as usize);
            *offset += 1;
        }
    }

    if *offset + len > data.len() {
        return None;
    }

    let s = String::from_utf8_lossy(&data[*offset..*offset + len]).to_string();
    *offset += len;
    Some(s)
}

/// Parses DER-encoded X.509 certificate to extract CN and SANs
pub fn parse_x509_certificate(cert_der: &[u8]) -> TlsCertificateInfo {
    let mut info = TlsCertificateInfo::default();
    let mut i = 0;

    // Search for OID_COMMON_NAME (2.5.4.3)
    while i + OID_COMMON_NAME.len() + 2 < cert_der.len() {
        if cert_der[i..i + OID_COMMON_NAME.len()] == OID_COMMON_NAME {
            let mut offset = i + OID_COMMON_NAME.len();
            if let Some(cn) = parse_asn1_string(cert_der, &mut offset) {
                if !cn.is_empty() && info.common_name.is_none() {
                    info.common_name = Some(cn);
                } else if !cn.is_empty() && info.issuer_cn.is_none() {
                    info.issuer_cn = Some(cn);
                }
            }
        }
        i += 1;
    }

    // Search for Subject Alternative Names (OID 2.5.29.17)
    let mut j = 0;
    while j + OID_SUBJECT_ALT_NAME.len() + 4 < cert_der.len() {
        if cert_der[j..j + OID_SUBJECT_ALT_NAME.len()] == OID_SUBJECT_ALT_NAME {
            // Within SAN extension, DNS names are context tag [2] (0x82)
            let search_window = &cert_der[j..cert_der.len().min(j + 512)];
            let mut k = 0;
            while k + 2 < search_window.len() {
                if search_window[k] == 0x82 {
                    let len = search_window[k + 1] as usize;
                    if k + 2 + len <= search_window.len() {
                        let name =
                            String::from_utf8_lossy(&search_window[k + 2..k + 2 + len]).to_string();
                        // The scan looks for a context tag byte, which also occurs inside
                        // signatures and key material, so anything that does not look like
                        // a DNS name is signature bytes rather than a SAN entry.
                        if is_plausible_dns_name(&name) && !info.alt_names.contains(&name) {
                            info.alt_names.push(name);
                        }
                    }
                }
                k += 1;
            }
        }
        j += 1;
    }

    info
}

/// Parses TLS server handshake records to find and decode the certificate
pub fn parse_tls_response(buf: &[u8]) -> Option<TlsCertificateInfo> {
    let mut offset = 0;

    while offset + 5 < buf.len() {
        let record_type = buf[offset];
        offset += 1;
        let _version = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        offset += 2;
        let record_len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
        offset += 2;

        if record_type != 0x16 {
            // Not a handshake record, skip
            offset += record_len;
            continue;
        }

        let record_end = (offset + record_len).min(buf.len());
        while offset + 4 < record_end {
            let hs_type = buf[offset];
            offset += 1;
            let hs_len = ((buf[offset] as usize) << 16)
                | ((buf[offset + 1] as usize) << 8)
                | (buf[offset + 2] as usize);
            offset += 3;

            // Handshake type 11 = Certificate
            if hs_type == 0x0B {
                if offset + 3 <= record_end {
                    let _certs_list_len = ((buf[offset] as usize) << 16)
                        | ((buf[offset + 1] as usize) << 8)
                        | (buf[offset + 2] as usize);
                    offset += 3;

                    if offset + 3 <= record_end {
                        let first_cert_len = ((buf[offset] as usize) << 16)
                            | ((buf[offset + 1] as usize) << 8)
                            | (buf[offset + 2] as usize);
                        offset += 3;

                        if offset + first_cert_len <= buf.len() {
                            let cert_bytes = &buf[offset..offset + first_cert_len];
                            return Some(parse_x509_certificate(cert_bytes));
                        }
                    }
                }
            } else {
                offset += hs_len;
            }
        }
    }

    None
}

/// Asynchronously probes a target IP and port for TLS certificate details
/// True when a string could be a DNS name in a certificate SAN.
///
/// Guards a byte scan that cannot distinguish a real context tag from the same byte value
/// appearing inside a signature; without it, raw key material was reported as a hostname.
pub fn is_plausible_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    // A wildcard prefix is legitimate; everything else must be a hostname character.
    let body = name.strip_prefix("*.").unwrap_or(name);
    if body.is_empty() {
        return false;
    }
    body.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && body.chars().any(|c| c.is_ascii_alphanumeric())
        && !body.starts_with('.')
        && !body.ends_with('.')
}

pub async fn probe_tls_certificate(
    target: &Endpoint,
    port: u16,
    timeout_duration: Duration,
) -> Option<TlsCertificateInfo> {
    let connect_fut = TcpStream::connect(target.socket_addr(port));
    let mut stream = timeout(timeout_duration, connect_fut).await.ok()?.ok()?;

    let client_hello = build_client_hello();
    stream.write_all(&client_hello).await.ok()?;

    let mut buf = vec![0u8; 8192];
    let read_fut = stream.read(&mut buf);
    let bytes_read = timeout(timeout_duration, read_fut).await.ok()?.ok()?;

    if bytes_read > 0 {
        parse_tls_response(&buf[..bytes_read])
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
    fn test_client_hello_wire_format() {
        let hello = build_client_hello();
        assert!(hello.len() > 50);
        assert_eq!(hello[0], 0x16); // TLS Handshake
        assert_eq!(hello[1], 0x03); // Version 3.1
        assert_eq!(hello[2], 0x01);
        assert_eq!(hello[5], 0x01); // Handshake Type: ClientHello
    }

    #[test]
    fn test_parse_x509_synthetic_certificate() {
        // Construct a synthetic DER certificate containing CN=rt-be58.local and SAN=asusrouter.com
        let mut cert_der = Vec::new();
        cert_der.extend_from_slice(&[0x30, 0x82, 0x01, 0x00]); // Sequence

        // Append Common Name: OID 2.5.4.3 + UTF8String "rt-be58.local"
        cert_der.extend_from_slice(&OID_COMMON_NAME);
        let cn_str = b"rt-be58.local";
        cert_der.push(0x0C); // UTF8String
        cert_der.push(cn_str.len() as u8);
        cert_der.extend_from_slice(cn_str);

        // Append SAN OID 2.5.29.17 + context tag [2] "asusrouter.com"
        cert_der.extend_from_slice(&OID_SUBJECT_ALT_NAME);
        let san_str = b"asusrouter.com";
        cert_der.push(0x82); // Context tag [2] (dNSName)
        cert_der.push(san_str.len() as u8);
        cert_der.extend_from_slice(san_str);

        let parsed = parse_x509_certificate(&cert_der);
        assert_eq!(parsed.common_name.as_deref(), Some("rt-be58.local"));
        assert!(parsed.alt_names.contains(&"asusrouter.com".to_string()));
    }

    #[test]
    fn signature_bytes_are_not_mistaken_for_san_entries() {
        // The exact failure this guards: a byte scan matched inside key material and
        // reported raw bytes as a hostname.
        assert!(!is_plausible_dns_name("J\u{19}\u{1c}g\u{7}m"));
        assert!(!is_plausible_dns_name(""));
        assert!(!is_plausible_dns_name("has space"));
        assert!(!is_plausible_dns_name(".leading"));
        assert!(!is_plausible_dns_name("trailing."));
        assert!(!is_plausible_dns_name("\u{1}"));
    }

    #[test]
    fn real_san_entries_are_accepted() {
        for name in [
            "linksyssmartwifi.com",
            "www.linksyssmartwifi.com",
            "myrouter.local",
            "EA6350.home.linksys.com",
            "*.example.org",
            "router",
        ] {
            assert!(is_plausible_dns_name(name), "{name} should be accepted");
        }
    }
}
