//! DNS server confirmation.
//!
//! An open port 53 is reachability, not a resolver. This asks the device an actual DNS
//! question and requires a well-formed DNS answer carrying the transaction id it was sent,
//! which is the difference between "port 53 accepted a connection" and "this device answers
//! DNS queries".
//!
//! The query is a CHAOS-class `version.bind` TXT lookup, the conventional identification
//! question, falling back to what any resolver must answer. A server that refuses still
//! proves it speaks DNS, because refusing requires parsing the query.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::net::endpoint::Endpoint;
use crate::net::socket::SocketBinding;

/// Which transport carried the answer.
///
/// Recorded because it is not interchangeable: a resolver that answers UDP but has TCP 53
/// filtered is common, and labelling its service "tcp" would be simply false.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTransport {
    Udp,
    Tcp,
}

impl DnsTransport {
    pub fn label(&self) -> &'static str {
        match self {
            DnsTransport::Udp => "udp",
            DnsTransport::Tcp => "tcp",
        }
    }
}

/// What a resolver disclosed about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsIdentity {
    /// DNS response code from the header.
    pub response_code: u8,
    /// Contents of a `version.bind` TXT answer, where the server published one.
    pub version: Option<String>,
    /// The transport the answer arrived over.
    pub transport: DnsTransport,
}

/// Builds a `version.bind` CHAOS TXT query.
///
/// Transaction id is supplied by the caller so the response can be matched to it; an
/// unmatched id means something other than an answer to this question arrived.
pub fn version_bind_query(transaction_id: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(30);
    query.extend_from_slice(&transaction_id.to_be_bytes());
    // Flags: standard query, recursion desired.
    query.extend_from_slice(&[0x01, 0x00]);
    // One question, no answer/authority/additional records.
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in ["version", "bind"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    // QTYPE TXT (16), QCLASS CHAOS (3).
    query.extend_from_slice(&[0x00, 0x10, 0x00, 0x03]);
    query
}

/// Parses a DNS response, requiring it to answer the query that was sent.
///
/// Returns `None` for anything that is not a DNS response to this transaction, so arbitrary
/// bytes from a service that merely happens to sit on port 53 are not mistaken for one.
pub fn parse_dns_response(data: &[u8], transaction_id: u16) -> Option<DnsIdentity> {
    if data.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([data[0], data[1]]) != transaction_id {
        return None;
    }
    // QR bit must be set: this has to be a response, not an echo of the query.
    if data[2] & 0x80 == 0 {
        return None;
    }
    let response_code = data[3] & 0x0f;
    let question_count = u16::from_be_bytes([data[4], data[5]]);
    let answer_count = u16::from_be_bytes([data[6], data[7]]);

    Some(DnsIdentity {
        response_code,
        version: extract_txt_answer(data, question_count, answer_count),
        // Overwritten by the caller that owns the socket; parsing alone cannot know.
        transport: DnsTransport::Udp,
    })
}

/// Extracts the first TXT record's text, when the response carries one.
fn extract_txt_answer(data: &[u8], question_count: u16, answer_count: u16) -> Option<String> {
    if answer_count == 0 {
        return None;
    }
    let mut cursor = 12usize;

    // Skip the questions. Names in a question section are never compressed.
    for _ in 0..question_count {
        cursor = skip_name(data, cursor)?;
        cursor = cursor.checked_add(4)?; // QTYPE + QCLASS
    }

    for _ in 0..answer_count {
        cursor = skip_name(data, cursor)?;
        let record_type = u16::from_be_bytes([*data.get(cursor)?, *data.get(cursor + 1)?]);
        let length = u16::from_be_bytes([*data.get(cursor + 8)?, *data.get(cursor + 9)?]) as usize;
        let rdata_start = cursor + 10;
        let rdata = data.get(rdata_start..rdata_start.checked_add(length)?)?;

        // TXT rdata is one or more length-prefixed strings.
        if record_type == 16 && !rdata.is_empty() {
            let text_len = rdata[0] as usize;
            if let Some(text) = rdata.get(1..1 + text_len)
                && let Ok(text) = std::str::from_utf8(text)
                && !text.trim().is_empty()
            {
                return Some(text.trim().to_string());
            }
        }
        cursor = rdata_start + length;
    }
    None
}

/// Advances past a domain name, following the compression pointer convention.
fn skip_name(data: &[u8], mut cursor: usize) -> Option<usize> {
    loop {
        let length = *data.get(cursor)? as usize;
        if length == 0 {
            return Some(cursor + 1);
        }
        // A pointer terminates the name and is two bytes wide.
        if length & 0xc0 == 0xc0 {
            return Some(cursor + 2);
        }
        cursor = cursor.checked_add(1 + length)?;
    }
}

/// Asks a device to answer a DNS query over UDP.
///
/// Independent of whether TCP 53 is open. Gating DNS confirmation on an open TCP port
/// missed every UDP-only resolver and every device with TCP 53 filtered, which between
/// them are most resolvers on a home or office network.
pub async fn confirm_dns_udp(
    target: &Endpoint,
    binding: &SocketBinding,
    timeout_duration: Duration,
) -> Option<DnsIdentity> {
    let transaction_id = transaction_id_for(target);
    let query = version_bind_query(transaction_id);
    let mut identity =
        confirm_over_udp(target, binding, &query, transaction_id, timeout_duration).await?;
    identity.transport = DnsTransport::Udp;
    Some(identity)
}

/// Asks a device to answer a DNS query over TCP.
pub async fn confirm_dns_tcp(
    target: &Endpoint,
    binding: &SocketBinding,
    timeout_duration: Duration,
) -> Option<DnsIdentity> {
    let transaction_id = transaction_id_for(target);
    let query = version_bind_query(transaction_id);
    let mut identity =
        confirm_over_tcp(target, binding, &query, transaction_id, timeout_duration).await?;
    identity.transport = DnsTransport::Tcp;
    Some(identity)
}

/// Asks a device to answer a DNS query, over UDP first and then TCP.
///
/// `None` means it did not answer DNS, which says nothing else about it.
pub async fn confirm_dns(
    target: &Endpoint,
    binding: &SocketBinding,
    timeout_duration: Duration,
) -> Option<DnsIdentity> {
    // Derived from the address so a run is reproducible, while still differing between
    // devices so that a stray response cannot match every probe.
    let transaction_id = transaction_id_for(target);
    let query = version_bind_query(transaction_id);

    if let Some(mut identity) =
        confirm_over_udp(target, binding, &query, transaction_id, timeout_duration).await
    {
        identity.transport = DnsTransport::Udp;
        return Some(identity);
    }
    let mut identity =
        confirm_over_tcp(target, binding, &query, transaction_id, timeout_duration).await?;
    identity.transport = DnsTransport::Tcp;
    Some(identity)
}

fn transaction_id_for(target: &Endpoint) -> u16 {
    let mut id: u16 = 0x1d;
    for byte in match target.address {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    } {
        id = id.rotate_left(3) ^ byte as u16;
    }
    // Zero is legal but indistinguishable from an uninitialised field in some stacks.
    id.max(1)
}

async fn confirm_over_udp(
    target: &Endpoint,
    binding: &SocketBinding,
    query: &[u8],
    transaction_id: u16,
    timeout_duration: Duration,
) -> Option<DnsIdentity> {
    let destination = target.socket_addr(53);
    let socket = binding.udp_socket(&destination).await.ok()?;
    socket.send_to(query, destination).await.ok()?;

    let mut buf = [0u8; 1500];
    let (len, from) = timeout(timeout_duration, socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    // Only accept an answer from the device that was asked.
    if from.ip() != target.address {
        return None;
    }
    parse_dns_response(&buf[..len], transaction_id)
}

async fn confirm_over_tcp(
    target: &Endpoint,
    binding: &SocketBinding,
    query: &[u8],
    transaction_id: u16,
    timeout_duration: Duration,
) -> Option<DnsIdentity> {
    let mut stream = binding
        .tcp_connect(target.socket_addr(53), timeout_duration)
        .await
        .ok()?;

    // DNS over TCP prefixes each message with its length.
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(query);
    timeout(timeout_duration, stream.write_all(&framed))
        .await
        .ok()?
        .ok()?;

    let mut length = [0u8; 2];
    timeout(timeout_duration, stream.read_exact(&mut length))
        .await
        .ok()?
        .ok()?;
    let declared = u16::from_be_bytes(length) as usize;
    if declared == 0 || declared > 4096 {
        return None;
    }
    let mut body = vec![0u8; declared];
    timeout(timeout_duration, stream.read_exact(&mut body))
        .await
        .ok()?
        .ok()?;
    parse_dns_response(&body, transaction_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(id: u16, flags: [u8; 2], counts: [u16; 4]) -> Vec<u8> {
        let mut out = id.to_be_bytes().to_vec();
        out.extend_from_slice(&flags);
        for count in counts {
            out.extend_from_slice(&count.to_be_bytes());
        }
        out
    }

    #[test]
    fn the_query_asks_version_bind_in_the_chaos_class() {
        let query = version_bind_query(0xbeef);
        assert_eq!(&query[0..2], &[0xbe, 0xef]);
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1, "one question");
        // The label is length-prefixed: one byte of length followed by seven of text.
        assert!(
            query.windows(8).any(|w| w == b"\x07version"),
            "the version label is present"
        );
        // QTYPE TXT, QCLASS CHAOS.
        assert_eq!(&query[query.len() - 4..], &[0x00, 0x10, 0x00, 0x03]);
    }

    #[test]
    fn a_refusal_still_proves_the_device_speaks_dns() {
        // Refusing requires parsing the query, which nothing but a resolver does.
        let response = header(0x1234, [0x81, 0x85], [1, 0, 0, 0]);
        let identity = parse_dns_response(&response, 0x1234).expect("a response");
        assert_eq!(identity.response_code, 5, "REFUSED");
        assert!(identity.version.is_none());
    }

    #[test]
    fn a_version_answer_is_extracted() {
        let mut response = header(0x0007, [0x81, 0x80], [1, 1, 0, 0]);
        // Question: version.bind CHAOS TXT.
        response.extend_from_slice(b"\x07version\x04bind\x00");
        response.extend_from_slice(&[0x00, 0x10, 0x00, 0x03]);
        // Answer: compressed name, TXT, CHAOS, ttl, rdlength, then the text.
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&[0x00, 0x10, 0x00, 0x03]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let text = b"dnsmasq-2.90";
        response.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
        response.push(text.len() as u8);
        response.extend_from_slice(text);

        let identity = parse_dns_response(&response, 0x0007).expect("a response");
        assert_eq!(identity.response_code, 0);
        assert_eq!(identity.version.as_deref(), Some("dnsmasq-2.90"));
    }

    #[test]
    fn a_response_to_a_different_question_is_not_accepted() {
        // A stray packet arriving on the socket must not confirm this device.
        let response = header(0x0001, [0x81, 0x80], [1, 0, 0, 0]);
        assert!(parse_dns_response(&response, 0x0002).is_none());
    }

    #[test]
    fn a_query_echoed_back_is_not_a_response() {
        // The QR bit is what separates a resolver from a service that reflects bytes.
        let echoed = header(0x0003, [0x01, 0x00], [1, 0, 0, 0]);
        assert!(parse_dns_response(&echoed, 0x0003).is_none());
    }

    #[test]
    fn arbitrary_bytes_on_port_53_are_not_a_resolver() {
        assert!(parse_dns_response(b"", 1).is_none());
        assert!(parse_dns_response(b"SSH-2.0-OpenSSH", 1).is_none());
        assert!(parse_dns_response(&[0u8; 8], 0).is_none());
    }

    #[test]
    fn a_truncated_answer_section_does_not_panic() {
        // Appliance resolvers send malformed responses; losing the version is acceptable,
        // reading out of bounds is not.
        let mut response = header(0x0009, [0x81, 0x80], [1, 1, 0, 0]);
        response.extend_from_slice(b"\x07version\x04bind\x00");
        response.extend_from_slice(&[0x00, 0x10, 0x00, 0x03]);
        response.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x10]);
        let identity = parse_dns_response(&response, 0x0009).expect("a response");
        assert!(identity.version.is_none());
    }

    #[test]
    fn the_transport_is_recorded_rather_than_assumed() {
        // A resolver answering UDP with TCP 53 filtered is common; labelling its service
        // "tcp" would be false.
        let response = header(0x1234, [0x81, 0x80], [1, 0, 0, 0]);
        let parsed = parse_dns_response(&response, 0x1234).expect("a response");
        assert_eq!(parsed.transport, DnsTransport::Udp);
        assert_eq!(DnsTransport::Tcp.label(), "tcp");
    }

    #[test]
    fn each_device_gets_a_distinct_transaction_id() {
        let a = transaction_id_for(&Endpoint::global("10.0.0.1".parse().unwrap()));
        let b = transaction_id_for(&Endpoint::global("10.0.0.2".parse().unwrap()));
        assert_ne!(a, b);
        assert_ne!(a, 0);
    }
}
