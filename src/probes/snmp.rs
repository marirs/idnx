//! Pure-Rust, asynchronous SNMP v1/v2c BER client and infrastructure harvester.
//!
//! Provides zero-dependency ASN.1 Basic Encoding Rules (BER) encoding and decoding
//! over UDP socket (port 161) to query standard MIB-II tables:
//! - `sysDescr` & `sysName` (`1.3.6.1.2.1.1`) - Device identification
//! - `ipNetToMediaTable` (`1.3.6.1.2.1.4.22.1`) - Remote router/switch ARP cache
//! - `ipRouteTable` (`1.3.6.1.2.1.4.21.1`) - Routing table (adjacent subnet discovery)
//! - `ipAddrTable` (`1.3.6.1.2.1.4.20.1`) - Multi-homed interface addresses

use crate::net::socket::SocketBinding;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::time::Duration;

// ASN.1 BER Universal and Context Tags
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;

// SNMP Application Tags
const TAG_IP_ADDRESS: u8 = 0x40; // Application 0
const TAG_COUNTER32: u8 = 0x41; // Application 1
const TAG_GAUGE32: u8 = 0x42; // Application 2
const TAG_TIMETICKS: u8 = 0x43; // Application 3

// SNMP PDU Tags
pub const PDU_GET_REQUEST: u8 = 0xA0;
pub const PDU_GET_NEXT_REQUEST: u8 = 0xA1;
pub const PDU_GET_RESPONSE: u8 = 0xA2;

// Standard MIB-II OIDs
/// SNMPv2c exception markers, carried in the varbind value rather than the error status.
pub const TAG_NO_SUCH_OBJECT: u8 = 0x80;
pub const TAG_NO_SUCH_INSTANCE: u8 = 0x81;
pub const TAG_END_OF_MIB_VIEW: u8 = 0x82;

pub const OID_SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
pub const OID_SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
pub const OID_IP_NET_TO_MEDIA_TABLE: &str = "1.3.6.1.2.1.4.22.1"; // ARP table
pub const OID_IP_ROUTE_TABLE: &str = "1.3.6.1.2.1.4.21.1"; // Route table
/// `ipForwarding.0`: 1 means this device forwards, 2 means it does not.
pub const OID_IP_FORWARDING: &str = "1.3.6.1.2.1.4.1.0";
pub const OID_IP_ADDR_TABLE: &str = "1.3.6.1.2.1.4.20.1"; // Interface addresses

/// Represents an ASN.1 Object Identifier
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(pub Vec<u32>);

impl Oid {
    pub fn new(components: Vec<u32>) -> Self {
        Self(components)
    }

    /// Checks if this OID begins with the given prefix OID
    pub fn starts_with(&self, prefix: &Oid) -> bool {
        if self.0.len() < prefix.0.len() {
            return false;
        }
        self.0[..prefix.0.len()] == prefix.0[..]
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self
            .0
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(".");
        write!(f, "{}", s)
    }
}

impl FromStr for Oid {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim_start_matches('.');
        if trimmed.is_empty() {
            return Err("Empty OID string".to_string());
        }
        let parts: Result<Vec<u32>, _> = trimmed.split('.').map(|p| p.parse::<u32>()).collect();
        match parts {
            Ok(vec) if vec.len() >= 2 => Ok(Oid(vec)),
            Ok(_) => Err("OID must have at least 2 components".to_string()),
            Err(e) => Err(format!("Invalid OID component: {}", e)),
        }
    }
}

/// Represents an ASN.1 / SNMP decoded value
#[derive(Debug, Clone, PartialEq)]
pub enum BerValue {
    Integer(i64),
    OctetString(Vec<u8>),
    Null,
    Oid(Oid),
    IpAddress(Ipv4Addr),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Unknown(u8, Vec<u8>),
}

impl BerValue {
    /// Whether this value is the agent saying the MIB view ends here.
    pub fn is_end_of_mib_view(&self) -> bool {
        matches!(self, BerValue::Unknown(TAG_END_OF_MIB_VIEW, _))
    }

    /// Whether this value is the agent saying the object or instance does not exist.
    pub fn is_absent(&self) -> bool {
        matches!(
            self,
            BerValue::Unknown(TAG_NO_SUCH_OBJECT, _) | BerValue::Unknown(TAG_NO_SUCH_INSTANCE, _)
        )
    }

    pub fn as_str(&self) -> Option<String> {
        match self {
            BerValue::OctetString(bytes) => String::from_utf8(bytes.clone()).ok().or_else(|| {
                Some(
                    bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(":"),
                )
            }),
            BerValue::Oid(o) => Some(o.to_string()),
            BerValue::IpAddress(ip) => Some(ip.to_string()),
            BerValue::Integer(i) => Some(i.to_string()),
            BerValue::Counter32(c) => Some(c.to_string()),
            BerValue::Gauge32(g) => Some(g.to_string()),
            BerValue::TimeTicks(t) => Some(format!("{} ticks", t)),
            _ => None,
        }
    }

    pub fn as_mac(&self) -> Option<String> {
        match self {
            BerValue::OctetString(bytes) if bytes.len() == 6 => Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
            )),
            _ => None,
        }
    }

    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            BerValue::IpAddress(ip) => Some(*ip),
            BerValue::OctetString(bytes) if bytes.len() == 4 => {
                Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            }
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            BerValue::Integer(i) => Some(*i as u32),
            BerValue::Counter32(c) => Some(*c),
            BerValue::Gauge32(g) => Some(*g),
            BerValue::TimeTicks(t) => Some(*t),
            _ => None,
        }
    }
}

/// An SNMP PDU (Protocol Data Unit)
#[derive(Debug, Clone)]
pub struct SnmpPdu {
    pub pdu_type: u8,
    pub request_id: i32,
    pub error_status: i32,
    pub error_index: i32,
    pub varbinds: Vec<(Oid, BerValue)>,
}

/// A complete SNMP Message
#[derive(Debug, Clone)]
pub struct SnmpMessage {
    pub version: i32, // 0 = SNMPv1, 1 = SNMPv2c
    pub community: String,
    pub pdu: SnmpPdu,
}

// ---------------------------------------------------------------------------
// BER ENCODING HELPERS
// ---------------------------------------------------------------------------

fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else if len < 65536 {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + value.len());
    out.push(tag);
    out.extend(encode_length(value.len()));
    out.extend_from_slice(value);
    out
}

fn encode_integer(val: i64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut v = val;
    loop {
        bytes.push((v & 0xFF) as u8);
        v >>= 8;
        if (v == 0 && (bytes.last().unwrap() & 0x80) == 0)
            || (v == -1 && (bytes.last().unwrap() & 0x80) != 0)
        {
            break;
        }
    }
    bytes.reverse();
    encode_tlv(TAG_INTEGER, &bytes)
}

fn encode_octet_string(val: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OCTET_STRING, val)
}

fn encode_null() -> Vec<u8> {
    vec![TAG_NULL, 0x00]
}

fn encode_oid(oid: &Oid) -> Vec<u8> {
    if oid.0.len() < 2 {
        return vec![TAG_OBJECT_IDENTIFIER, 0x00];
    }

    let mut body = Vec::new();
    // The first two components are encoded as (X * 40) + Y
    let first = (oid.0[0] * 40 + oid.0[1]) as u8;
    body.push(first);

    for &comp in &oid.0[2..] {
        if comp < 128 {
            body.push(comp as u8);
        } else {
            let mut stack = Vec::new();
            let mut val = comp;
            stack.push((val & 0x7F) as u8);
            val >>= 7;
            while val > 0 {
                stack.push(((val & 0x7F) | 0x80) as u8);
                val >>= 7;
            }
            while let Some(b) = stack.pop() {
                body.push(b);
            }
        }
    }

    encode_tlv(TAG_OBJECT_IDENTIFIER, &body)
}

/// Builds an SNMP GetRequest or GetNextRequest packet
pub fn build_snmp_request(
    version: i32,
    community: &str,
    request_id: i32,
    pdu_type: u8,
    oid: &Oid,
) -> Vec<u8> {
    // 1. Build VarBind: SEQUENCE { name OID, value NULL }
    let mut varbind_body = Vec::new();
    varbind_body.extend(encode_oid(oid));
    varbind_body.extend(encode_null());
    let varbind = encode_tlv(TAG_SEQUENCE, &varbind_body);

    // 2. Build VarBindList: SEQUENCE OF VarBind
    let varbind_list = encode_tlv(TAG_SEQUENCE, &varbind);

    // 3. Build PDU: GetRequest/GetNextRequest [tag] { request_id, error_status, error_index, varbind_list }
    let mut pdu_body = Vec::new();
    pdu_body.extend(encode_integer(request_id as i64));
    pdu_body.extend(encode_integer(0)); // error-status = 0
    pdu_body.extend(encode_integer(0)); // error-index = 0
    pdu_body.extend(varbind_list);
    let pdu = encode_tlv(pdu_type, &pdu_body);

    // 4. Build SNMP Message: SEQUENCE { version, community, pdu }
    let mut msg_body = Vec::new();
    msg_body.extend(encode_integer(version as i64));
    msg_body.extend(encode_octet_string(community.as_bytes()));
    msg_body.extend(pdu);

    encode_tlv(TAG_SEQUENCE, &msg_body)
}

// ---------------------------------------------------------------------------
// BER DECODING HELPERS
//
// Decoding runs through `Reader`, which carries the bounds of the TLV it is inside.
// The free-standing length reader that used to live here parsed against the whole
// datagram, so a child could claim bytes belonging to its parent's siblings.
// ---------------------------------------------------------------------------

fn decode_oid_value(data: &[u8]) -> Result<Oid, String> {
    if data.is_empty() {
        return Ok(Oid(Vec::new()));
    }

    let mut comps = Vec::new();
    let first = data[0] as u32;
    comps.push(first / 40);
    comps.push(first % 40);

    let mut current = 0u32;
    for &b in &data[1..] {
        current = (current << 7) | ((b & 0x7F) as u32);
        if (b & 0x80) == 0 {
            comps.push(current);
            current = 0;
        }
    }

    Ok(Oid(comps))
}

fn decode_integer_value(data: &[u8]) -> i64 {
    if data.is_empty() {
        return 0;
    }
    let mut val = if (data[0] & 0x80) != 0 { -1i64 } else { 0i64 };
    for &b in data {
        val = (val << 8) | (b as i64);
    }
    val
}

/// A cursor over one BER container, which cannot read past it.
///
/// Every field this decoder reads is now taken through one of these. The previous version
/// decoded the outer message, PDU and varbind lengths and then ignored them: `offset + len`
/// was computed against the whole datagram, so a nested length could point past its
/// enclosing object and the next `data[offset]` could panic or read a neighbouring field as
/// its own. A declared length is a claim by the sender, and every one of them is now
/// checked against the container it appears in.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    /// Reads one tag-length-value, returning the tag and a reader bounded to its contents.
    fn tlv(&mut self, what: &str) -> Result<(u8, Reader<'a>), String> {
        let tag = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| format!("{what}: the container ended before its tag"))?;
        self.at += 1;

        let len = self.length(what)?;
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| format!("{what}: its declared length overflows"))?;
        let value = self.bytes.get(self.at..end).ok_or_else(|| {
            format!(
                "{what}: declares {len} bytes and its container holds {}",
                self.remaining()
            )
        })?;
        self.at = end;
        Ok((tag, Reader::new(value)))
    }

    /// Reads one tag-length-value and requires the tag.
    fn expect(&mut self, tag: u8, what: &str) -> Result<Reader<'a>, String> {
        let (found, value) = self.tlv(what)?;
        if found != tag {
            return Err(format!(
                "{what}: expected tag {tag:#04x}, found {found:#04x}"
            ));
        }
        Ok(value)
    }

    /// The BER length at the cursor, definite form only.
    fn length(&mut self, what: &str) -> Result<usize, String> {
        let first = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| format!("{what}: the container ended before its length"))?;
        self.at += 1;

        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let count = (first & 0x7f) as usize;
        // Indefinite length is not used by SNMP, and a length longer than a pointer is not
        // a length this will honour.
        if count == 0 || count > 4 {
            return Err(format!("{what}: unsupported length encoding"));
        }
        let bytes = self
            .bytes
            .get(self.at..self.at + count)
            .ok_or_else(|| format!("{what}: its length field is truncated"))?;
        self.at += count;

        let mut len = 0usize;
        for byte in bytes {
            len = len
                .checked_shl(8)
                .and_then(|shifted| shifted.checked_add(*byte as usize))
                .ok_or_else(|| format!("{what}: its declared length overflows"))?;
        }
        Ok(len)
    }

    /// The whole of what remains, for a primitive value.
    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }

    /// Requires that the container has been read to its end.
    ///
    /// Trailing bytes inside a container mean the message is not what it declares itself to
    /// be: something is being smuggled past the fields this decoder knows, and a decoder
    /// that ignores them accepts two readings of one message.
    fn finished(&self, what: &str) -> Result<(), String> {
        if self.done() {
            return Ok(());
        }
        Err(format!(
            "{what}: {} byte(s) remain after its declared fields",
            self.remaining()
        ))
    }
}

/// Reads one integer field.
fn integer(reader: &mut Reader<'_>, what: &str) -> Result<i64, String> {
    let value = reader.expect(TAG_INTEGER, what)?;
    Ok(decode_integer_value(value.rest()))
}

pub fn decode_snmp_response(data: &[u8]) -> Result<SnmpMessage, String> {
    let mut outer = Reader::new(data);
    let mut message = outer.expect(TAG_SEQUENCE, "the message")?;
    // Anything after the outer SEQUENCE is not part of this message.
    outer.finished("the datagram")?;

    let version = integer(&mut message, "the version")? as i32;
    let community =
        String::from_utf8_lossy(message.expect(TAG_OCTET_STRING, "the community")?.rest())
            .to_string();

    let (pdu_type, mut pdu) = message.tlv("the PDU")?;
    message.finished("the message")?;

    let request_id = integer(&mut pdu, "the request id")? as i32;
    let error_status = integer(&mut pdu, "the error status")? as i32;
    let error_index = integer(&mut pdu, "the error index")? as i32;

    let mut list = pdu.expect(TAG_SEQUENCE, "the varbind list")?;
    pdu.finished("the PDU")?;

    let mut varbinds = Vec::new();
    while !list.done() {
        let mut varbind = list.expect(TAG_SEQUENCE, "a varbind")?;
        let oid = decode_oid_value(
            varbind
                .expect(TAG_OBJECT_IDENTIFIER, "a varbind's OID")?
                .rest(),
        )?;

        let (tag, value) = varbind.tlv("a varbind's value")?;
        varbind.finished("a varbind")?;
        let bytes = value.rest();

        let decoded = match tag {
            TAG_INTEGER => BerValue::Integer(decode_integer_value(bytes)),
            TAG_OCTET_STRING => BerValue::OctetString(bytes.to_vec()),
            TAG_NULL => BerValue::Null,
            TAG_OBJECT_IDENTIFIER => BerValue::Oid(decode_oid_value(bytes)?),
            TAG_IP_ADDRESS if bytes.len() == 4 => {
                BerValue::IpAddress(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            }
            TAG_COUNTER32 => BerValue::Counter32(decode_integer_value(bytes) as u32),
            TAG_GAUGE32 => BerValue::Gauge32(decode_integer_value(bytes) as u32),
            TAG_TIMETICKS => BerValue::TimeTicks(decode_integer_value(bytes) as u32),
            _ => BerValue::Unknown(tag, bytes.to_vec()),
        };
        varbinds.push((oid, decoded));

        if varbinds.len() > MAX_VARBINDS {
            return Err(format!(
                "the varbind list carries more than the {MAX_VARBINDS} this reads"
            ));
        }
    }

    Ok(SnmpMessage {
        version,
        community,
        pdu: SnmpPdu {
            pdu_type,
            request_id,
            error_status,
            error_index,
            varbinds,
        },
    })
}

// ---------------------------------------------------------------------------
// ASYNC SNMP CLIENT ENGINE
// ---------------------------------------------------------------------------

/// Performs a single SNMP GET or GET-NEXT request over UDP
/// Where an SNMP conversation goes, and which device it is about.
///
/// Two addresses, because they are two different things. `device` is the identity every
/// resulting fact is attributed to; `transport` is where the datagrams are sent. They are
/// the same in every real run, and separating them is what lets a test drive the whole
/// provider path against a loopback agent while the topology it produces still describes
/// documentation addresses. It is deliberately not reachable from the command line: an
/// operator asking about one device and probing another is not a mode worth having.
#[derive(Debug, Clone)]
pub(crate) struct SnmpTarget {
    /// The identity every resulting fact is attributed to.
    pub device: Ipv4Addr,
    pub transport: SocketAddrV4,
    pub community: String,
}

impl SnmpTarget {
    /// The ordinary case: ask the device itself, on the standard port.
    pub fn direct(device: Ipv4Addr, port: u16, community: &str) -> Self {
        Self {
            device,
            transport: SocketAddrV4::new(device, port),
            community: community.to_string(),
        }
    }
}

/// The largest response this will read.
///
/// A bound rather than a buffer size: an agent that answers with more than this is either
/// broken or not an agent, and reading further would let one device dictate how much memory
/// a run spends.
const MAX_RESPONSE_BYTES: usize = 8192;

/// The most varbinds one response may carry.
const MAX_VARBINDS: usize = 128;

/// Sends one request and validates the answer against it.
///
/// Everything checked here is something an unvalidated implementation would accept from any
/// host that happened to answer: the source address, the version, the community, the PDU
/// type and the request id. A response failing any of them is not a weaker answer -- it is
/// an answer to a different question, or from a different party.
///
/// The community never appears in an error. It is a shared secret in every deployment that
/// changes it from the default, and a diagnostic is exactly where one leaks.
async fn snmp_request(
    target: &SnmpTarget,
    pdu_type: u8,
    oid: &Oid,
    binding: &SocketBinding,
    timeout: Duration,
) -> Result<SnmpMessage, String> {
    let dest = target.transport;
    let socket = binding
        .udp_socket(&std::net::SocketAddr::V4(dest))
        .await
        .map_err(|e| format!("UDP bind error: {}", e))?;

    // Derived from the clock and the OID, so two requests in one run do not share an id and
    // a late reply to an earlier question cannot be read as an answer to this one.
    let request_id = {
        let clock = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;
        let mixed = clock ^ (oid.0.iter().map(|part| *part as i64).sum::<i64>() << 16);
        (mixed & 0x7FFF_FFFF) as i32
    };

    let req_bytes = build_snmp_request(1, &target.community, request_id, pdu_type, oid);
    socket
        .send_to(&req_bytes, dest)
        .await
        .map_err(|e| format!("UDP send error: {}", e))?;

    let deadline = tokio::time::Instant::now() + timeout;
    // One byte more than the bound, so an oversized datagram is detected rather than
    // silently truncated into something that happens to parse.
    let mut buf = [0u8; MAX_RESPONSE_BYTES + 1];

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("SNMP request timed out".to_string());
        }
        let (len, from) = match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok(received)) => received,
            Ok(Err(e)) => return Err(format!("UDP recv error: {}", e)),
            Err(_) => return Err("SNMP request timed out".to_string()),
        };

        // A datagram from anywhere else is not this device's answer, whatever it contains.
        match from {
            std::net::SocketAddr::V4(v4) if v4 == dest => {}
            _ => continue,
        }

        if len > MAX_RESPONSE_BYTES {
            return Err(format!(
                "response exceeds the {MAX_RESPONSE_BYTES}-byte bound this reads"
            ));
        }
        let message = decode_snmp_response(&buf[..len])?;
        // Version 1 on the wire is SNMPv2c, which is what was asked.
        if message.version != 1 {
            return Err(format!(
                "response used SNMP version {} where v2c was asked",
                message.version
            ));
        }
        if message.community != target.community {
            // Neither community is named: the one we sent is a secret, and the one that
            // came back is whatever an unrelated agent happens to use.
            return Err("response carried a different community".to_string());
        }
        if message.pdu.pdu_type != PDU_GET_RESPONSE {
            return Err(format!(
                "response was PDU type {:#04x}, not a GetResponse",
                message.pdu.pdu_type
            ));
        }
        if message.pdu.request_id != request_id {
            return Err("response did not carry the request id it answers".to_string());
        }
        // One OID was asked, so one varbind is the answer. More than one is a response to
        // a different request, or an agent volunteering rows nobody asked for -- and taking
        // the first would attribute an arbitrary value to the OID that was requested.
        if message.pdu.error_status == 0 && message.pdu.varbinds.len() != 1 {
            return Err(format!(
                "response carried {} varbinds where one OID was asked",
                message.pdu.varbinds.len()
            ));
        }
        // A GET must answer about the OID it was given. A GETNEXT answers about the next
        // one, which the walk checks for itself.
        if pdu_type == PDU_GET_REQUEST
            && message.pdu.error_status == 0
            && message.pdu.varbinds.first().map(|(found, _)| found) != Some(oid)
        {
            return Err("response answered about a different OID than the one asked".to_string());
        }
        return Ok(message);
    }
}

/// Why a walk stopped.
///
/// Named rather than collapsed into an empty result. "The table ended" and "the agent
/// repeated an OID" produce the same rows and mean opposite things about the agent, and a
/// walk that stopped because it hit a bound has not seen the whole table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkEnd {
    /// The agent said the MIB view ends here (SNMPv2c endOfMibView).
    EndOfMibView,
    /// The next OID left the subtree, which is the ordinary end of a table.
    LeftSubtree,
    /// The agent reported an error status, SNMPv1 noSuchName among them.
    AgentError(i32),
    /// The agent answered with an OID that did not advance. Repeating or going backwards
    /// makes a walk loop, so it terminates as invalid rather than continuing.
    OidDidNotAdvance,
    /// A response failed validation, or none arrived.
    Invalid(String),
    /// A bound stopped it: the step limit or the total time.
    Bounded(&'static str),
}

/// The rows a walk collected, and why it stopped.
#[derive(Debug, Clone)]
pub struct Walk {
    pub rows: Vec<(Oid, BerValue)>,
    pub end: WalkEnd,
}

impl Walk {
    /// Whether the walk saw the whole subtree rather than stopping early.
    pub fn complete(&self) -> bool {
        matches!(self.end, WalkEnd::EndOfMibView | WalkEnd::LeftSubtree)
    }
}

/// Walks an SNMP subtree starting from `root_oid`.
///
/// Bounded three ways, because an agent controls how long this runs otherwise: a step
/// limit, a total time limit, and the per-response limits the request path enforces. Each
/// bound is reported rather than being indistinguishable from a table that simply ended.
pub(crate) async fn snmp_walk_target(
    target: &SnmpTarget,
    root_oid: &Oid,
    binding: &SocketBinding,
    timeout: Duration,
    max_steps: usize,
    total_budget: Duration,
) -> Walk {
    let mut rows = Vec::new();
    let mut current_oid = root_oid.clone();
    let deadline = tokio::time::Instant::now() + total_budget;

    for step in 0..max_steps {
        if tokio::time::Instant::now() >= deadline {
            return Walk {
                rows,
                end: WalkEnd::Bounded("the walk's total time budget"),
            };
        }
        let _ = step;

        // Never more than what is left: a per-request timeout larger than the remaining
        // budget let one slow step consume a deadline the walk had already spent.
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let message = match snmp_request(
            target,
            PDU_GET_NEXT_REQUEST,
            &current_oid,
            binding,
            timeout.min(remaining),
        )
        .await
        {
            Ok(message) => message,
            Err(reason) => {
                return Walk {
                    rows,
                    end: WalkEnd::Invalid(reason),
                };
            }
        };

        // An error status ends the walk and says so. SNMPv1 agents end a table with
        // noSuchName (2) where v2c uses an endOfMibView marker in the varbind.
        if message.pdu.error_status != 0 {
            return Walk {
                rows,
                end: WalkEnd::AgentError(message.pdu.error_status),
            };
        }
        let Some((next_oid, value)) = message.pdu.varbinds.first().cloned() else {
            return Walk {
                rows,
                end: WalkEnd::Invalid("response carried no varbind".to_string()),
            };
        };

        // SNMPv2c marks the end of the view in the value rather than in the error status.
        if value.is_end_of_mib_view() {
            return Walk {
                rows,
                end: WalkEnd::EndOfMibView,
            };
        }
        if value.is_absent() {
            return Walk {
                rows,
                end: WalkEnd::LeftSubtree,
            };
        }

        if !next_oid.starts_with(root_oid) {
            return Walk {
                rows,
                end: WalkEnd::LeftSubtree,
            };
        }
        // Strictly increasing, always. An agent that repeats an OID -- or answers with an
        // earlier one -- makes this loop until a bound stops it, and the rows after such an
        // answer describe an order nobody guaranteed.
        if next_oid <= current_oid {
            return Walk {
                rows,
                end: WalkEnd::OidDidNotAdvance,
            };
        }

        current_oid = next_oid.clone();
        rows.push((next_oid, value));
    }

    Walk {
        rows,
        end: WalkEnd::Bounded("the walk's step limit"),
    }
}

/// Walks a subtree on a device, at its own address.
pub async fn snmp_walk(
    target: Ipv4Addr,
    port: u16,
    community: &str,
    root_oid: &Oid,
    binding: &SocketBinding,
    timeout: Duration,
    max_steps: usize,
) -> Vec<(Oid, BerValue)> {
    snmp_walk_target(
        &SnmpTarget::direct(target, port, community),
        root_oid,
        binding,
        timeout,
        max_steps,
        // A table that has not finished in this long is not going to.
        Duration::from_secs(20),
    )
    .await
    .rows
}

// ---------------------------------------------------------------------------
// HIGH-LEVEL MIB-II HARVESTERS
// ---------------------------------------------------------------------------

/// Remote ARP entry harvested from `ipNetToMediaTable`
#[derive(Debug, Clone)]
pub struct SnmpArpEntry {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub if_index: u32,
}

/// Routing entry harvested from `ipRouteTable`
#[derive(Debug, Clone)]
pub struct SnmpRouteEntry {
    pub dest_network: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub next_hop: Ipv4Addr,
    /// `ipRouteType`: 2 invalid, 3 direct, 4 indirect (RFC 1213).
    ///
    /// An invalid row is a routing table entry the device itself has struck out; treating
    /// one as a route would put a network on the map that the device says it does not
    /// reach. Direct and indirect stay distinguishable because they are different claims:
    /// one says the device is on that network, the other that it forwards toward it.
    pub route_type: Option<i64>,
}

impl SnmpRouteEntry {
    /// Whether the device presents this row as a usable route.
    pub fn usable(&self) -> bool {
        !matches!(self.route_type, Some(2))
    }

    /// Whether the device says it is directly attached to the destination.
    pub fn direct(&self) -> bool {
        matches!(self.route_type, Some(3))
    }
}

/// Router/Switch hardware information
#[derive(Debug, Clone, Default)]
pub struct SnmpDeviceInfo {
    /// The device the answers came from, which is what every resulting fact is about.
    pub device: Option<Ipv4Addr>,
    /// `ipForwarding.0`, where the device answered it. `Some(true)` is the device stating
    /// that it forwards, which is the only thing that makes it a router by SNMP alone.
    pub forwarding: Option<bool>,
    /// Per-table walk outcomes, so a partial table is never reported as a whole one.
    pub table_status: Vec<(&'static str, String)>,
    pub sys_descr: Option<String>,
    pub sys_name: Option<String>,
    pub arp_cache: Vec<SnmpArpEntry>,
    pub routes: Vec<SnmpRouteEntry>,
    pub local_ips: Vec<(Ipv4Addr, Ipv4Addr)>, // (IP, Netmask)
}

/// Harvester that queries MIB-II to extract ARP cache, routes, and multi-homed IPs
pub async fn harvest_snmp_device(
    target: Ipv4Addr,
    port: u16,
    community: &str,
    binding: &SocketBinding,
    timeout: Duration,
) -> Option<SnmpDeviceInfo> {
    harvest_snmp_target(
        &SnmpTarget::direct(target, port, community),
        binding,
        timeout,
    )
    .await
}

/// One bounded walk's rows, with the reason it stopped discarded.
///
/// The harvesters want the table; the reason a walk ended matters to the caller that is
/// testing the walk, and is reported there.
async fn walk_table(
    target: &SnmpTarget,
    root: &Oid,
    binding: &SocketBinding,
    timeout: Duration,
    name: &'static str,
    info: &mut SnmpDeviceInfo,
) -> Vec<(Oid, BerValue)> {
    let walk = snmp_walk_target(target, root, binding, timeout, 512, Duration::from_secs(20)).await;
    // Recorded whether it completed or not. A table that timed out, hit a bound or was
    // refused mid-way has rows that are individually valid and is not the whole table, and
    // discarding that distinction let a partial answer look complete.
    let status = match &walk.end {
        WalkEnd::EndOfMibView | WalkEnd::LeftSubtree => {
            format!("{} row(s), complete", walk.rows.len())
        }
        WalkEnd::AgentError(status) => format!(
            "{} row(s), incomplete: the agent reported error status {status}",
            walk.rows.len()
        ),
        WalkEnd::OidDidNotAdvance => format!(
            "{} row(s), incomplete: the agent stopped advancing the OID",
            walk.rows.len()
        ),
        WalkEnd::Invalid(reason) => {
            format!("{} row(s), incomplete: {reason}", walk.rows.len())
        }
        WalkEnd::Bounded(bound) => {
            format!("{} row(s), incomplete: stopped at {bound}", walk.rows.len())
        }
    };
    info.table_status.push((name, status));
    walk.rows
}

/// Harvests one device, sending to wherever the target says.
pub(crate) async fn harvest_snmp_target(
    target: &SnmpTarget,
    binding: &SocketBinding,
    timeout: Duration,
) -> Option<SnmpDeviceInfo> {
    // 1. Probe sysDescr to verify SNMP responsiveness and community validity
    let sys_descr_oid = Oid::from_str(OID_SYS_DESCR).ok()?;
    let sys_descr_msg = snmp_request(target, PDU_GET_REQUEST, &sys_descr_oid, binding, timeout)
        .await
        .ok()?;

    if sys_descr_msg.pdu.varbinds.is_empty() {
        return None;
    }

    let sys_descr = sys_descr_msg.pdu.varbinds[0].1.as_str();

    // 2. Query sysName
    let sys_name_oid = Oid::from_str(OID_SYS_NAME).ok()?;
    let sys_name = if let Ok(msg) =
        snmp_request(target, PDU_GET_REQUEST, &sys_name_oid, binding, timeout).await
    {
        msg.pdu.varbinds.first().and_then(|vb| vb.1.as_str())
    } else {
        None
    };

    // What the device says about its own forwarding. A printer and a UPS answer SNMP as
    // readily as a router does, and sysDescr succeeding says only that something answered.
    let forwarding = match Oid::from_str(OID_IP_FORWARDING) {
        Ok(oid) => snmp_request(target, PDU_GET_REQUEST, &oid, binding, timeout)
            .await
            .ok()
            .and_then(|msg| msg.pdu.varbinds.first().cloned())
            .and_then(|(_, value)| match value {
                BerValue::Integer(1) => Some(true),
                BerValue::Integer(2) => Some(false),
                _ => None,
            }),
        Err(_) => None,
    };

    let mut info = SnmpDeviceInfo {
        device: Some(target.device),
        forwarding,
        table_status: Vec::new(),
        sys_descr,
        sys_name,
        arp_cache: Vec::new(),
        routes: Vec::new(),
        local_ips: Vec::new(),
    };

    // 3. Walk `ipNetToMediaTable` (`1.3.6.1.2.1.4.22.1`)
    // Columns:
    // .2 = ipNetToMediaPhysAddress (MAC)
    // .3 = ipNetToMediaNetAddress (IP)
    if let Ok(arp_root) = Oid::from_str(OID_IP_NET_TO_MEDIA_TABLE) {
        let arp_results = walk_table(
            target,
            &arp_root,
            binding,
            timeout,
            "ipNetToMediaTable",
            &mut info,
        )
        .await;
        let mut ip_map: std::collections::HashMap<
            Vec<u32>,
            (Option<Ipv4Addr>, Option<String>, u32),
        > = std::collections::HashMap::new();

        for (oid, val) in arp_results {
            // OID structure: 1.3.6.1.2.1.4.22.1.<column>.<ifIndex>.<ip0>.<ip1>.<ip2>.<ip3>
            if oid.0.len() >= 11 {
                let column = oid.0[9];
                let if_index = oid.0[10];
                let entry_key = oid.0[10..].to_vec();
                let entry = ip_map.entry(entry_key).or_insert((None, None, if_index));

                match column {
                    2 => entry.1 = val.as_mac(),
                    3 => entry.0 = val.as_ipv4(),
                    _ => {}
                }
            }
        }

        for (_, (maybe_ip, maybe_mac, if_idx)) in ip_map {
            if let (Some(ip), Some(mac)) = (maybe_ip, maybe_mac) {
                // Avoid loopback / broadcast
                if !ip.is_loopback() && !ip.is_broadcast() && mac != "00:00:00:00:00:00" {
                    info.arp_cache.push(SnmpArpEntry {
                        ip,
                        mac,
                        if_index: if_idx,
                    });
                }
            }
        }
    }

    // 4. Walk `ipRouteTable` (`1.3.6.1.2.1.4.21.1`)
    // Columns:
    // .1 = ipRouteDest
    // .7 = ipRouteNextHop
    // .11 = ipRouteMask
    if let Ok(route_root) = Oid::from_str(OID_IP_ROUTE_TABLE) {
        let route_results = walk_table(
            target,
            &route_root,
            binding,
            timeout,
            "ipRouteTable",
            &mut info,
        )
        .await;
        type RouteTuple = (
            Option<Ipv4Addr>,
            Option<Ipv4Addr>,
            Option<Ipv4Addr>,
            Option<i64>,
        );
        let mut route_map: std::collections::HashMap<Vec<u32>, RouteTuple> =
            std::collections::HashMap::new();

        for (oid, val) in route_results {
            if oid.0.len() >= 11 {
                let col = oid.0[9];
                let key = oid.0[10..].to_vec();
                let entry = route_map.entry(key).or_insert((None, None, None, None));
                match col {
                    1 => entry.0 = val.as_ipv4(),
                    7 => entry.2 = val.as_ipv4(),
                    // ipRouteType, which says whether the device presents this row as a
                    // route at all.
                    8 => {
                        if let BerValue::Integer(kind) = val {
                            entry.3 = Some(kind);
                        }
                    }
                    11 => entry.1 = val.as_ipv4(),
                    _ => {}
                }
            }
        }

        for (_, (dest, mask, nexthop, route_type)) in route_map {
            if let (Some(dest), Some(mask), Some(next_hop)) = (dest, mask, nexthop)
                && !dest.is_loopback()
            {
                info.routes.push(SnmpRouteEntry {
                    dest_network: dest,
                    mask,
                    next_hop,
                    route_type,
                });
            }
        }
    }

    // 5. Walk `ipAddrTable` (`1.3.6.1.2.1.4.20.1`)
    // Columns:
    // .1 = ipAdEntAddr
    // .3 = ipAdEntNetMask
    if let Ok(addr_root) = Oid::from_str(OID_IP_ADDR_TABLE) {
        let addr_results = walk_table(
            target,
            &addr_root,
            binding,
            timeout,
            "ipAddrTable",
            &mut info,
        )
        .await;
        let mut addr_map: std::collections::HashMap<
            Vec<u32>,
            (Option<Ipv4Addr>, Option<Ipv4Addr>),
        > = std::collections::HashMap::new();

        for (oid, val) in addr_results {
            if oid.0.len() >= 11 {
                let col = oid.0[9];
                let key = oid.0[10..].to_vec();
                let entry = addr_map.entry(key).or_insert((None, None));
                match col {
                    1 => entry.0 = val.as_ipv4(),
                    3 => entry.1 = val.as_ipv4(),
                    _ => {}
                }
            }
        }

        for (_, (ip, mask)) in addr_map {
            if let (Some(ip), Some(mask)) = (ip, mask)
                && !ip.is_loopback()
            {
                info.local_ips.push((ip, mask));
            }
        }
    }

    Some(info)
}

// ---------------------------------------------------------------------------
// UNIT TESTS
// ---------------------------------------------------------------------------

/// A scripted agent on loopback, for testing the conversation rather than the codec.
///
/// Parsing a hand-built response proves the decoder reads bytes. It does not prove the walk
/// terminates, that a reply to someone else's request is refused, or that an agent which
/// repeats an OID is stopped -- those are properties of the exchange, and the only way to
/// exercise them is against something that answers, including answering wrongly.
#[cfg(test)]
pub mod fake_agent {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// How the agent answers one request.
    #[derive(Debug, Clone)]
    pub enum Reply {
        /// The varbind to return, echoing the request id.
        Varbind(Oid, BerValue),
        /// An SNMPv2c end-of-view marker.
        EndOfMibView(Oid),
        /// An error status in the response PDU (noSuchName is 2). A table can end this
        /// way; it is not the same thing as a table that ended at its own last row.
        Error(i32),
        /// A well-formed response carrying someone else's request id.
        WrongRequestId(Oid, BerValue),
        /// A well-formed response carrying a different community.
        WrongCommunity(Oid, BerValue),
        /// A response that is not a GetResponse.
        WrongPduType(Oid, BerValue),
        /// A well-formed response whose varbind names an OID nobody asked for.
        WrongOid(Oid, BerValue),
        /// Two varbinds where one OID was requested.
        TwoVarbinds(Oid, BerValue, Oid, BerValue),
        /// A response larger than the reader's bound, padded to `bytes`.
        Oversized(Oid, usize),
        /// Bytes that are not a decodable message.
        Malformed(Vec<u8>),
        /// No answer at all.
        Silence,
    }

    /// A running agent. Dropping it stops the thread.
    pub struct FakeAgent {
        pub port: u16,
        stop: Arc<AtomicBool>,
        served: Arc<AtomicUsize>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeAgent {
        /// Binds an ephemeral loopback port and answers with `script` in order, repeating
        /// the last entry once it runs out.
        pub fn start(community: &str, script: Vec<Reply>) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").expect("an ephemeral loopback port");
            socket
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("a read timeout");
            let port = socket.local_addr().expect("a bound address").port();

            let stop = Arc::new(AtomicBool::new(false));
            let served = Arc::new(AtomicUsize::new(0));
            let community = community.to_string();
            let (stopper, counter) = (Arc::clone(&stop), Arc::clone(&served));

            let handle = std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stopper.load(Ordering::Relaxed) {
                    let Ok((len, from)) = socket.recv_from(&mut buf) else {
                        continue;
                    };
                    let Ok(request) = decode_snmp_response(&buf[..len]) else {
                        continue;
                    };
                    let step = counter.fetch_add(1, Ordering::Relaxed);
                    let reply = script
                        .get(step)
                        .or_else(|| script.last())
                        .cloned()
                        .unwrap_or(Reply::Silence);

                    let response = match reply {
                        Reply::Silence => continue,
                        Reply::Malformed(bytes) => bytes,
                        Reply::Varbind(oid, value) => response(
                            &community,
                            request.pdu.request_id,
                            PDU_GET_RESPONSE,
                            0,
                            &oid,
                            &value,
                        ),
                        Reply::EndOfMibView(oid) => response(
                            &community,
                            request.pdu.request_id,
                            PDU_GET_RESPONSE,
                            0,
                            &oid,
                            &BerValue::Unknown(TAG_END_OF_MIB_VIEW, Vec::new()),
                        ),
                        Reply::Error(status) => response(
                            &community,
                            request.pdu.request_id,
                            PDU_GET_RESPONSE,
                            status,
                            &Oid(vec![1, 3, 6, 1]),
                            &BerValue::Null,
                        ),
                        Reply::WrongRequestId(oid, value) => response(
                            &community,
                            request.pdu.request_id.wrapping_add(1),
                            PDU_GET_RESPONSE,
                            0,
                            &oid,
                            &value,
                        ),
                        Reply::WrongCommunity(oid, value) => response(
                            "someone-elses-agent",
                            request.pdu.request_id,
                            PDU_GET_RESPONSE,
                            0,
                            &oid,
                            &value,
                        ),
                        Reply::WrongOid(oid, value) => response(
                            &community,
                            request.pdu.request_id,
                            PDU_GET_RESPONSE,
                            0,
                            &oid,
                            &value,
                        ),
                        Reply::Oversized(oid, bytes) => response(
                            &community,
                            request.pdu.request_id,
                            PDU_GET_RESPONSE,
                            0,
                            &oid,
                            &BerValue::OctetString(vec![b'x'; bytes]),
                        ),
                        Reply::TwoVarbinds(first, first_value, second, second_value) => {
                            two_varbind_response(
                                &community,
                                request.pdu.request_id,
                                &first,
                                &first_value,
                                &second,
                                &second_value,
                            )
                        }
                        Reply::WrongPduType(oid, value) => response(
                            &community,
                            request.pdu.request_id,
                            PDU_GET_NEXT_REQUEST,
                            0,
                            &oid,
                            &value,
                        ),
                    };
                    let _ = socket.send_to(&response, from);
                }
            });

            Self {
                port,
                stop,
                served,
                handle: Some(handle),
            }
        }

        /// How many requests it has answered.
        pub fn served(&self) -> usize {
            self.served.load(Ordering::Relaxed)
        }

        /// A target whose device address is a documentation address and whose transport is
        /// this agent: the topology describes 192.0.2.x while the datagrams stay on
        /// loopback.
        pub(crate) fn target_for(&self, device: std::net::Ipv4Addr, community: &str) -> SnmpTarget {
            SnmpTarget {
                device,
                transport: SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, self.port),
                community: community.to_string(),
            }
        }

        pub(crate) fn target(&self, device: &str, community: &str) -> SnmpTarget {
            SnmpTarget {
                device: device.parse().expect("a documentation address"),
                transport: SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, self.port),
                community: community.to_string(),
            }
        }
    }

    impl Drop for FakeAgent {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    /// Encodes one response message.
    fn response(
        community: &str,
        request_id: i32,
        pdu_type: u8,
        error_status: i32,
        oid: &Oid,
        value: &BerValue,
    ) -> Vec<u8> {
        let mut varbind = Vec::new();
        varbind.extend_from_slice(&encode_oid(oid));
        varbind.extend_from_slice(&encode_value(value));
        let varbind = encode_tlv(TAG_SEQUENCE, &varbind);
        let varbinds = encode_tlv(TAG_SEQUENCE, &varbind);

        let mut pdu = Vec::new();
        pdu.extend_from_slice(&encode_integer(request_id as i64));
        pdu.extend_from_slice(&encode_integer(error_status as i64));
        pdu.extend_from_slice(&encode_integer(0)); // error index
        pdu.extend_from_slice(&varbinds);
        let pdu = encode_tlv(pdu_type, &pdu);

        let mut message = Vec::new();
        message.extend_from_slice(&encode_integer(1)); // SNMPv2c
        message.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, community.as_bytes()));
        message.extend_from_slice(&pdu);
        encode_tlv(TAG_SEQUENCE, &message)
    }

    /// A GetResponse carrying two varbinds, which no request of ours ever asks for.
    fn two_varbind_response(
        community: &str,
        request_id: i32,
        first: &Oid,
        first_value: &BerValue,
        second: &Oid,
        second_value: &BerValue,
    ) -> Vec<u8> {
        let mut varbinds = Vec::new();
        for (oid, value) in [(first, first_value), (second, second_value)] {
            let mut varbind = Vec::new();
            varbind.extend_from_slice(&encode_oid(oid));
            varbind.extend_from_slice(&encode_value(value));
            varbinds.extend_from_slice(&encode_tlv(TAG_SEQUENCE, &varbind));
        }
        let varbinds = encode_tlv(TAG_SEQUENCE, &varbinds);

        let mut pdu = Vec::new();
        pdu.extend_from_slice(&encode_integer(request_id as i64));
        pdu.extend_from_slice(&encode_integer(0));
        pdu.extend_from_slice(&encode_integer(0));
        pdu.extend_from_slice(&varbinds);
        let pdu = encode_tlv(PDU_GET_RESPONSE, &pdu);

        let mut message = Vec::new();
        message.extend_from_slice(&encode_integer(1));
        message.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, community.as_bytes()));
        message.extend_from_slice(&pdu);
        encode_tlv(TAG_SEQUENCE, &message)
    }

    fn encode_value(value: &BerValue) -> Vec<u8> {
        match value {
            BerValue::Null => encode_tlv(TAG_NULL, &[]),
            BerValue::Integer(number) => encode_integer(*number),
            BerValue::OctetString(bytes) => encode_tlv(TAG_OCTET_STRING, bytes),
            BerValue::IpAddress(address) => encode_tlv(TAG_IP_ADDRESS, &address.octets()),
            BerValue::Counter32(number) => encode_integer(*number as i64),
            BerValue::Gauge32(number) => encode_integer(*number as i64),
            BerValue::TimeTicks(number) => encode_integer(*number as i64),
            BerValue::Oid(oid) => encode_oid(oid),
            BerValue::Unknown(tag, bytes) => encode_tlv(*tag, bytes),
        }
    }
}

#[cfg(test)]
mod lifecycle {
    //! The conversation, not the codec.
    //!
    //! Every test here runs against an agent that actually answers on loopback, because the
    //! properties worth proving are properties of an exchange: that a walk terminates, that
    //! a reply to someone else's request is refused, that an agent repeating an OID is
    //! stopped rather than followed until a bound. A hand-built byte string cannot fail in
    //! any of those ways.

    use super::fake_agent::{FakeAgent, Reply};
    use super::*;

    /// The device every fixture describes. Documentation address: the topology produced is
    /// about 192.0.2.1 while the datagrams never leave loopback.
    const DEVICE: &str = "192.0.2.1";
    const COMMUNITY: &str = "fixture-community";

    fn binding() -> SocketBinding {
        SocketBinding::unbound()
    }

    fn oid(text: &str) -> Oid {
        Oid::from_str(text).expect("a literal OID")
    }

    /// A single GET, as the harvester issues one.
    fn get(agent: &FakeAgent, oid_text: &str) -> Result<SnmpMessage, String> {
        let target = agent.target(DEVICE, COMMUNITY);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(snmp_request(
                &target,
                PDU_GET_REQUEST,
                &oid(oid_text),
                &binding(),
                Duration::from_millis(400),
            ))
    }

    /// A walk with an explicit total budget, for the tests about the budget itself.
    fn walk_within(agent: &FakeAgent, root: &str, request: Duration, total: Duration) -> Walk {
        let target = agent.target(DEVICE, COMMUNITY);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(snmp_walk_target(
                &target,
                &oid(root),
                &binding(),
                request,
                16,
                total,
            ))
    }

    fn walk(agent: &FakeAgent, root: &str) -> Walk {
        let target = agent.target(DEVICE, COMMUNITY);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(snmp_walk_target(
                &target,
                &oid(root),
                &binding(),
                Duration::from_millis(400),
                16,
                Duration::from_secs(5),
            ))
    }

    #[test]
    fn a_walk_collects_a_table_and_ends_at_the_mib_view() {
        // Three rows and then the agent says the view ends. That is a complete walk, and it
        // is distinguishable from one that stopped for any other reason.
        let root = "1.3.6.1.2.1.4.20.1.1";
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![
                Reply::Varbind(
                    oid("1.3.6.1.2.1.4.20.1.1.192.0.2.1"),
                    BerValue::IpAddress("192.0.2.1".parse().unwrap()),
                ),
                Reply::Varbind(
                    oid("1.3.6.1.2.1.4.20.1.1.198.51.100.1"),
                    BerValue::IpAddress("198.51.100.1".parse().unwrap()),
                ),
                Reply::EndOfMibView(oid("1.3.6.1.2.1.4.20.1.2")),
            ],
        );

        let result = walk(&agent, root);
        assert_eq!(result.end, WalkEnd::EndOfMibView);
        assert!(result.complete());
        assert_eq!(result.rows.len(), 2);
        assert_eq!(agent.served(), 3, "one request per step, and no more");
    }

    #[test]
    fn a_walk_ends_when_the_next_oid_leaves_the_subtree() {
        // The ordinary end of a table on an agent that keeps walking into the next one.
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![
                Reply::Varbind(oid("1.3.6.1.2.1.4.21.1.1.0.0.0.0"), BerValue::Integer(1)),
                Reply::Varbind(oid("1.3.6.1.2.1.4.22.1.1.1"), BerValue::Integer(2)),
            ],
        );

        let result = walk(&agent, "1.3.6.1.2.1.4.21.1");
        assert_eq!(result.end, WalkEnd::LeftSubtree);
        assert!(result.complete());
        assert_eq!(
            result.rows.len(),
            1,
            "the row from the next table is not ours"
        );
    }

    #[test]
    fn an_error_status_ends_the_walk_and_is_reported_as_an_error() {
        // Not a v1 exchange: the decoder refuses anything but v2c, so this is a v2c agent
        // answering noSuchName rather than an end-of-view marker. Either way the walk did
        // not reach the end of the table, and reporting it as complete would be a lie about
        // coverage. The rows already validated are kept; the status says incomplete.
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![
                Reply::Varbind(oid("1.3.6.1.2.1.4.21.1.1.0.0.0.0"), BerValue::Integer(1)),
                Reply::Error(2), // noSuchName
            ],
        );

        let result = walk(&agent, "1.3.6.1.2.1.4.21.1");
        assert_eq!(result.end, WalkEnd::AgentError(2));
        assert!(!result.complete());
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn an_agent_that_repeats_an_oid_terminates_the_walk_as_invalid() {
        // The failure this prevents: an agent that answers every GETNEXT with the same OID
        // makes a walk run until a bound stops it, and every row after the repeat describes
        // an order nobody guaranteed.
        let stuck = oid("1.3.6.1.2.1.4.21.1.1.10.0.0.0");
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![
                Reply::Varbind(stuck.clone(), BerValue::Integer(1)),
                Reply::Varbind(stuck.clone(), BerValue::Integer(1)),
            ],
        );

        let result = walk(&agent, "1.3.6.1.2.1.4.21.1");
        assert_eq!(result.end, WalkEnd::OidDidNotAdvance);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            agent.served(),
            2,
            "it stopped at the repeat, not at the bound"
        );
    }

    #[test]
    fn an_agent_that_walks_backwards_is_stopped_too() {
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![
                Reply::Varbind(oid("1.3.6.1.2.1.4.21.1.1.10.0.0.0"), BerValue::Integer(1)),
                Reply::Varbind(oid("1.3.6.1.2.1.4.21.1.1.9.0.0.0"), BerValue::Integer(2)),
            ],
        );

        let result = walk(&agent, "1.3.6.1.2.1.4.21.1");
        assert_eq!(result.end, WalkEnd::OidDidNotAdvance);
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn a_response_to_someone_elses_request_is_refused() {
        // Correlation is what makes an answer ours. Without it, any agent answering on the
        // same socket would have its table attributed to the device we asked.
        for wrong in [
            Reply::WrongRequestId(oid("1.3.6.1.2.1.4.21.1.1.10.0.0.0"), BerValue::Integer(1)),
            Reply::WrongCommunity(oid("1.3.6.1.2.1.4.21.1.1.10.0.0.0"), BerValue::Integer(1)),
            Reply::WrongPduType(oid("1.3.6.1.2.1.4.21.1.1.10.0.0.0"), BerValue::Integer(1)),
        ] {
            let agent = FakeAgent::start(COMMUNITY, vec![wrong.clone()]);
            let result = walk(&agent, "1.3.6.1.2.1.4.21.1");
            assert!(
                matches!(result.end, WalkEnd::Invalid(_)),
                "{wrong:?} must not be accepted, got {:?}",
                result.end
            );
            assert!(result.rows.is_empty());
        }
    }

    #[test]
    fn a_diagnostic_never_carries_the_community() {
        // A community is a shared secret wherever it is not the default, and a diagnostic
        // is exactly where one leaks.
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![Reply::WrongCommunity(
                oid("1.3.6.1.2.1.4.21.1.1.10.0.0.0"),
                BerValue::Integer(1),
            )],
        );

        let WalkEnd::Invalid(reason) = walk(&agent, "1.3.6.1.2.1.4.21.1").end else {
            panic!("a mismatched community must be refused");
        };
        assert!(
            !reason.contains(COMMUNITY) && !reason.contains("someone-elses-agent"),
            "neither community may appear in a diagnostic: {reason}"
        );
        assert!(reason.contains("different community"), "{reason}");
    }

    #[test]
    fn malformed_and_truncated_replies_are_refused_rather_than_parsed() {
        // A length byte claiming more than arrived, a truncated value, and bytes that are
        // not BER at all.
        for bytes in [
            vec![0x30, 0x82, 0xff, 0xff, 0x02, 0x01, 0x01],
            vec![0x30, 0x0a, 0x02, 0x01, 0x01, 0x04, 0x20, b'x'],
            b"this is not BER".to_vec(),
            Vec::new(),
        ] {
            let agent = FakeAgent::start(COMMUNITY, vec![Reply::Malformed(bytes.clone())]);
            let result = walk(&agent, "1.3.6.1.2.1.4.21.1");
            assert!(
                matches!(result.end, WalkEnd::Invalid(_)),
                "{bytes:?} must not parse into a walk step, got {:?}",
                result.end
            );
        }
    }

    #[test]
    fn an_agent_that_never_answers_ends_the_walk_at_the_timeout() {
        // Silence is not a table. It is reported as the request timing out, and the walk
        // does not spin until its step limit.
        let agent = FakeAgent::start(COMMUNITY, vec![Reply::Silence]);
        let result = walk(&agent, "1.3.6.1.2.1.4.21.1");

        match result.end {
            WalkEnd::Invalid(reason) => assert!(reason.contains("timed out"), "{reason}"),
            other => panic!("silence must end the walk as a timeout: {other:?}"),
        }
        assert!(result.rows.is_empty());
    }

    #[test]
    fn a_walk_is_bounded_by_its_step_limit() {
        // An agent with an endless table cannot make a run endless: the walk stops at its
        // own bound and says which one.
        let mut script = Vec::new();
        for index in 1..64u32 {
            script.push(Reply::Varbind(
                oid(&format!("1.3.6.1.2.1.4.21.1.1.10.0.0.{index}")),
                BerValue::Integer(index as i64),
            ));
        }
        let agent = FakeAgent::start(COMMUNITY, script);

        let result = walk(&agent, "1.3.6.1.2.1.4.21.1");
        assert_eq!(result.end, WalkEnd::Bounded("the walk's step limit"));
        assert_eq!(result.rows.len(), 16, "the step limit passed to the walk");
        assert!(!result.complete());
    }

    // -----------------------------------------------------------------------
    // Negative fixtures: an agent that is wrong, hostile, or merely truncated.
    // Each of these produced a fact -- or a crash -- before the correlation,
    // bounding and completion rules landed.
    // -----------------------------------------------------------------------

    #[test]
    fn a_get_answered_with_a_different_oid_is_refused() {
        // The failure this prevents: an agent answering sysName with sysDescr's value, or
        // an ipRouteTable column with a neighbour's address. Without correlating the
        // returned OID to the requested one, the value is filed under the wrong question
        // and every fact derived from it describes something that was never asked about.
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![Reply::WrongOid(
                oid("1.3.6.1.2.1.1.1.0"),
                BerValue::OctetString(b"an answer to a different question".to_vec()),
            )],
        );

        let error = get(&agent, OID_SYS_NAME).expect_err("the OID does not match the request");
        assert!(
            error.contains("a different OID"),
            "the diagnostic says what was wrong: {error}"
        );
    }

    #[test]
    fn a_response_carrying_two_varbinds_for_one_request_is_refused() {
        // Every request this sends names exactly one OID. Two varbinds back means the
        // response does not correspond to the request, and taking varbinds[0] would be
        // choosing which half of a mismatched answer to believe.
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![Reply::TwoVarbinds(
                oid(OID_SYS_NAME),
                BerValue::OctetString(b"fixture-router".to_vec()),
                oid(OID_SYS_DESCR),
                BerValue::OctetString(b"and one more, unasked".to_vec()),
            )],
        );

        let error = get(&agent, OID_SYS_NAME).expect_err("one request, one varbind");
        assert!(
            error.contains("varbind"),
            "the diagnostic names the varbind count: {error}"
        );
    }

    #[test]
    fn a_response_larger_than_the_bound_is_refused_rather_than_truncated() {
        // A datagram larger than the buffer used to be read as its first 8192 bytes, which
        // decodes as a truncated message -- or, worse, as a shorter valid one. It is
        // refused instead: the reader cannot know what it did not receive.
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![Reply::Oversized(oid(OID_SYS_NAME), MAX_RESPONSE_BYTES)],
        );

        let error = get(&agent, OID_SYS_NAME).expect_err("the datagram exceeds the bound");
        assert!(
            error.contains("exceeds"),
            "the diagnostic says the response was too large: {error}"
        );
    }

    #[test]
    fn an_inner_length_that_escapes_its_container_is_refused() {
        // The defect the bounded reader closed: child TLVs were parsed against the whole
        // datagram rather than against the bytes of their parent. A PDU claiming more
        // length than its message holds, or a varbind list claiming more than its PDU
        // holds, therefore read fields belonging to nothing.
        let mut varbind = Vec::new();
        varbind.extend_from_slice(&encode_oid(&oid(OID_SYS_NAME)));
        varbind.extend_from_slice(&encode_octet_string(b"fixture-router"));
        let varbind = encode_tlv(TAG_SEQUENCE, &varbind);
        let varbinds = encode_tlv(TAG_SEQUENCE, &varbind);

        let mut pdu_body = Vec::new();
        pdu_body.extend_from_slice(&encode_integer(1)); // request id
        pdu_body.extend_from_slice(&encode_integer(0)); // error status
        pdu_body.extend_from_slice(&encode_integer(0)); // error index
        pdu_body.extend_from_slice(&varbinds);

        let build = |pdu: Vec<u8>| {
            let mut message = Vec::new();
            message.extend_from_slice(&encode_integer(1)); // SNMPv2c
            message.extend_from_slice(&encode_octet_string(COMMUNITY.as_bytes()));
            message.extend_from_slice(&pdu);
            encode_tlv(TAG_SEQUENCE, &message)
        };

        // Well formed, as the control: the same bytes decode when no length lies.
        let honest = encode_tlv(PDU_GET_RESPONSE, &pdu_body);
        assert!(
            decode_snmp_response(&build(honest.clone())).is_ok(),
            "the control message is the one being mutated, so it must decode"
        );

        // The PDU claims more bytes than the message contains.
        let mut long_pdu = honest.clone();
        assert!(
            long_pdu[1] < 0x80,
            "short-form length, so this test can bump it"
        );
        long_pdu[1] += 8;
        let error = decode_snmp_response(&build(long_pdu))
            .expect_err("the PDU claims bytes the message does not hold");
        assert!(!error.is_empty());

        // And the varbind list claims more bytes than the PDU contains.
        let list_at = honest
            .windows(varbinds.len())
            .position(|window| window == varbinds.as_slice())
            .expect("the varbind list is in the PDU");
        let mut long_list = honest;
        assert!(long_list[list_at + 1] < 0x80);
        long_list[list_at + 1] += 8;
        let error = decode_snmp_response(&build(long_list))
            .expect_err("the varbind list claims bytes the PDU does not hold");
        assert!(!error.is_empty());
    }

    #[test]
    fn an_exhausted_total_budget_stops_the_walk_before_it_sends() {
        // The budget is checked before each step, so a walk with none left sends nothing.
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![Reply::Varbind(
                oid("1.3.6.1.2.1.4.21.1.1.0.0.0.0"),
                BerValue::Integer(1),
            )],
        );

        let result = walk_within(
            &agent,
            "1.3.6.1.2.1.4.21.1",
            Duration::from_millis(400),
            Duration::ZERO,
        );
        assert_eq!(result.end, WalkEnd::Bounded("the walk's total time budget"));
        assert!(result.rows.is_empty());
        assert_eq!(agent.served(), 0, "nothing was sent");
    }

    #[test]
    fn a_request_timeout_larger_than_the_remaining_budget_is_clamped_to_it() {
        // Before the clamp, a per-request timeout larger than the total budget made the
        // total meaningless: one silent step waited out its own timeout regardless of how
        // little of the walk's budget was left. Rows already validated are kept.
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![
                Reply::Varbind(
                    oid("1.3.6.1.2.1.4.21.1.1.192.0.2.0"),
                    BerValue::IpAddress("192.0.2.0".parse().unwrap()),
                ),
                Reply::Silence,
            ],
        );

        let started = std::time::Instant::now();
        let result = walk_within(
            &agent,
            "1.3.6.1.2.1.4.21.1",
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let elapsed = started.elapsed();

        assert_eq!(result.rows.len(), 1, "the answered row is still evidence");
        assert!(!result.complete(), "the table did not reach its end");
        assert!(
            elapsed < Duration::from_secs(2),
            "the walk honoured its budget rather than the request timeout: {elapsed:?}"
        );
    }

    #[test]
    fn a_table_that_stops_early_keeps_its_rows_and_reports_itself_incomplete() {
        // Rows validated individually stay evidence; the coverage claim does not. Absence
        // of a route in a truncated table is absence of an answer, not absence of a route,
        // and the status is what keeps those two readings apart.
        let agent = FakeAgent::start(
            COMMUNITY,
            vec![
                Reply::Varbind(
                    oid(OID_SYS_DESCR),
                    BerValue::OctetString(b"Synthetic router, fixture only".to_vec()),
                ),
                Reply::Varbind(
                    oid(OID_SYS_NAME),
                    BerValue::OctetString(b"fixture-router".to_vec()),
                ),
                Reply::Varbind(oid(OID_IP_FORWARDING), BerValue::Integer(1)),
                // ipNetToMediaTable: one row, then the agent gives up on the table.
                Reply::Varbind(
                    oid("1.3.6.1.2.1.4.22.1.3.1.192.0.2.50"),
                    BerValue::IpAddress("192.0.2.50".parse().unwrap()),
                ),
                Reply::Error(5), // genErr, mid-table
            ],
        );

        let target = agent.target(DEVICE, COMMUNITY);
        let info = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(harvest_snmp_target(
                &target,
                &binding(),
                Duration::from_millis(400),
            ))
            .expect("sysDescr answered, so the device is harvested");

        assert!(
            info.table_status
                .iter()
                .any(|(_, status)| status.contains("incomplete")),
            "a table that stopped early says so: {:?}",
            info.table_status
        );
        assert!(
            info.table_status
                .iter()
                .all(|(_, status)| !status.contains("row(s), complete")),
            "no table reached its own end here: {:?}",
            info.table_status
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_parse_and_display() {
        let s = "1.3.6.1.2.1.1.1.0";
        let oid = Oid::from_str(s).expect("Failed to parse OID");
        assert_eq!(oid.to_string(), s);
        assert_eq!(oid.0, vec![1, 3, 6, 1, 2, 1, 1, 1, 0]);

        let prefix = Oid::from_str("1.3.6.1.2.1").unwrap();
        assert!(oid.starts_with(&prefix));

        let unrelated = Oid::from_str("1.3.6.1.4.1").unwrap();
        assert!(!oid.starts_with(&unrelated));
    }

    #[test]
    fn test_ber_length_encoding() {
        assert_eq!(encode_length(10), vec![10]);
        assert_eq!(encode_length(127), vec![127]);
        assert_eq!(encode_length(128), vec![0x81, 128]);
        assert_eq!(encode_length(300), vec![0x82, 0x01, 0x2C]);
    }

    #[test]
    fn test_ber_oid_encode_decode() {
        let oid = Oid::from_str("1.3.6.1.2.1.1.1.0").unwrap();
        let encoded = encode_oid(&oid);
        assert_eq!(encoded[0], TAG_OBJECT_IDENTIFIER);

        // Decode value back
        let val_len = encoded[1] as usize;
        let decoded = decode_oid_value(&encoded[2..2 + val_len]).unwrap();
        assert_eq!(decoded, oid);
    }

    #[test]
    fn test_build_and_decode_snmp_packet() {
        let oid = Oid::from_str("1.3.6.1.2.1.1.1.0").unwrap();
        let request_id = 12345;
        let bytes = build_snmp_request(1, "public", request_id, PDU_GET_REQUEST, &oid);

        // Decode back
        let msg = decode_snmp_response(&bytes).expect("Failed to decode synthetic packet");
        assert_eq!(msg.version, 1);
        assert_eq!(msg.community, "public");
        assert_eq!(msg.pdu.pdu_type, PDU_GET_REQUEST);
        assert_eq!(msg.pdu.request_id, request_id);
        assert_eq!(msg.pdu.error_status, 0);
        assert_eq!(msg.pdu.varbinds.len(), 1);
        assert_eq!(msg.pdu.varbinds[0].0, oid);
        assert_eq!(msg.pdu.varbinds[0].1, BerValue::Null);
    }

    #[test]
    fn test_ber_decode_synthetic_response() {
        // Construct a synthetic GetResponse packet with sysDescr = "RT-BE92U"
        let oid = Oid::from_str("1.3.6.1.2.1.1.1.0").unwrap();
        let mut vb_body = Vec::new();
        vb_body.extend(encode_oid(&oid));
        vb_body.extend(encode_octet_string(b"ASUS RT-BE92U"));
        let vb = encode_tlv(TAG_SEQUENCE, &vb_body);
        let vbl = encode_tlv(TAG_SEQUENCE, &vb);

        let mut pdu_body = Vec::new();
        pdu_body.extend(encode_integer(999));
        pdu_body.extend(encode_integer(0));
        pdu_body.extend(encode_integer(0));
        pdu_body.extend(vbl);
        let pdu = encode_tlv(PDU_GET_RESPONSE, &pdu_body);

        let mut msg_body = Vec::new();
        msg_body.extend(encode_integer(1));
        msg_body.extend(encode_octet_string(b"public"));
        msg_body.extend(pdu);
        let packet = encode_tlv(TAG_SEQUENCE, &msg_body);

        let decoded = decode_snmp_response(&packet).unwrap();
        assert_eq!(decoded.pdu.request_id, 999);
        assert_eq!(decoded.pdu.varbinds.len(), 1);
        assert_eq!(decoded.pdu.varbinds[0].0, oid);
        assert_eq!(decoded.pdu.varbinds[0].1.as_str().unwrap(), "ASUS RT-BE92U");
    }
}
