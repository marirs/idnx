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
pub const OID_SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
pub const OID_SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
pub const OID_IP_NET_TO_MEDIA_TABLE: &str = "1.3.6.1.2.1.4.22.1"; // ARP table
pub const OID_IP_ROUTE_TABLE: &str = "1.3.6.1.2.1.4.21.1"; // Route table
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
// ---------------------------------------------------------------------------

fn decode_length(data: &[u8], offset: &mut usize) -> Result<usize, String> {
    if *offset >= data.len() {
        return Err("Unexpected end of data reading length".to_string());
    }
    let first = data[*offset];
    *offset += 1;

    if (first & 0x80) == 0 {
        Ok(first as usize)
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return Err(format!("Unsupported multi-byte length: {}", num_bytes));
        }
        if *offset + num_bytes > data.len() {
            return Err("Length exceeds packet boundary".to_string());
        }
        let mut len = 0usize;
        for _ in 0..num_bytes {
            len = (len << 8) | (data[*offset] as usize);
            *offset += 1;
        }
        Ok(len)
    }
}

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

pub fn decode_snmp_response(data: &[u8]) -> Result<SnmpMessage, String> {
    let mut offset = 0;
    if offset >= data.len() || data[offset] != TAG_SEQUENCE {
        return Err("Invalid SNMP message: expected SEQUENCE tag".to_string());
    }
    offset += 1;
    let _msg_len = decode_length(data, &mut offset)?;

    // 1. Version
    if offset >= data.len() || data[offset] != TAG_INTEGER {
        return Err("Expected version INTEGER".to_string());
    }
    offset += 1;
    let vlen = decode_length(data, &mut offset)?;
    let version = decode_integer_value(&data[offset..offset + vlen]) as i32;
    offset += vlen;

    // 2. Community
    if offset >= data.len() || data[offset] != TAG_OCTET_STRING {
        return Err("Expected community OCTET STRING".to_string());
    }
    offset += 1;
    let clen = decode_length(data, &mut offset)?;
    let community = String::from_utf8_lossy(&data[offset..offset + clen]).to_string();
    offset += clen;

    // 3. PDU
    if offset >= data.len() {
        return Err("Missing PDU in response".to_string());
    }
    let pdu_type = data[offset];
    offset += 1;
    let _pdu_len = decode_length(data, &mut offset)?;

    // PDU: request-id
    if offset >= data.len() || data[offset] != TAG_INTEGER {
        return Err("Expected PDU request-id".to_string());
    }
    offset += 1;
    let rlen = decode_length(data, &mut offset)?;
    let request_id = decode_integer_value(&data[offset..offset + rlen]) as i32;
    offset += rlen;

    // PDU: error-status
    if offset >= data.len() || data[offset] != TAG_INTEGER {
        return Err("Expected PDU error-status".to_string());
    }
    offset += 1;
    let elen = decode_length(data, &mut offset)?;
    let error_status = decode_integer_value(&data[offset..offset + elen]) as i32;
    offset += elen;

    // PDU: error-index
    if offset >= data.len() || data[offset] != TAG_INTEGER {
        return Err("Expected PDU error-index".to_string());
    }
    offset += 1;
    let ilen = decode_length(data, &mut offset)?;
    let error_index = decode_integer_value(&data[offset..offset + ilen]) as i32;
    offset += ilen;

    // PDU: VarBindList (SEQUENCE OF VarBind)
    if offset >= data.len() || data[offset] != TAG_SEQUENCE {
        return Err("Expected VarBindList SEQUENCE".to_string());
    }
    offset += 1;
    let varbind_list_len = decode_length(data, &mut offset)?;
    let varbind_end = offset + varbind_list_len;

    let mut varbinds = Vec::new();
    while offset < varbind_end && offset < data.len() {
        if data[offset] != TAG_SEQUENCE {
            break;
        }
        offset += 1;
        let vb_len = decode_length(data, &mut offset)?;
        let vb_end = offset + vb_len;

        // OID
        if offset >= vb_end || data[offset] != TAG_OBJECT_IDENTIFIER {
            offset = vb_end;
            continue;
        }
        offset += 1;
        let oid_len = decode_length(data, &mut offset)?;
        let oid = decode_oid_value(&data[offset..offset + oid_len])?;
        offset += oid_len;

        // Value
        if offset < vb_end {
            let val_tag = data[offset];
            offset += 1;
            let val_len = decode_length(data, &mut offset)?;
            let val_bytes = &data[offset..offset + val_len];

            let val = match val_tag {
                TAG_INTEGER => BerValue::Integer(decode_integer_value(val_bytes)),
                TAG_OCTET_STRING => BerValue::OctetString(val_bytes.to_vec()),
                TAG_NULL => BerValue::Null,
                TAG_OBJECT_IDENTIFIER => BerValue::Oid(decode_oid_value(val_bytes)?),
                TAG_IP_ADDRESS if val_bytes.len() == 4 => BerValue::IpAddress(Ipv4Addr::new(
                    val_bytes[0],
                    val_bytes[1],
                    val_bytes[2],
                    val_bytes[3],
                )),
                TAG_COUNTER32 => BerValue::Counter32(decode_integer_value(val_bytes) as u32),
                TAG_GAUGE32 => BerValue::Gauge32(decode_integer_value(val_bytes) as u32),
                TAG_TIMETICKS => BerValue::TimeTicks(decode_integer_value(val_bytes) as u32),
                _ => BerValue::Unknown(val_tag, val_bytes.to_vec()),
            };
            varbinds.push((oid, val));
            offset += val_len;
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
async fn snmp_request(
    target: Ipv4Addr,
    port: u16,
    community: &str,
    pdu_type: u8,
    oid: &Oid,
    binding: &SocketBinding,
    timeout: Duration,
) -> Result<SnmpMessage, String> {
    let dest = SocketAddrV4::new(target, port);
    let socket = binding
        .udp_socket(&std::net::SocketAddr::V4(dest))
        .await
        .map_err(|e| format!("UDP bind error: {}", e))?;
    let request_id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        & 0x7FFFFFFF) as i32;

    let req_bytes = build_snmp_request(1, community, request_id, pdu_type, oid); // SNMPv2c
    socket
        .send_to(&req_bytes, dest)
        .await
        .map_err(|e| format!("UDP send error: {}", e))?;

    let mut buf = [0u8; 4096];
    let recv_fut = socket.recv_from(&mut buf);
    match tokio::time::timeout(timeout, recv_fut).await {
        Ok(Ok((len, _from))) => decode_snmp_response(&buf[..len]),
        Ok(Err(e)) => Err(format!("UDP recv error: {}", e)),
        Err(_) => Err("SNMP request timed out".to_string()),
    }
}

/// Walks an SNMP subtree starting from `root_oid`
pub async fn snmp_walk(
    target: Ipv4Addr,
    port: u16,
    community: &str,
    root_oid: &Oid,
    binding: &SocketBinding,
    timeout: Duration,
    max_steps: usize,
) -> Vec<(Oid, BerValue)> {
    let mut results = Vec::new();
    let mut current_oid = root_oid.clone();

    for _ in 0..max_steps {
        match snmp_request(
            target,
            port,
            community,
            PDU_GET_NEXT_REQUEST,
            &current_oid,
            binding,
            timeout,
        )
        .await
        {
            Ok(msg) => {
                if msg.pdu.error_status != 0 || msg.pdu.varbinds.is_empty() {
                    break;
                }
                let (next_oid, value) = msg.pdu.varbinds[0].clone();

                // Stop if we walked outside the root subtree
                if !next_oid.starts_with(root_oid) {
                    break;
                }

                // Stop if OID didn't advance (loop protection)
                if next_oid <= current_oid {
                    break;
                }

                current_oid = next_oid.clone();
                results.push((next_oid, value));
            }
            Err(_) => break,
        }
    }

    results
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
}

/// Router/Switch hardware information
#[derive(Debug, Clone, Default)]
pub struct SnmpDeviceInfo {
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
    // 1. Probe sysDescr to verify SNMP responsiveness and community validity
    let sys_descr_oid = Oid::from_str(OID_SYS_DESCR).ok()?;
    let sys_descr_msg = snmp_request(
        target,
        port,
        community,
        PDU_GET_REQUEST,
        &sys_descr_oid,
        binding,
        timeout,
    )
    .await
    .ok()?;

    if sys_descr_msg.pdu.varbinds.is_empty() {
        return None;
    }

    let sys_descr = sys_descr_msg.pdu.varbinds[0].1.as_str();

    // 2. Query sysName
    let sys_name_oid = Oid::from_str(OID_SYS_NAME).ok()?;
    let sys_name = if let Ok(msg) = snmp_request(
        target,
        port,
        community,
        PDU_GET_REQUEST,
        &sys_name_oid,
        binding,
        timeout,
    )
    .await
    {
        msg.pdu.varbinds.first().and_then(|vb| vb.1.as_str())
    } else {
        None
    };

    let mut info = SnmpDeviceInfo {
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
        let arp_results =
            snmp_walk(target, port, community, &arp_root, binding, timeout, 512).await;
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
        let route_results =
            snmp_walk(target, port, community, &route_root, binding, timeout, 256).await;
        type RouteTuple = (Option<Ipv4Addr>, Option<Ipv4Addr>, Option<Ipv4Addr>);
        let mut route_map: std::collections::HashMap<Vec<u32>, RouteTuple> =
            std::collections::HashMap::new();

        for (oid, val) in route_results {
            if oid.0.len() >= 11 {
                let col = oid.0[9];
                let key = oid.0[10..].to_vec();
                let entry = route_map.entry(key).or_insert((None, None, None));
                match col {
                    1 => entry.0 = val.as_ipv4(),
                    7 => entry.2 = val.as_ipv4(),
                    11 => entry.1 = val.as_ipv4(),
                    _ => {}
                }
            }
        }

        for (_, (dest, mask, nexthop)) in route_map {
            if let (Some(dest), Some(mask), Some(next_hop)) = (dest, mask, nexthop)
                && !dest.is_loopback()
            {
                info.routes.push(SnmpRouteEntry {
                    dest_network: dest,
                    mask,
                    next_hop,
                });
            }
        }
    }

    // 5. Walk `ipAddrTable` (`1.3.6.1.2.1.4.20.1`)
    // Columns:
    // .1 = ipAdEntAddr
    // .3 = ipAdEntNetMask
    if let Ok(addr_root) = Oid::from_str(OID_IP_ADDR_TABLE) {
        let addr_results =
            snmp_walk(target, port, community, &addr_root, binding, timeout, 64).await;
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
