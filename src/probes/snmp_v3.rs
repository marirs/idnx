//! The SNMPv3 message layer: encoding, decoding, and the exact bytes authentication covers.
//!
//! Two properties shape everything here.
//!
//! **The MAC covers a byte string, not a structure.** RFC 3414 computes the digest over the
//! whole serialised message with `msgAuthenticationParameters` present and zero-filled, then
//! transmits the message with the digest written into that same field. A verifier must
//! therefore reproduce the *received* bytes exactly -- not an equivalent re-encoding of the
//! parsed message. BER admits several encodings of the same value, and a manager that
//! re-serialises before verifying rejects perfectly valid messages from agents whose encoder
//! differs from its own, while accepting nothing it should not. So both directions here
//! carry the field's byte range: the encoder returns where it left the zeros, and the decoder
//! returns where it found the digest, both as offsets into the one buffer that exists.
//!
//! **Nothing learned before authentication is a fact.** Engine discovery is unauthenticated
//! by necessity -- the keys cannot be localised until the engine identifier is known -- so
//! whatever it returns is provisional: an input to key derivation and timeliness, never
//! identity and never topology. This module marks it as such in the type, so a caller cannot
//! use a discovered engine ID as though something had vouched for it.

use std::ops::Range;

use crate::probes::snmp::{
    Oid, PDU_GET_REQUEST, TAG_INTEGER, TAG_OCTET_STRING, TAG_SEQUENCE, encode_integer, encode_null,
    encode_octet_string, encode_oid, encode_tlv,
};
use crate::probes::usm::{AuthProtocol, SecurityLevel};
use crate::secret::SecretBytes;

/// `msgVersion` for SNMPv3.
pub const VERSION_3: i64 = 3;
/// `msgSecurityModel` for the User-based Security Model.
pub const SECURITY_MODEL_USM: i64 = 3;
/// Report PDU, which carries a counter rather than an answer.
pub const PDU_REPORT: u8 = 0xA8;

/// The largest message this reads. A datagram beyond it is refused rather than truncated.
pub const MAX_MESSAGE_BYTES: usize = 8192;

/// The largest value RFC 3412 permits for msgID, msgMaxSize, engine boots and engine time.
const MAX_COUNTER: i64 = 2_147_483_647;

/// The smallest `msgMaxSize` RFC 3412 permits an implementation to declare.
const MIN_MAX_SIZE: i64 = 484;

/// `msgUserName` is bounded at 32 octets by the USM MIB.
const MAX_USER_NAME: usize = 32;

/// An `snmpEngineID` is 5 to 32 octets (RFC 3411).
const MIN_ENGINE_ID: usize = 5;
const MAX_ENGINE_ID: usize = 32;

/// The privacy parameters of an AES-128-CFB message are exactly the eight-octet salt.
const AES_SALT_LEN: usize = 8;

/// Checks the invariants that must hold of any message this code sends or accepts.
///
/// One function for both directions on purpose. An encoder that can build what its own
/// decoder refuses is a source of messages nobody can explain: the failure surfaces at the
/// far end, as an agent that "does not answer", with nothing local to point at.
fn check_message_invariants(
    message_id: i64,
    max_size: i64,
    flags: u8,
    security_model: i64,
    usm: &UsmParameters,
) -> Result<(), String> {
    if !(0..=MAX_COUNTER).contains(&message_id) {
        return Err("msgID outside the range RFC 3412 defines".to_string());
    }
    if !(MIN_MAX_SIZE..=MAX_COUNTER).contains(&max_size) {
        return Err(format!(
            "msgMaxSize {max_size} outside the {MIN_MAX_SIZE}..=2^31-1 RFC 3412 defines"
        ));
    }
    if security_model != SECURITY_MODEL_USM {
        return Err(format!(
            "security model {security_model} is not the User-based Security Model"
        ));
    }

    let authenticated = flags & flags::AUTH != 0;
    let encrypted = flags & flags::PRIV != 0;
    // Privacy without authentication is not a level USM defines: encryption with no way to
    // tell who encrypted it protects the bytes and establishes nothing about their origin.
    if encrypted && !authenticated {
        return Err("msgFlags claims privacy without authentication".to_string());
    }

    if usm.user_name.len() > MAX_USER_NAME {
        return Err(format!(
            "msgUserName is longer than the {MAX_USER_NAME} octets USM defines"
        ));
    }

    if !(0..=MAX_COUNTER).contains(&i64::from(usm.engine_boots))
        || !(0..=MAX_COUNTER).contains(&i64::from(usm.engine_time))
    {
        return Err("engine boots or time outside the range RFC 3414 defines".to_string());
    }

    // The lengths of the two variable security fields are fixed by the level, and a message
    // whose fields disagree with its flags is one whose flags cannot be trusted to describe
    // it. A 24-octet digest on an unauthenticated message, in particular, is a field nothing
    // will check.
    let expected_auth = if authenticated {
        AuthProtocol::HmacSha256.tag_len()
    } else {
        0
    };
    if usm.authentication.len() != expected_auth {
        return Err(format!(
            "msgAuthenticationParameters is {} octet(s) where {expected_auth} were required",
            usm.authentication.len()
        ));
    }
    let expected_priv = if encrypted { AES_SALT_LEN } else { 0 };
    if usm.privacy.len() != expected_priv {
        return Err(format!(
            "msgPrivacyParameters is {} octet(s) where {expected_priv} were required",
            usm.privacy.len()
        ));
    }

    if authenticated {
        // An authenticated message names the engine whose key signed it, and names a user.
        // Either being absent means the digest was computed against something that cannot be
        // identified.
        if !(MIN_ENGINE_ID..=MAX_ENGINE_ID).contains(&usm.engine_id.len()) {
            return Err(format!(
                "an authenticated message carries a {}-octet engine ID; RFC 3411 defines \
                 {MIN_ENGINE_ID}..={MAX_ENGINE_ID}",
                usm.engine_id.len()
            ));
        }
        if usm.user_name.is_empty() {
            return Err("an authenticated message names no user".to_string());
        }
    }

    Ok(())
}

/// `msgFlags` bits (RFC 3412 §6.4).
pub mod flags {
    pub const AUTH: u8 = 0x01;
    pub const PRIV: u8 = 0x02;
    pub const REPORTABLE: u8 = 0x04;
}

/// What a manager asks of one exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Unauthenticated, and used only for engine discovery.
    ///
    /// Deliberately not a security level a caller may select for topology: an unauthenticated
    /// answer establishes nothing about who sent it.
    Discovery,
    Secured(SecurityLevel),
}

impl Level {
    fn flags(&self, reportable: bool) -> u8 {
        let base = match self {
            Level::Discovery => 0,
            Level::Secured(level) => level.flags(),
        };
        base | if reportable { flags::REPORTABLE } else { 0 }
    }

    fn authenticated(&self) -> bool {
        matches!(self, Level::Secured(_))
    }

    fn encrypted(&self) -> bool {
        matches!(self, Level::Secured(SecurityLevel::AuthPriv))
    }
}

/// The USM security parameters of one message.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UsmParameters {
    pub engine_id: Vec<u8>,
    pub engine_boots: u32,
    pub engine_time: u32,
    pub user_name: Vec<u8>,
    /// The digest as it appeared on the wire. Public: it is worthless without the key, and
    /// it must be comparable against a computed one.
    pub authentication: Vec<u8>,
    /// The privacy salt, which travels in the clear by design (RFC 3826 §3.1.2.1).
    pub privacy: Vec<u8>,
}

impl std::fmt::Debug for UsmParameters {
    /// Shapes and identifiers, never the octets that identify a person or authenticate a
    /// message.
    ///
    /// The user name is omitted for the same reason a community string never appears in a
    /// diagnostic: it is half a credential, and a formatted structure ends up in logs, in
    /// panic output and in bug reports. The engine identifier is kept because it names a
    /// device rather than an operator, and diagnosing an engine mismatch without it is
    /// guesswork.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsmParameters")
            .field(
                "engine_id",
                &self
                    .engine_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
            .field("engine_boots", &self.engine_boots)
            .field("engine_time", &self.engine_time)
            .field("user_name_len", &self.user_name.len())
            .field("authentication_len", &self.authentication.len())
            .field("privacy_len", &self.privacy.len())
            .finish()
    }
}

/// A message ready to send, with the range the digest belongs in.
pub struct Encoded {
    pub bytes: Vec<u8>,
    /// Where `msgAuthenticationParameters`' content sits inside `bytes`.
    ///
    /// Empty for an unauthenticated message. The digest is written here in place rather than
    /// by re-encoding, because re-encoding could produce different bytes from the ones the
    /// digest was computed over.
    pub authentication_range: Range<usize>,
}

impl Encoded {
    /// Computes the digest over the complete message and writes it into its own field.
    ///
    /// The field already holds the right number of zeroes, which is what the digest was
    /// defined over; writing the result back into that exact range is what makes the sent
    /// bytes verifiable by the receiver.
    pub fn sign(mut self, key: &SecretBytes, protocol: AuthProtocol) -> Result<Vec<u8>, String> {
        if self.authentication_range.is_empty() {
            return Err("an unauthenticated message has no digest field to sign".to_string());
        }
        if self.authentication_range.len() != protocol.tag_len() {
            return Err("the digest field is not the length this protocol produces".to_string());
        }
        let tag = crate::probes::usm::authenticate(key, &self.bytes, protocol);
        self.bytes[self.authentication_range.clone()].copy_from_slice(&tag);
        Ok(self.bytes)
    }
}

/// Builds one SNMPv3 message.
///
/// `scoped_pdu` is the already-encoded scoped PDU: plaintext for authNoPriv, ciphertext for
/// authPriv. Encryption happens above this layer, because the salt and the engine counters
/// that form the IV belong to the per-engine state rather than to message encoding.
///
/// Whether the payload is wrapped as an OCTET STRING is taken from the level rather than
/// from a separate argument, so the privacy flag and the shape of `msgData` cannot disagree
/// in anything this encoder produces.
pub fn encode_message(
    message_id: i32,
    level: Level,
    reportable: bool,
    usm: &UsmParameters,
    scoped_pdu: &[u8],
) -> Result<Encoded, String> {
    let encrypted = level.encrypted();
    let flags = level.flags(reportable);
    // The same invariants the decoder enforces, checked before any bytes exist. An encoder
    // that can build what its own decoder refuses produces messages that fail at the far
    // end with nothing local to point at.
    //
    // The digest field is checked as it will be *sent*: `sign` writes the tag into the
    // zeroes reserved here, so the message is validated with a field of the right length
    // even though the caller passes none.
    let outgoing = UsmParameters {
        authentication: vec![
            0;
            if level.authenticated() {
                AuthProtocol::HmacSha256.tag_len()
            } else {
                0
            }
        ],
        ..usm.clone()
    };
    check_message_invariants(
        i64::from(message_id),
        MAX_MESSAGE_BYTES as i64,
        flags,
        SECURITY_MODEL_USM,
        &outgoing,
    )?;
    if !usm.authentication.is_empty() {
        return Err("the digest is written by sign(), not supplied to the encoder".to_string());
    }
    let header = encode_tlv(
        TAG_SEQUENCE,
        &[
            encode_integer(i64::from(message_id)),
            encode_integer(MAX_MESSAGE_BYTES as i64),
            encode_octet_string(&[flags]),
            encode_integer(SECURITY_MODEL_USM),
        ]
        .concat(),
    );

    // The digest field is written as the right number of zeroes now, and the offset of those
    // zeroes is tracked out through every enclosing header, so the digest can be spliced in
    // afterwards without the message being built a second time.
    let auth_len = if level.authenticated() {
        AuthProtocol::HmacSha256.tag_len()
    } else {
        0
    };
    let mut usm_body = Vec::new();
    usm_body.extend_from_slice(&encode_octet_string(&usm.engine_id));
    usm_body.extend_from_slice(&encode_integer(i64::from(usm.engine_boots)));
    usm_body.extend_from_slice(&encode_integer(i64::from(usm.engine_time)));
    usm_body.extend_from_slice(&encode_octet_string(&usm.user_name));
    let auth_header = encode_octet_string(&vec![0u8; auth_len]);
    let auth_offset_in_usm_body = usm_body.len() + (auth_header.len() - auth_len);
    usm_body.extend_from_slice(&auth_header);
    usm_body.extend_from_slice(&encode_octet_string(&usm.privacy));

    let usm_sequence = encode_tlv(TAG_SEQUENCE, &usm_body);
    let usm_octets = encode_octet_string(&usm_sequence);
    // Two headers stand between the message and those zeroes: the OCTET STRING wrapping the
    // security parameters, and the SEQUENCE inside it.
    let usm_prefix =
        (usm_octets.len() - usm_sequence.len()) + (usm_sequence.len() - usm_body.len());

    let data = if encrypted {
        encode_octet_string(scoped_pdu)
    } else {
        scoped_pdu.to_vec()
    };

    let mut body = Vec::new();
    body.extend_from_slice(&encode_integer(VERSION_3));
    body.extend_from_slice(&header);
    let usm_start_in_body = body.len();
    body.extend_from_slice(&usm_octets);
    body.extend_from_slice(&data);

    let message = encode_tlv(TAG_SEQUENCE, &body);
    let body_offset = message.len() - body.len();

    let authentication_range = if auth_len == 0 {
        0..0
    } else {
        let start = body_offset + usm_start_in_body + usm_prefix + auth_offset_in_usm_body;
        start..start + auth_len
    };

    // A message this size cannot be received by anything that declares the same limit, so
    // producing one would mean sending bytes nobody will read.
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(format!(
            "the encoded message is {} octets, beyond the {MAX_MESSAGE_BYTES}-octet limit \
             this declares",
            message.len()
        ));
    }

    Ok(Encoded {
        bytes: message,
        authentication_range,
    })
}

/// Builds a scoped PDU carrying one request.
pub fn encode_scoped_pdu(
    context_engine_id: &[u8],
    context_name: &[u8],
    pdu_type: u8,
    request_id: i32,
    oid: &Oid,
) -> Vec<u8> {
    let varbind = encode_tlv(TAG_SEQUENCE, &[encode_oid(oid), encode_null()].concat());
    let varbinds = encode_tlv(TAG_SEQUENCE, &varbind);
    let pdu = encode_tlv(
        pdu_type,
        &[
            encode_integer(request_id as i64),
            encode_integer(0),
            encode_integer(0),
            varbinds,
        ]
        .concat(),
    );
    encode_tlv(
        TAG_SEQUENCE,
        &[
            encode_octet_string(context_engine_id),
            encode_octet_string(context_name),
            pdu,
        ]
        .concat(),
    )
}

/// A scoped PDU: the context it applies to, and the PDU itself.
#[derive(Debug, Clone)]
pub struct ScopedPdu {
    pub context_engine_id: Vec<u8>,
    pub context_name: Vec<u8>,
    pub pdu: crate::probes::snmp::SnmpPdu,
}

/// Decodes a scoped PDU, plaintext or freshly decrypted.
///
/// The PDU body is read by the same code that reads a v2c PDU, so a varbind cannot be
/// interpreted two subtly different ways depending on which version delivered it. The
/// context fields are read strictly and the structure must be consumed exactly: a decrypted
/// buffer whose trailing bytes happen to parse is a buffer that decrypted wrongly, and
/// padding an attacker controls is not something to skip past.
pub fn decode_scoped_pdu(bytes: &[u8]) -> Result<ScopedPdu, String> {
    use crate::probes::snmp::Reader;

    let mut outer = Reader::new(bytes);
    let mut scoped = outer.expect(TAG_SEQUENCE, "the scoped PDU")?;
    outer.finished("the scoped PDU")?;

    let context_engine_id = scoped
        .expect(TAG_OCTET_STRING, "contextEngineID")?
        .rest()
        .to_vec();
    let context_name = scoped
        .expect(TAG_OCTET_STRING, "contextName")?
        .rest()
        .to_vec();

    let (pdu_type, mut pdu) = scoped.tlv("the PDU")?;
    scoped.finished("the scoped PDU")?;
    let pdu = crate::probes::snmp::decode_pdu_body(pdu_type, &mut pdu)?;

    Ok(ScopedPdu {
        context_engine_id,
        context_name,
        pdu,
    })
}

/// One TLV read at an absolute offset, with its content located rather than copied.
///
/// Offsets, not slices, because the digest has to be located in the buffer the datagram
/// arrived in. A parser that hands back copies cannot say where anything was.
struct Tlv {
    tag: u8,
    content: Range<usize>,
    /// Where the next TLV begins.
    end: usize,
}

/// Reads one TLV at `at`, refusing anything that runs past `limit`.
fn read_tlv(bytes: &[u8], at: usize, limit: usize, what: &str) -> Result<Tlv, String> {
    if at >= limit || limit > bytes.len() {
        return Err(format!("{what}: no bytes where one was expected"));
    }
    let tag = bytes[at];
    let mut cursor = at + 1;
    if cursor >= limit {
        return Err(format!("{what}: length byte missing"));
    }
    let first = bytes[cursor];
    cursor += 1;

    let length = if first & 0x80 == 0 {
        first as usize
    } else {
        let count = (first & 0x7F) as usize;
        // Indefinite length is not permitted in BER-encoded SNMP, and more than four length
        // octets describes a message larger than this reads.
        if count == 0 || count > 4 {
            return Err(format!("{what}: unsupported length form"));
        }
        if cursor + count > limit {
            return Err(format!("{what}: truncated length"));
        }
        let mut value = 0usize;
        for _ in 0..count {
            value = value
                .checked_shl(8)
                .and_then(|shifted| shifted.checked_add(bytes[cursor] as usize))
                .ok_or_else(|| format!("{what}: length out of range"))?;
            cursor += 1;
        }
        value
    };

    let end = cursor
        .checked_add(length)
        .ok_or_else(|| format!("{what}: length overflows the buffer"))?;
    if end > limit {
        return Err(format!("{what}: declared length runs past its container"));
    }
    Ok(Tlv {
        tag,
        content: cursor..end,
        end,
    })
}

fn expect(bytes: &[u8], at: usize, limit: usize, tag: u8, what: &str) -> Result<Tlv, String> {
    let tlv = read_tlv(bytes, at, limit, what)?;
    if tlv.tag != tag {
        return Err(format!(
            "{what}: tag {:#04x} where {tag:#04x} was required",
            tlv.tag
        ));
    }
    Ok(tlv)
}

fn read_integer(bytes: &[u8], tlv: &Tlv, what: &str) -> Result<i64, String> {
    let raw = &bytes[tlv.content.clone()];
    if raw.is_empty() || raw.len() > 8 {
        return Err(format!("{what}: integer of {} octet(s)", raw.len()));
    }
    let mut value = if raw[0] & 0x80 != 0 { -1i64 } else { 0 };
    for byte in raw {
        value = (value << 8) | i64::from(*byte);
    }
    Ok(value)
}

/// A decoded message, borrowing the datagram it was decoded from.
///
/// The borrow is the point. Every range here is an offset into one specific buffer, and an
/// earlier version took the buffer again at verification time -- which let a caller pass a
/// different, shorter one and panic on the slice. Holding the datagram means the ranges can
/// only ever be applied to the bytes they came from.
#[derive(Clone)]
pub struct DecodedMessage<'a> {
    datagram: &'a [u8],
    pub message_id: i32,
    pub flags: u8,
    pub security_model: i64,
    pub usm: UsmParameters,
    /// Where `msgAuthenticationParameters`' content sits in the received datagram.
    pub authentication_range: Range<usize>,
    /// The scoped PDU, plaintext or ciphertext, as a range of the received datagram.
    pub scoped_pdu: Range<usize>,
    pub encrypted: bool,
}

impl std::fmt::Debug for DecodedMessage<'_> {
    /// Metadata only. The datagram itself is never formatted.
    ///
    /// A derived implementation printed the entire received message -- every varbind of an
    /// authNoPriv exchange in the clear, and the ciphertext of an authPriv one -- which is
    /// exactly why `Encoded` has no Debug at all. A structure that is cheap to print is a
    /// structure that ends up printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedMessage")
            .field("message_id", &self.message_id)
            .field("flags", &format_args!("{:#04x}", self.flags))
            .field("security_model", &self.security_model)
            .field("usm", &self.usm)
            .field("authentication_range", &self.authentication_range)
            .field("scoped_pdu_len", &self.scoped_pdu.len())
            .field("encrypted", &self.encrypted)
            .field("datagram_len", &self.datagram.len())
            .finish()
    }
}

impl<'a> DecodedMessage<'a> {
    /// The datagram this was decoded from.
    pub fn datagram(&self) -> &'a [u8] {
        self.datagram
    }

    /// The scoped PDU, plaintext or ciphertext, as it arrived.
    pub fn scoped_pdu(&self) -> &'a [u8] {
        &self.datagram[self.scoped_pdu.clone()]
    }

    pub fn reportable(&self) -> bool {
        self.flags & flags::REPORTABLE != 0
    }

    pub fn authenticated(&self) -> bool {
        self.flags & flags::AUTH != 0
    }

    /// Verifies the digest over the received bytes with the field zeroed in place.
    ///
    /// No second buffer: the bytes hashed are the bytes this message was decoded from, and
    /// nothing is re-encoded. The message is copied once so the zeroing does not disturb the
    /// caller's datagram.
    pub fn verify(&self, key: &SecretBytes, protocol: AuthProtocol) -> bool {
        if self.authentication_range.len() != protocol.tag_len() {
            return false;
        }
        let mut zeroed = self.datagram.to_vec();
        zeroed[self.authentication_range.clone()].fill(0);
        crate::probes::usm::verify(key, &zeroed, &self.usm.authentication, protocol)
    }
}

/// Decodes an SNMPv3 message, locating every field in the buffer it arrived in.
pub fn decode_message(datagram: &[u8]) -> Result<DecodedMessage<'_>, String> {
    if datagram.len() > MAX_MESSAGE_BYTES {
        return Err(format!(
            "message exceeds the {MAX_MESSAGE_BYTES}-byte bound this reads"
        ));
    }
    let limit = datagram.len();
    let message = expect(datagram, 0, limit, TAG_SEQUENCE, "the message")?;
    if message.end != limit {
        return Err("trailing bytes after the message".to_string());
    }
    let inside = message.content.end;

    let version_tlv = expect(
        datagram,
        message.content.start,
        inside,
        TAG_INTEGER,
        "msgVersion",
    )?;
    let version = read_integer(datagram, &version_tlv, "msgVersion")?;
    if version != VERSION_3 {
        return Err(format!("message declared version {version}, not 3"));
    }

    let header = expect(
        datagram,
        version_tlv.end,
        inside,
        TAG_SEQUENCE,
        "msgGlobalData",
    )?;
    let header_end = header.content.end;
    let id_tlv = expect(
        datagram,
        header.content.start,
        header_end,
        TAG_INTEGER,
        "msgID",
    )?;
    let message_id = read_integer(datagram, &id_tlv, "msgID")?;
    let max_size = expect(datagram, id_tlv.end, header_end, TAG_INTEGER, "msgMaxSize")?;
    let flags_tlv = expect(
        datagram,
        max_size.end,
        header_end,
        TAG_OCTET_STRING,
        "msgFlags",
    )?;
    if flags_tlv.content.len() != 1 {
        return Err("msgFlags is not a single octet".to_string());
    }
    let flags = datagram[flags_tlv.content.start];
    let model_tlv = expect(
        datagram,
        flags_tlv.end,
        header_end,
        TAG_INTEGER,
        "msgSecurityModel",
    )?;
    let security_model = read_integer(datagram, &model_tlv, "msgSecurityModel")?;
    if model_tlv.end != header_end {
        return Err("trailing bytes in msgGlobalData".to_string());
    }
    let max_size_value = read_integer(datagram, &max_size, "msgMaxSize")?;
    // Checked before the security parameters are read *as USM*: the model decides how those
    // octets are to be parsed at all, so reading them first would be interpreting a
    // structure under a model the sender did not claim.
    if security_model != SECURITY_MODEL_USM {
        return Err(format!(
            "security model {security_model} is not the User-based Security Model"
        ));
    }

    // The security parameters are an OCTET STRING whose content is itself a BER SEQUENCE.
    let params = expect(
        datagram,
        header.end,
        inside,
        TAG_OCTET_STRING,
        "msgSecurityParameters",
    )?;
    let params_end = params.content.end;
    let usm_seq = expect(
        datagram,
        params.content.start,
        params_end,
        TAG_SEQUENCE,
        "usmSecurityParameters",
    )?;
    let usm_end = usm_seq.content.end;

    let engine_tlv = expect(
        datagram,
        usm_seq.content.start,
        usm_end,
        TAG_OCTET_STRING,
        "msgAuthoritativeEngineID",
    )?;
    let boots_tlv = expect(
        datagram,
        engine_tlv.end,
        usm_end,
        TAG_INTEGER,
        "msgAuthoritativeEngineBoots",
    )?;
    let time_tlv = expect(
        datagram,
        boots_tlv.end,
        usm_end,
        TAG_INTEGER,
        "msgAuthoritativeEngineTime",
    )?;
    let user_tlv = expect(
        datagram,
        time_tlv.end,
        usm_end,
        TAG_OCTET_STRING,
        "msgUserName",
    )?;
    let auth_tlv = expect(
        datagram,
        user_tlv.end,
        usm_end,
        TAG_OCTET_STRING,
        "msgAuthenticationParameters",
    )?;
    let priv_tlv = expect(
        datagram,
        auth_tlv.end,
        usm_end,
        TAG_OCTET_STRING,
        "msgPrivacyParameters",
    )?;
    if priv_tlv.end != usm_end || usm_seq.end != params_end {
        return Err("trailing bytes in the security parameters".to_string());
    }

    let boots = read_integer(datagram, &boots_tlv, "msgAuthoritativeEngineBoots")?;
    let time = read_integer(datagram, &time_tlv, "msgAuthoritativeEngineTime")?;
    if !(0..=MAX_COUNTER).contains(&boots) || !(0..=MAX_COUNTER).contains(&time) {
        return Err("engine boots or time outside the range RFC 3414 defines".to_string());
    }

    let usm = UsmParameters {
        engine_id: datagram[engine_tlv.content.clone()].to_vec(),
        engine_boots: boots as u32,
        engine_time: time as u32,
        user_name: datagram[user_tlv.content.clone()].to_vec(),
        authentication: datagram[auth_tlv.content.clone()].to_vec(),
        privacy: datagram[priv_tlv.content.clone()].to_vec(),
    };
    // The same invariants the encoder enforces. A message whose fields contradict its flags
    // is one whose flags do not describe it, whatever else it parses into.
    check_message_invariants(message_id, max_size_value, flags, security_model, &usm)?;

    let data = read_tlv(datagram, params.end, inside, "msgData")?;
    if data.end != inside {
        return Err("trailing bytes after msgData".to_string());
    }
    let encrypted = flags & flags::PRIV != 0;
    // An encrypted scoped PDU arrives as an OCTET STRING; a plaintext one as the SEQUENCE
    // itself. A message whose flags and shape disagree is not one this reads.
    let scoped_pdu = match (encrypted, data.tag) {
        (true, TAG_OCTET_STRING) => data.content.clone(),
        // The whole SEQUENCE, header included: a scoped PDU is parsed from its own tag.
        (false, TAG_SEQUENCE) => params.end..data.end,
        _ => {
            return Err("msgData does not match the privacy flag".to_string());
        }
    };

    Ok(DecodedMessage {
        datagram,
        message_id: i32::try_from(message_id).map_err(|_| "msgID out of range".to_string())?,
        flags,
        security_model,
        usm,
        authentication_range: auth_tlv.content,
        scoped_pdu,
        encrypted,
    })
}

/// Why an agent sent a Report instead of an answer (RFC 3414 §5, RFC 3412 §6).
///
/// Each is a distinct operational finding and none of them names a credential. Note what is
/// deliberately absent: a reason that claims to know which algorithms the agent supports.
/// USM does not negotiate, so a refusal says only that this user, at this level, with these
/// algorithms, was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportReason {
    /// The manager used an engine ID this agent is not authoritative for. Expected once, as
    /// the answer to discovery.
    UnknownEngineId,
    /// The agent does not know the user name.
    UnknownUserName,
    /// The user exists but not at the level asked for.
    UnsupportedSecurityLevel,
    /// The digest did not verify at the agent.
    WrongDigest,
    /// The message was outside the agent's time window. One resynchronisation is warranted.
    NotInTimeWindow,
    /// The agent could not decrypt the scoped PDU.
    DecryptionError,
    /// The agent does not implement the security model asked for.
    UnknownSecurityModel,
    /// The message was malformed as far as the agent was concerned.
    InvalidMessage,
    /// A Report carrying a counter this code does not classify.
    Other,
}

impl ReportReason {
    /// Classifies a Report by the OID of the counter it carries.
    ///
    /// Exact scalar instances only, each ending in `.0`. Matching on a prefix classified
    /// `...15.1.1.5.999` as a wrong-digest report, so an agent -- or anything able to send a
    /// datagram -- could dress an arbitrary object up as any USM failure it liked, and the
    /// run would act on it. An instance this code does not know is `Other`.
    pub fn from_oid(oid: &Oid) -> Self {
        match oid.0.as_slice() {
            [1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0] => ReportReason::UnsupportedSecurityLevel,
            [1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0] => ReportReason::NotInTimeWindow,
            [1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0] => ReportReason::UnknownUserName,
            [1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0] => ReportReason::UnknownEngineId,
            [1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0] => ReportReason::WrongDigest,
            [1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0] => ReportReason::DecryptionError,
            [1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0] => ReportReason::UnknownSecurityModel,
            [1, 3, 6, 1, 6, 3, 11, 2, 1, 2, 0] => ReportReason::InvalidMessage,
            _ => ReportReason::Other,
        }
    }

    /// What an operator is told. Never names a user, a passphrase or a key.
    pub fn describe(&self) -> &'static str {
        match self {
            ReportReason::UnknownEngineId => {
                "the agent is not authoritative for the engine ID used (expected during discovery)"
            }
            ReportReason::UnknownUserName => "the agent does not know the configured user",
            ReportReason::UnsupportedSecurityLevel => {
                "the agent does not accept that user at the requested security level"
            }
            ReportReason::WrongDigest => {
                "the agent rejected the message digest; the authentication key or protocol does \
                 not match what it holds"
            }
            ReportReason::NotInTimeWindow => {
                "the message fell outside the agent's time window; one resynchronisation follows"
            }
            ReportReason::DecryptionError => {
                "the agent could not decrypt the message; the privacy key or protocol does not \
                 match what it holds"
            }
            ReportReason::UnknownSecurityModel => {
                "the agent does not implement the User-based Security Model"
            }
            ReportReason::InvalidMessage => "the agent rejected the message as malformed",
            ReportReason::Other => "the agent reported a condition this client does not classify",
        }
    }
}

/// What an unauthenticated discovery exchange established.
///
/// Provisional by construction. Nothing here was authenticated -- it cannot be, since the
/// keys are localised to the identifier this exchange exists to learn -- so it is an input to
/// key derivation and timeliness and nothing else. It is not identity, it is not evidence,
/// and no topology may be derived from it. The type keeps that distinction visible at every
/// use site rather than relying on a comment at the call that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalEngine {
    pub engine_id: Vec<u8>,
    pub boots: u32,
    pub time: u32,
    /// The Report that carried it, where the agent sent one.
    pub reason: Option<ReportReason>,
}

impl ProvisionalEngine {
    /// Reads what a discovery answer establishes, and refuses what it does not.
    ///
    /// The engine identifier is the one thing this exchange exists to learn, and it is used
    /// to localise every key that follows -- so an empty or oversized one must fail here
    /// rather than produce keys derived from nothing. Nothing else in the message is
    /// believed: the counters are synchronisation inputs, and the fact that they arrived
    /// unauthenticated is why this type is named the way it is.
    pub fn from_message(
        message: &DecodedMessage<'_>,
        reason: Option<ReportReason>,
    ) -> Result<Self, String> {
        let engine_id = message.usm.engine_id.clone();
        if !(MIN_ENGINE_ID..=MAX_ENGINE_ID).contains(&engine_id.len()) {
            return Err(format!(
                "discovery returned a {}-octet engine ID; RFC 3411 defines \
                 {MIN_ENGINE_ID}..={MAX_ENGINE_ID}",
                engine_id.len()
            ));
        }
        Ok(Self {
            engine_id,
            boots: message.usm.engine_boots,
            time: message.usm.engine_time,
            reason,
        })
    }
}

/// Builds the discovery request: unauthenticated, reportable, empty engine ID.
///
/// RFC 3414 §4: a manager that does not know an agent's engine ID sends a request with an
/// empty one and a reportable flag; the agent answers with a Report naming itself. The
/// request asks for sysDescr rather than nothing, so an agent that answers discovery with a
/// response instead of a Report still produces a message this code can correlate.
pub fn discovery_request(message_id: i32, request_id: i32) -> Result<Encoded, String> {
    let scoped = encode_scoped_pdu(
        &[],
        &[],
        PDU_GET_REQUEST,
        request_id,
        &Oid::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]),
    );
    encode_message(
        message_id,
        Level::Discovery,
        true,
        &UsmParameters::default(),
        &scoped,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::usm::{PrivProtocol, SecurityLevel, derive_auth_key};

    fn key() -> SecretBytes {
        derive_auth_key(
            &SecretBytes::new(b"maplesyrup".to_vec()),
            b"\x80\x00\x1f\x88\x80\x01",
            AuthProtocol::HmacSha256,
        )
        .expect("derives")
    }

    fn parameters() -> UsmParameters {
        UsmParameters {
            engine_id: b"\x80\x00\x1f\x88\x80\x01".to_vec(),
            engine_boots: 7,
            engine_time: 1234,
            user_name: b"fixture-user".to_vec(),
            authentication: Vec::new(),
            privacy: Vec::new(),
        }
    }

    fn scoped() -> Vec<u8> {
        encode_scoped_pdu(
            b"\x80\x00\x1f\x88\x80\x01",
            b"",
            PDU_GET_REQUEST,
            42,
            &Oid::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]),
        )
    }

    /// Builds a message from parts, bypassing the encoder's checks -- which is the only way
    /// to produce the shapes an agent or an attacker can send and this code must refuse.
    fn handmade(
        message_id: i64,
        max_size: i64,
        flags: u8,
        security_model: i64,
        usm: &UsmParameters,
        data: Vec<u8>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&encode_octet_string(&usm.engine_id));
        body.extend_from_slice(&encode_integer(i64::from(usm.engine_boots)));
        body.extend_from_slice(&encode_integer(i64::from(usm.engine_time)));
        body.extend_from_slice(&encode_octet_string(&usm.user_name));
        body.extend_from_slice(&encode_octet_string(&usm.authentication));
        body.extend_from_slice(&encode_octet_string(&usm.privacy));
        let params = encode_octet_string(&encode_tlv(TAG_SEQUENCE, &body));

        let header = encode_tlv(
            TAG_SEQUENCE,
            &[
                encode_integer(message_id),
                encode_integer(max_size),
                encode_octet_string(&[flags]),
                encode_integer(security_model),
            ]
            .concat(),
        );
        encode_tlv(
            TAG_SEQUENCE,
            &[encode_integer(VERSION_3), header, params, data].concat(),
        )
    }

    fn authenticated_usm() -> UsmParameters {
        UsmParameters {
            authentication: vec![0u8; 24],
            ..parameters()
        }
    }

    #[test]
    fn the_header_must_describe_a_message_this_protocol_defines() {
        let usm = authenticated_usm();
        let auth = flags::AUTH | flags::REPORTABLE;

        for (message, expected, why) in [
            (
                handmade(-1, 8192, auth, 3, &usm, scoped()),
                "msgID",
                "a negative msgID cannot correlate anything",
            ),
            (
                handmade(1, 400, auth, 3, &usm, scoped()),
                "msgMaxSize",
                "below the 484 octets RFC 3412 requires an implementation to accept",
            ),
            (
                handmade(1, 1 << 32, auth, 3, &usm, scoped()),
                "msgMaxSize",
                "beyond 2^31 - 1",
            ),
            (
                handmade(1, 8192, flags::PRIV | flags::REPORTABLE, 3, &usm, scoped()),
                "privacy without authentication",
                "encryption with no way to tell who encrypted it",
            ),
            (
                handmade(1, 8192, auth, 2, &usm, scoped()),
                "User-based Security Model",
                "another security model's parameters are not USM's",
            ),
        ] {
            let Err(error) = decode_message(&message) else {
                panic!("{why}");
            };
            assert!(error.contains(expected), "{why}: {error}");
        }

        // Unknown flag bits are ignored, as RFC 3412 requires of a receiver. The message is
        // otherwise valid, so it must still decode.
        let tolerated = handmade(1, 8192, auth | 0x80 | 0x40, 3, &usm, scoped());
        let decoded = decode_message(&tolerated).expect("unknown bits are ignored, not refused");
        assert!(decoded.authenticated());
    }

    #[test]
    fn the_usm_fields_must_agree_with_the_flags_that_describe_them() {
        let auth = flags::AUTH | flags::REPORTABLE;

        for (usm, flags_byte, expected, why) in [
            (
                UsmParameters {
                    authentication: vec![0u8; 12],
                    ..parameters()
                },
                auth,
                "msgAuthenticationParameters",
                "a 12-octet digest is not what this protocol produces",
            ),
            (
                UsmParameters {
                    authentication: vec![0u8; 24],
                    ..parameters()
                },
                flags::REPORTABLE,
                "msgAuthenticationParameters",
                "a digest on an unauthenticated message is a field nothing checks",
            ),
            (
                UsmParameters {
                    authentication: vec![0u8; 24],
                    privacy: vec![0u8; 4],
                    ..parameters()
                },
                auth | flags::PRIV,
                "msgPrivacyParameters",
                "AES-128 salts are exactly eight octets",
            ),
            (
                UsmParameters {
                    authentication: vec![0u8; 24],
                    privacy: vec![0u8; 8],
                    ..parameters()
                },
                auth,
                "msgPrivacyParameters",
                "a salt on a message with no privacy",
            ),
            (
                UsmParameters {
                    authentication: vec![0u8; 24],
                    user_name: vec![b'u'; 33],
                    ..parameters()
                },
                auth,
                "msgUserName",
                "beyond the 32 octets USM defines",
            ),
            (
                UsmParameters {
                    authentication: vec![0u8; 24],
                    user_name: Vec::new(),
                    ..parameters()
                },
                auth,
                "names no user",
                "an authenticated message signed on behalf of nobody",
            ),
            (
                UsmParameters {
                    authentication: vec![0u8; 24],
                    engine_id: vec![1, 2, 3],
                    ..parameters()
                },
                auth,
                "engine ID",
                "shorter than RFC 3411 permits",
            ),
            (
                UsmParameters {
                    authentication: vec![0u8; 24],
                    engine_id: vec![1u8; 33],
                    ..parameters()
                },
                auth,
                "engine ID",
                "longer than RFC 3411 permits",
            ),
        ] {
            let data = if flags_byte & flags::PRIV != 0 {
                encode_octet_string(&[0xAB; 16])
            } else {
                scoped()
            };
            let message = handmade(1, 8192, flags_byte, 3, &usm, data);
            let Err(error) = decode_message(&message) else {
                panic!("{why}");
            };
            assert!(error.contains(expected), "{why}: {error}");
        }
    }

    #[test]
    fn the_encoder_refuses_what_its_own_decoder_would() {
        // The property that matters: anything this encoder emits, this decoder accepts. An
        // encoder able to build a message its own decoder rejects produces failures that
        // only ever appear at the far end.
        assert!(
            encode_message(
                -1,
                Level::Secured(SecurityLevel::AuthNoPriv),
                true,
                &parameters(),
                &scoped(),
            )
            .is_err(),
            "a negative msgID"
        );

        for usm in [
            UsmParameters {
                engine_boots: u32::MAX,
                ..parameters()
            },
            UsmParameters {
                engine_time: u32::MAX,
                ..parameters()
            },
            UsmParameters {
                user_name: vec![b'u'; 33],
                ..parameters()
            },
            UsmParameters {
                user_name: Vec::new(),
                ..parameters()
            },
            UsmParameters {
                engine_id: vec![1, 2],
                ..parameters()
            },
        ] {
            assert!(
                encode_message(
                    1,
                    Level::Secured(SecurityLevel::AuthNoPriv),
                    true,
                    &usm,
                    &scoped(),
                )
                .is_err(),
                "the encoder accepted a message its decoder refuses"
            );
        }

        // A digest supplied by the caller: it would be overwritten by `sign`, so accepting
        // one invites a caller to believe it was used.
        assert!(
            encode_message(
                1,
                Level::Secured(SecurityLevel::AuthNoPriv),
                true,
                &UsmParameters {
                    authentication: vec![0xAA; 24],
                    ..parameters()
                },
                &scoped(),
            )
            .is_err()
        );

        // And a message too large for the size this implementation declares. Matched
        // rather than unwrapped: `Encoded` holds a message that may carry a digest field,
        // and giving it a Debug impl to satisfy `expect_err` would put message bytes into
        // panic output.
        let Err(error) = encode_message(
            1,
            Level::Secured(SecurityLevel::AuthNoPriv),
            true,
            &parameters(),
            &vec![0x04; MAX_MESSAGE_BYTES],
        ) else {
            panic!("a message beyond the declared limit must not be encodable");
        };
        assert!(error.contains("beyond the"), "{error}");
    }

    #[test]
    fn verification_cannot_be_pointed_at_another_buffer() {
        // The panic this removes: ranges from one datagram applied to a shorter one. The
        // message now holds the bytes it was decoded from, so there is no second buffer to
        // pass and no length to get wrong.
        let signed = encode_message(
            5,
            Level::Secured(SecurityLevel::AuthNoPriv),
            true,
            &parameters(),
            &scoped(),
        )
        .expect("valid")
        .sign(&key(), AuthProtocol::HmacSha256)
        .expect("signs");

        let decoded = decode_message(&signed).expect("decodes");
        assert!(decoded.verify(&key(), AuthProtocol::HmacSha256));
        assert_eq!(decoded.datagram(), &signed[..]);
        assert_eq!(decoded.scoped_pdu(), &scoped()[..]);

        // A truncated copy is a different datagram: it either fails to decode or verifies
        // against its own bytes. Either way nothing indexes past an end.
        for cut in [1usize, 8, signed.len() / 2, signed.len() - 1] {
            if let Ok(other) = decode_message(&signed[..cut]) {
                let _ = other.verify(&key(), AuthProtocol::HmacSha256);
            }
        }
    }

    #[test]
    fn a_report_counter_is_matched_exactly_and_not_by_prefix() {
        // Prefix matching let any instance under a counter's subtree be presented as that
        // counter -- so anything able to send a datagram could dress an arbitrary object up
        // as "wrong digest" or "not in time window" and steer the run's behaviour.
        for suffix in [999u32, 1, 2] {
            let mut oid = vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 5];
            oid.push(suffix);
            let classified = ReportReason::from_oid(&Oid::new(oid.clone()));
            if suffix == 0 {
                assert_eq!(classified, ReportReason::WrongDigest);
            } else {
                assert_eq!(
                    classified,
                    ReportReason::Other,
                    "{oid:?} is not the wrong-digest counter"
                );
            }
        }

        // The column itself, without an instance, is not a counter either.
        assert_eq!(
            ReportReason::from_oid(&Oid::new(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 5])),
            ReportReason::Other
        );
        // Nor is a longer OID that merely begins with one.
        assert_eq!(
            ReportReason::from_oid(&Oid::new(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0, 1])),
            ReportReason::Other
        );
    }

    #[test]
    fn a_discovery_answer_must_name_an_engine() {
        // The identifier is what every following key is localised to, so an empty or
        // oversized one must fail here rather than produce keys derived from nothing.
        for engine_id in [Vec::new(), vec![1, 2, 3, 4], vec![1u8; 33]] {
            let usm = UsmParameters {
                engine_id,
                authentication: Vec::new(),
                privacy: Vec::new(),
                ..parameters()
            };
            let message = handmade(1, 8192, flags::REPORTABLE, 3, &usm, scoped());
            let decoded = match decode_message(&message) {
                Ok(decoded) => decoded,
                // An oversized engine ID on an unauthenticated message decodes; the
                // extraction below is what refuses it.
                Err(_) => continue,
            };
            assert!(
                ProvisionalEngine::from_message(&decoded, Some(ReportReason::UnknownEngineId))
                    .is_err(),
                "an engine ID of {} octet(s) must not become a key derivation input",
                decoded.usm.engine_id.len()
            );
        }

        // A conforming answer is accepted, and is provisional by type.
        let usm = UsmParameters {
            engine_id: b"\x80\x00\x1f\x88\x80\x01".to_vec(),
            engine_boots: 3,
            engine_time: 900,
            user_name: Vec::new(),
            authentication: Vec::new(),
            privacy: Vec::new(),
        };
        let message = handmade(1, 8192, flags::REPORTABLE, 3, &usm, scoped());
        let decoded = decode_message(&message).expect("decodes");
        let engine = ProvisionalEngine::from_message(&decoded, Some(ReportReason::UnknownEngineId))
            .expect("a conforming discovery answer");
        assert_eq!(engine.engine_id, usm.engine_id);
        assert_eq!((engine.boots, engine.time), (3, 900));
    }

    #[test]
    fn every_level_still_round_trips() {
        // The invariants must not have made a valid exchange unrepresentable.
        let discovery = discovery_request(1, 2).expect("encodes");
        assert!(decode_message(&discovery.bytes).is_ok());

        let auth_no_priv = encode_message(
            2,
            Level::Secured(SecurityLevel::AuthNoPriv),
            true,
            &parameters(),
            &scoped(),
        )
        .expect("encodes")
        .sign(&key(), AuthProtocol::HmacSha256)
        .expect("signs");
        assert!(
            decode_message(&auth_no_priv)
                .expect("decodes")
                .verify(&key(), AuthProtocol::HmacSha256)
        );

        let auth_priv = encode_message(
            3,
            Level::Secured(SecurityLevel::AuthPriv),
            true,
            &UsmParameters {
                privacy: vec![9u8; 8],
                ..parameters()
            },
            &[0xAB; 32],
        )
        .expect("encodes")
        .sign(&key(), AuthProtocol::HmacSha256)
        .expect("signs");
        let decoded = decode_message(&auth_priv).expect("decodes");
        assert!(decoded.verify(&key(), AuthProtocol::HmacSha256));
        assert!(decoded.encrypted);
    }

    #[test]
    fn formatting_a_message_reveals_no_message() {
        // A derived Debug printed the whole received datagram: every varbind of an
        // authNoPriv exchange in the clear, and the ciphertext of an authPriv one. Formatted
        // structures reach logs, panic output and bug reports, so what a message prints is
        // part of its interface.
        let signed = encode_message(
            77,
            Level::Secured(SecurityLevel::AuthNoPriv),
            true,
            &UsmParameters {
                user_name: b"an-operators-account".to_vec(),
                ..parameters()
            },
            &scoped(),
        )
        .expect("encodes")
        .sign(&key(), AuthProtocol::HmacSha256)
        .expect("signs");

        let decoded = decode_message(&signed).expect("decodes");
        let rendered = format!("{decoded:?}");

        assert!(rendered.contains("message_id: 77"), "{rendered}");
        assert!(rendered.contains("datagram_len"), "{rendered}");
        assert!(
            !rendered.contains("an-operators-account"),
            "the user name is half a credential: {rendered}"
        );
        // No run of message bytes, and no digest.
        let digest: String = decoded
            .usm
            .authentication
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(
            !rendered.contains(&digest),
            "the digest is printed: {rendered}"
        );
        for window in signed.windows(8) {
            let hex: String = window.iter().map(|byte| format!("{byte:02x}")).collect();
            assert!(
                !rendered.contains(&hex),
                "eight consecutive message bytes appear in the output: {rendered}"
            );
        }
        // The engine identifier is kept: it names a device, not an operator, and an engine
        // mismatch cannot be diagnosed without it.
        assert!(rendered.contains("8000"), "{rendered}");
    }

    #[test]
    fn the_encoder_and_the_decoder_agree_on_where_the_digest_lives() {
        // The property everything else rests on. If the two disagree by even one byte, the
        // digest is computed over one string and verified over another, and every exchange
        // fails in a way that looks like a wrong key.
        let encoded = encode_message(
            99,
            Level::Secured(SecurityLevel::AuthNoPriv),
            true,
            &parameters(),
            &scoped(),
        )
        .expect("the fixture is a valid message");
        let range = encoded.authentication_range.clone();
        assert_eq!(range.len(), 24, "the field is sized for the tag");
        assert!(
            encoded.bytes[range.clone()].iter().all(|byte| *byte == 0),
            "and holds zeroes until it is signed"
        );

        let signed = encoded
            .sign(&key(), AuthProtocol::HmacSha256)
            .expect("signs");
        let decoded = decode_message(&signed).expect("decodes");
        assert_eq!(
            decoded.authentication_range, range,
            "the decoder finds the field exactly where the encoder left it"
        );
        assert_eq!(decoded.usm.authentication, signed[range.clone()].to_vec());
        assert!(decoded.verify(&key(), AuthProtocol::HmacSha256));
    }

    #[test]
    fn the_digest_covers_every_byte_of_the_message() {
        // Not the scoped PDU, and not a re-encoding: the whole received string with the
        // field zeroed. Flipping any byte outside the field must break verification, and
        // flipping one inside it must too.
        let signed = encode_message(
            99,
            Level::Secured(SecurityLevel::AuthNoPriv),
            true,
            &parameters(),
            &scoped(),
        )
        .expect("the fixture is a valid message")
        .sign(&key(), AuthProtocol::HmacSha256)
        .expect("signs");
        let decoded = decode_message(&signed).expect("decodes");
        assert!(decoded.verify(&key(), AuthProtocol::HmacSha256));

        for at in [0usize, 5, 20, 40] {
            let mut tampered = signed.clone();
            if at >= tampered.len() || decoded.authentication_range.contains(&at) {
                continue;
            }
            tampered[at] ^= 0x01;
            // The tampered message may or may not still parse; either way it must not
            // verify. A parse failure is an equally good refusal.
            if let Ok(reparsed) = decode_message(&tampered) {
                assert!(
                    !reparsed.verify(&key(), AuthProtocol::HmacSha256),
                    "a message altered at byte {at} must not verify"
                );
            }
        }

        let mut forged = signed.clone();
        forged[decoded.authentication_range.start] ^= 0x01;
        let reparsed = decode_message(&forged).expect("still parses");
        assert!(!reparsed.verify(&key(), AuthProtocol::HmacSha256));

        // And a different key never verifies a message it did not sign.
        let other = derive_auth_key(
            &SecretBytes::new(b"different-passphrase".to_vec()),
            b"\x80\x00\x1f\x88\x80\x01",
            AuthProtocol::HmacSha256,
        )
        .expect("derives");
        assert!(!decoded.verify(&other, AuthProtocol::HmacSha256));
    }

    #[test]
    fn an_encrypted_message_carries_its_ciphertext_and_salt() {
        let mut usm = parameters();
        usm.privacy = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ciphertext = vec![0xAB; 40];

        let signed = encode_message(
            7,
            Level::Secured(SecurityLevel::AuthPriv),
            true,
            &usm,
            &ciphertext,
        )
        .expect("the fixture is a valid message")
        .sign(&key(), AuthProtocol::HmacSha256)
        .expect("signs");

        let decoded = decode_message(&signed).expect("decodes");
        assert!(decoded.encrypted, "the privacy flag is set");
        assert_eq!(
            decoded.usm.privacy, usm.privacy,
            "the salt travels in the clear"
        );
        assert_eq!(&signed[decoded.scoped_pdu.clone()], &ciphertext[..]);
        assert!(decoded.verify(&key(), AuthProtocol::HmacSha256));
        let _ = PrivProtocol::AesCfb128;
    }

    #[test]
    fn a_plaintext_scoped_pdu_is_returned_whole() {
        let signed = encode_message(
            7,
            Level::Secured(SecurityLevel::AuthNoPriv),
            true,
            &parameters(),
            &scoped(),
        )
        .expect("the fixture is a valid message")
        .sign(&key(), AuthProtocol::HmacSha256)
        .expect("signs");
        let decoded = decode_message(&signed).expect("decodes");
        assert!(!decoded.encrypted);
        assert_eq!(
            &signed[decoded.scoped_pdu.clone()],
            &scoped()[..],
            "the scoped PDU comes back with its own header, ready to parse"
        );
    }

    #[test]
    fn a_message_whose_shape_contradicts_its_flags_is_refused() {
        // An encrypted message must carry an OCTET STRING and a plaintext one a SEQUENCE.
        // Accepting either shape under either flag would let an attacker present ciphertext
        // as a plaintext PDU, or hand the decryptor a structure it never encrypted.
        // Built by hand: the encoder takes the shape from the level, so it cannot produce
        // this. Only an agent -- or an attacker -- can.
        let mut body = Vec::new();
        body.extend_from_slice(&encode_octet_string(b"\x80\x00\x1f\x88\x80\x01"));
        body.extend_from_slice(&encode_integer(1));
        body.extend_from_slice(&encode_integer(1));
        body.extend_from_slice(&encode_octet_string(b"user"));
        body.extend_from_slice(&encode_octet_string(&[0u8; 24]));
        body.extend_from_slice(&encode_octet_string(&[0u8; 8]));
        let params = encode_octet_string(&encode_tlv(TAG_SEQUENCE, &body));
        let header = encode_tlv(
            TAG_SEQUENCE,
            &[
                encode_integer(1),
                encode_integer(8192),
                // Claims privacy...
                encode_octet_string(&[flags::AUTH | flags::PRIV | flags::REPORTABLE]),
                encode_integer(SECURITY_MODEL_USM),
            ]
            .concat(),
        );
        let claims_privacy = encode_tlv(
            TAG_SEQUENCE,
            // ... and then carries a plaintext SEQUENCE.
            &[encode_integer(VERSION_3), header, params, scoped()].concat(),
        );

        let Err(error) = decode_message(&claims_privacy) else {
            panic!("a message whose shape contradicts its flags must be refused");
        };
        assert!(error.contains("privacy flag"), "{error}");
    }

    #[test]
    fn malformed_messages_are_refused_rather_than_partially_read() {
        let signed = encode_message(
            7,
            Level::Secured(SecurityLevel::AuthNoPriv),
            true,
            &parameters(),
            &scoped(),
        )
        .expect("the fixture is a valid message")
        .sign(&key(), AuthProtocol::HmacSha256)
        .expect("signs");

        // Every truncation, from nothing to one byte short.
        for cut in 0..signed.len() {
            assert!(
                decode_message(&signed[..cut]).is_err(),
                "a message cut at {cut} byte(s) must not decode"
            );
        }

        // Trailing bytes after a complete message: two messages in one datagram, or padding
        // an attacker controls.
        let mut extended = signed.clone();
        extended.push(0x00);
        assert!(decode_message(&extended).is_err());

        // A version this code does not speak.
        let mut v2c = signed.clone();
        let version_at = 2 + 2; // SEQUENCE header, then the INTEGER's header
        v2c[version_at] = 1;
        let Err(error) = decode_message(&v2c) else {
            panic!("a message declaring another version must be refused");
        };
        assert!(error.contains("version"), "{error}");

        // Beyond the bound this reads.
        assert!(decode_message(&vec![0x30; MAX_MESSAGE_BYTES + 1]).is_err());
    }

    #[test]
    fn engine_counters_outside_their_range_are_refused() {
        // RFC 3414 bounds boots and time at 2^31 - 1. A negative counter is not a counter,
        // and one beyond the bound cannot have come from a conforming agent -- both would
        // otherwise feed the timeliness window and the privacy IV.
        let mut body = Vec::new();
        body.extend_from_slice(&encode_octet_string(b"\x80\x00\x1f\x88\x80\x01"));
        body.extend_from_slice(&encode_integer(-1));
        body.extend_from_slice(&encode_integer(1));
        body.extend_from_slice(&encode_octet_string(b"user"));
        body.extend_from_slice(&encode_octet_string(&[0u8; 24]));
        body.extend_from_slice(&encode_octet_string(b""));
        let params = encode_octet_string(&encode_tlv(TAG_SEQUENCE, &body));

        let header = encode_tlv(
            TAG_SEQUENCE,
            &[
                encode_integer(1),
                encode_integer(8192),
                encode_octet_string(&[flags::AUTH | flags::REPORTABLE]),
                encode_integer(SECURITY_MODEL_USM),
            ]
            .concat(),
        );
        let message = encode_tlv(
            TAG_SEQUENCE,
            &[encode_integer(VERSION_3), header, params, scoped()].concat(),
        );

        let Err(error) = decode_message(&message) else {
            panic!("counters outside their range must be refused");
        };
        assert!(error.contains("RFC 3414"), "{error}");
    }

    #[test]
    fn a_discovery_request_is_unauthenticated_reportable_and_anonymous() {
        // RFC 3414 section 4: an empty engine ID, no user, no digest, reportable set. It
        // asks a question only so that a correlated answer exists.
        let request = discovery_request(11, 22).expect("discovery is always encodable");
        assert!(
            request.authentication_range.is_empty(),
            "there is no digest field to sign"
        );
        let decoded = decode_message(&request.bytes).expect("decodes");
        assert_eq!(decoded.message_id, 11);
        assert_eq!(decoded.security_model, SECURITY_MODEL_USM);
        assert!(decoded.reportable(), "the agent is asked to report");
        assert!(!decoded.authenticated(), "and nothing is claimed about it");
        assert!(decoded.usm.engine_id.is_empty(), "the engine is unknown");
        assert!(decoded.usm.user_name.is_empty(), "and no user is named");
        assert!(decoded.usm.authentication.is_empty());
        assert!(!decoded.encrypted);
    }

    #[test]
    fn report_counters_classify_to_their_own_findings() {
        use ReportReason::*;
        for (oid, expected) in [
            (
                vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0],
                UnsupportedSecurityLevel,
            ),
            (vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0], NotInTimeWindow),
            (vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0], UnknownUserName),
            (vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0], UnknownEngineId),
            (vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0], WrongDigest),
            (vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0], DecryptionError),
            (vec![1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0], UnknownSecurityModel),
            (vec![1, 3, 6, 1, 6, 3, 11, 2, 1, 2, 0], InvalidMessage),
            (vec![1, 3, 6, 1, 2, 1, 1, 1, 0], Other),
        ] {
            assert_eq!(
                ReportReason::from_oid(&Oid::new(oid.clone())),
                expected,
                "{oid:?}"
            );
        }

        // No description names a user, a passphrase or an algorithm the agent supports --
        // USM does not negotiate, so a refusal cannot say what would have worked.
        for reason in [
            UnsupportedSecurityLevel,
            NotInTimeWindow,
            UnknownUserName,
            UnknownEngineId,
            WrongDigest,
            DecryptionError,
            UnknownSecurityModel,
            InvalidMessage,
            Other,
        ] {
            let text = reason.describe();
            for forbidden in [
                "MD5",
                "DES",
                "SHA",
                "AES",
                "password",
                "passphrase",
                "key is",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{reason:?} says too much: {text}"
                );
            }
        }
    }
}
