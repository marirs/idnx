//! SNMPv3 User-based Security Model: keys, authentication and privacy (RFC 3414, 7860, 3826).
//!
//! This module holds the cryptography and nothing else -- no sockets, no message layout --
//! so each piece can be checked against a published vector rather than against the rest of
//! the implementation.
//!
//! Algorithm scope is deliberately narrow. HMAC-SHA-256-192 (RFC 7860) and AES-128-CFB
//! (RFC 3826) are implemented; MD5, DES and SHA-1 are not, and will not be added without
//! interoperability evidence that requires them. Shipping a broken primitive to widen
//! compatibility would make every result obtained through it worthless while looking exactly
//! like a result obtained safely.
//!
//! One correction that matters for how failures are reported: **USM does not negotiate
//! algorithms.** A manager states the user, the security level and the algorithms it will
//! use; the agent either recognises that user with those parameters or refuses. A refusal
//! therefore says nothing whatsoever about which other algorithms the agent supports, and no
//! diagnostic here may claim it does.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::secret::SecretBytes;

/// The authentication algorithms this implementation speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    /// `usmHMAC192SHA256AuthProtocol` (RFC 7860): HMAC-SHA-256 truncated to 192 bits.
    HmacSha256,
}

impl AuthProtocol {
    /// The length of the authentication parameters field, in octets.
    ///
    /// 24, not 32: RFC 7860 truncates the 256-bit HMAC output to 192 bits for transmission.
    /// A message carrying any other length is not one this protocol produced.
    pub const fn tag_len(&self) -> usize {
        match self {
            AuthProtocol::HmacSha256 => 24,
        }
    }

    pub const fn label(&self) -> &'static str {
        match self {
            AuthProtocol::HmacSha256 => "usmHMAC192SHA256AuthProtocol",
        }
    }
}

/// The privacy algorithms this implementation speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivProtocol {
    /// `usmAesCfb128PrivProtocol` (RFC 3826).
    AesCfb128,
}

impl PrivProtocol {
    pub const fn label(&self) -> &'static str {
        match self {
            PrivProtocol::AesCfb128 => "usmAesCfb128PrivProtocol",
        }
    }
}

/// What a user is permitted -- and required -- to do.
///
/// `noAuthNoPriv` is absent by design. An unauthenticated v3 exchange establishes nothing
/// about who answered, which is the entire reason for preferring v3 over v2c here; the only
/// unauthenticated exchange this implementation performs is the engine discovery required to
/// bootstrap USM, and that discovers an engine identifier rather than any topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Authenticated, not encrypted.
    AuthNoPriv,
    /// Authenticated and encrypted. RFC 3826 permits privacy only with authentication.
    AuthPriv,
}

impl SecurityLevel {
    /// The `msgFlags` bits for this level, without the reportable flag.
    pub const fn flags(&self) -> u8 {
        match self {
            SecurityLevel::AuthNoPriv => 0x01,
            SecurityLevel::AuthPriv => 0x03,
        }
    }

    pub const fn label(&self) -> &'static str {
        match self {
            SecurityLevel::AuthNoPriv => "authNoPriv",
            SecurityLevel::AuthPriv => "authPriv",
        }
    }
}

/// The shortest passphrase RFC 3414 permits an implementation to accept.
///
/// Section 11.2 requires at least eight characters. This is a floor, not a policy: the
/// profile loader applies the project's own, higher minimum, and RFC 3826 recommends twelve.
pub const MIN_PASSPHRASE_OCTETS: usize = 8;

/// Expands a passphrase into a master key, as RFC 3414 A.2 defines and RFC 7860 reuses with
/// SHA-2.
///
/// The passphrase is repeated to fill exactly 1,048,576 octets and that buffer is hashed. The
/// megabyte is not incidental: it is the work factor, and shortening it -- hashing the
/// passphrase once, or filling a smaller buffer -- produces a different key that no agent
/// will accept, while looking like a working implementation until the first real device
/// refuses.
///
/// Fails rather than deriving from a passphrase shorter than RFC 3414 permits. A four-octet
/// passphrase expands into a perfectly well-formed key, so accepting one produces a working
/// exchange protected by almost nothing -- the failure has to happen here, where the input is
/// still visible as a passphrase.
///
/// The error never contains the passphrase, its length, or anything derived from it beyond
/// the fact that it was too short.
pub fn password_to_key(
    passphrase: &SecretBytes,
    protocol: AuthProtocol,
) -> Result<SecretBytes, String> {
    const EXPANDED: usize = 1_048_576;
    let AuthProtocol::HmacSha256 = protocol;

    let password = passphrase.expose();
    if password.len() < MIN_PASSPHRASE_OCTETS {
        return Err(format!(
            "passphrase shorter than the {MIN_PASSPHRASE_OCTETS} octets RFC 3414 requires"
        ));
    }

    let mut hasher = Sha256::new();
    let mut written = 0usize;
    while written < EXPANDED {
        let take = (EXPANDED - written).min(password.len());
        hasher.update(&password[..take]);
        written += take;
    }
    Ok(SecretBytes::new(hasher.finalize().to_vec()))
}

/// Localises a key to one authoritative engine: `Kul = H(Ku || engineID || Ku)`.
///
/// Localisation is what stops a key learned from one agent being replayed at another: the
/// key actually used on the wire exists only in the context of one engine identifier. It is
/// also why the cache holding these is keyed by the complete engine ID, and why a changed
/// engine ID must invalidate it rather than reuse what was derived for the old one.
pub fn localize_key(master: &SecretBytes, engine_id: &[u8], protocol: AuthProtocol) -> SecretBytes {
    let AuthProtocol::HmacSha256 = protocol;
    let mut hasher = Sha256::new();
    hasher.update(master.expose());
    hasher.update(engine_id);
    hasher.update(master.expose());
    SecretBytes::new(hasher.finalize().to_vec())
}

/// The localised authentication key for one user at one engine.
///
/// `auth passphrase -> Ku_auth -> Kul_auth`. This key authenticates messages and is used for
/// nothing else.
pub fn derive_auth_key(
    auth_passphrase: &SecretBytes,
    engine_id: &[u8],
    protocol: AuthProtocol,
) -> Result<SecretBytes, String> {
    let master = password_to_key(auth_passphrase, protocol)?;
    Ok(localize_key(&master, engine_id, protocol))
}

/// The AES-128 key for one user at one engine, derived from the *privacy* passphrase.
///
/// `privacy passphrase -> Ku_priv -> Kul_priv -> first 16 octets`.
///
/// The privacy passphrase is a separate credential from the authentication passphrase, and
/// USM does not require them to be equal. Deriving the privacy key from the authentication
/// passphrase therefore produces a key the agent does not hold: every message decrypts to
/// noise on the far side while authenticating perfectly, which is a failure that looks like a
/// malformed device rather than like a wrong key. The two derivations are separate functions
/// so that a caller cannot pass one passphrase where the other belongs without writing it.
///
/// The hash is the authentication protocol's, as RFC 3826 §3.1.2.1 specifies; the localised
/// result is truncated to the 128 bits AES-128 takes, and the remainder is discarded rather
/// than folded in.
pub fn derive_privacy_key(
    privacy_passphrase: &SecretBytes,
    engine_id: &[u8],
    auth_protocol: AuthProtocol,
    privacy_protocol: PrivProtocol,
) -> Result<SecretBytes, String> {
    let PrivProtocol::AesCfb128 = privacy_protocol;
    let master = password_to_key(privacy_passphrase, auth_protocol)?;
    let localized = localize_key(&master, engine_id, auth_protocol);
    Ok(localized.prefix(16))
}

/// Computes the authentication tag over a complete message.
///
/// "Complete" is the part that is easy to get wrong and impossible to notice: the HMAC covers
/// the whole serialised message with the authentication parameters field present and set to
/// zeroes of the right length. Computing it over the scoped PDU alone, or over the message
/// with the field absent, produces a tag that verifies against itself and against nothing
/// any agent sends.
pub fn authenticate(key: &SecretBytes, message: &[u8], protocol: AuthProtocol) -> Vec<u8> {
    let AuthProtocol::HmacSha256 = protocol;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.expose()).expect("HMAC accepts a key of any length");
    mac.update(message);
    let full = mac.finalize().into_bytes();
    full[..protocol.tag_len()].to_vec()
}

/// Verifies a received tag against a message, in constant time.
pub fn verify(key: &SecretBytes, message: &[u8], claimed: &[u8], protocol: AuthProtocol) -> bool {
    if claimed.len() != protocol.tag_len() {
        return false;
    }
    let expected = authenticate(key, message, protocol);
    crate::secret::constant_time_eq(&expected, claimed)
}

/// The AES-128-CFB initialisation vector for one message (RFC 3826 §3.1.2.1).
///
/// Engine boots, engine time, then the eight-octet salt that travels in
/// `msgPrivacyParameters`. Boots and time are inside the IV, which is why a manager that
/// loses its per-engine boots/time state cannot simply invent one: the receiver derives the
/// same IV from the values in the message, and a mismatch decrypts to noise rather than
/// failing cleanly.
pub fn privacy_iv(engine_boots: u32, engine_time: u32, salt: &[u8; 8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
    iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
    iv[8..16].copy_from_slice(salt);
    iv
}

/// Encrypts a scoped PDU. Returns the ciphertext; the caller sends the salt alongside it.
pub fn encrypt(
    key: &SecretBytes,
    engine_boots: u32,
    engine_time: u32,
    salt: &[u8; 8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    use aes::cipher::{AsyncStreamCipher, KeyIvInit};

    let iv = privacy_iv(engine_boots, engine_time, salt);
    let cipher = cfb_mode::Encryptor::<aes::Aes128>::new_from_slices(key.expose(), &iv)
        .map_err(|_| "the privacy key is not 128 bits".to_string())?;
    let mut buffer = plaintext.to_vec();
    cipher.encrypt(&mut buffer);
    Ok(buffer)
}

/// Decrypts a scoped PDU into a secret buffer.
///
/// The plaintext is a secret until it has been parsed: it is the contents of an authenticated
/// exchange, and a decryption failure produces bytes that must not be logged while someone
/// works out why they did not parse.
pub fn decrypt(
    key: &SecretBytes,
    engine_boots: u32,
    engine_time: u32,
    salt: &[u8; 8],
    ciphertext: &[u8],
) -> Result<SecretBytes, String> {
    use aes::cipher::{AsyncStreamCipher, KeyIvInit};

    let iv = privacy_iv(engine_boots, engine_time, salt);
    let cipher = cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(key.expose(), &iv)
        .map_err(|_| "the privacy key is not 128 bits".to_string())?;
    let mut buffer = ciphertext.to_vec();
    cipher.decrypt(&mut buffer);
    Ok(SecretBytes::new(buffer))
}

/// A source of privacy salts.
///
/// RFC 3826 requires each message under one key to use a different salt, because CFB with a
/// repeated IV leaks the relationship between two plaintexts. The guarantee here is exact:
/// one source issues up to `2^64 - 1` distinct salts, and refuses to issue beyond that
/// rather than wrapping back onto values it has already given out. "Never repeats" would
/// have been a claim about arithmetic that `wrapping_add` does not make.
///
/// Across runs the seed is random, so two runs against one agent are unlikely to walk the
/// same sequence -- a probabilistic argument rather than a guarantee, and one reason the salt
/// is only half of the IV: engine boots and engine time carry the rest.
pub struct SaltSource {
    counter: u64,
    issued: u64,
}

impl SaltSource {
    /// Seeds from the operating system, and fails if that is unavailable.
    ///
    /// There is deliberately no fallback. Seeding a privacy salt from the clock, a process
    /// id or a constant would produce a source that looks identical to this one and repeats
    /// predictably, so a caller that cannot get randomness must be told rather than quietly
    /// given something weaker.
    pub fn new() -> Result<Self, String> {
        let mut seed = [0u8; 8];
        getrandom::getrandom(&mut seed)
            .map_err(|error| format!("no randomness available for privacy salts: {error}"))?;
        Ok(Self {
            counter: u64::from_be_bytes(seed),
            issued: 0,
        })
    }

    /// The next salt, distinct from every salt this source has already issued.
    ///
    /// Fails once the sequence is exhausted instead of wrapping onto a value already used.
    /// That point is unreachable in any real run -- it is `2^64 - 1` messages to one engine --
    /// and
    /// the refusal exists so the guarantee above is a fact about the code rather than an
    /// estimate about how long a run lasts.
    ///
    /// Not named `next`: this is not an iterator, and a salt source that could be consumed by
    /// iterator combinators is one that could silently produce salts nobody sends.
    pub fn take_salt(&mut self) -> Result<[u8; 8], String> {
        if self.issued == u64::MAX {
            return Err("the privacy salt sequence for this engine is exhausted".to_string());
        }
        self.issued += 1;
        self.counter = self.counter.wrapping_add(1);
        Ok(self.counter.to_be_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn hmac_matches_an_independent_vector() {
        // RFC 4231 test case 1, truncated to the 192 bits RFC 7860 transmits. Until this
        // existed, the authentication tests verified the implementation against itself: a
        // wrong HMAC agrees with its own verifier perfectly and with no agent at all.
        let key = SecretBytes::new(vec![0x0b; 20]);
        let tag = authenticate(&key, b"Hi There", AuthProtocol::HmacSha256);
        assert_eq!(
            hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da7"
        );

        // Test case 2, with a key shorter than the block size.
        let key = SecretBytes::new(b"Jefe".to_vec());
        let tag = authenticate(
            &key,
            b"what do ya want for nothing?",
            AuthProtocol::HmacSha256,
        );
        assert_eq!(
            hex(&tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d273983"
        );
    }

    #[test]
    fn aes_cfb_matches_an_independent_vector() {
        // NIST SP 800-38A F.3.13, CFB128-AES128 encryption. A symmetric implementation can
        // round-trip against itself while being incompatible with every agent on the
        // network -- a wrong segment size, or feedback taken from the plaintext instead of
        // the ciphertext, decrypts its own output and nobody else's.
        let key = SecretBytes::new(
            (0..16)
                .map(|i| {
                    u8::from_str_radix(&"2b7e151628aed2a6abf7158809cf4f3c"[i * 2..i * 2 + 2], 16)
                        .unwrap()
                })
                .collect(),
        );
        let iv: Vec<u8> = (0u8..16).collect();
        let plaintext: Vec<u8> = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                        [i * 2..i * 2 + 2],
                    16,
                )
                .unwrap()
            })
            .collect();

        // The vector's IV is 000102..0f, which is what boots, time and salt produce here.
        let boots = u32::from_be_bytes([iv[0], iv[1], iv[2], iv[3]]);
        let time = u32::from_be_bytes([iv[4], iv[5], iv[6], iv[7]]);
        let mut salt = [0u8; 8];
        salt.copy_from_slice(&iv[8..16]);

        let ciphertext = encrypt(&key, boots, time, &salt, &plaintext).expect("encrypts");
        assert_eq!(
            hex(&ciphertext),
            "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
        );
        let recovered = decrypt(&key, boots, time, &salt, &ciphertext).expect("decrypts");
        assert_eq!(recovered.expose(), &plaintext[..]);
    }

    #[test]
    fn authentication_and_privacy_keys_come_from_their_own_passphrases() {
        // USM does not require the two credentials to be equal, and deriving the privacy key
        // from the authentication passphrase produces a key the agent does not hold: every
        // message authenticates perfectly and decrypts to noise on the far side, which looks
        // like a malformed device rather than a wrong key.
        let engine = [0x80u8, 0x00, 0x1f, 0x88, 0x80, 0x01];
        let auth = SecretBytes::new(b"maplesyrup".to_vec());
        let privacy = SecretBytes::new(b"different-privacy-secret".to_vec());

        let auth_key = derive_auth_key(&auth, &engine, AuthProtocol::HmacSha256).expect("derives");
        let priv_key = derive_privacy_key(
            &privacy,
            &engine,
            AuthProtocol::HmacSha256,
            PrivProtocol::AesCfb128,
        )
        .expect("derives");

        assert_eq!(priv_key.len(), 16, "AES-128 takes 128 bits");
        assert_ne!(
            hex(priv_key.expose()),
            hex(&auth_key.expose()[..16]),
            "the privacy key is not the front of the authentication key"
        );

        // Deriving privacy from the authentication passphrase gives a different key again,
        // which is the mistake this API separation exists to make unwritable.
        let wrong = derive_privacy_key(
            &auth,
            &engine,
            AuthProtocol::HmacSha256,
            PrivProtocol::AesCfb128,
        )
        .expect("derives");
        assert_ne!(hex(wrong.expose()), hex(priv_key.expose()));
    }

    #[test]
    fn a_passphrase_below_the_rfc_minimum_derives_nothing() {
        // A four-octet passphrase expands into a perfectly well-formed key, so accepting one
        // yields a working exchange protected by almost nothing. RFC 3414 §11.2 requires at
        // least eight; the profile loader applies the project's higher minimum on top.
        for short in ["", "a", "1234567"] {
            // Matched rather than unwrapped: `expect_err` would require the success type to
            // be printable, and a key that can be printed is the hazard this whole module
            // exists to remove. The type refusing that is the guarantee working.
            let Err(error) = password_to_key(
                &SecretBytes::new(short.as_bytes().to_vec()),
                AuthProtocol::HmacSha256,
            ) else {
                panic!(
                    "a passphrase of {} octet(s) must not derive a key",
                    short.len()
                );
            };
            assert!(error.contains("RFC 3414"), "{error}");
        }
        assert!(
            password_to_key(
                &SecretBytes::new(b"12345678".to_vec()),
                AuthProtocol::HmacSha256
            )
            .is_ok(),
            "eight octets is the floor, not one above it"
        );

        // And the refusal quotes nothing of what was rejected. Checked with a passphrase
        // distinctive enough for the test to mean something: a one-character passphrase
        // appears in almost any English sentence, so asserting its absence proves nothing.
        let Err(error) = password_to_key(
            &SecretBytes::new(b"Xq7Vz".to_vec()),
            AuthProtocol::HmacSha256,
        ) else {
            panic!("five octets must not derive a key");
        };
        assert!(
            !error.contains("Xq7Vz"),
            "the diagnostic quoted the passphrase: {error}"
        );
        assert!(!error.contains('5'), "nor its length: {error}");
    }

    #[test]
    fn password_expansion_matches_the_published_vector() {
        // Reference values computed independently from the normative procedure -- RFC 3414
        // Appendix A.2 expansion, RFC 7860 section 9.3 for SHA-256 -- with a separate
        // SHA-256 implementation, for the conventional inputs: passphrase "maplesyrup" and
        // engine ID 00 00 00 00 00 00 00 00 00 00 00 02.
        //
        // Not transcribed from an RFC appendix: RFC 7860 publishes no such vector. What this
        // checks is that the expansion here agrees with an implementation that shares no
        // code with it, which is the property that matters and is weaker than a normative
        // vector would be. The HMAC and AES tests below use genuinely published vectors.
        let passphrase = SecretBytes::new(b"maplesyrup".to_vec());
        let master = password_to_key(&passphrase, AuthProtocol::HmacSha256).expect("derives");
        assert_eq!(
            hex(master.expose()),
            "ab51014d1e077f6017df2b12bee5f5aa72993177e9bb569c4dff5a4ca0b4afac"
        );

        let engine_id = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let localized = localize_key(&master, &engine_id, AuthProtocol::HmacSha256);
        assert_eq!(
            hex(localized.expose()),
            "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"
        );

        // And the whole sequence through the public derivation, which is what callers use.
        assert_eq!(
            hex(
                derive_auth_key(&passphrase, &engine_id, AuthProtocol::HmacSha256)
                    .expect("derives")
                    .expose()
            ),
            "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"
        );
        // AES-128 takes the first half of the localised key and no more.
        assert_eq!(
            hex(derive_privacy_key(
                &passphrase,
                &engine_id,
                AuthProtocol::HmacSha256,
                PrivProtocol::AesCfb128
            )
            .expect("derives")
            .expose()),
            "8982e0e549e866db361a6b625d84cccc"
        );
    }

    #[test]
    fn localisation_binds_a_key_to_one_engine() {
        // The property that makes localisation worth doing: a key learned from one agent is
        // useless at another, so a compromised device does not yield a credential for the
        // rest of the estate.
        let master = password_to_key(
            &SecretBytes::new(b"maplesyrup".to_vec()),
            AuthProtocol::HmacSha256,
        )
        .expect("derives");
        let first = localize_key(
            &master,
            b"\x80\x00\x1f\x88\x80\x01",
            AuthProtocol::HmacSha256,
        );
        let second = localize_key(
            &master,
            b"\x80\x00\x1f\x88\x80\x02",
            AuthProtocol::HmacSha256,
        );
        assert_ne!(hex(first.expose()), hex(second.expose()));
    }

    #[test]
    fn the_tag_is_truncated_to_192_bits_and_verified_in_full() {
        let key = SecretBytes::new(vec![0x42; 32]);
        let message = b"the complete serialised message, tag field zeroed";
        let tag = authenticate(&key, message, AuthProtocol::HmacSha256);

        assert_eq!(tag.len(), 24, "RFC 7860 transmits 192 of the 256 bits");
        assert!(verify(&key, message, &tag, AuthProtocol::HmacSha256));

        // A tag of the wrong length is refused before anything is computed: an agent that
        // sends 12 or 32 octets is not speaking this protocol.
        assert!(!verify(&key, message, &tag[..12], AuthProtocol::HmacSha256));
        assert!(!verify(
            &key,
            message,
            &[tag.clone(), vec![0; 8]].concat(),
            AuthProtocol::HmacSha256
        ));

        // A different message, and a different key, both fail.
        assert!(!verify(
            &key,
            b"another message",
            &tag,
            AuthProtocol::HmacSha256
        ));
        let other = SecretBytes::new(vec![0x43; 32]);
        assert!(!verify(&other, message, &tag, AuthProtocol::HmacSha256));
    }

    #[test]
    fn privacy_round_trips_and_the_iv_carries_boots_and_time() {
        let key = SecretBytes::new(vec![0x11; 16]);
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let plaintext = b"a scoped PDU, encrypted under AES-128-CFB";

        let ciphertext = encrypt(&key, 7, 1234, &salt, plaintext).expect("encrypts");
        assert_ne!(&ciphertext[..], &plaintext[..]);
        // CFB is a stream mode: the ciphertext is exactly as long as the plaintext, with no
        // padding to strip and none to get wrong.
        assert_eq!(ciphertext.len(), plaintext.len());

        let recovered = decrypt(&key, 7, 1234, &salt, &ciphertext).expect("decrypts");
        assert_eq!(recovered.expose(), plaintext);

        // Boots and time are inside the IV, so a receiver whose counters disagree recovers
        // noise rather than a message that merely fails a later check.
        let wrong = decrypt(&key, 8, 1234, &salt, &ciphertext).expect("decrypts");
        assert_ne!(wrong.expose(), plaintext);
        let wrong = decrypt(&key, 7, 1235, &salt, &ciphertext).expect("decrypts");
        assert_ne!(wrong.expose(), plaintext);

        let iv = privacy_iv(0x01020304, 0x05060708, &salt);
        assert_eq!(&iv[0..4], &[1, 2, 3, 4]);
        assert_eq!(&iv[4..8], &[5, 6, 7, 8]);
        assert_eq!(&iv[8..16], &salt);
    }

    #[test]
    fn salts_do_not_repeat() {
        let mut source = SaltSource::new().expect("the OS has randomness");
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..1000 {
            assert!(
                seen.insert(source.take_salt().expect("the sequence is not exhausted")),
                "a salt was reused"
            );
        }
        // And two sources do not start from the same place, so two runs against one agent
        // do not walk the same sequence.
        let mut other = SaltSource::new().expect("the OS has randomness");
        assert_ne!(
            source.take_salt().expect("available"),
            other.take_salt().expect("available")
        );
    }
}
