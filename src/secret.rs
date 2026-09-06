//! Key material that cannot be printed, serialised, or left in freed memory.
//!
//! Every other value in this crate is written to be *shown*: evidence carries its
//! provenance, providers explain what they attempted, and exports reproduce all of it. Key
//! material is the one category where that instinct is a defect. A passphrase, a derived
//! key or a decrypted buffer must never reach a note, an export, a golden file or a panic
//! message, and the reliable way to guarantee that is to make it impossible rather than to
//! remember it at every call site.
//!
//! So [`SecretBytes`] implements neither `Debug` nor `Display` nor `Serialize`, and it does
//! not implement `Clone`: a copy of a secret is a second place it has to be erased from, so
//! copies are made deliberately through [`SecretBytes::duplicate`] where the caller has a
//! reason. Contents are zeroised when the value is dropped.
//!
//! What this does not claim: memory that has already been copied elsewhere by the allocator,
//! swapped to disk, or captured in a core dump is beyond a type's reach. This removes the
//! ordinary ways a secret escapes -- formatting, serialising, logging and reuse after free --
//! not every conceivable one.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Bytes that are secret: a passphrase, a derived key, or a decrypted payload.
///
/// The type cannot be formatted, and that is enforced rather than documented:
///
/// ```compile_fail
/// let secret = idnx::secret::SecretBytes::new(vec![1, 2, 3]);
/// println!("{secret:?}");
/// ```
///
/// ```compile_fail
/// let secret = idnx::secret::SecretBytes::new(vec![1, 2, 3]);
/// println!("{secret}");
/// ```
///
/// Nor serialised, which is how a secret reaches an export, a report or a cache file:
///
/// ```compile_fail
/// let secret = idnx::secret::SecretBytes::new(vec![1, 2, 3]);
/// let leaked = serde_json::to_string(&secret).unwrap();
/// ```
///
/// Nor cloned implicitly, so a copy is always a decision:
///
/// ```compile_fail
/// let secret = idnx::secret::SecretBytes::new(vec![1, 2, 3]);
/// let copy = secret.clone();
/// ```
///
/// What it does allow is use:
///
/// ```
/// let secret = idnx::secret::SecretBytes::new(b"key material".to_vec());
/// assert!(secret.constant_time_eq(b"key material"));
/// assert_eq!(secret.duplicate().len(), secret.len());
///
/// // The control for the serialisation example above: serde_json is in scope here, so
/// // that example fails to compile because the type has no Serialize impl, and not
/// // because the crate could not be found.
/// assert_eq!(serde_json::to_string(&vec![1, 2, 3]).unwrap(), "[1,2,3]");
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes, for a caller that is about to use them in a cryptographic operation.
    ///
    /// Deliberately named: `expose` reads wrong in a formatting argument or a log line, which
    /// is exactly where a borrowed slice should never appear.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A second copy, where one is genuinely needed.
    ///
    /// Not `Clone`, so a copy cannot happen by accident in a closure capture or a struct
    /// update: each copy is another place the material has to be erased from.
    pub fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }

    /// The first `n` bytes, as a secret of their own.
    ///
    /// AES-128 takes the first sixteen octets of a localised key, and that truncation must
    /// not be done by exposing the whole key to a slice expression in the caller.
    pub fn prefix(&self, n: usize) -> Self {
        Self(self.0[..n.min(self.0.len())].to_vec())
    }

    /// Whether two secrets are equal, in time independent of where they differ.
    ///
    /// Authentication tags are compared with this. A byte-by-byte comparison that returns
    /// early tells an attacker how much of a forged tag was right, which is enough to build
    /// the rest one byte at a time.
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        if self.0.len() != other.len() {
            return false;
        }
        self.0.ct_eq(other).into()
    }
}

/// Whether two byte strings are equal, in constant time.
///
/// For tags that are not held in a `SecretBytes` -- the one arriving in a message, for
/// instance, which is public until it is checked against a computed one.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.ct_eq(right).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_compares_in_constant_time_and_by_length_first() {
        let secret = SecretBytes::new(b"0123456789abcdef".to_vec());
        assert!(secret.constant_time_eq(b"0123456789abcdef"));
        assert!(!secret.constant_time_eq(b"0123456789abcdee"));
        assert!(!secret.constant_time_eq(b"short"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    #[test]
    fn a_prefix_is_a_secret_of_its_own() {
        let key = SecretBytes::new((0u8..32).collect());
        let privacy = key.prefix(16);
        assert_eq!(privacy.len(), 16);
        assert_eq!(privacy.expose(), &(0u8..16).collect::<Vec<u8>>()[..]);
        // Asking for more than there is yields what there is, rather than panicking in the
        // middle of a key schedule.
        assert_eq!(key.prefix(64).len(), 32);
    }

    /// The non-printability guarantee is enforced by the `compile_fail` examples on
    /// `SecretBytes` itself, which is where rustdoc will actually compile them: examples
    /// written inside a `#[cfg(test)]` module are never collected, so one placed here would
    /// have asserted nothing at all.
    #[test]
    fn a_secret_still_reports_its_length_without_exposing_it() {
        let secret = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(secret.len(), 3);
        assert!(!secret.is_empty());
    }
}
