//! Hard limits on anything arriving from a peer.
//!
//! Every bound here is checked *before* the bytes are parsed or the memory is reserved. A
//! limit applied after deserialization is not a limit: by then the allocation has already
//! happened, and a peer that can make the receiver allocate can stop it running. The frame
//! length is read first and refused on its own, so an absurd claim costs one comparison.
//!
//! Also the point where remote text stops being arbitrary bytes. A peer controls the
//! contents of hostnames, descriptions and service banners, and those are printed to a
//! terminal: escape sequences in them can rewrite the display, hide lines, or forge output
//! that appears to come from the tool itself.

/// Largest encrypted envelope accepted, before decryption.
///
/// Generous for a real bundle and far below anything that threatens the receiver. Chosen so
/// that a subnet's worth of evidence fits comfortably while a single frame can never exceed
/// a megabyte of buffer.
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

/// Largest decrypted bundle accepted, before deserialization.
pub const MAX_BUNDLE_BYTES: usize = MAX_ENVELOPE_BYTES;

/// Most evidence records one bundle may carry.
pub const MAX_RECORDS: usize = 20_000;

/// Longest single text field accepted from a peer.
pub use crate::text::MAX_TEXT_BYTES;

/// Longest peer-supplied vantage name.
pub const MAX_VANTAGE_BYTES: usize = 64;

/// What a limit check refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitError {
    /// The frame declared more bytes than are ever accepted.
    TooLarge { limit: usize, claimed: usize },
    /// More records than are ever accepted.
    TooManyRecords { limit: usize, claimed: usize },
    /// A text field exceeded its bound.
    TextTooLong {
        field: &'static str,
        limit: usize,
        length: usize,
    },
}

impl std::fmt::Display for LimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitError::TooLarge { limit, claimed } => {
                write!(f, "frame claims {claimed} bytes, limit is {limit}")
            }
            LimitError::TooManyRecords { limit, claimed } => {
                write!(f, "bundle claims {claimed} records, limit is {limit}")
            }
            LimitError::TextTooLong {
                field,
                limit,
                length,
            } => write!(f, "{field} is {length} bytes, limit is {limit}"),
        }
    }
}

impl std::error::Error for LimitError {}

/// Checks a declared frame length before any buffer is reserved for it.
pub fn check_frame_length(claimed: usize, limit: usize) -> Result<(), LimitError> {
    if claimed > limit {
        return Err(LimitError::TooLarge { limit, claimed });
    }
    Ok(())
}

/// Checks a text field arriving from a peer.
pub fn check_text(field: &'static str, text: &str, limit: usize) -> Result<(), LimitError> {
    if text.len() > limit {
        return Err(LimitError::TextTooLong {
            field,
            limit,
            length: text.len(),
        });
    }
    Ok(())
}

pub fn check_record_count(claimed: usize) -> Result<(), LimitError> {
    if claimed > MAX_RECORDS {
        return Err(LimitError::TooManyRecords {
            limit: MAX_RECORDS,
            claimed,
        });
    }
    Ok(())
}

pub use crate::text::sanitize;

pub use crate::text::clip;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absurd_frame_length_is_refused_before_anything_is_allocated() {
        // The whole point: this is a comparison against a number read off the wire, not a
        // check on a buffer that has already been filled.
        assert_eq!(
            check_frame_length(usize::MAX, MAX_ENVELOPE_BYTES),
            Err(LimitError::TooLarge {
                limit: MAX_ENVELOPE_BYTES,
                claimed: usize::MAX
            })
        );
        assert!(check_frame_length(MAX_ENVELOPE_BYTES, MAX_ENVELOPE_BYTES).is_ok());
        assert!(check_frame_length(MAX_ENVELOPE_BYTES + 1, MAX_ENVELOPE_BYTES).is_err());
    }

    #[test]
    fn record_counts_and_text_lengths_are_bounded() {
        assert!(check_record_count(MAX_RECORDS).is_ok());
        assert!(check_record_count(MAX_RECORDS + 1).is_err());

        assert!(check_text("hostname", &"a".repeat(MAX_TEXT_BYTES), MAX_TEXT_BYTES).is_ok());
        assert_eq!(
            check_text("hostname", &"a".repeat(MAX_TEXT_BYTES + 1), MAX_TEXT_BYTES),
            Err(LimitError::TextTooLong {
                field: "hostname",
                limit: MAX_TEXT_BYTES,
                length: MAX_TEXT_BYTES + 1
            })
        );
    }

    #[test]
    fn terminal_escape_sequences_cannot_survive_into_output() {
        // A peer that can emit ESC can move the cursor, clear the screen, or print text
        // that appears to come from idnx itself.
        let hostile = "\u{1b}[2J\u{1b}[1;31mrouter\u{7}\r\nfake line";
        let safe = sanitize(hostile);
        assert!(!safe.contains('\u{1b}'));
        assert!(!safe.contains('\r'));
        assert!(!safe.contains('\n'));
        assert!(!safe.contains('\u{7}'));
        assert!(safe.contains("router"));
    }

    #[test]
    fn sanitizing_marks_rather_than_hides() {
        // Stripping would let "ro\u{1b}uter" print as "router", indistinguishable from a
        // device that really is called that.
        assert_ne!(sanitize("ro\u{1b}uter"), "router");
        assert_eq!(sanitize("router"), "router");
        // Ordinary text, including non-ASCII, is untouched.
        assert_eq!(sanitize("café-räuter-日本"), "café-räuter-日本");
    }

    #[test]
    fn clipping_counts_characters_not_bytes() {
        // Byte truncation would split a multi-byte character and panic.
        let text = "🔑".repeat(10);
        let clipped = clip(&text, 4);
        assert_eq!(clipped.chars().count(), 4);
        assert!(clipped.ends_with('…'));
        assert_eq!(clip("short", 40), "short");
    }
}
