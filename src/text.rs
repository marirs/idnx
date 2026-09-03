//! Making device-supplied text safe to handle.
//!
//! Hostnames, vendor strings, descriptions and service banners are chosen by the devices
//! they describe. None of it is trustworthy, all of it is printed, and a device that can
//! emit an escape sequence can move a terminal's cursor, clear lines, or print text that
//! appears to come from this tool.
//!
//! Neutral ground on purpose: both rendering and any protocol that carries remote text need
//! these, and neither should have to depend on the other to get them.

/// Longest single text field accepted from a device.
///
/// Comfortably above anything legitimate: a DNS name is bounded at 253, and a certificate
/// subject rarely exceeds a few hundred characters.
pub const MAX_TEXT_BYTES: usize = 1024;

/// Replaces control characters, leaving the text visibly changed.
///
/// Replaced rather than stripped, so text that contained them stays distinguishable from
/// text that did not -- a device must not be able to make its name render identically to
/// another's. Tab is the one control character kept, because it cannot reposition output.
pub fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\t' => ' ',
            c if c.is_control() => '\u{fffd}',
            c => c,
        })
        .collect()
}

/// Truncates to a character count, marking that it happened.
///
/// By characters, not bytes: splitting a multi-byte character would panic. Marked so a
/// shortened value is not mistaken for the whole one.
pub fn clip(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let kept: String = text.chars().take(limit.saturating_sub(1)).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_neutralised() {
        let hostile = "\u{1b}[2Krouter\r\nVantage: forged";
        let safe = sanitize(hostile);
        assert!(!safe.contains('\u{1b}'));
        assert!(!safe.contains('\n'));
        assert!(!safe.contains('\r'));
        assert!(safe.contains("router"));
    }

    #[test]
    fn sanitizing_marks_rather_than_hides() {
        // Stripping would let "ro\u{1b}uter" print as "router", indistinguishable from a
        // device that really is called that.
        assert_ne!(sanitize("ro\u{1b}uter"), "router");
        assert_eq!(sanitize("router"), "router");
        assert_eq!(sanitize("café-räuter-日本"), "café-räuter-日本");
    }

    #[test]
    fn clipping_counts_characters_not_bytes() {
        let text = "🔑".repeat(10);
        let clipped = clip(&text, 4);
        assert_eq!(clipped.chars().count(), 4);
        assert!(clipped.ends_with('…'));
        assert_eq!(clip("short", 40), "short");
    }
}
