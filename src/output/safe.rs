//! Making untrusted text safe to render.
//!
//! Hostnames, vendor strings, descriptions and service banners are chosen by the devices
//! they describe, and now also by federated peers. None of it is trustworthy, and all of it
//! is printed, serialised and embedded in a web page.
//!
//! Three different destinations need three different treatments, and using the wrong one is
//! how a device name ends up executing as script. A terminal needs control characters
//! neutralised; a `<script>` block needs the sequences that can close it neutralised; the
//! structured exports need only the first, because their own encoders handle quoting.

use crate::federation::limits::{MAX_TEXT_BYTES, clip, sanitize};

/// Text safe to print to a terminal or write into a structured export.
///
/// Control characters are replaced rather than removed, so text that contained them stays
/// visibly different from text that did not -- a device must not be able to make its name
/// render identically to another's. Also bounded, because a locally observed name has never
/// been through the federation limits.
pub fn text(value: &str) -> String {
    clip(&sanitize(value), MAX_TEXT_BYTES)
}

/// Applies [`text`] to a whole collection.
pub fn all<'a, I: IntoIterator<Item = &'a String>>(values: I) -> Vec<String> {
    values.into_iter().map(|v| text(v)).collect()
}

/// Makes serialised JSON safe to embed inside an HTML `<script>` block.
///
/// JSON encoders escape quotes and backslashes, which is enough for JSON and not enough
/// for HTML: a hostname containing `</script>` closes the block and everything after it is
/// parsed as markup. Escaping the three characters that can start such a sequence keeps the
/// value byte-identical to a JSON parser while making it inert to an HTML one.
///
/// U+2028 and U+2029 are included because JavaScript treats them as line terminators, so
/// an unescaped one inside a string literal is a syntax error that breaks the page.
pub fn embeddable_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_never_reach_a_terminal() {
        let hostile = "\u{1b}[2Krouter\r\nVantage: forged";
        let safe = text(hostile);
        assert!(!safe.contains('\u{1b}'));
        assert!(!safe.contains('\n'));
        assert!(!safe.contains('\r'));
        assert!(safe.contains("router"));
    }

    #[test]
    fn ordinary_names_are_untouched() {
        for name in [
            "router",
            "SG-Air",
            "dmaker-fan-p30",
            "café.local",
            "日本-nas",
        ] {
            assert_eq!(text(name), name);
        }
    }

    #[test]
    fn overlong_text_is_clipped_rather_than_printed_whole() {
        let long = "a".repeat(MAX_TEXT_BYTES * 2);
        let safe = text(&long);
        assert!(safe.chars().count() <= MAX_TEXT_BYTES);
        assert!(safe.ends_with('…'), "truncation is marked");
    }

    #[test]
    fn a_hostname_cannot_close_the_script_block_it_is_embedded_in() {
        // The failure this prevents: a device named "</script><img onerror=...>" turning a
        // topology export into an executable page.
        let json = r#"{"name":"</script><img src=x onerror=alert(1)>"}"#;
        let embedded = embeddable_json(json);

        assert!(!embedded.contains("</script"));
        assert!(!embedded.contains('<'));
        assert!(!embedded.contains('>'));
        // Still the same value to a JSON parser.
        let parsed: serde_json::Value = serde_json::from_str(&embedded).expect("still valid JSON");
        assert_eq!(
            parsed["name"],
            serde_json::Value::String("</script><img src=x onerror=alert(1)>".to_string())
        );
    }

    #[test]
    fn javascript_line_terminators_are_escaped() {
        // Unescaped, these are a syntax error inside a JavaScript string literal and break
        // the whole page.
        let json = "{\"name\":\"a\u{2028}b\u{2029}c\"}";
        let embedded = embeddable_json(json);
        assert!(!embedded.contains('\u{2028}'));
        assert!(!embedded.contains('\u{2029}'));
        assert!(serde_json::from_str::<serde_json::Value>(&embedded).is_ok());
    }

    #[test]
    fn embedding_does_not_alter_ordinary_json() {
        let json = r#"{"prefix":"192.168.51.0/24","name":"café"}"#;
        assert_eq!(embeddable_json(json), json);
    }
}
