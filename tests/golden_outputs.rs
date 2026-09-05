//! Byte-for-byte snapshots of every output format, from the acceptance run.
//!
//! The formats are the product. A change in how a network's reachability is stated, or in
//! whether a VLAN carries a prefix, or in which section a silent forwarding interface is
//! listed under, is a change to what an operator and every downstream consumer are told --
//! and none of it is covered by asserting on the graph, which is where every other test
//! stops. These files are that coverage: a diff here means the output changed, and the
//! reviewer decides whether it should have.
//!
//! They snapshot the same scripted run the acceptance reasons about, so the two cannot
//! drift apart into two different topologies.
//!
//! Regenerate deliberately, never reflexively:
//!
//! ```text
//! UPDATE_GOLDENS=1 cargo test --test golden_outputs
//! ```
//!
//! Determinism is arranged, not hoped for: colour is disabled, and the fields that cannot
//! be stable -- the generation timestamp and measured durations -- are replaced with fixed
//! placeholders rather than left to vary. Anything else that differs between two runs is a
//! real nondeterminism in the output and should fail here.

mod common;

use common::run_scripted;

use idnx::net::vantage::StartingScope;
use idnx::output::export::{OutputFormat, build_export, render};

use std::path::PathBuf;

/// Replaces the values that legitimately differ between two identical runs.
///
/// Only these. A placeholder for anything else would hide the very drift this file exists
/// to catch, so the list is deliberately short: the generation timestamp, and measured
/// durations. Everything else that differs between two runs is a real nondeterminism.
fn normalise(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        out.push_str(&replace_durations(&mask_timestamps(line)));
        out.push('\n');
    }
    out
}

/// Masks anything shaped like an RFC 3339 timestamp, in whatever field a format spells it.
fn mask_timestamps(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    while at < chars.len() {
        // YYYY-MM-DDT... is the only shape any of these formats emits.
        let looks_like_date = at + 10 < chars.len()
            && chars[at..at + 4].iter().all(|c| c.is_ascii_digit())
            && chars[at + 4] == '-'
            && chars[at + 5..at + 7].iter().all(|c| c.is_ascii_digit())
            && chars[at + 7] == '-'
            && chars[at + 8..at + 10].iter().all(|c| c.is_ascii_digit());
        if looks_like_date {
            out.push_str("GENERATED-AT");
            while at < chars.len()
                && (chars[at].is_ascii_digit()
                    || matches!(chars[at], '-' | ':' | '.' | '+' | 'T' | 'Z'))
            {
                at += 1;
            }
            continue;
        }
        out.push(chars[at]);
        at += 1;
    }
    out
}

/// Measured times, wherever they appear.
fn replace_durations(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    while at < chars.len() {
        if chars[at].is_ascii_digit() {
            let start = at;
            while at < chars.len() && (chars[at].is_ascii_digit() || chars[at] == '.') {
                at += 1;
            }
            let number: String = chars[start..at].iter().collect();
            let suffix: String = chars[at..].iter().take(4).collect();
            let elapsed_field = line.contains("elapsed") || line.contains("Elapsed");
            if suffix.starts_with("ms") || elapsed_field {
                out.push_str("DURATION");
            } else {
                out.push_str(&number);
            }
            continue;
        }
        out.push(chars[at]);
        at += 1;
    }
    out
}

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/goldens")
}

/// Compares one rendered output against its golden, or writes it when asked to.
fn assert_golden(name: &str, rendered: &str) {
    let path = goldens_dir().join(name);
    let normalised = normalise(rendered);

    if std::env::var("UPDATE_GOLDENS").is_ok() {
        std::fs::write(&path, &normalised).expect("the golden is writable");
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{}: {error}. Run UPDATE_GOLDENS=1 cargo test --test golden_outputs to create it.",
            path.display()
        )
    });

    if expected != normalised {
        // The first differing line, which is what a reviewer needs to see first.
        let mismatch = expected
            .lines()
            .zip(normalised.lines())
            .enumerate()
            .find(|(_, (want, got))| want != got)
            .map(|(at, (want, got))| format!("line {}:\n  golden: {want}\n  now:    {got}", at + 1))
            .unwrap_or_else(|| {
                format!(
                    "length differs: golden has {} line(s), this run produced {}",
                    expected.lines().count(),
                    normalised.lines().count()
                )
            });
        panic!(
            "{} changed.\n{mismatch}\n\nIf the change is intended, regenerate with \
             UPDATE_GOLDENS=1 cargo test --test golden_outputs",
            path.display()
        );
    }
}

/// The starting scope the terminal view is rendered against.
fn starting_scope() -> StartingScope {
    StartingScope {
        vantage: idnx::providers::Vantage {
            interface: common::VANTAGE.to_string(),
            kind: idnx::providers::VantageKind::Wired,
            index: 0,
            capture_available: false,
        },
        network: Some(common::net("192.0.2.0/24")),
        reason: "scripted fixture".to_string(),
    }
}

#[test]
fn every_output_format_matches_its_golden() {
    // Colour is a terminal decision, not part of the content, and escape codes would make
    // the goldens unreadable and machine-dependent besides.
    colored::control::set_override(false);

    let (report, _) = run_scripted();
    let data = build_export(&report);

    for (format, name) in [
        (OutputFormat::Json, "acceptance.json"),
        (OutputFormat::Yaml, "acceptance.yaml"),
        (OutputFormat::Xml, "acceptance.xml"),
        (OutputFormat::Csv, "acceptance.csv"),
        (OutputFormat::Text, "acceptance.txt"),
    ] {
        let rendered = render(&data, format).expect("the format renders");
        assert_golden(name, &rendered);
    }

    // The terminal view: the output an operator actually reads.
    let mut terminal = String::new();
    idnx::output::topology_view::render_to(&mut terminal, &report, &starting_scope());
    assert_golden("acceptance.terminal.txt", &terminal);

    // And the interactive graph, which carries the same topology as a page.
    let html = idnx::output::graph::topology_html(&report).expect("the graph renders");
    assert_golden("acceptance.html", &html);
}

#[test]
fn the_run_renders_identically_twice() {
    // A golden that only matches its own generation proves nothing. Two runs of the same
    // fixture must produce the same bytes, or the goldens are recording one arbitrary
    // ordering out of many.
    colored::control::set_override(false);

    let first = build_export(&run_scripted().0);
    let second = build_export(&run_scripted().0);

    for format in [
        OutputFormat::Json,
        OutputFormat::Yaml,
        OutputFormat::Xml,
        OutputFormat::Csv,
        OutputFormat::Text,
    ] {
        assert_eq!(
            normalise(&render(&first, format).expect("renders")),
            normalise(&render(&second, format).expect("renders")),
            "{format:?} is not deterministic"
        );
    }
}
