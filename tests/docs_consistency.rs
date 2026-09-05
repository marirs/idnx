//! The documentation, checked against the code it describes.
//!
//! Prose drifts silently. Six rounds of behaviour changes left the docs claiming a `--subnets`
//! flag that never existed on this CLI, an SNMP client speaking v1, a manufacturer string
//! creating a router boundary, and PCAP fixtures listed as planned while sitting in the
//! repository. None of that is catchable by review alone once the documents are long enough,
//! so the mechanically checkable parts are checked here.
//!
//! What this can prove is deliberately narrow: that every option the docs name exists, that
//! options which were removed are only ever mentioned as removed, that specific retracted
//! claims have not come back, and that nothing implemented is still listed as planned. It
//! cannot prove a document is *right*; it can stop it from contradicting the binary.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The marker that takes a document out of scope.
///
/// A design record from before the code existed cannot be held to the code's behaviour, and
/// rewriting one to match would destroy the reason it is kept. It is excluded by saying so
/// in the document, in a form both a reader and this test can see -- never by a path
/// exclusion in the test, which the document's author would never know about.
const SUPERSEDED: &str = "Status: Superseded";

/// Whether a document declares itself superseded.
///
/// A whole line in the header, not the phrase anywhere in the body: this document's own
/// banner explains the marker in prose, and a substring match let that explanation count as
/// the marker itself -- which would have excluded the file even after someone deliberately
/// changed its status back.
fn is_superseded(text: &str) -> bool {
    text.lines().take(30).any(|line| line.trim() == SUPERSEDED)
}

/// Every Markdown file in the repository's documentation, at any depth.
///
/// Recursive, because it was not: the design specification two directories down still
/// required an `OpaqueBoundary` node the default build deliberately does not emit, and
/// nothing noticed.
fn markdown_files() -> Vec<(String, String)> {
    fn walk(dir: &Path, into: &mut Vec<PathBuf>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("{} is readable: {error}", dir.display()))
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, into);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                into.push(path);
            }
        }
    }

    let root = repo();
    let mut files = vec![root.join("README.md")];
    walk(&root.join("docs"), &mut files);

    files
        .into_iter()
        .map(|path| {
            let name = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let text = std::fs::read_to_string(&path).expect("readable");
            (name, text)
        })
        .collect()
}

/// The documents that describe current behaviour, which is what the checks below apply to.
fn docs() -> Vec<(String, String)> {
    markdown_files()
        .into_iter()
        .filter(|(_, text)| !is_superseded(text))
        .collect()
}

/// Every long option the CLI actually defines, read from its definition rather than from a
/// list kept in this test -- a list here would drift exactly like the prose does.
fn defined_options() -> Vec<String> {
    let source = std::fs::read_to_string(repo().join("src/main.rs")).expect("main.rs is readable");
    let mut options = vec!["--help".to_string(), "--version".to_string()];

    let mut pending_long_from_field = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(at) = trimmed.find("long = \"") {
            let rest = &trimmed[at + "long = \"".len()..];
            if let Some(end) = rest.find('"') {
                options.push(format!("--{}", &rest[..end]));
            }
            continue;
        }
        // `#[arg(short, long)]` and `#[arg(short, long, default_value_t = ...)]` take the
        // option name from the field below them.
        if trimmed.starts_with("#[arg(")
            && (trimmed.contains("long)")
                || trimmed.contains("long,")
                || trimmed.contains("long ="))
        {
            pending_long_from_field = true;
            continue;
        }
        if pending_long_from_field {
            if let Some(field) = trimmed.split(':').next() {
                let field = field.trim_start_matches("pub ").trim();
                if !field.is_empty() {
                    options.push(format!("--{}", field.replace('_', "-")));
                }
            }
            pending_long_from_field = false;
        }
    }
    options.sort();
    options.dedup();
    options
}

/// Options belonging to other tools, which the docs legitimately mention.
const FOREIGN_OPTIONS: &[&str] = &["--release", "--features"];

/// Options this CLI once had. They may appear only in a sentence saying they are gone.
const REMOVED_OPTIONS: &[&str] = &[
    "--recursive",
    "--max-depth",
    "--threads",
    "--listen-seconds",
    "--heuristic-sweep",
    "--no-deep",
    "--max-sweep-hosts",
    "--subnets",
    "--ports",
];

fn mentioned_options(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let bytes: Vec<char> = line.chars().collect();
        let mut at = 0;
        while at + 2 < bytes.len() {
            if bytes[at] == '-' && bytes[at + 1] == '-' && bytes[at + 2].is_ascii_lowercase() {
                let start = at;
                at += 2;
                while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == '-') {
                    at += 1;
                }
                found.push((number + 1, bytes[start..at].iter().collect()));
                continue;
            }
            at += 1;
        }
    }
    found
}

#[test]
fn every_option_the_docs_name_exists() {
    let defined = defined_options();
    assert!(
        defined.contains(&"--snmp-community".to_string()),
        "the option list was parsed from main.rs, so it must find the known options: {defined:?}"
    );

    for (file, text) in docs() {
        for (line, option) in mentioned_options(&text) {
            if FOREIGN_OPTIONS.contains(&option.as_str())
                || REMOVED_OPTIONS.contains(&option.as_str())
            {
                continue;
            }
            assert!(
                defined.contains(&option),
                "{file}:{line} documents {option}, which the CLI does not define. \
                 Defined: {defined:?}"
            );
        }
    }
}

#[test]
fn a_removed_option_is_only_ever_mentioned_as_removed() {
    // The docs may say "there is no --recursive"; they may not tell anyone to use one.
    let denials = [
        "no ", "not ", "removed", "retired", "never", "gone", "have no", "has no",
    ];

    for (file, text) in docs() {
        let lines: Vec<&str> = text.lines().collect();
        for (number, line) in lines.iter().enumerate() {
            for removed in REMOVED_OPTIONS {
                if !line.contains(removed) {
                    continue;
                }
                // The sentence, not the line: a denial routinely wraps across a line break,
                // and prose that has to avoid wrapping is prose nobody will maintain.
                let context = lines[number.saturating_sub(1)..(number + 2).min(lines.len())]
                    .join(" ")
                    .to_ascii_lowercase();
                assert!(
                    denials.iter().any(|denial| context.contains(denial)),
                    "{file}:{} mentions {removed} as though it existed: {line}",
                    number + 1
                );
            }
        }
    }
}

#[test]
fn retracted_claims_do_not_come_back() {
    // Each of these was in the documentation and contradicted the code. They are listed by
    // the phrase that carried the claim, with what the code actually does.
    let retracted: &[(&str, &str)] = &[
        (
            "v1/v2c",
            "the SNMP client speaks v2c only and refuses a v1 response",
        ),
        (
            "evidence: hardware vendor",
            "manufacturer is never evidence of a role or a boundary",
        ),
        (
            "mechanism that makes cascading real",
            "several credential-free sources disclose networks beyond the link; SNMP is one",
        ),
        (
            "unexplored boundary",
            "the default build reports unresolved forwarding interfaces, not boundaries",
        ),
        (
            "reports an opaque boundary",
            "nothing in the default build asserts an opaque boundary",
        ),
        (
            "`opaqueboundary` node is created",
            "no provider creates one; a forwarding interface with unresolved downstream \
             prefixes is what the evidence supports",
        ),
        (
            "appears as an opaque boundary",
            "a NAT relationship is a claim about what is behind a device, which a single \
             endpoint cannot establish",
        ),
        (
            "ICMP echo sweeps with dynamic timeout",
            "the ICMP path is interface-bound, correlated, and reports what it sent",
        ),
        (
            "ergonomic `scannerbuilder` api",
            "there is no ScannerBuilder; embedding goes through DiscoveryEngine",
        ),
        (
            "stealth icmp echo sweep fallback",
            "the ICMP fallback is the correlated, interface-bound echo path",
        ),
    ];

    for (file, text) in docs() {
        let lowered = text.to_ascii_lowercase();
        for (phrase, why) in retracted {
            assert!(
                !lowered.contains(&phrase.to_ascii_lowercase()),
                "{file} still claims {phrase:?}, but {why}"
            );
        }
    }
}

#[test]
fn nothing_implemented_is_still_listed_as_planned() {
    // A planned-work list that includes finished work is worse than no list: it tells a
    // reader the tool cannot do something it does.
    let implemented: &[(&str, &str, &str)] = &[
        (
            "tests/fixtures/pcap/lldp_neighbor.pcap",
            "PCAP fixtures for LLDP",
            "an LLDP fixture is in the repository",
        ),
        (
            "tests/fixtures/pcap/cdp_neighbor.pcap",
            "PCAP fixtures for CDP",
            "a CDP fixture is in the repository",
        ),
        (
            "src/probes/ra.rs",
            "IPv6 neighbour discovery and router advertisements as topology evidence",
            "router advertisements are decoded and produce evidence",
        ),
        (
            "src/probes/ndp.rs",
            "- [ ] Cross-platform NDP",
            "neighbour discovery is implemented",
        ),
    ];

    let roadmap = std::fs::read_to_string(repo().join("docs/roadmap.md")).expect("readable");
    for (artefact, planned_line, why) in implemented {
        if !Path::new(&repo().join(artefact)).exists() {
            continue;
        }
        assert!(
            !roadmap.contains(planned_line),
            "the roadmap lists {planned_line:?} as planned, but {why} ({artefact})"
        );
    }
}

#[test]
fn the_recursive_walk_reaches_nested_documents() {
    // The check that this test is looking where it claims to. Scanning only the top level of
    // docs/ is how a design specification two directories down went on requiring behaviour
    // the code deliberately does not have.
    let all = markdown_files();
    assert!(
        all.iter().any(|(name, _)| name.contains("superpowers")),
        "nested documents are walked: {:?}",
        all.iter().map(|(name, _)| name).collect::<Vec<_>>()
    );
    assert!(
        all.len() > docs().len(),
        "and something is excluded by marker"
    );
}

#[test]
fn a_superseded_document_says_so_and_says_what_replaced_it() {
    // Exclusion is a claim about a document, so the document has to carry it -- and carry
    // enough for a reader who lands there first to know where current behaviour is written
    // down. A file that merely disagrees with the code is not superseded; it is wrong.
    for (name, text) in markdown_files() {
        if !is_superseded(&text) {
            continue;
        }
        let head: String = text.lines().take(30).collect::<Vec<_>>().join(" ");
        assert!(
            head.contains("README.md") || head.contains("docs/architecture.md"),
            "{name} is superseded but does not say what to read instead"
        );
        assert!(
            text.contains("Addendum") || text.contains("addendum"),
            "{name} is superseded but does not record where the implementation departed \
             from it, which is the only reason to keep it"
        );
    }
}

#[test]
fn the_default_build_has_no_opaque_boundary_emitter() {
    // The claim the docs are now forbidden from making is checked against the code, so the
    // two cannot drift apart in the other direction either: if a provider starts emitting
    // one, this fails and the documentation gets revisited.
    let providers = repo().join("src/providers");
    let mut emitters = Vec::new();
    for entry in std::fs::read_dir(&providers).expect("providers/ is readable") {
        let path = entry.expect("readable").path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("readable");
        for (number, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            // A construction, not a match arm: `Fact::OpaqueBoundary { device, why }` builds
            // one; `| Fact::OpaqueBoundary { .. }` matches one.
            if trimmed.contains("Fact::OpaqueBoundary {")
                && !trimmed.contains("{ .. }")
                && !trimmed.starts_with('|')
            {
                emitters.push(format!("{}:{}", path.display(), number + 1));
            }
        }
    }
    assert!(
        emitters.is_empty(),
        "a provider now emits an opaque boundary; the documentation says none does: {emitters:?}"
    );
}
