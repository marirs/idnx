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
use idnx::output::export::{OutputFormat, TopologyExport, build_export, render};

use std::path::PathBuf;

/// Makes the run's own nondeterminism go away structurally, before anything is rendered.
///
/// Not by masking text. The previous approach scanned rendered output for numbers near the
/// word "elapsed" and replaced them -- and XML is a single line, so every address, prefix,
/// VLAN id, count and version number on it matched and was replaced: 1,415 substitutions,
/// leaving a golden that proved almost nothing. The fixture is fixed at the source instead,
/// so the rendered bytes are compared exactly as they are produced.
fn make_deterministic(report: &mut idnx::engine::orchestrator::DiscoveryReport) {
    report.enrichment_elapsed = std::time::Duration::ZERO;
    report.enrichment_sequential_equivalent = std::time::Duration::ZERO;
    for record in &mut report.coverage {
        record.elapsed = std::time::Duration::ZERO;
    }
    // A pivot's note is a summary rendered during the run, so it carries the measured time
    // as text and zeroing the field it came from is too late. The duration is trimmed from
    // that one field rather than scanned for across rendered output -- which is the mistake
    // the previous harness made.
    for pivot in &mut report.pivot_runs {
        for run in &mut pivot.runs {
            if let Some(note) = run.note.take() {
                run.note = Some(zero_trailing_duration(&note));
            }
        }
    }
}

/// Rewrites a trailing `, 12ms` to `, 0ms`, leaving everything else alone.
fn zero_trailing_duration(note: &str) -> String {
    let Some(stripped) = note.strip_suffix("ms") else {
        return note.to_string();
    };
    let digits: String = stripped
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return note.to_string();
    }
    format!("{}0ms", &stripped[..stripped.len() - digits.len()])
}

/// The one value that cannot be fixed in the report, because the exporter stamps it.
const FIXED_GENERATED_AT: &str = "2020-01-01T00:00:00+00:00";

fn fixed_export(report: &idnx::engine::orchestrator::DiscoveryReport) -> TopologyExport {
    let mut data = build_export(report);
    data.generated_at = FIXED_GENERATED_AT.to_string();
    data
}

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/goldens")
}

/// Compares one rendered output against its golden, or writes it when asked to.
fn assert_golden(name: &str, rendered: &str) {
    let path = goldens_dir().join(name);
    let normalised = rendered.to_string();

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

    let (mut report, _) = run_scripted();
    make_deterministic(&mut report);
    let data = fixed_export(&report);

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
fn every_format_renders_identically_twice() {
    // A golden that only matches its own generation proves nothing. Two runs of the same
    // fixture must produce the same bytes, or the goldens are recording one arbitrary
    // ordering out of many -- and that includes the terminal view and the HTML page, which
    // are built from different traversals than the serialised formats.
    colored::control::set_override(false);

    let (mut first_report, _) = run_scripted();
    let (mut second_report, _) = run_scripted();
    make_deterministic(&mut first_report);
    make_deterministic(&mut second_report);
    let first = fixed_export(&first_report);
    let second = fixed_export(&second_report);

    for format in [
        OutputFormat::Json,
        OutputFormat::Yaml,
        OutputFormat::Xml,
        OutputFormat::Csv,
        OutputFormat::Text,
    ] {
        assert_eq!(
            render(&first, format).expect("renders"),
            render(&second, format).expect("renders"),
            "{format:?} is not deterministic"
        );
    }

    let mut first_terminal = String::new();
    let mut second_terminal = String::new();
    idnx::output::topology_view::render_to(&mut first_terminal, &first_report, &starting_scope());
    idnx::output::topology_view::render_to(&mut second_terminal, &second_report, &starting_scope());
    assert_eq!(
        first_terminal, second_terminal,
        "the terminal view is not deterministic"
    );

    assert_eq!(
        idnx::output::graph::topology_html(&first_report).expect("renders"),
        idnx::output::graph::topology_html(&second_report).expect("renders"),
        "the HTML page is not deterministic"
    );
}

#[test]
fn the_xml_golden_retains_the_literal_topology() {
    // The previous harness scanned rendered text for numbers near the word "elapsed" and
    // replaced them. XML is one line, so every address, prefix, VLAN id and count on it
    // matched: 1,415 substitutions, and a golden that proved almost nothing. Nothing is
    // masked now, and this states what the file has to contain.
    colored::control::set_override(false);

    let (mut report, _) = run_scripted();
    make_deterministic(&mut report);
    let xml = render(&fixed_export(&report), OutputFormat::Xml).expect("renders");

    for literal in [
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "198.18.0.0/24",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.254",
        "<id>42</id>",
        "<id>77</id>",
        "probed_unreachable",
        "reachable",
    ] {
        assert!(
            xml.contains(literal),
            "the XML must carry {literal} literally, not a placeholder"
        );
    }
    assert!(
        !xml.contains("DURATION"),
        "nothing in the topology is masked any more"
    );
}

#[test]
fn the_html_page_carries_each_network_s_reachability() {
    // The page's network nodes had empty detail arrays: an operator opening the map could
    // not tell a network that answered from one that was never probed.
    colored::control::set_override(false);

    let (mut report, _) = run_scripted();
    make_deterministic(&mut report);
    let html = idnx::output::graph::topology_html(&report).expect("renders");

    for fragment in [
        "reachability: reachable",
        "reachability: probed_unreachable",
        "answered: 203.0.113.9",
        "address(es) probed",
        "discovered: advertised by 198.51.100.1",
    ] {
        assert!(
            html.contains(fragment),
            "the page must state {fragment:?} on its network nodes"
        );
    }
}

#[test]
fn the_csv_carries_every_record_type_and_not_only_devices() {
    // CSV was a device inventory while every other format carried the topology, which
    // contradicted the contract that an export preserves what was discovered.
    colored::control::set_override(false);

    let (mut report, _) = run_scripted();
    make_deterministic(&mut report);
    let csv = render(&fixed_export(&report), OutputFormat::Csv).expect("renders");

    let mut kinds: Vec<&str> = csv
        .lines()
        .skip(1)
        .filter_map(|line| line.split(',').next())
        .collect();
    kinds.sort();
    kinds.dedup();
    for expected in [
        "network",
        "vlan",
        "device",
        "relationship",
        "coverage",
        "device_coverage",
    ] {
        assert!(
            kinds.contains(&expected),
            "the CSV must carry {expected} records: {kinds:?}"
        );
    }

    // And the rows carry their own content, not just their type.
    assert!(csv.contains("198.18.0.0/24"), "networks appear as rows");
    assert!(
        csv.contains("reachability=probed_unreachable"),
        "with their reachability state"
    );
    assert!(csv.contains("VLAN 77"), "VLANs appear as rows");
    assert!(csv.contains("carries"), "relationships appear as rows");
}

#[test]
fn a_layer_three_switch_is_presented_as_one() {
    // It carried spanning-tree and forwarding evidence and was rendered under "Routers &
    // gateways", with no switch section anywhere: the switching evidence reached the graph
    // and then vanished from every output.
    colored::control::set_override(false);

    let (mut report, _) = run_scripted();
    make_deterministic(&mut report);

    let mut terminal = String::new();
    idnx::output::topology_view::render_to(&mut terminal, &report, &starting_scope());

    assert!(
        terminal.contains("Layer-3 switches (bridging and routing)"),
        "it gets its own section:\n{terminal}"
    );

    // Under that section, and not under routers.
    let section = terminal
        .split("Layer-3 switches")
        .nth(1)
        .expect("the section exists");
    assert!(
        section.contains("198.51.100.1"),
        "the device is listed there"
    );
    let routers = terminal
        .split("Routers & gateways")
        .nth(1)
        .and_then(|rest| rest.split("Layer-3 switches").next())
        .unwrap_or_default();
    assert!(
        !routers.contains("198.51.100.1"),
        "and not also among the routers"
    );

    // One node, both signals, both routed edges.
    let holders: Vec<_> = report
        .graph
        .nodes()
        .filter(|node| {
            node.addresses
                .contains(&"198.51.100.1".parse().expect("a literal address"))
        })
        .collect();
    assert_eq!(holders.len(), 1, "still one device");
    let signals: Vec<&String> = holders[0].role_signals.iter().collect();
    assert!(signals.iter().any(|s| s.contains("spanning-tree")));
    assert!(signals.iter().any(|s| s.contains("forward")));

    let data = fixed_export(&report);
    assert_eq!(
        data.summary.layer3_switches, 1,
        "counted in its own category"
    );
    assert!(
        data.devices
            .iter()
            .any(|device| device.category.contains("layer-3 switch")),
        "and exported as one"
    );
}
