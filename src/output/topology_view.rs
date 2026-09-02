//! Renders the topology graph.
//!
//! The renderer's job is to be honest about grades. Observed topology, advertised
//! topology, inferred facts, opaque boundaries and the limits of this vantage are all
//! shown distinctly, so a partial map is never presented as a complete one.

use colored::*;
use comfy_table::{Cell, Color as TableColor, ContentArrangement, Table, presets::UTF8_FULL};
use ipnet::IpNet;

use crate::engine::orchestrator::{DiscoveryReport, is_virtual_network};
use crate::net::vantage::StartingScope;
use crate::topology::evidence::DeviceKey;
use crate::topology::graph::DeviceCategory;
use crate::topology::graph::{NodeKind, Relationship};
use crate::topology::{NodeId, TopologyGraph};

/// Prints the complete topology view.
pub fn render(report: &DiscoveryReport, start: &StartingScope) {
    render_vantage(report, start);
    render_networks(report);
    let vantage = report.visibility.vantage.interface.as_str();
    render_infrastructure(&report.graph, vantage);
    render_hosts(&report.graph, vantage);
    render_boundaries(&report.graph, vantage);
    render_device_table(&report.graph, vantage);
    render_coverage(report);
}

fn render_vantage(report: &DiscoveryReport, start: &StartingScope) {
    let v = &report.visibility.vantage;
    println!(
        "\n{} {} — {}",
        "Vantage:".bold(),
        v.label().cyan().bold(),
        start.reason.dimmed()
    );

    // Says which guarantee actually applies to active probes, rather than implying the
    // strongest one. Source binding constrains egress only as far as the routing table
    // agrees; the kernel pinning the interface is stronger and is not available everywhere.
    println!(
        "    {} {}",
        "Active probes:".dimmed(),
        report.visibility.binding_mode.label().dimmed()
    );

    if !report.visibility.blind_to.is_empty() {
        println!(
            "    {} {}",
            "Not visible from here:".dimmed(),
            report.visibility.blind_to.join(", ").dimmed()
        );
    }
    for note in &report.visibility.unavailable {
        println!("    {} {}", "Unavailable:".dimmed(), note.dimmed());
    }

    // An empty capture and an absent capture produce identical topology, so the two are
    // reported differently and never conflated.
    // Frames prove the reader delivered packets; accepted facts prove the whole path
    // through decoding, draining and absorption actually worked.
    if let Some(frames) = report.visibility.observed_frames {
        let accepted = report.visibility.accepted_facts.unwrap_or(0);
        let detail = match (frames, accepted) {
            (0, _) => "active; no frames observed on this link".to_string(),
            (f, 0) => format!("active; {f} frames observed, no topology evidence among them"),
            (f, a) => format!("active; {f} frames observed, {a} facts accepted"),
        };
        println!("    {} {}", "Passive capture:".dimmed(), detail.dimmed());
    }
}

fn render_networks(report: &DiscoveryReport) {
    let graph = &report.graph;
    let mut physical: Vec<IpNet> = Vec::new();
    let mut virtual_nets: Vec<IpNet> = Vec::new();

    for net in graph.networks() {
        let ifaces = graph.interfaces_for_network(&net);
        if is_virtual_network(&ifaces) {
            virtual_nets.push(net);
        } else {
            physical.push(net);
        }
    }
    physical.sort_by_key(|n| n.to_string());
    virtual_nets.sort_by_key(|n| n.to_string());

    if !physical.is_empty() {
        println!("\n{}", "Networks".bold().green());
        for net in &physical {
            let oversized = report.oversized_scopes.contains(net);
            let note = if net.addr().is_ipv6() {
                // IPv6 host space is never swept: it is not a size limit but a design
                // choice, since devices arrive from neighbour and advertisement evidence.
                " (devices from neighbour evidence; IPv6 host space is not swept)".to_string()
            } else if oversized {
                " (too large to enumerate; devices come from neighbour evidence)".to_string()
            } else {
                String::new()
            };
            println!("  ├── {}{}", net.to_string().cyan().bold(), note.dimmed());
            for iface in graph.interfaces_for_network(net) {
                println!("  │     via {}", iface.dimmed());
            }
        }
    }

    // Virtualisation plumbing is shown separately and never as cascaded physical topology.
    if !virtual_nets.is_empty() {
        println!(
            "\n{}",
            "Virtual & VPN networks (local to this machine)".bold()
        );
        for net in &virtual_nets {
            let ifaces = graph.interfaces_for_network(net).join(", ");
            println!(
                "  ├── {} {}",
                net.to_string().yellow(),
                format!("via {}", ifaces).dimmed()
            );
        }
    }

    let vlans: Vec<u16> = graph.vlans_without_prefix().collect();
    if !vlans.is_empty() {
        println!("\n{}", "VLANs".bold());
        for id in vlans {
            // A tag proves the VLAN exists and nothing more. Never a synthesised prefix.
            println!(
                "  ├── VLAN {} {}",
                id.to_string().cyan().bold(),
                "observed; prefix unknown".dimmed()
            );
        }
    }
}

fn render_infrastructure(graph: &TopologyGraph, vantage: &str) {
    use crate::topology::graph::DeviceCategory;

    // Sections are mutually exclusive, so their counts sum to the unique device total. A
    // router that also hosts AI stays here and carries the capability as an annotation
    // rather than appearing in two sections.
    for (category, heading) in [
        (DeviceCategory::Router, "Routers & gateways"),
        (DeviceCategory::Switch, "Switches & bridges"),
        (DeviceCategory::AiSystem, "AI agents & runtimes"),
    ] {
        let devices = graph.devices_in(category);
        if devices.is_empty() {
            continue;
        }
        println!(
            "\n{} ({})",
            heading.bold().green(),
            devices.len().to_string().bold()
        );
        for node in devices {
            print_device(graph, node, vantage);
        }
    }

    // Stated explicitly when absent, so "no AI found" is distinguishable from "AI was
    // never looked for".
    if graph.devices_in(DeviceCategory::AiSystem).is_empty() {
        println!(
            "\n{} {}",
            "AI agents & runtimes (0)".bold(),
            "no protocol-confirmed AI runtime, agent or MCP server".dimmed()
        );
    }
}

fn print_device(graph: &TopologyGraph, node: &crate::topology::Node, vantage: &str) {
    let addrs = display_addresses(node, vantage);
    println!(
        "  ├── {} {} {}",
        node.display_name().cyan().bold(),
        if addrs.is_empty() {
            String::new()
        } else {
            format!("[{}]", addrs.join(", "))
        }
        .yellow(),
        node.vendor
            .as_deref()
            .map(|v| format!("({})", v))
            .unwrap_or_default()
            .dimmed()
    );
    // Capabilities first: they say what the device does, which is more precise than the
    // single word its role collapses to.
    if !node.capabilities.is_empty() {
        println!(
            "  │     {} {}",
            "Capabilities:".bold(),
            node.capabilities
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
                .green()
        );
    }
    for signal in &node.role_signals {
        println!("  │     • {}", signal.dimmed());
    }

    // Networks this device serves, with the relationship that established it.
    for edge in graph.edges() {
        if edge.from != node.id {
            continue;
        }
        if matches!(
            edge.relationship,
            Relationship::GatewayFor | Relationship::RoutesTo
        ) && let NodeId::Network(net) = &edge.to
        {
            println!(
                "  │     └── {} {} [{}]",
                edge.relationship.label().dimmed(),
                net.to_string().cyan(),
                edge.confidence.label().dimmed()
            );
        }
    }
}

/// A device's addresses for display, routable first, link-local addresses scoped.
///
/// `fe80::1` on its own names no device: the same address on another link is a different
/// device. Rendering it bare made two distinct neighbours indistinguishable.
fn display_addresses(node: &crate::topology::graph::Node, vantage: &str) -> Vec<String> {
    let mut routable: Vec<String> = Vec::new();
    let mut scoped: Vec<String> = Vec::new();

    for address in &node.addresses {
        if crate::topology::graph::is_interrogable(address) {
            routable.push(address.to_string());
            continue;
        }
        // The zone comes from the identity where the identity carries one, and otherwise
        // from the vantage: a link-local neighbour was, by definition, seen on this link.
        let zone = match &node.id {
            NodeId::Device(DeviceKey::ScopedAddress(_, zone)) => zone.as_str(),
            _ => vantage,
        };
        scoped.push(if crate::net::endpoint::requires_zone(address) {
            format!("{address}%{zone}")
        } else {
            address.to_string()
        });
    }

    routable.sort();
    scoped.sort();
    routable.extend(scoped);
    routable
}

fn render_hosts(graph: &TopologyGraph, vantage: &str) {
    use crate::topology::graph::DeviceCategory;

    let all_hosts = graph.devices_in(DeviceCategory::Host);
    if all_hosts.is_empty() {
        return;
    }

    // Every host is shown. Hiding those known only by a link-local address dismissed them
    // as "this machine's plumbing", which they are not: they are discovered devices on the
    // link, several of which answer TCP probes. The count and the list disagreeing was the
    // visible symptom.
    println!(
        "\n{} ({})",
        "Hosts".bold().green(),
        all_hosts.len().to_string().bold()
    );

    for node in all_hosts {
        let addrs = display_addresses(node, vantage);
        let name = node
            .hostnames
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "-".to_string());
        println!(
            "  |-- {:<24} {:<22} {}",
            addrs.first().cloned().unwrap_or_default().cyan(),
            name.green(),
            node.vendor.as_deref().unwrap_or("").dimmed()
        );
        for extra in addrs.iter().skip(1) {
            println!("  |     {}", extra.dimmed());
        }
        if !node.capabilities.is_empty() {
            println!(
                "  |     {}",
                node.capabilities
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
                    .green()
            );
        }
    }
}

fn render_boundaries(graph: &TopologyGraph, vantage: &str) {
    let boundaries: Vec<_> = graph.nodes_of_kind(NodeKind::OpaqueBoundary).collect();
    if boundaries.is_empty() {
        return;
    }

    println!("\n{}", "Opaque boundaries".bold().yellow());
    for node in boundaries {
        let addrs = display_addresses(node, vantage);
        println!(
            "  ├── {} {}",
            node.display_name().cyan().bold(),
            format!("[{}]", addrs.join(", ")).yellow()
        );
        for signal in &node.role_signals {
            println!("  │     • {}", signal.dimmed());
        }
        if let Some(reason) = &node.opaque_reason {
            println!("  │     └── {}", reason.yellow());
        }
    }
}

/// Detailed per-device table with the services observed on each.
///
/// The tree shows relationships; this shows the inventory. Services live on their own nodes
/// in the graph, so they are gathered back onto their owning device here rather than being
/// stored twice.
fn render_device_table(graph: &TopologyGraph, vantage: &str) {
    let mut devices: Vec<&crate::topology::Node> = graph
        .nodes()
        // No reachability filter. A device known only by a link-local address -- the IPv6
        // router on this link among them -- is a discovered device and belongs in the
        // inventory; omitting it made the table disagree with the sections above it.
        .filter(|n| crate::topology::graph::categorize(n).is_some())
        .collect();
    if devices.is_empty() {
        return;
    }
    devices.sort_by_key(|n| n.addresses.iter().next().copied());

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Role").fg(TableColor::Cyan),
            Cell::new("Address").fg(TableColor::Cyan),
            Cell::new("Name").fg(TableColor::Cyan),
            Cell::new("MAC / Vendor").fg(TableColor::Cyan),
            Cell::new("Capabilities").fg(TableColor::Cyan),
            Cell::new("Services").fg(TableColor::Cyan),
            Cell::new("Evidence").fg(TableColor::Cyan),
        ]);

    for node in devices {
        // Scoped addresses are shown as such: fe80::1 alone does not identify a device,
        // because the same address on another link is another device entirely.
        let address = display_addresses(node, vantage)
            .first()
            .cloned()
            .unwrap_or_default();

        let services = services_for(graph, node);
        let identity = match (&node.id, &node.vendor) {
            (NodeId::Device(key), Some(vendor)) => format!("{key}\n{vendor}"),
            (NodeId::Device(key), None) => key.to_string(),
            (_, Some(vendor)) => vendor.clone(),
            _ => String::new(),
        };

        // The presentation category, not the raw node kind. An AI system is rendered in its
        // own section above, so labelling it "host" here contradicted the same page.
        let category = crate::topology::graph::categorize(node);
        table.add_row(vec![
            Cell::new(
                category
                    .map(|c| c.label())
                    .unwrap_or_else(|| node.kind.label()),
            )
            .fg(match category {
                Some(DeviceCategory::Router) => TableColor::Blue,
                Some(DeviceCategory::Switch) => TableColor::Magenta,
                Some(DeviceCategory::OpaqueBoundary) => TableColor::Yellow,
                Some(DeviceCategory::AiSystem) => TableColor::Green,
                _ => TableColor::White,
            }),
            Cell::new(address),
            Cell::new(
                node.hostnames
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::new(identity),
            Cell::new(if node.capabilities.is_empty() {
                "-".to_string()
            } else {
                node.capabilities
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n")
            }),
            Cell::new(if services.is_empty() {
                "-".to_string()
            } else {
                services.join(", ")
            }),
            Cell::new(if node.role_signals.is_empty() {
                "-".to_string()
            } else {
                node.role_signals
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n")
            }),
        ]);
    }

    println!("\n{}", "Device inventory".bold().green());
    println!("{table}");
}

/// Service descriptions belonging to a device, gathered from its addresses.
/// One line per service port, carrying its strongest description.
///
/// Collapsed by port across every address the device answers on. A dual-stack device is
/// probed at both of its addresses, producing a service node per address, and a port that
/// answered on both was printed twice -- once bare and once with whatever the protocol
/// handshake established, as though two services had been found. Every record is retained
/// in the graph and in exports; only the display is collapsed.
fn services_for(graph: &TopologyGraph, node: &crate::topology::Node) -> Vec<String> {
    let mut best: std::collections::BTreeMap<u16, String> = std::collections::BTreeMap::new();

    for service in graph.nodes_of_kind(NodeKind::Service) {
        let NodeId::Service(addr, port) = &service.id else {
            continue;
        };
        if !node.addresses.contains(addr) {
            continue;
        }
        let Some(description) = strongest_description(service, *port) else {
            continue;
        };
        best.entry(*port)
            .and_modify(|current| {
                if description.len() > current.len() {
                    *current = description.clone();
                }
            })
            .or_insert(description);
    }

    best.into_values().collect()
}

/// The most informative description a service node holds.
///
/// A confirmed protocol beats a bare open port. Where several are confirmed, the longest is
/// the one carrying the most identity -- a certificate subject or a server banner rather
/// than a protocol name alone.
fn strongest_description(service: &crate::topology::Node, port: u16) -> Option<String> {
    service
        .descriptions
        .iter()
        .filter(|d| {
            !d.contains("protocol not yet confirmed") && !d.contains("protocol unconfirmed")
        })
        .max_by_key(|d| d.len())
        .cloned()
        .or_else(|| service.descriptions.iter().next().cloned())
        .or_else(|| Some(format!("{port}/tcp")))
}

/// Sorts an endpoint string by address rather than lexically, so .9 precedes .10.
fn parse_sort_key(endpoint: Option<&str>) -> (u8, Option<std::net::IpAddr>, String) {
    let Some(endpoint) = endpoint else {
        return (2, None, String::new());
    };
    let bare = endpoint.split('%').next().unwrap_or(endpoint);
    match bare.parse::<std::net::IpAddr>() {
        Ok(address) => (0, Some(address), endpoint.to_string()),
        Err(_) => (1, None, endpoint.to_string()),
    }
}

/// How a device was prioritised in the work queue.
///
/// Deliberately not a role name. The tier decides scheduling order only; the role comes
/// from what the device's answers contain and is rendered in the topology sections.
fn scheduling_priority(tier: crate::providers::target::DeviceTier) -> &'static str {
    use crate::providers::target::DeviceTier;
    match tier {
        DeviceTier::EstablishedPivot => "infrastructure first",
        DeviceTier::Candidate => "elevated",
        DeviceTier::Host => "normal",
    }
}

/// Per-device interrogation coverage.
///
/// Reports what was attempted against each device, not merely whether it produced
/// evidence. "no response" answered neither of the two questions an operator actually has:
/// was this device asked, and did it refuse or stay silent.
fn render_device_coverage(report: &DiscoveryReport) {
    if report.coverage.is_empty() {
        return;
    }

    println!("\n{}", "Device coverage".bold());
    println!(
        "  {} device(s) interrogated in {}ms wall clock ({}ms if run one at a time), {} probes",
        report.coverage.len(),
        report.enrichment_elapsed.as_millis(),
        report.enrichment_sequential_equivalent.as_millis(),
        report.probes_attempted,
    );

    // Ordered by address for reading. The ledger itself is keyed by device, so its own
    // order follows identity rather than anything an operator would scan down.
    let mut records: Vec<&crate::providers::target::DeviceCoverage> =
        report.coverage.iter().collect();
    records.sort_by(|a, b| {
        parse_sort_key(a.primary_endpoint()).cmp(&parse_sort_key(b.primary_endpoint()))
    });

    for record in records {
        println!(
            "  {} {}",
            record
                .primary_endpoint()
                .unwrap_or(&record.device.to_string())
                .cyan()
                .bold(),
            // The scheduling tier, not the device's role: a device the graph later scores
            // as a router was rendered here as "[host]", contradicting the sections above.
            format!("priority: {}", scheduling_priority(record.tier)).dimmed()
        );
        if record.addresses.len() > 1 {
            println!(
                "    {:<18} {}",
                "addresses",
                record.addresses.join(", ").dimmed()
            );
        }
        if !record.discovery_sources.is_empty() {
            println!(
                "    {:<18} {}",
                "discovered by",
                record.discovery_sources.join(", ").dimmed()
            );
        }
        println!("    {:<18} {}", "interrogation", record.summary().dimmed());
        if !record.vendor_adapters.is_empty() {
            println!(
                "    {:<18} {}",
                "vendor adapters",
                record.vendor_adapters.join(", ").dimmed()
            );
        }
        for omission in record.omissions() {
            // Stated rather than glossed: a pass that left work out must not read as
            // complete exploration.
            println!("    {:<18} {}", "not attempted", omission.dimmed());
        }
        if record.silent() {
            // A device that was asked and stayed silent is a finding about the device;
            // one that was never asked is a gap in coverage. They must not read alike.
            println!(
                "    {:<18} {}",
                "outcome",
                "asked, no response on any probed port".dimmed()
            );
        }
    }
}

fn render_coverage(report: &DiscoveryReport) {
    println!("\n{}", "Discovery coverage".bold());

    // Per-scope provider outcomes. Reported before pivots so it is clear which sources
    // examined each network, including the ones that returned nothing.
    for scope in &report.scope_runs {
        let label = match scope.scope {
            Some(net) => net.to_string(),
            None => "local machine".to_string(),
        };
        println!("  {}", label.cyan().bold());
        for run in &scope.runs {
            let outcome = match &run.note {
                Some(note) => note.clone(),
                None => format!("{} facts", run.evidence_count),
            };
            println!("    {:<18} {}", run.provider, outcome.dimmed());
        }
    }

    // Every pivot is accounted for, including the ones that disclosed nothing. Silent
    // failure is what made an incomplete map look finished.
    for pivot in &report.pivot_runs {
        println!("  {}", pivot.address.to_string().cyan().bold());
        for run in &pivot.runs {
            let outcome = match &run.note {
                Some(note) => note.clone(),
                None => format!("{} facts", run.evidence_count),
            };
            println!("    {:<18} {}", run.provider, outcome.dimmed());
        }
        if pivot.networks_learned.is_empty() {
            println!("    {}", "networks learned: none".dimmed());
        } else {
            let list: Vec<String> = pivot
                .networks_learned
                .iter()
                .map(|n| n.to_string())
                .collect();
            println!("    networks learned: {}", list.join(", ").green());
        }
    }

    render_device_coverage(report);

    // Three separate tallies. A node carries only its strongest supporting grade, so
    // counting nodes alone reported "0 advertised" on a run that was displaying advertised
    // RA prefixes and gateway relationships.
    let nodes = grade_counts_nodes(&report.graph);
    let facts = grade_counts_facts(&report.graph);
    let edges = grade_counts_edges(&report.graph);

    // Device counts first, because that is what an operator actually asked. The graph node
    // total is reported alongside so the difference is explained rather than looking wrong.
    let counts = report.graph.counts();

    println!("\n{}", "Topology summary".bold());
    println!(
        "  {:<16}{}",
        "Devices:".bold(),
        counts.devices().to_string().bold()
    );
    println!("    {:<14}{}", "Routers", counts.routers);
    println!("    {:<14}{}", "Switches", counts.switches);
    if counts.opaque_boundaries > 0 {
        println!("    {:<14}{}", "Boundaries", counts.opaque_boundaries);
    }
    println!("    {:<14}{}", "AI systems", counts.ai_systems);
    println!("    {:<14}{}", "Other hosts", counts.other_hosts);
    println!("  {:<16}{}", "Networks:".bold(), counts.networks);
    if counts.vlans > 0 {
        println!("  {:<16}{}", "VLANs:".bold(), counts.vlans);
    }
    println!("  {:<16}{}", "Services:".bold(), counts.services);
    println!("  {:<16}{}", "Interfaces:".bold(), counts.interfaces);
    println!(
        "  {:<16}{} {}",
        "Graph nodes:".bold(),
        counts.graph_nodes,
        "(devices plus networks, interfaces and services)".dimmed()
    );

    println!(
        "  {:<16}{} observed · {} advertised · {} inferred",
        "by grade:".dimmed(),
        nodes.observed.to_string().green().bold(),
        nodes.advertised.to_string().cyan().bold(),
        nodes.inferred.to_string().yellow().bold(),
    );
    println!(
        "  {:<16}{} observed · {} advertised · {} inferred",
        "Facts:".bold(),
        facts.observed.to_string().green().bold(),
        facts.advertised.to_string().cyan().bold(),
        facts.inferred.to_string().yellow().bold(),
    );
    println!(
        "  {:<16}{} observed · {} advertised · {} inferred",
        "Relationships:".bold(),
        edges.observed.to_string().green().bold(),
        edges.advertised.to_string().cyan().bold(),
        edges.inferred.to_string().yellow().bold(),
    );
    if !report.converged {
        println!("  {}", "(stopped at the safety budget)".dimmed());
    }
}

#[derive(Default)]
struct GradeCounts {
    observed: usize,
    advertised: usize,
    inferred: usize,
}

impl GradeCounts {
    fn tally(&mut self, confidence: crate::topology::Confidence) {
        use crate::topology::Confidence;
        match confidence {
            Confidence::Observed => self.observed += 1,
            Confidence::Advertised => self.advertised += 1,
            Confidence::Inferred => self.inferred += 1,
            Confidence::UserSupplied => {}
        }
    }
}

/// Nodes by their single strongest supporting grade.
fn grade_counts_nodes(graph: &TopologyGraph) -> GradeCounts {
    let mut c = GradeCounts::default();
    for node in graph.nodes() {
        c.tally(node.confidence);
    }
    c
}

/// Individual facts, which is where advertised evidence actually lives.
fn grade_counts_facts(graph: &TopologyGraph) -> GradeCounts {
    let mut c = GradeCounts::default();
    for node in graph.nodes() {
        for p in &node.provenance {
            c.tally(p.confidence);
        }
    }
    for edge in graph.edges() {
        for p in &edge.provenance {
            c.tally(p.confidence);
        }
    }
    c
}

/// Relationships by their strongest supporting grade.
fn grade_counts_edges(graph: &TopologyGraph) -> GradeCounts {
    let mut c = GradeCounts::default();
    for edge in graph.edges() {
        c.tally(edge.confidence);
    }
    c
}
