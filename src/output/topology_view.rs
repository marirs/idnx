//! Renders the topology graph.
//!
//! The renderer's job is to be honest about grades. Observed topology, advertised
//! topology, inferred facts, opaque boundaries and the limits of this vantage are all
//! shown distinctly, so a partial map is never presented as a complete one.

use colored::*;
use ipnet::IpNet;

use crate::engine::orchestrator::{DiscoveryReport, is_virtual_network};
use crate::net::vantage::StartingScope;
use crate::topology::graph::{NodeKind, Relationship};
use crate::topology::{NodeId, TopologyGraph};

/// Prints the complete topology view.
pub fn render(report: &DiscoveryReport, start: &StartingScope) {
    render_vantage(report, start);
    render_networks(report);
    render_infrastructure(&report.graph);
    render_hosts(&report.graph);
    render_boundaries(&report.graph);
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
            let note = if oversized {
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

fn render_infrastructure(graph: &TopologyGraph) {
    let mut routers: Vec<_> = graph.nodes_of_kind(NodeKind::Router).collect();
    let mut switches: Vec<_> = graph.nodes_of_kind(NodeKind::Switch).collect();
    routers.sort_by_key(|n| n.display_name());
    switches.sort_by_key(|n| n.display_name());

    if !routers.is_empty() {
        println!("\n{}", "Routers & gateways".bold().green());
        for node in routers {
            print_device(graph, node);
        }
    }

    if !switches.is_empty() {
        println!("\n{}", "Switches & bridges".bold().green());
        for node in switches {
            print_device(graph, node);
        }
    }
}

fn print_device(graph: &TopologyGraph, node: &crate::topology::Node) {
    let addrs: Vec<String> = node.addresses.iter().map(|a| a.to_string()).collect();
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

fn render_hosts(graph: &TopologyGraph) {
    let mut hosts: Vec<_> = graph
        .nodes_of_kind(NodeKind::Host)
        // A device known only by a loopback or link-local address is this machine's own
        // plumbing, not a discovered host.
        .filter(|n| {
            n.addresses
                .iter()
                .any(crate::topology::graph::is_interrogable)
        })
        .collect();
    if hosts.is_empty() {
        return;
    }
    hosts.sort_by_key(|n| n.addresses.iter().next().copied());

    println!("\n{} ({})", "Hosts".bold().green(), hosts.len());
    for node in hosts {
        // Lead with a routable address; link-local ones are shown as extras.
        let mut addrs: Vec<String> = node
            .addresses
            .iter()
            .filter(|a| crate::topology::graph::is_interrogable(a))
            .map(|a| a.to_string())
            .collect();
        addrs.extend(
            node.addresses
                .iter()
                .filter(|a| !crate::topology::graph::is_interrogable(a))
                .map(|a| a.to_string()),
        );
        let name = node
            .hostnames
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "-".to_string());
        println!(
            "  ├── {:<24} {:<22} {}",
            addrs.first().cloned().unwrap_or_default().cyan(),
            name.green(),
            node.vendor.as_deref().unwrap_or("").dimmed()
        );
        // Additional addresses on the same device, which is how a dual-stack host or a
        // multi-homed router is shown as one entry rather than several.
        for extra in addrs.iter().skip(1) {
            println!("  │     {}", extra.dimmed());
        }
    }
}

fn render_boundaries(graph: &TopologyGraph) {
    let boundaries: Vec<_> = graph.nodes_of_kind(NodeKind::OpaqueBoundary).collect();
    if boundaries.is_empty() {
        return;
    }

    println!("\n{}", "Opaque boundaries".bold().yellow());
    for node in boundaries {
        let addrs: Vec<String> = node.addresses.iter().map(|a| a.to_string()).collect();
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

    let counts = grade_counts(&report.graph);
    println!(
        "\n  {} observed · {} advertised · {} inferred · {} nodes total{}",
        counts.observed.to_string().green().bold(),
        counts.advertised.to_string().cyan().bold(),
        counts.inferred.to_string().yellow().bold(),
        report.graph.node_count().to_string().bold(),
        if report.converged {
            String::new()
        } else {
            " (stopped at the safety budget)".to_string()
        }
        .dimmed()
    );
}

struct GradeCounts {
    observed: usize,
    advertised: usize,
    inferred: usize,
}

fn grade_counts(graph: &TopologyGraph) -> GradeCounts {
    use crate::topology::Confidence;
    let mut c = GradeCounts {
        observed: 0,
        advertised: 0,
        inferred: 0,
    };
    for node in graph.nodes() {
        match node.confidence {
            Confidence::Observed => c.observed += 1,
            Confidence::Advertised => c.advertised += 1,
            Confidence::Inferred => c.inferred += 1,
            Confidence::UserSupplied => {}
        }
    }
    c
}
