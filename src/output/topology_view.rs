//! Renders the topology graph.
//!
//! The renderer's job is to be honest about grades. Observed topology, advertised
//! topology, inferred facts, opaque boundaries and the limits of this vantage are all
//! shown distinctly, so a partial map is never presented as a complete one.

use colored::*;
use comfy_table::{Cell, Color as TableColor, ContentArrangement, Table, presets::UTF8_FULL};

use crate::engine::orchestrator::{DiscoveryReport, is_virtual_network};
use crate::net::vantage::StartingScope;
use crate::output::safe;
use crate::topology::evidence::DeviceKey;
use crate::topology::graph::{DeviceCategory, NetworkRef};
use crate::topology::graph::{NodeKind, Relationship};
use crate::topology::{NodeId, TopologyGraph};

/// Writes one line into the sink.
///
/// Rendering goes through a writer rather than straight to stdout so the whole terminal
/// view can be captured verbatim and compared against a golden file. A `println!` is
/// unobservable to a test in the same process, which left the view -- the output an
/// operator actually reads -- as the one surface with no regression cover at all.
macro_rules! emit {
    ($out:expr) => {{ let _ = writeln!($out); }};
    ($out:expr, $($arg:tt)*) => {{ let _ = writeln!($out, $($arg)*); }};
}

/// Prints the complete topology view.
pub fn render(report: &DiscoveryReport, start: &StartingScope) {
    let mut rendered = String::new();
    render_to(&mut rendered, report, start);
    print!("{rendered}");
}

/// The same view, into any sink.
pub fn render_to(out: &mut dyn std::fmt::Write, report: &DiscoveryReport, start: &StartingScope) {
    render_vantage(out, report, start);
    render_networks(out, report);
    let vantage = report.visibility.vantage.interface.as_str();
    render_infrastructure(out, &report.graph, vantage);
    render_hosts(out, &report.graph, vantage);
    render_egress_path(out, &report.graph, vantage);
    render_boundaries(out, &report.graph, vantage);
    render_device_table(out, &report.graph, vantage);
    render_coverage(out, report);
}

fn render_vantage(out: &mut dyn std::fmt::Write, report: &DiscoveryReport, start: &StartingScope) {
    let v = &report.visibility.vantage;
    emit!(
        out,
        "\n{} {} — {}",
        "Vantage:".bold(),
        v.label().cyan().bold(),
        start.reason.dimmed()
    );

    // Says which guarantee actually applies to active probes, rather than implying the
    // strongest one. Source binding constrains egress only as far as the routing table
    // agrees; the kernel pinning the interface is stronger and is not available everywhere.
    emit!(
        out,
        "    {} {}",
        "Active probes:".dimmed(),
        report.visibility.binding_mode.label().dimmed()
    );

    if !report.visibility.blind_to.is_empty() {
        emit!(
            out,
            "    {} {}",
            "Not visible from here:".dimmed(),
            report.visibility.blind_to.join(", ").dimmed()
        );
    }
    for note in &report.visibility.unavailable {
        emit!(out, "    {} {}", "Unavailable:".dimmed(), note.dimmed());
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
        emit!(
            out,
            "    {} {}",
            "Passive capture:".dimmed(),
            detail.dimmed()
        );
    }

    // The routing control plane gets its own line. A link where no router speaks RIP and a
    // build where RIP was never decoded produce the same empty graph, and only the first is
    // a statement about the network.
    if let Some(routing) = &report.visibility.routing_updates {
        emit!(
            out,
            "    {} {}",
            "Passive RIPv2/RIPng:".dimmed(),
            routing.dimmed()
        );
    }
    // OSPF and IS-IS get their own line: a link can carry an enterprise's whole prefix list
    // in IS-IS while no router on it speaks RIP at all.
    if let Some(control) = &report.visibility.control_plane {
        emit!(
            out,
            "    {} {}",
            "Passive OSPF/IS-IS:".dimmed(),
            control.dimmed()
        );
    }
}

/// A network's peer attribution, where it has one.
///
/// Takes the realm-aware reference, not a bare prefix: two peers can each hold a
/// 10.0.0.0/24, and looking one up by prefix returned whichever was found first -- so the
/// second rendered with the first's provenance.
fn network_origin(graph: &TopologyGraph, net: &NetworkRef) -> Option<String> {
    let node = graph.network_ref_node(net)?;
    let origins = node.peer_origins();
    if origins.is_empty() {
        return None;
    }
    Some(format!(
        "{} {}",
        if node.only_remote() {
            "observed by"
        } else {
            "also reported by"
        },
        origins.join(", ")
    ))
}

fn render_networks(out: &mut dyn std::fmt::Write, report: &DiscoveryReport) {
    let graph = &report.graph;
    let mut physical: Vec<NetworkRef> = Vec::new();
    let mut virtual_nets: Vec<NetworkRef> = Vec::new();

    for net in graph.network_refs() {
        let ifaces = graph.interfaces_for_network(&net);
        if is_virtual_network(&ifaces) {
            virtual_nets.push(net);
        } else {
            physical.push(net);
        }
    }
    physical.sort();
    virtual_nets.sort();

    if !physical.is_empty() {
        emit!(out, "\n{}", "Networks".bold().green());
        for net in &physical {
            let oversized = report.oversized_scopes.contains(&net.prefix);
            let note = if net.prefix.addr().is_ipv6() {
                // IPv6 host space is never swept: it is not a size limit but a design
                // choice, since devices arrive from neighbour and advertisement evidence.
                " (devices from neighbour evidence; IPv6 host space is not swept)".to_string()
            } else if oversized {
                " (too large to enumerate; devices come from neighbour evidence)".to_string()
            } else {
                String::new()
            };
            emit!(
                out,
                "  ├── {}{}",
                net.to_string().cyan().bold(),
                note.dimmed()
            );
            for iface in graph.interfaces_for_network(net) {
                emit!(out, "  │     via {}", iface.dimmed());
            }
            // A network this machine cannot reach, reported by a peer that can, must not
            // be presented as though this vantage had seen it.
            if let Some(origin) = network_origin(graph, net) {
                emit!(out, "  │     {}", origin.magenta());
            }
            // Rendered from the run's reachability state, not from any provider's prose.
            // An advertised prefix nothing answered on stays listed and says so; silence
            // and never having asked are different lines because they are different
            // findings.
            if let Some(outcome) = report.network_reachability.get(net) {
                emit!(out, "  │     {}", outcome.describe().dimmed());
            }
        }
    }

    render_prefix_disclosure(out, report, &physical);

    // Virtualisation plumbing is shown separately and never as cascaded physical topology.
    if !virtual_nets.is_empty() {
        emit!(
            out,
            "\n{}",
            "Virtual & VPN networks (local to this machine)".bold()
        );
        for net in &virtual_nets {
            let ifaces = graph.interfaces_for_network(net).join(", ");
            emit!(
                out,
                "  ├── {} {}",
                net.to_string().yellow(),
                format!("via {}", ifaces).dimmed()
            );
        }
    }

    // VLANs whose prefix one observation actually stated. Shown apart from the tags of
    // unknown extent below, because the two are different findings and only one of them
    // names a network.
    let bound = graph.vlan_networks();
    if !bound.is_empty() {
        emit!(out, "\n{}", "VLANs carrying a known prefix".bold());
        for (vlan, prefix, provenance) in &bound {
            let domain = if vlan.realm.is_local() {
                String::new()
            } else {
                format!(" [{}]", vlan.realm.label())
            };
            // The observation that joined them, named. A binding without its evidence is
            // indistinguishable from a guess.
            let how = provenance
                .iter()
                .map(|p| p.source.label())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            emit!(
                out,
                "  ├── VLAN {}{} {} {}",
                vlan.to_string().cyan().bold(),
                domain.magenta(),
                prefix.to_string().yellow(),
                format!("(from {how})").dimmed()
            );
        }
    }

    let vlans: Vec<&crate::topology::graph::VlanRef> = graph.vlans_without_prefix().collect();
    if !vlans.is_empty() {
        emit!(out, "\n{}", "VLANs".bold());
        for vlan in vlans {
            // A tag proves the VLAN exists and nothing more. Never a synthesised prefix.
            // The domain is shown for a remote one, because VLAN 20 here and VLAN 20 on a
            // peer's switch are two different VLANs.
            let domain = if vlan.realm.is_local() {
                String::new()
            } else {
                format!(" [{}]", vlan.realm.label())
            };
            emit!(
                out,
                "  ├── VLAN {}{} {}",
                vlan.to_string().cyan().bold(),
                domain.magenta(),
                "observed; prefix unknown".dimmed()
            );
        }
    }
}

/// Which mechanisms could have disclosed an IPv4 prefix beyond this link, and whether any
/// did.
///
/// An IPv4 network this machine is not attached to can only arrive one way: something told
/// us about it. DHCP option 121/249, a RIPv2 advertisement, an authenticated read-only
/// routing source, or another response carrying a prefix outright. When none of them
/// disclosed anything, the honest report names what was asked rather than leaving an empty
/// section that reads as "there is nothing there".
fn render_prefix_disclosure(
    out: &mut dyn std::fmt::Write,
    report: &DiscoveryReport,
    physical: &[NetworkRef],
) {
    let attached: Vec<&NetworkRef> = physical
        .iter()
        .filter(|net| {
            net.prefix.addr().is_ipv4() && !report.graph.interfaces_for_network(net).is_empty()
        })
        .collect();
    let routed = physical.iter().any(|net| {
        net.prefix.addr().is_ipv4() && report.graph.interfaces_for_network(net).is_empty()
    });
    if routed {
        // Something did disclose a network beyond this link; it is already listed above
        // with the relationship that established it.
        return;
    }

    // Named from the provider runs, so the list is what actually ran rather than what the
    // build happens to contain.
    let asked: Vec<&str> = report
        .scope_runs
        .iter()
        .flat_map(|scope| scope.runs.iter())
        .filter(|run| {
            matches!(
                run.provider,
                "dhcp-inform" | "snmp" | "kernel-routes" | "egress-path"
            )
        })
        .map(|run| run.provider)
        .collect();
    let mut asked: Vec<String> = asked.iter().map(|name| name.to_string()).collect();
    // Passive routing decoding is a continuous source rather than a provider run, so it
    // does not appear in the scope runs; leaving it out of this list would understate what
    // was asked.
    if report
        .visibility
        .routing_updates
        .as_ref()
        .is_some_and(|state| !state.starts_with("not decoded"))
    {
        asked.push("passive RIPv2/RIPng".to_string());
    }
    if report
        .visibility
        .control_plane
        .as_ref()
        .is_some_and(|state| !state.starts_with("not decoded"))
    {
        asked.push("passive OSPF/IS-IS".to_string());
    }
    asked.sort();
    asked.dedup();
    if asked.is_empty() {
        return;
    }

    // Named so the absence is attributable. "No prefix disclosed" is a statement about
    // what every implemented credential-free mechanism returned, and it is not a statement
    // that there is nothing beyond this link -- the forwarding boundaries above are still
    // on the map with their far sides unresolved.
    let boundaries = report
        .graph
        .devices_in(DeviceCategory::ForwardingInterface)
        .len();
    emit!(
        out,
        "  {} {}",
        "IPv4 beyond this link:".dimmed(),
        format!(
            "no prefix was disclosed by {} (attached: {})",
            asked.join(", "),
            if attached.is_empty() {
                "none".to_string()
            } else {
                attached
                    .iter()
                    .map(|net| net.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        )
        .dimmed()
    );
    if boundaries > 0 {
        emit!(
            out,
            "  {} {}",
            "".dimmed(),
            format!(
                "{boundaries} forwarding boundary/boundaries were found; their downstream \
                 IPv4 prefixes remain unresolved"
            )
            .yellow()
        );
    }
}

fn render_infrastructure(out: &mut dyn std::fmt::Write, graph: &TopologyGraph, vantage: &str) {
    use crate::topology::graph::DeviceCategory;

    // Sections are mutually exclusive, so their counts sum to the unique device total. A
    // router that also hosts AI stays here and carries the capability as an annotation
    // rather than appearing in two sections.
    for (category, heading) in [
        (DeviceCategory::Router, "Routers & gateways"),
        (DeviceCategory::Switch, "Switches & bridges"),
        // Named for what was established. These interfaces forwarded our traffic; who
        // administers them is a separate question that a hop count cannot answer, and
        // listing them among hosts contradicted the forwarding evidence they carry.
        (
            DeviceCategory::ForwardingInterface,
            "Forwarding interfaces (routing confirmed, ownership unknown)",
        ),
        (DeviceCategory::AiSystem, "AI agents & runtimes"),
    ] {
        let devices = graph.devices_in(category);
        if devices.is_empty() {
            continue;
        }
        emit!(
            out,
            "\n{} ({})",
            heading.bold().green(),
            devices.len().to_string().bold()
        );
        for node in devices {
            print_device(out, graph, node, vantage);
        }
    }

    // Stated explicitly when absent, so "no AI found" is distinguishable from "AI was
    // never looked for".
    if graph.devices_in(DeviceCategory::AiSystem).is_empty() {
        emit!(
            out,
            "\n{} {}",
            "AI agents & runtimes (0)".bold(),
            "no protocol-confirmed AI runtime, agent or MCP server".dimmed()
        );
    }
}

fn print_device(
    out: &mut dyn std::fmt::Write,
    graph: &TopologyGraph,
    node: &crate::topology::Node,
    vantage: &str,
) {
    let addrs = display_addresses(node, vantage);
    emit!(
        out,
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
            .map(|v| format!("({})", safe::text(v)))
            .unwrap_or_default()
            .dimmed()
    );
    // Capabilities first: they say what the device does, which is more precise than the
    // single word its role collapses to.
    if !node.capabilities.is_empty() {
        emit!(
            out,
            "  │     {} {}",
            "Capabilities:".bold(),
            safe::all(node.capabilities.iter()).join(", ").green()
        );
    }
    // Liveness and role, stated rather than implied.
    //
    // A device rendered with no qualifier read as though its presence and its function had
    // both been established. Neither may be inferred from the other, and neither may be
    // inferred from the manufacturer or from where the scheduler put it in the queue.
    emit!(
        out,
        "  │     {} · {}",
        liveness_label(node),
        role_label(node).dimmed()
    );
    for address in &node.contested_addresses {
        // Two stations answered for this address and both answers validated. Naming one of
        // them as its holder would report a device identity that is half the truth.
        emit!(
            out,
            "  │     {} {}",
            "contested:".yellow(),
            format!("{address} is also answered for by another station").yellow()
        );
    }
    for (address, holder) in &node.superseded_addresses {
        emit!(
            out,
            "  │     {} {}",
            "reassigned:".dimmed(),
            format!("{address} now answers as {}", safe::text(holder)).dimmed()
        );
    }
    render_peer_origin(out, node, "  │     ");
    for signal in &node.role_signals {
        emit!(out, "  │     • {}", safe::text(signal).dimmed());
    }

    // Networks this device serves, with the relationship that established it.
    let mut serves = 0usize;
    for edge in graph.edges() {
        if edge.from != node.id {
            continue;
        }
        if matches!(
            edge.relationship,
            Relationship::GatewayFor | Relationship::RoutesTo
        ) && let NodeId::Network(net, _) = &edge.to
        {
            serves += 1;
            emit!(
                out,
                "  │     └── {} {} [{}]",
                edge.relationship.label().dimmed(),
                net.to_string().cyan(),
                edge.confidence.label().dimmed()
            );
        }
    }

    // A boundary whose far side is unknown stays on the map and says so.
    //
    // This device forwards -- that is established -- and nothing disclosed a prefix behind
    // it. Rendering it without this line would let a discovered forwarding boundary read as
    // a finished branch of the topology, which is the difference between "there is nothing
    // there" and "nothing told us what is there".
    if serves == 0 && crate::topology::graph::forwards_traffic(node) {
        emit!(
            out,
            "  │     {}",
            "downstream prefixes unresolved: no source disclosed a network behind this \
             interface"
                .yellow()
        );
    }
}

/// Whether anything answered for this device during this run, and on what basis.
///
/// Three states, because two of them were previously indistinguishable. A validated reply
/// to a request we sent says the device is answering now. A neighbour-cache or DHCP entry
/// says only that something learned of it once -- the kernel keeps such entries long after
/// a host is gone. Anything else says nothing about presence at all, and none of the three
/// ever means "offline": silence is not confirmation of absence.
fn liveness_label(node: &crate::topology::graph::Node) -> colored::ColoredString {
    let mut fresh: Vec<&'static str> = node
        .provenance
        .iter()
        .filter(|p| crate::engine::enrich::currently_live(p.source))
        .map(|p| p.source.label())
        .collect();
    fresh.sort_unstable();
    fresh.dedup();
    if !fresh.is_empty() {
        return format!("currently live ({})", fresh.join(", ")).green();
    }

    let remembered = node.provenance.iter().any(|p| {
        matches!(
            p.source,
            crate::topology::evidence::EvidenceSource::ArpCache
                | crate::topology::evidence::EvidenceSource::NdpCache
                | crate::topology::evidence::EvidenceSource::DhcpLease
        )
    });
    if remembered {
        return "cache-only, liveness not confirmed".yellow();
    }
    "liveness not confirmed".dimmed()
}

/// Whether the device's role rests on evidence, or on nothing at all.
///
/// "role unconfirmed" is the honest rendering for a device with no behavioural signal.
/// Without it, a host appearing under a heading implied that its manufacturer, or the
/// order the scheduler happened to reach it in, had established what it is.
fn role_label(node: &crate::topology::graph::Node) -> String {
    if node.role_signals.is_empty() {
        return "role unconfirmed".to_string();
    }
    format!("role confirmed by {} signal(s)", node.role_signals.len())
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

/// States which peer reported a node, where one did.
///
/// Never blended into the surrounding output. A fact observed on this link and a fact a
/// peer asserted about a network this machine cannot reach are different kinds of claim,
/// and presenting them identically would make the second look verified by this vantage.
fn render_peer_origin(
    out: &mut dyn std::fmt::Write,
    node: &crate::topology::graph::Node,
    indent: &str,
) {
    let origins = node.peer_origins();
    if origins.is_empty() {
        return;
    }
    let label = if node.only_remote() {
        "observed by"
    } else {
        "also reported by"
    };
    emit!(
        out,
        "{indent}{}",
        format!("{label} {}", origins.join(", ")).magenta()
    );
}

fn render_hosts(out: &mut dyn std::fmt::Write, graph: &TopologyGraph, vantage: &str) {
    use crate::topology::graph::DeviceCategory;

    let all_hosts = graph.devices_in(DeviceCategory::Host);
    if all_hosts.is_empty() {
        return;
    }

    // Every host is shown. Hiding those known only by a link-local address dismissed them
    // as "this machine's plumbing", which they are not: they are discovered devices on the
    // link, several of which answer TCP probes. The count and the list disagreeing was the
    // visible symptom.
    emit!(
        out,
        "\n{} ({})",
        "Hosts".bold().green(),
        all_hosts.len().to_string().bold()
    );

    for node in all_hosts {
        // Routers on the way out have their own section: they are not devices on this
        // network, and repeating them here would imply they are.
        if graph.is_egress_only(&node.id) {
            continue;
        }
        let addrs = display_addresses(node, vantage);
        let name = node
            .hostnames
            .iter()
            .next()
            .map(|h| safe::text(h))
            .unwrap_or_else(|| "-".to_string());
        emit!(
            out,
            "  |-- {:<24} {:<22} {}",
            addrs.first().cloned().unwrap_or_default().cyan(),
            name.green(),
            node.vendor.as_deref().unwrap_or("").dimmed()
        );
        for extra in addrs.iter().skip(1) {
            emit!(out, "  |     {}", extra.dimmed());
        }
        render_peer_origin(out, node, "  |     ");
        // A shared hostname across two MACs is usually one computer with two interfaces,
        // but a hostname is self-reported and reused, so it is offered as a possibility
        // rather than acted on by merging the devices.
        let related = node.possible_same_machine(graph);
        if !related.is_empty() {
            let names: Vec<String> = related
                .iter()
                .flat_map(|n| display_addresses(n, vantage))
                .collect();
            emit!(
                out,
                "  |     {}",
                format!(
                    "possibly the same machine as {} (shared hostname; unconfirmed)",
                    names.join(", ")
                )
                .dimmed()
            );
        }
        if !node.capabilities.is_empty() {
            emit!(
                out,
                "  |     {}",
                safe::all(node.capabilities.iter()).join(", ").green()
            );
        }
    }
}

/// Routers on the way out, listed apart from the operator's own topology.
///
/// Separate on purpose. These interfaces answered a TTL-expired probe, which establishes
/// that they forward and nothing more: they may belong to the operator, to a landlord, or
/// to a carrier, and hop count cannot tell them apart. Listing them among discovered
/// infrastructure would imply they are part of the network being mapped, and that they
/// expose something of it.
fn render_egress_path(out: &mut dyn std::fmt::Write, graph: &TopologyGraph, vantage: &str) {
    let hops = graph.egress_path();
    if hops.is_empty() {
        return;
    }

    emit!(out, "\n{}", "Egress path".bold());
    emit!(
        out,
        "    {}",
        "routers that forwarded a probe out of this vantage; ownership unknown, and none \
         has disclosed a network"
            .dimmed()
    );
    for (distance, node) in &hops {
        let addresses = display_addresses(node, vantage).join(", ");
        let services = services_for(graph, node);
        let note = if services.is_empty() {
            "no service answered".to_string()
        } else {
            services.join(", ")
        };
        emit!(
            out,
            "  ├── hop {} {} {}",
            distance,
            addresses.cyan().bold(),
            format!("[{note}]").dimmed()
        );
    }
}

fn render_boundaries(out: &mut dyn std::fmt::Write, graph: &TopologyGraph, vantage: &str) {
    let boundaries: Vec<_> = graph.nodes_of_kind(NodeKind::OpaqueBoundary).collect();
    if boundaries.is_empty() {
        return;
    }

    emit!(out, "\n{}", "Opaque boundaries".bold().yellow());
    for node in boundaries {
        let addrs = display_addresses(node, vantage);
        emit!(
            out,
            "  ├── {} {}",
            node.display_name().cyan().bold(),
            format!("[{}]", addrs.join(", ")).yellow()
        );
        for signal in &node.role_signals {
            emit!(out, "  │     • {}", safe::text(signal).dimmed());
        }
        if let Some(reason) = &node.opaque_reason {
            emit!(out, "  │     └── {}", safe::text(reason).yellow());
        }
    }
}

/// Detailed per-device table with the services observed on each.
///
/// The tree shows relationships; this shows the inventory. Services live on their own nodes
/// in the graph, so they are gathered back onto their owning device here rather than being
/// stored twice.
fn render_device_table(out: &mut dyn std::fmt::Write, graph: &TopologyGraph, vantage: &str) {
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
        // The vendor comes from an OUI table, but a peer can assert one too, so it is
        // neutralised like every other device-supplied string.
        let identity = match (&node.id, &node.vendor) {
            (NodeId::Device(key), Some(vendor)) => {
                format!("{}\n{}", safe::text(&key.to_string()), safe::text(vendor))
            }
            (NodeId::Device(key), None) => safe::text(&key.to_string()),
            (_, Some(vendor)) => safe::text(vendor),
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
                    .map(|h| safe::text(h))
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::new(identity),
            Cell::new(if node.capabilities.is_empty() {
                "-".to_string()
            } else {
                safe::all(node.capabilities.iter()).join("\n")
            }),
            Cell::new(if services.is_empty() {
                "-".to_string()
            } else {
                services.join(", ")
            }),
            Cell::new(if node.role_signals.is_empty() {
                "-".to_string()
            } else {
                safe::all(node.role_signals.iter()).join("\n")
            }),
        ]);
    }

    emit!(out, "\n{}", "Device inventory".bold().green());
    emit!(out, "{table}");
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

    // Followed through the graph's own edges rather than matched by address. Two domains
    // can hold the same address, and matching on it listed one peer's service against
    // another peer's device.
    for service in graph.services_of(&node.id) {
        let NodeId::Service(_, port, _) = &service.id else {
            continue;
        };
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
    // Certificate subjects, HTTP banners and peer-supplied service detail all end up here,
    // and this is the last point before they reach a terminal.
    service
        .descriptions
        .iter()
        .filter(|d| {
            !d.contains("protocol not yet confirmed") && !d.contains("protocol unconfirmed")
        })
        .max_by_key(|d| d.len())
        .map(|d| safe::text(d))
        .or_else(|| service.descriptions.iter().next().map(|d| safe::text(d)))
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
/// How the graph classified a device, for the coverage report.
///
/// The scheduling tier is not a classification, and printing it alone let the coverage
/// section say "priority: normal" about an interface the topology sections had established
/// as forwarding. Two truths about one device must not read as a contradiction.
fn classified_as(
    report: &DiscoveryReport,
    record: &crate::providers::target::DeviceCoverage,
) -> Option<String> {
    let node = report
        .graph
        .nodes()
        .find(|node| node.id == NodeId::Device(record.device.clone()))?;
    crate::topology::graph::categorize(node).map(|category| category.label().to_string())
}

fn render_device_coverage(out: &mut dyn std::fmt::Write, report: &DiscoveryReport) {
    if report.coverage.is_empty() {
        return;
    }

    emit!(out, "\n{}", "Device coverage".bold());
    emit!(
        out,
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
        emit!(
            out,
            "  {} {}",
            record
                .primary_endpoint()
                .unwrap_or(&record.device.to_string())
                .cyan()
                .bold(),
            // What the graph concluded, with the scheduling tier beside it rather than in
            // place of it: the tier decides queue order and nothing else.
            match classified_as(report, record) {
                Some(category) =>
                    format!("{category}; queued {}", scheduling_priority(record.tier)),
                None => format!("queued {}", scheduling_priority(record.tier)),
            }
            .dimmed()
        );
        if record.addresses.len() > 1 {
            emit!(
                out,
                "    {:<18} {}",
                "addresses",
                record.addresses.join(", ").dimmed()
            );
        }
        if !record.discovery_sources.is_empty() {
            emit!(
                out,
                "    {:<18} {}",
                "discovered by",
                record.discovery_sources.join(", ").dimmed()
            );
        }
        emit!(
            out,
            "    {:<18} {}",
            "interrogation",
            record.summary().dimmed()
        );
        if !record.vendor_adapters.is_empty() {
            emit!(
                out,
                "    {:<18} {}",
                "vendor adapters",
                record.vendor_adapters.join(", ").dimmed()
            );
        }
        // What each selected adapter managed to do. Selection was being printed on its own,
        // which read as though a vendor-specific interrogation had happened; every adapter
        // in the registry is a stub, so nothing had been sent.
        for outcome in &record.adapter_outcomes {
            let rendered = if outcome.contains("unavailable") {
                outcome.yellow()
            } else {
                outcome.dimmed()
            };
            emit!(out, "    {:<18} {}", "adapter outcome", rendered);
        }
        for failure in record.local_failures() {
            // A probe that never left this machine is a local fault, not remote silence.
            emit!(out, "    {:<18} {}", "not sent", failure.red());
        }
        for omission in record.omissions() {
            // Stated rather than glossed: a pass that left work out must not read as
            // complete exploration.
            emit!(out, "    {:<18} {}", "not attempted", omission.dimmed());
        }
        if record.silent() {
            // A device that was asked and stayed silent is a finding about the device;
            // one that was never asked is a gap in coverage. They must not read alike.
            emit!(
                out,
                "    {:<18} {}",
                "outcome",
                "asked, no response on any probed port".dimmed()
            );
        }
    }
}

/// Whether a note describes work that never reached the device.
fn never_asked(note: &str) -> bool {
    note.contains("unavailable")
        || note.contains("not applicable")
        || note.contains("not attempted")
        || note.contains("not sent")
}

/// What did not finish asking this pivot, or `None` when everything applicable did.
///
/// Both halves matter. A provider that reported itself unavailable never put a question to
/// the device, and so did a vendor adapter that was selected and has no implementation --
/// and the adapter outcomes live beside the device's coverage rather than in its provider
/// runs. With either outstanding, "disclosed nothing" would be our gap reported as their
/// silence.
fn incomplete_for_pivot(
    pivot: &crate::engine::orchestrator::PivotRun,
    report: &DiscoveryReport,
) -> Option<String> {
    let address = pivot.address.to_string();
    let adapters: Vec<String> = report
        .coverage
        .iter()
        .filter(|record| record.addresses.contains(&address))
        .flat_map(|record| record.adapter_outcomes.clone())
        .collect();
    unfinished_work(&pivot.runs, &adapters)
}

/// The named work that never reached the device, from provider runs and adapter outcomes.
fn unfinished_work(
    runs: &[crate::providers::ProviderRun],
    adapter_outcomes: &[String],
) -> Option<String> {
    let mut unfinished: Vec<String> = runs
        .iter()
        .filter(|run| run.note.as_deref().is_some_and(never_asked))
        .map(|run| run.provider.to_string())
        .collect();
    unfinished.extend(
        adapter_outcomes
            .iter()
            .filter(|outcome| never_asked(outcome))
            .cloned(),
    );

    unfinished.sort();
    unfinished.dedup();
    (!unfinished.is_empty()).then(|| unfinished.join("; "))
}

fn render_coverage(out: &mut dyn std::fmt::Write, report: &DiscoveryReport) {
    emit!(out, "\n{}", "Discovery coverage".bold());

    // Per-scope provider outcomes. Reported before pivots so it is clear which sources
    // examined each network, including the ones that returned nothing.
    for scope in &report.scope_runs {
        let label = match scope.scope {
            Some(net) => net.to_string(),
            None => "local machine".to_string(),
        };
        emit!(out, "  {}", label.cyan().bold());
        for run in &scope.runs {
            let outcome = match &run.note {
                Some(note) => note.clone(),
                None => format!("{} facts", run.evidence_count),
            };
            emit!(out, "    {:<18} {}", run.provider, outcome.dimmed());
        }
    }

    // Every pivot is accounted for, including the ones that disclosed nothing. Silent
    // failure is what made an incomplete map look finished.
    for pivot in &report.pivot_runs {
        emit!(out, "  {}", pivot.address.to_string().cyan().bold());
        for run in &pivot.runs {
            let outcome = match &run.note {
                Some(note) => note.clone(),
                None => format!("{} facts", run.evidence_count),
            };
            emit!(out, "    {:<18} {}", run.provider, outcome.dimmed());
        }
        if pivot.networks_learned.is_empty() {
            // "None" is a conclusion, and it can only be drawn once everything applicable
            // actually ran. Where a provider was unavailable or never transmitted, the
            // honest statement is that the interrogation is incomplete -- otherwise an
            // operator reads a gap in our coverage as a fact about their network.
            match incomplete_for_pivot(pivot, report) {
                None => emit!(out, "    {}", "networks disclosed: none".dimmed()),
                Some(unfinished) => emit!(
                    out,
                    "    {} {}",
                    "no network established; interrogation incomplete".yellow(),
                    format!("({unfinished})").dimmed()
                ),
            }
        } else {
            let list: Vec<String> = pivot
                .networks_learned
                .iter()
                .map(|n| n.to_string())
                .collect();
            emit!(out, "    networks learned: {}", list.join(", ").green());
        }
    }

    render_device_coverage(out, report);

    // Three separate tallies. A node carries only its strongest supporting grade, so
    // counting nodes alone reported "0 advertised" on a run that was displaying advertised
    // RA prefixes and gateway relationships.
    let nodes = grade_counts_nodes(&report.graph);
    let facts = grade_counts_facts(&report.graph);
    let edges = grade_counts_edges(&report.graph);

    // Device counts first, because that is what an operator actually asked. The graph node
    // total is reported alongside so the difference is explained rather than looking wrong.
    let counts = report.graph.counts();

    emit!(out, "\n{}", "Topology summary".bold());
    emit!(
        out,
        "  {:<16}{}",
        "Devices:".bold(),
        counts.devices().to_string().bold()
    );
    emit!(out, "    {:<14}{}", "Routers", counts.routers);
    emit!(out, "    {:<14}{}", "Switches", counts.switches);
    if counts.opaque_boundaries > 0 {
        emit!(out, "    {:<14}{}", "Boundaries", counts.opaque_boundaries);
    }
    if counts.forwarding_interfaces > 0 {
        // Named for the behaviour that was confirmed, not for an owner nobody established.
        emit!(
            out,
            "    {:<14}{}",
            "Forwarding",
            counts.forwarding_interfaces
        );
    }
    emit!(out, "    {:<14}{}", "AI systems", counts.ai_systems);
    emit!(out, "    {:<14}{}", "Other hosts", counts.other_hosts);
    emit!(out, "  {:<16}{}", "Networks:".bold(), counts.networks);
    if counts.vlans > 0 {
        emit!(out, "  {:<16}{}", "VLANs:".bold(), counts.vlans);
    }
    emit!(out, "  {:<16}{}", "Services:".bold(), counts.services);
    emit!(out, "  {:<16}{}", "Interfaces:".bold(), counts.interfaces);
    emit!(
        out,
        "  {:<16}{} {}",
        "Graph nodes:".bold(),
        counts.graph_nodes,
        "(devices plus networks, interfaces and services)".dimmed()
    );

    emit!(
        out,
        "  {:<16}{} observed · {} advertised · {} inferred",
        "by grade:".dimmed(),
        nodes.observed.to_string().green().bold(),
        nodes.advertised.to_string().cyan().bold(),
        nodes.inferred.to_string().yellow().bold(),
    );
    emit!(
        out,
        "  {:<16}{} observed · {} advertised · {} inferred",
        "Facts:".bold(),
        facts.observed.to_string().green().bold(),
        facts.advertised.to_string().cyan().bold(),
        facts.inferred.to_string().yellow().bold(),
    );
    emit!(
        out,
        "  {:<16}{} observed · {} advertised · {} inferred",
        "Relationships:".bold(),
        edges.observed.to_string().green().bold(),
        edges.advertised.to_string().cyan().bold(),
        edges.inferred.to_string().yellow().bold(),
    );
    if !report.converged {
        emit!(out, "  {}", "(stopped at the safety budget)".dimmed());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::ProviderRun;
    use crate::topology::TopologyEvidence;
    use crate::topology::evidence::{Confidence, EvidenceSource, Fact, RoleSignal};

    fn note(provider: &'static str, note: &str) -> ProviderRun {
        ProviderRun {
            provider,
            evidence_count: 0,
            note: Some(note.to_string()),
        }
    }

    fn absorb(graph: &mut TopologyGraph, fact: Fact, source: EvidenceSource) {
        graph.absorb(TopologyEvidence::new(
            fact,
            source,
            Confidence::Observed,
            "test0",
        ));
    }

    fn node_for<'a>(graph: &'a TopologyGraph, key: &DeviceKey) -> &'a crate::topology::Node {
        graph
            .nodes()
            .find(|node| node.id == NodeId::Device(key.clone()))
            .expect("the device exists")
    }

    #[test]
    fn nothing_disclosed_reads_as_incomplete_until_every_applicable_source_has_asked() {
        // "Disclosed nothing" is a claim about the device. It may only be made once every
        // applicable source actually put a question to it; otherwise our own gap is being
        // reported as their silence.
        let finished = [
            note("device-enrichment", "3 stage(s), 0/79 tcp responsive"),
            note("snmp", "no response"),
        ];
        assert_eq!(unfinished_work(&finished, &[]), None);

        // A provider that could not run here.
        let blocked = [note("arp-liveness", "unavailable: needs root")];
        assert_eq!(
            unfinished_work(&blocked, &[]).as_deref(),
            Some("arp-liveness")
        );

        // Nothing on this link to ask is equally not an answer from the device.
        let nothing_to_ask = [note(
            "ndp-liveness",
            "not applicable: no neighbour reported",
        )];
        assert!(unfinished_work(&nothing_to_ask, &[]).is_some());

        // A selected adapter with no implementation never sent a packet either, and its
        // outcome lives beside the device's coverage rather than in the provider runs.
        let adapters = vec!["vendor:asus unavailable: framing unverified".to_string()];
        assert_eq!(
            unfinished_work(&finished, &adapters).as_deref(),
            Some("vendor:asus unavailable: framing unverified")
        );

        // An adapter that ran and heard nothing leaves the account complete.
        let answered = vec!["vendor:mikrotik no response (8728/tcp)".to_string()];
        assert_eq!(unfinished_work(&finished, &answered), None);
    }

    #[test]
    fn a_device_is_never_rendered_as_live_on_a_remembered_entry() {
        let mut graph = TopologyGraph::new();

        // Remembered by the kernel, and nothing has answered during this run.
        let remembered = DeviceKey::mac("02:00:5e:00:00:11");
        absorb(
            &mut graph,
            Fact::DeviceAddress {
                device: remembered.clone(),
                address: "10.7.0.1".parse().unwrap(),
            },
            EvidenceSource::ArpCache,
        );
        let rendered = liveness_label(node_for(&graph, &remembered)).to_string();
        assert!(rendered.contains("cache-only"), "{rendered}");
        assert!(!rendered.contains("currently live"), "{rendered}");

        // Answered a request we sent and validated.
        let answering = DeviceKey::mac("02:00:5e:00:00:12");
        absorb(
            &mut graph,
            Fact::DeviceAddress {
                device: answering.clone(),
                address: "10.7.0.2".parse().unwrap(),
            },
            EvidenceSource::ArpProbe,
        );
        assert!(
            liveness_label(node_for(&graph, &answering))
                .to_string()
                .contains("currently live")
        );

        // Named by a route, which says nothing about whether it is answering.
        let routed = DeviceKey::Address("10.7.0.3".parse().unwrap());
        absorb(
            &mut graph,
            Fact::DeviceAddress {
                device: routed.clone(),
                address: "10.7.0.3".parse().unwrap(),
            },
            EvidenceSource::KernelRoute,
        );
        let rendered = liveness_label(node_for(&graph, &routed)).to_string();
        assert!(rendered.contains("not confirmed"), "{rendered}");
        assert!(!rendered.contains("cache-only"), "{rendered}");
    }

    #[test]
    fn a_device_with_no_behavioural_signal_renders_as_role_unconfirmed() {
        // Neither the manufacturer nor the scheduler's ordering establishes what a device
        // is; without a behavioural signal the honest rendering says so.
        let mut graph = TopologyGraph::new();
        let key = DeviceKey::mac("02:00:5e:00:00:13");
        absorb(
            &mut graph,
            Fact::DeviceAddress {
                device: key.clone(),
                address: "10.7.0.4".parse().unwrap(),
            },
            EvidenceSource::ArpProbe,
        );
        absorb(
            &mut graph,
            Fact::DeviceVendor {
                device: key.clone(),
                vendor: "ASUSTek COMPUTER INC.".to_string(),
            },
            EvidenceSource::ArpProbe,
        );
        assert_eq!(role_label(node_for(&graph, &key)), "role unconfirmed");

        absorb(
            &mut graph,
            Fact::DeviceRoleSignal {
                device: key.clone(),
                signal: RoleSignal::ObservedForwarding,
            },
            EvidenceSource::IcmpProbe,
        );
        assert!(role_label(node_for(&graph, &key)).contains("role confirmed"));
    }
}
