use crate::engine::deep::ChildNetworkResult;
use crate::engine::scanner::ScanSummary;
use colored::Colorize;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color as TableColor, ContentArrangement, Table};
use ipnet::Ipv4Net;

pub fn print_scan_results(
    parent_cidr: &Ipv4Net,
    summary: &ScanSummary,
    child_networks: &[ChildNetworkResult],
) {
    let mut total_active = summary.active_hosts.len();
    for child in child_networks {
        total_active += child.summary.active_hosts.len();
    }

    if total_active == 0 {
        println!(
            "{} No responsive hosts discovered out of {} scanned targets ({:.2?}).",
            "[!]".yellow().bold(),
            summary.total_hosts,
            summary.elapsed
        );
        return;
    }

    let total_subnets = 1 + child_networks.len();
    println!(
        "\n{} Discovered {} active host(s) across {} network(s) in {:.2?}:\n",
        "[+]".green().bold(),
        total_active.to_string().green().bold(),
        total_subnets.to_string().cyan().bold(),
        summary.elapsed
    );

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Network")
                .add_attribute(Attribute::Bold)
                .fg(TableColor::Cyan),
            Cell::new("Host IP")
                .add_attribute(Attribute::Bold)
                .fg(TableColor::Cyan),
            Cell::new("Hostname")
                .add_attribute(Attribute::Bold)
                .fg(TableColor::Magenta),
            Cell::new("MAC & Vendor")
                .add_attribute(Attribute::Bold)
                .fg(TableColor::Blue),
            Cell::new("Status")
                .add_attribute(Attribute::Bold)
                .fg(TableColor::Green),
            Cell::new("Open Ports & Services")
                .add_attribute(Attribute::Bold)
                .fg(TableColor::Yellow),
            Cell::new("Latency")
                .add_attribute(Attribute::Bold)
                .fg(TableColor::White),
        ]);

    // 1. Add Local Primary Subnet hosts
    for host in &summary.active_hosts {
        add_host_row(&mut table, &format!("{} (Local)", parent_cidr), host);
    }

    // 2. Add Cascaded Downstream Subnet hosts
    for child in child_networks {
        let net_label = format!("{} (Cascaded)", child.cidr);
        for host in &child.summary.active_hosts {
            add_host_row(&mut table, &net_label, host);
        }
    }

    println!("{table}\n");
}

fn add_host_row(table: &mut Table, network_label: &str, host: &crate::engine::scanner::HostResult) {
    let net_cell = Cell::new(network_label).fg(TableColor::Cyan);
    let ip_desc = if host.ip.is_unspecified() {
        if !host.ipv6_addrs.is_empty() {
            format!("[IPv6 Only]\n{}", host.ipv6_addrs[0])
        } else {
            "-".to_string()
        }
    } else if host.ipv6_addrs.is_empty() {
        host.ip.to_string()
    } else {
        format!("{}\n{}", host.ip, host.ipv6_addrs[0])
    };
    let ip_cell = Cell::new(ip_desc).fg(TableColor::Cyan);

    let hostname_desc = host.hostname.as_deref().unwrap_or("-");
    let hostname_cell = Cell::new(hostname_desc).fg(if host.hostname.is_some() {
        TableColor::Magenta
    } else {
        TableColor::DarkGrey
    });

    let mac_desc = match (&host.mac_address, &host.vendor) {
        (Some(mac), Some(vendor)) => format!("{} ({})", mac, vendor),
        (Some(mac), None) => mac.clone(),
        (None, Some(vendor)) => vendor.clone(),
        (None, None) => "-".to_string(),
    };
    let mac_cell = Cell::new(mac_desc).fg(if host.mac_address.is_some() || host.vendor.is_some() {
        TableColor::Blue
    } else {
        TableColor::DarkGrey
    });

    let status_cell = Cell::new("UP")
        .fg(TableColor::Green)
        .add_attribute(Attribute::Bold);

    let mut ports_desc = if host.open_ports.is_empty() {
        "Host responsive (stealth / no open target ports)".to_string()
    } else {
        host.open_ports
            .iter()
            .map(|p| format!("{}/tcp ({})", p.port, p.service))
            .collect::<Vec<_>>()
            .join(", ")
    };

    if let Some(ref ai) = host.ai_runtime {
        ports_desc = format!("🤖 {}\n{}", ai.summary_label(), ports_desc);
    }

    let ports_cell = Cell::new(ports_desc).fg(if host.open_ports.is_empty() {
        TableColor::DarkGrey
    } else {
        TableColor::Yellow
    });

    let latency_desc = match host.min_latency {
        Some(lat) => format!("{:.2} ms", lat.as_secs_f64() * 1000.0),
        None => "-".to_string(),
    };
    let latency_cell = Cell::new(latency_desc);

    table.add_row(vec![
        net_cell,
        ip_cell,
        hostname_cell,
        mac_cell,
        status_cell,
        ports_cell,
        latency_cell,
    ]);
}
