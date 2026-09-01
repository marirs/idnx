use crate::engine::deep::ChildNetworkResult;
use crate::engine::scanner::{HostResult, ScanSummary};
use crate::fingerprint::classifier::{DeviceRole, classify_host};
use crate::net::interface::LocalNetworkInfo;
use colored::Colorize;
use ipnet::Ipv4Net;

pub fn print_topology_tree(
    target_cidr: &Ipv4Net,
    local_info_opt: Option<&LocalNetworkInfo>,
    summary: &ScanSummary,
    physical_switches: &[&str],
    child_networks: &[ChildNetworkResult],
) {
    if summary.active_hosts.is_empty() {
        return;
    }

    let iface_desc = local_info_opt
        .map(|info| format!(" ({})", info.interface_name))
        .unwrap_or_default();

    println!(
        "\n{} {}\n",
        "🌐 Network Topology Tree:".bold(),
        format!(
            "{}{} [{} hosts active]",
            target_cidr,
            iface_desc,
            summary.active_hosts.len()
        )
        .cyan()
        .bold()
    );

    let local_ip = local_info_opt.map(|info| info.ip);

    // Group hosts by role
    let mut gateways = Vec::new();
    let mut switches = Vec::new();
    let mut workstations = Vec::new();
    let mut smart_devices = Vec::new();
    let mut generic_hosts = Vec::new();

    for host in &summary.active_hosts {
        let is_gateway = host.ip.octets()[3] == 1; // standard default gateway heuristic
        let role = classify_host(host, is_gateway);
        match role {
            DeviceRole::GatewayRouter => gateways.push(host),
            DeviceRole::Switch => switches.push(host),
            DeviceRole::Workstation => workstations.push(host),
            DeviceRole::SmartDevice => smart_devices.push(host),
            DeviceRole::GenericHost => generic_hosts.push(host),
        }
    }

    let mut categories: Vec<(&'static str, &'static str, Vec<&HostResult>)> = Vec::new();
    if !gateways.is_empty() {
        categories.push(("📡", "Gateways & Routers", gateways));
    }
    if !switches.is_empty() {
        categories.push(("🔀", "Managed Switches & Infrastructure", switches));
    }
    if !workstations.is_empty() {
        categories.push(("💻", "Workstations, Laptops & Servers", workstations));
    }
    if !smart_devices.is_empty() {
        categories.push(("🔌", "IoT & Connected Smart Devices", smart_devices));
    }
    if !generic_hosts.is_empty() {
        categories.push(("❓", "Other Active Hosts", generic_hosts));
    }

    let has_child_networks = !child_networks.is_empty();
    let has_switches_section = !physical_switches.is_empty();
    let total_top_level = categories.len()
        + if has_child_networks { 1 } else { 0 }
        + if has_switches_section { 1 } else { 0 };

    for (cat_idx, (icon, cat_name, hosts)) in categories.iter().enumerate() {
        let is_last_cat = cat_idx == total_top_level - 1;
        let cat_branch = if is_last_cat {
            "└──"
        } else {
            "├──"
        };
        let indent = if is_last_cat { "    " } else { "│   " };

        println!(
            "{} {} {}",
            cat_branch.bold(),
            icon,
            cat_name.bold().yellow()
        );

        let total_hosts = hosts.len();
        for (h_idx, host) in hosts.iter().enumerate() {
            let is_last_host = h_idx == total_hosts - 1;
            let host_branch = if is_last_host {
                "└──"
            } else {
                "├──"
            };
            let sub_indent = if is_last_host { "    " } else { "│   " };

            // Build node label
            let mut label = format!("{}", host.ip.to_string().cyan().bold());

            if !host.ipv6_addrs.is_empty() {
                let v6_str = host
                    .ipv6_addrs
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                label = format!("{} / {}", label, v6_str.cyan());
            }

            if let Some(ref name) = host.hostname {
                label = format!("{} [{}]", label, name.magenta().bold());
            }

            if let Some(ref mac) = host.mac_address {
                if let Some(ref vendor) = host.vendor {
                    label = format!("{} - {} ({})", label, mac.blue(), vendor.green());
                } else {
                    label = format!("{} - {}", label, mac.blue());
                }
            }

            if Some(host.ip) == local_ip {
                label = format!("{} {}", label, "[Local Machine]".green().bold());
            }

            let open_ports_str: Vec<String> = host
                .open_ports
                .iter()
                .map(|p| format!("{}/tcp", p.port))
                .collect();
            if !open_ports_str.is_empty() {
                label = format!("{} [{}]", label, open_ports_str.join(", ").yellow());
            }

            println!("{}{} {}", indent, host_branch, label);

            // Detailed service ports if router or has multiple ports
            if !host.open_ports.is_empty() && (icon == &"📡" || host.open_ports.len() > 1) {
                let services_summary: Vec<String> = host
                    .open_ports
                    .iter()
                    .map(|p| format!("{}/{} ({})", p.port, "tcp", p.service))
                    .collect();
                println!(
                    "{}{}└── Ports: {}",
                    indent,
                    sub_indent,
                    services_summary.join(", ").dimmed()
                );
            }
        }
    }

    // Render discovered cascaded child networks
    if has_child_networks {
        let is_last_sec = !has_switches_section;
        let branch = if is_last_sec {
            "└──"
        } else {
            "├──"
        };
        let indent = if is_last_sec { "    " } else { "│   " };

        println!(
            "{} 🌐 {}",
            branch.bold(),
            "Cascaded & Adjacent Networks (Upstream / Downstream Subnets)"
                .bold()
                .yellow()
        );

        for (c_idx, child) in child_networks.iter().enumerate() {
            let is_last_subnet = c_idx == child_networks.len() - 1;
            let sub_branch = if is_last_subnet {
                "└──"
            } else {
                "├──"
            };
            let sub_indent = if is_last_subnet { "    " } else { "│   " };

            let subnet_label = child.cidr.to_string().cyan().bold().to_string();

            println!(
                "{}{} 🔀 Subnet: {} [{} hosts active]",
                indent,
                sub_branch,
                subnet_label,
                child.summary.active_hosts.len()
            );

            // Separate gateway/switch from connected endpoints
            let mut switch_gws = Vec::new();
            let mut endpoints = Vec::new();

            for host in &child.summary.active_hosts {
                if host.ip.octets()[3] == 1
                    || host.open_ports.iter().any(|p| p.port == 23 || p.port == 80)
                {
                    switch_gws.push(host);
                } else {
                    endpoints.push(host);
                }
            }

            let has_endpoints = !endpoints.is_empty();

            for (gw_idx, gw) in switch_gws.iter().enumerate() {
                let is_last_gw = gw_idx == switch_gws.len() - 1 && !has_endpoints;
                let gw_branch = if is_last_gw { "└──" } else { "├──" };
                let gw_name = if let Some(ref sys) = child.snmp_system_name {
                    sys.as_str()
                } else if gw.open_ports.iter().any(|p| p.port == 23) {
                    "Managed Switch Gateway"
                } else if gw.open_ports.iter().any(|p| p.port == 53) {
                    "Subnet Gateway Router"
                } else {
                    "Subnet Gateway"
                };
                let ports_str: Vec<String> = gw
                    .open_ports
                    .iter()
                    .map(|p| format!("{}/{}", p.port, p.service))
                    .collect();
                let ports_tag = if !ports_str.is_empty() {
                    format!(" [{}]", ports_str.join(", ").yellow())
                } else {
                    String::new()
                };
                let descr_tag = if let Some(ref d) = child.snmp_system_descr {
                    format!(" ({})", d.dimmed())
                } else {
                    String::new()
                };
                println!(
                    "{}{}    {} 🔀 {} [{}]{}{}",
                    indent,
                    sub_indent,
                    gw_branch,
                    gw.ip.to_string().cyan().bold(),
                    gw_name.magenta().bold(),
                    ports_tag,
                    descr_tag
                );
            }

            if has_endpoints {
                println!(
                    "{}{}    └── 📱 {}",
                    indent,
                    sub_indent,
                    "Connected Devices Under Switch".bold().yellow()
                );
                for (e_idx, ep) in endpoints.iter().enumerate() {
                    let is_last_ep = e_idx == endpoints.len() - 1;
                    let ep_branch = if is_last_ep { "└──" } else { "├──" };
                    let mut ep_desc = ep.ip.to_string().cyan().bold().to_string();

                    if let Some(ref name) = ep.hostname {
                        ep_desc = format!("{} [{}]", ep_desc, name.magenta().bold());
                    } else if let Some(ref vendor) = ep.vendor {
                        ep_desc = format!("{} ({})", ep_desc, vendor.green());
                    }

                    let ports_str: Vec<String> = ep
                        .open_ports
                        .iter()
                        .map(|p| format!("{}/{}", p.port, p.service))
                        .collect();
                    if !ports_str.is_empty() {
                        ep_desc = format!("{} [{}]", ep_desc, ports_str.join(", ").yellow());
                    } else {
                        ep_desc = format!(
                            "{} [{}]",
                            ep_desc,
                            "Stealth / Firewalled (SNMP ARP)".dimmed().italic()
                        );
                    }

                    println!("{}{}        {} {}", indent, sub_indent, ep_branch, ep_desc);
                }
            }
        }
    }

    // Render physical unmanaged switches if provided
    if has_switches_section {
        println!(
            "└── 🔀 {}",
            "Physical Switches (Unmanaged Layer 2)".bold().yellow()
        );
        for (i, sw) in physical_switches.iter().enumerate() {
            let branch = if i == physical_switches.len() - 1 {
                "    └──"
            } else {
                "    ├──"
            };
            println!("{} {}", branch, sw.blue().bold());
        }
    }
}
