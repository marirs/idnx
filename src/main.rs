use idnx::{engine, net, output, probes};

use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

const BANNER_ART: &str = r#"
  _     _ _   _  __  __
 (_) __| | \ | | \ \/ /
 | |/ _` |  \| |  \  / 
 | | (_| | |\  |  /  \ 
 |_|\__,_|_| \_| /_/\_\"#;

#[derive(Parser, Debug)]
#[command(
    name = "idnx",
    author = "Sriram <marirs@gmail.com>",
    version,
    about = "Network Identification & Deep eXploration Tool",
    long_about = "A fast, asynchronous network scanner and deep infrastructure exploration tool in Rust."
)]
struct Cli {
    /// Target CIDR network, IP, or interface name to scan (e.g. 192.168.1.0/24 or en0).
    /// If omitted, automatically detects and scans the active local network.
    #[arg(value_name = "TARGET")]
    target: Option<String>,

    /// Target CIDR network, IP, or interface name to scan (e.g. 192.168.1.0/24 or en0).
    /// If flag is specified without an argument, auto-detects the local subnet.
    #[arg(
        short,
        long,
        num_args = 0..=1,
        default_missing_value = "auto"
    )]
    scan: Option<String>,

    /// Specific network interface to target (e.g. en0, eth0, wlan0)
    #[arg(short, long)]
    interface: Option<String>,

    /// Target ports or ranges separated by commas (e.g. 22,80,443 or 80-90 or 'common')
    #[arg(short, long, default_value = "21,22,23,25,53,80,161,443,445,8080,8443")]
    ports: String,

    /// Timeout in milliseconds per port probe
    #[arg(short, long, default_value_t = 800)]
    timeout: u64,

    /// Concurrency limit for simultaneous probes
    #[arg(short, long, default_value_t = 256)]
    concurrency: usize,

    /// Disable deep downstream infrastructure exploration
    #[arg(long, default_value_t = false)]
    no_deep: bool,

    /// Comma-separated list of child/downstream subnets to explore (e.g. 192.168.58.0/24)
    #[arg(long)]
    subnets: Option<String>,

    /// Physical unmanaged switches to document in the topology tree (e.g. "UGREEN 6-Port PoE, TP-Link LS1005")
    #[arg(long)]
    switches: Option<String>,

    /// Export scan results in the specified format (json, yaml, xml, csv, text)
    #[arg(short = 'o', long = "output", value_enum)]
    output: Option<idnx::output::export::OutputFormat>,

    /// Custom output file path (defaults to idnx_YYYYMMDD.<ext>)
    #[arg(long = "output-file")]
    output_file: Option<String>,

    /// SNMP community strings to probe (comma-separated, default: "public,private")
    #[arg(long, default_value = "public,private")]
    snmp_communities: String,

    /// SNMP target UDP port (default: 161)
    #[arg(long, default_value_t = 161)]
    snmp_port: u16,

    /// Disable SNMP deep exploration
    #[arg(long, default_value_t = false)]
    no_snmp: bool,

    /// Export interactive HTML topology graph (e.g. --export-graph topology.html)
    #[arg(long = "export-graph")]
    export_graph: Option<String>,

    /// Recursively pivot into subnets discovered via router routing tables
    #[arg(long, default_value_t = false)]
    recursive: bool,

    /// Maximum recursion depth for discovered subnets (default: 2)
    #[arg(long, default_value_t = 2)]
    max_depth: usize,

    /// Download and update the local IEEE OUI vendor registry (~/.cache/idnx/oui.txt)
    #[arg(long = "update-oui", default_value_t = false)]
    update_oui: bool,

    /// Disable IPv6 neighbor discovery and NDP table harvesting
    #[arg(long = "no-ipv6", default_value_t = false)]
    no_ipv6: bool,

    /// List all local network interfaces and exit
    #[arg(long, default_value_t = false)]
    list_interfaces: bool,
}

fn print_banner() {
    println!(
        "{}  {}\n",
        BANNER_ART.trim_matches('\n').cyan().bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).cyan().bold()
    );
    println!(
        "{} {}\n",
        "⚡ idNX:".bold(),
        "Network Identification & Deep eXploration Tool".italic()
    );
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    // If --list-interfaces requested, display and exit
    if cli.list_interfaces {
        match net::interface::list_ipv4_interfaces() {
            Ok(ifaces) => {
                println!("{}", "Available IPv4 Network Interfaces:".green().bold());
                for iface in ifaces {
                    println!(
                        "  • {:<10} IP: {:<16} Netmask: {:<16} Subnet: {}",
                        iface.interface_name.cyan().bold(),
                        iface.ip.to_string().yellow(),
                        iface.netmask.to_string().dimmed(),
                        iface.cidr.to_string().bold()
                    );
                }
            }
            Err(e) => {
                eprintln!("{} Failed to list interfaces: {}", "[!]".red().bold(), e);
            }
        }
        return;
    }

    // If --update-oui requested, download IEEE registry and exit
    if cli.update_oui {
        println!(
            "{} Downloading master IEEE OUI registry to ~/.cache/idnx/oui.txt...",
            "[*]".blue().bold()
        );
        match idnx::fingerprint::oui::update_oui_database().await {
            Ok(count) => {
                println!(
                    "{} Successfully updated IEEE OUI registry ({} vendors indexed)!",
                    "[+]".green().bold(),
                    count.to_string().cyan().bold()
                );
            }
            Err(e) => {
                eprintln!(
                    "{} Failed to update IEEE OUI registry: {}",
                    "[!]".red().bold(),
                    e
                );
            }
        }
        return;
    }

    // Determine target CIDR network
    let target_input = cli.target.as_deref().or(cli.scan.as_deref());
    let (target_cidr, local_info_opt) =
        match net::interface::resolve_target(target_input, cli.interface.as_deref()) {
            Ok(resolved) => resolved,
            Err(e) => {
                eprintln!("{} Target resolution failed: {}", "[!]".red().bold(), e);
                std::process::exit(1);
            }
        };

    if let Some(ref info) = local_info_opt {
        println!(
            "{} Target network on {}: {} (Subnet: {})",
            "[*]".blue().bold(),
            info.interface_name.cyan().bold(),
            format!("{}/{}", info.ip, info.cidr.prefix_len()).yellow(),
            info.cidr.to_string().bold()
        );
    }

    let ports = match engine::scanner::parse_ports(&cli.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Port parsing error: {}", "[!]".red().bold(), e);
            std::process::exit(1);
        }
    };

    let iface_filter = cli.interface.as_deref().or_else(|| {
        local_info_opt
            .as_ref()
            .map(|info| info.interface_name.as_str())
    });

    let iface_name = iface_filter.unwrap_or("en0");

    if let Some(speed_info) = crate::net::link_speed::get_interface_link_speed(iface_name) {
        println!(
            "{} Interface Link Speed: {}",
            "[*]".blue().bold(),
            speed_info.speed_display.green().bold()
        );
    }

    println!(
        "{} Target: {} ({} hosts) | Ports: {} probed | Concurrency: {} | Timeout: {}ms",
        "[+]".green().bold(),
        target_cidr.to_string().yellow().bold(),
        target_cidr.hosts().count(),
        ports.len().to_string().cyan().bold(),
        cli.concurrency.to_string().cyan(),
        cli.timeout
    );

    // Layer 2 Hardware Discovery (LLDP - IEEE 802.1AB)
    let iface_name = iface_filter.unwrap_or("en0");
    match probes::lldp::capture_lldp_neighbors(iface_name, Duration::from_millis(600)).await {
        probes::lldp::LldpCaptureResult::Success(neighbors) => {
            if !neighbors.is_empty() {
                println!(
                    "{} Captured {} Layer 2 LLDP hardware advertisement(s):",
                    "[+]".green().bold(),
                    neighbors.len().to_string().cyan().bold()
                );
                for n in &neighbors {
                    println!(
                        "    └── 🔌 [{}] Port: {} | System: {} | Desc: {}",
                        n.chassis_id.cyan().bold(),
                        n.port_id.yellow(),
                        n.system_name.as_deref().unwrap_or("Unknown").green().bold(),
                        n.system_description.as_deref().unwrap_or("N/A").dimmed()
                    );
                }
            }
        }
        probes::lldp::LldpCaptureResult::PermissionDenied => {
            println!(
                "{} PRIVILEGED DISCOVERY DISABLED (Non-Root / No Sudo):",
                "[!]".yellow().bold()
            );
            println!(
                "    ├── Layer 2 LLDP/CDP hardware switch discovery: DISABLED (Requires raw BPF / AF_PACKET)"
            );
            println!("    ├── Deep switch port map detection: REDUCED");
            println!(
                "    └── Recommendation: Run with 'sudo idnx' for full infrastructure visibility."
            );
        }
        probes::lldp::LldpCaptureResult::NotSupported(_) => {}
    }

    // MikroTik Neighbor Discovery Protocol (MNDP)
    let mndp_neighbors = probes::mndp::listen_mndp_neighbors(Duration::from_millis(300)).await;
    if !mndp_neighbors.is_empty() {
        println!(
            "{} Discovered {} MikroTik MNDP neighbor(s):",
            "[+]".green().bold(),
            mndp_neighbors.len().to_string().cyan().bold()
        );
        for m in &mndp_neighbors {
            println!(
                "    └── 📡 [{}] Identity: {} | Version: {} | Board: {} | Iface: {}",
                m.mac_address.cyan().bold(),
                m.identity.green().bold(),
                m.software_version.as_deref().unwrap_or("N/A").dimmed(),
                m.board_name.as_deref().unwrap_or("MikroTik").yellow(),
                m.interface_name.as_deref().unwrap_or("N/A")
            );
        }
    }

    if !cli.no_deep {
        println!(
            "{} Deep mode active. Probing router management endpoints and child subnets...",
            "[*]".blue().bold(),
        );
    }

    // Set up progress bar for the scan
    let total_hosts = target_cidr.hosts().count() as u64;
    let pb = ProgressBar::new(total_hosts);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hosts ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let timeout_duration = Duration::from_millis(cli.timeout);
    let summary = engine::scanner::scan_subnet(
        target_cidr,
        &ports,
        iface_filter,
        cli.concurrency,
        timeout_duration,
        Some(pb),
    )
    .await;

    let snmp_comms: Vec<String> = cli
        .snmp_communities
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Explore downstream child networks by default (unless --no-deep specified)
    let child_networks = if !cli.no_deep || cli.subnets.is_some() {
        println!(
            "{} Probing downstream networks and cascaded subnets (SNMP OID MIB-II active)...",
            "[*]".blue().bold()
        );
        let snmp_cfg = engine::deep::SnmpProbeConfig {
            enabled: !cli.no_snmp,
            communities: snmp_comms,
            port: cli.snmp_port,
        };

        engine::deep::explore_downstream_networks(
            &target_cidr,
            cli.subnets.as_deref(),
            &ports,
            cli.concurrency,
            timeout_duration,
            Some(&snmp_cfg),
            cli.recursive,
            cli.max_depth,
        )
        .await
    } else {
        Vec::new()
    };

    let physical_switches: Vec<&str> = cli
        .switches
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(|item| item.trim())
                .filter(|item| !item.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // 1. Render Network Topology Tree
    output::tree::print_topology_tree(
        &target_cidr,
        local_info_opt.as_ref(),
        &summary,
        &physical_switches,
        &child_networks,
    );

    // 2. Render Detailed Results Table
    output::terminal::print_scan_results(&target_cidr, &summary, &child_networks);

    // 3. Export to file if requested
    if let Some(format) = cli.output {
        match output::export::export_results(
            format,
            cli.output_file.as_deref(),
            &target_cidr,
            &summary,
            &child_networks,
        ) {
            Ok(path) => {
                println!(
                    "\n{} Results exported to: {}",
                    "[+]".green().bold(),
                    path.display().to_string().cyan().bold()
                );
            }
            Err(e) => {
                eprintln!("\n{} Export failed: {}", "[!]".red().bold(), e);
            }
        }
    }

    // 4. Export interactive HTML graph if requested
    if let Some(ref graph_path) = cli.export_graph {
        let p = std::path::Path::new(graph_path);
        match output::graph::export_interactive_topology_html(
            &target_cidr,
            &summary,
            &child_networks,
            &physical_switches,
            p,
        ) {
            Ok(_) => {
                println!(
                    "{} Interactive topology graph exported to: {}",
                    "[+]".green().bold(),
                    graph_path.cyan().bold()
                );
            }
            Err(e) => {
                eprintln!("{} Graph export failed: {}", "[!]".red().bold(), e);
            }
        }
    }
}
