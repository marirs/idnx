mod engine;
mod fingerprint;
mod net;
mod output;

use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

const BANNER: &str = r#"
  _     _ _   _  __  __
 (_) __| | \ | | \ \/ /
 | |/ _` |  \| |  \  / 
 | | (_| | |\  |  /  \ 
 |_|\__,_|_| \_| /_/\_\  v0.1.0
"#;

#[derive(Parser, Debug)]
#[command(
    name = "idnx",
    author = "Sriram <marirs@gmail.com>",
    version = "0.1.0",
    about = "Network Identification & Deep eXploration Tool",
    long_about = "A fast, asynchronous network scanner and deep infrastructure exploration tool in Rust."
)]
struct Cli {
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

    /// Enable deep infrastructure exploration (SNMP, router & switch interrogation)
    #[arg(long, default_value_t = false)]
    deep: bool,

    /// SNMP community strings for deep exploration (comma-separated)
    #[arg(long, default_value = "public,private")]
    snmp_communities: String,

    /// Recursively scan newly discovered subnets from routing tables
    #[arg(short, long, default_value_t = false)]
    recursive: bool,

    /// List all local network interfaces and exit
    #[arg(long, default_value_t = false)]
    list_interfaces: bool,
}

fn print_banner() {
    println!("{}", BANNER.cyan().bold());
    println!(
        "{} {}\n",
        "⚡ idNX:".bold(),
        "Network Identification & Deep eXploration Tool".italic()
    );
}

#[tokio::main]
async fn main() {
    print_banner();

    let cli = Cli::parse();

    if cli.list_interfaces {
        println!("{} Enumerating local IPv4 interfaces:\n", "[*]".blue().bold());
        match net::interface::list_ipv4_interfaces() {
            Ok(ifaces) => {
                for iface in ifaces {
                    println!(
                        "  • {} -> IP: {} | Mask: {} | Subnet: {}",
                        iface.interface_name.green().bold(),
                        iface.ip.to_string().yellow(),
                        iface.netmask.to_string().dimmed(),
                        iface.cidr.to_string().cyan()
                    );
                }
            }
            Err(e) => eprintln!("{} Error reading interfaces: {}", "[!]".red().bold(), e),
        }
        return;
    }

    let target_input = cli.scan.as_deref().or(if cli.interface.is_some() {
        None
    } else {
        Some("auto")
    });

    let (target_cidr, local_info_opt) =
        match net::interface::resolve_target(target_input, cli.interface.as_deref()) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("{} Target resolution failed: {}", "[!]".red().bold(), e);
                std::process::exit(1);
            }
        };

    let iface_filter = local_info_opt.as_ref().map(|info| info.interface_name.as_str());

    if let Some(ref info) = local_info_opt {
        println!(
            "{} Target network on {}: {} (Subnet: {})",
            "[*]".blue().bold(),
            info.interface_name.green().bold(),
            format!("{}/{}", info.ip, info.prefix_len).yellow(),
            info.cidr.to_string().cyan().bold()
        );
    }

    let ports = match engine::scanner::parse_ports(&cli.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Invalid port specification: {}", "[!]".red().bold(), e);
            std::process::exit(1);
        }
    };

    println!(
        "{} Target: {} ({} hosts) | Ports: {} probed | Concurrency: {} | Timeout: {}ms",
        "[+]".green().bold(),
        target_cidr.to_string().yellow().bold(),
        target_cidr.hosts().count(),
        ports.len().to_string().cyan().bold(),
        cli.concurrency.to_string().cyan(),
        cli.timeout
    );

    if cli.deep {
        println!(
            "{} Deep mode enabled. SNMP communities: {}",
            "[*]".blue().bold(),
            cli.snmp_communities.cyan()
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

    // 1. Render Network Topology Tree
    output::tree::print_topology_tree(&target_cidr, local_info_opt.as_ref(), &summary);

    // 2. Render Detailed Results Table
    output::terminal::print_scan_results(&summary);
}
