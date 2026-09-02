use idnx::{engine, net, output, providers};

use clap::Parser;
use colored::*;
use std::time::Duration;

const BANNER_ART: &str = r#"
  _     _ _   _  __  __
 (_) __| | \ | | \ \/ /
 | |/ _` |  \| |  \  /
 | | (_| | |\  |  /  \
 |_|\__,_|_| \_| /_/\_\"#;

/// Command line surface.
///
/// Deliberately small. Options express operator intent — where to start, what to emit —
/// and never discovery mechanics. Recursion, observation lifetime, worker count, provider
/// selection and stopping conditions belong to the engine, so there is no `--recursive`,
/// `--threads`, `--listen-seconds`, `--heuristic-sweep` or `--no-deep` to get wrong.
#[derive(Parser, Debug)]
#[command(
    name = "idnx",
    author = "Sriram <marirs@gmail.com>",
    version,
    about = "Network topology discovery",
    long_about = "Maps the network topology observable from a chosen vantage point.\n\
                  Run `idnx` to start from the interface carrying the default route, or\n\
                  name an interface or network to start somewhere else. Discovery depth,\n\
                  provider selection and concurrency are handled automatically."
)]
struct Cli {
    /// Interface or network to start from (e.g. `en0`, `eth1`, `10.20.0.0/16`).
    /// Defaults to the interface carrying the default route.
    #[arg(value_name = "INTERFACE|NETWORK")]
    start: Option<String>,

    /// Export results in the given format (json, yaml, xml, csv, text).
    #[arg(short = 'o', long = "output", value_enum)]
    output: Option<idnx::output::export::OutputFormat>,

    /// Write the export to this path instead of the default timestamped filename.
    #[arg(long = "output-file")]
    output_file: Option<String>,

    /// Export an interactive HTML topology graph.
    #[arg(long = "export-graph")]
    export_graph: Option<String>,

    /// Per-probe timeout in milliseconds.
    #[arg(short, long, default_value_t = 800)]
    timeout: u64,

    /// SNMP community strings to try, when you have them. SNMP is one optional source
    /// among many; discovery does not depend on it.
    #[arg(long)]
    snmp_community: Vec<String>,

    /// List local network interfaces and exit.
    #[arg(long)]
    list_interfaces: bool,

    /// Download and update the IEEE OUI vendor registry, then exit.
    #[arg(long = "update-oui")]
    update_oui: bool,
}

fn print_banner() {
    println!(
        "{}  {}\n",
        BANNER_ART.trim_matches('\n').cyan().bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).cyan().bold()
    );
}

/// True when the process can open raw sockets for link-layer capture.
///
/// Privileges only ever *add* sources. They never change the workflow or its scope.
fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        // Safe: geteuid cannot fail and touches no memory we own.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn main() {
    // Worker count is derived, not configured: the operator has no way to know a better
    // value than the machine reports, and a wrong one silently degrades the run.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, 32);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!(
                "{} Failed to start async runtime: {}",
                "[!]".red().bold(),
                e
            );
            std::process::exit(1);
        }
    };

    runtime.block_on(run());
}

async fn run() {
    let cli = Cli::parse();
    print_banner();

    if cli.list_interfaces {
        list_interfaces();
        return;
    }

    if cli.update_oui {
        update_oui().await;
        return;
    }

    let privileged = is_privileged();

    // Resolve where to start. This only moves the starting point; the workflow that runs
    // from it is always the same.
    let start = match net::vantage::resolve_starting_scope(cli.start.as_deref(), privileged) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} {}", "[!]".red().bold(), e);
            std::process::exit(1);
        }
    };

    println!(
        "{} Starting from {} ({})",
        "[*]".blue().bold(),
        start.vantage.label().cyan().bold(),
        start.reason
    );
    if !privileged {
        println!(
            "    {}",
            "Unprivileged: link-layer observation unavailable. `sudo idnx` adds it.".dimmed()
        );
    }

    let mut context = providers::DiscoveryContext::seed(
        start.vantage.clone(),
        Duration::from_millis(cli.timeout),
        256,
    );
    context.privileged = privileged;
    context.snmp_communities = cli.snmp_community.clone();

    // Physical link characteristics of the chosen vantage.
    if let Some(speed) = net::link_speed::get_interface_link_speed(&start.vantage.interface) {
        println!(
            "{} Link: {}",
            "[*]".blue().bold(),
            speed.speed_display.green().bold()
        );
    }

    // Passive observation opens now and runs alongside everything else. It is
    // opportunistic: nothing waits on it, and there is no listening period to sit through.
    //
    // A device is opened only where the vantage can actually carry link-layer evidence.
    // Attempting capture on a tunnel or an unprivileged run reports a failure for something
    // that was never applicable, which is noise rather than a finding.
    let observation = std::sync::Arc::new(if start.vantage.capture_available {
        providers::passive::PassiveObservation::start(&start.vantage.interface)
    } else {
        providers::passive::PassiveObservation::not_applicable(
            &start.vantage.interface,
            if privileged {
                format!(
                    "not applicable from a {} vantage",
                    start.vantage.kind.label()
                )
            } else {
                "requires elevated privileges".to_string()
            },
        )
    });

    // The engine owns the observation's lifecycle: it polls before every convergence
    // decision and stops capture itself, so no frame is stranded in the buffer.
    let mut engine = engine::orchestrator::DiscoveryEngine::new(
        providers::local::local_providers(),
        providers::network::network_providers(),
    );
    if observation.is_running() {
        engine = engine.with_continuous_source(
            observation.clone() as std::sync::Arc<dyn providers::ContinuousSource>
        );
    }

    println!("{} Discovering topology...", "[*]".blue().bold());
    let mut report = engine.run(context, start.network).await;

    if let Some(reason) = observation.unavailable_reason() {
        report
            .visibility
            .unavailable
            .push(format!("passive capture: {reason}"));
    } else {
        // Read only after the engine stopped capture, so both counts are final.
        debug_assert!(observation.is_stopped());
        report.visibility.observed_frames = Some(observation.frames_seen());
        report.visibility.accepted_facts = Some(observation.facts_accepted());
    }

    output::topology_view::render(&report, &start);

    if let Some(format) = cli.output {
        match output::export::export(&report, format, cli.output_file.as_deref()) {
            Ok(path) => println!(
                "\n{} Exported to {}",
                "[+]".green().bold(),
                path.display().to_string().cyan().bold()
            ),
            Err(e) => eprintln!("\n{} Export failed: {}", "[!]".red().bold(), e),
        }
    }

    if let Some(ref graph_path) = cli.export_graph {
        let path = std::path::Path::new(graph_path);
        match output::graph::export_interactive_topology_html(&report, path) {
            Ok(()) => println!(
                "{} Interactive topology written to {}",
                "[+]".green().bold(),
                graph_path.cyan().bold()
            ),
            Err(e) => eprintln!("{} Graph export failed: {}", "[!]".red().bold(), e),
        }
    }
}

fn list_interfaces() {
    match net::interface::list_ipv4_interfaces() {
        Ok(ifaces) => {
            println!("{}", "Local IPv4 interfaces:".green().bold());
            for iface in ifaces {
                let kind = net::vantage::classify_interface(&iface.interface_name);
                println!(
                    "  • {:<10} {:<18} {:<18} {}",
                    iface.interface_name.cyan().bold(),
                    iface.ip.to_string().yellow(),
                    iface.cidr.to_string(),
                    kind.label().dimmed()
                );
            }
        }
        Err(e) => {
            eprintln!("{} Failed to list interfaces: {}", "[!]".red().bold(), e);
            std::process::exit(1);
        }
    }
}

async fn update_oui() {
    println!(
        "{} Downloading the IEEE OUI registry...",
        "[*]".blue().bold()
    );
    match idnx::fingerprint::oui::update_oui_database().await {
        Ok(count) => println!(
            "{} Indexed {} vendors.",
            "[+]".green().bold(),
            count.to_string().cyan().bold()
        ),
        Err(e) => {
            eprintln!("{} Update failed: {}", "[!]".red().bold(), e);
            std::process::exit(1);
        }
    }
}
