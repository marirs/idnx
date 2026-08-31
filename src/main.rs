use clap::Parser;
use colored::*;

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
    author = "idNX Contributors",
    version = "0.1.0",
    about = "Network Identification & Deep eXploration Tool",
    long_about = "A fast, asynchronous network scanner and deep infrastructure exploration tool in Rust."
)]
struct Cli {
    /// Target CIDR network to scan (e.g. 192.168.1.0/24)
    #[arg(short, long)]
    scan: Option<String>,

    /// Target ports separated by commas (e.g. 22,80,443,161)
    #[arg(short, long, default_value = "21,22,23,25,53,80,161,443,8080,8443")]
    ports: String,

    /// Enable deep infrastructure exploration (SNMP, router & switch interrogation)
    #[arg(long, default_value_t = false)]
    deep: bool,

    /// SNMP community strings for deep exploration (comma-separated)
    #[arg(long, default_value = "public,private")]
    snmp_communities: String,

    /// Recursively scan newly discovered subnets from routing tables
    #[arg(short, long, default_value_t = false)]
    recursive: bool,

    /// Concurrency limit for simultaneous probes
    #[arg(short, long, default_value_t = 256)]
    concurrency: usize,
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

    match &cli.scan {
        Some(target) => {
            println!(
                "{} Target: {} | Ports: {} | Deep Mode: {}",
                "[+]".green().bold(),
                target.yellow().bold(),
                cli.ports.yellow(),
                if cli.deep { "Enabled".green().bold() } else { "Disabled".dimmed() }
            );

            if cli.deep {
                println!(
                    "{} Deep exploration enabled. SNMP communities: {}",
                    "[*]".blue().bold(),
                    cli.snmp_communities.cyan()
                );
            }
            println!("{} Initializing scan engine...", "[*]".blue().bold());
        }
        None => {
            println!(
                "{} No target specified. Run with {} or {} for options.",
                "[!]".yellow().bold(),
                "--scan <CIDR>".cyan(),
                "--help".cyan()
            );
        }
    }
}
