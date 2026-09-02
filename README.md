# idNX 🚀
### Network Identification & Deep eXploration Tool


[![CI](https://github.com/marirs/idnx/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/idnx/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-windows%20|%20macos%20|%20linux-blue?logo=gnubash&logoColor=white)

**idNX** is a fast, asynchronous network discovery and deep infrastructure exploration utility and Rust library.

**idNX** is a fast, asynchronous network topology discovery and infrastructure exploration utility and Rust library.

Unlike target-list scanners that require manual subnet inputs, **idNX begins with the active interface and automatically expands into reachable adjacent networks learned from gateways, routing tables, and link-layer advertisements**, producing one correlated topology in a single run.

---

## ⚡ Why idNX? (Topology Inference Through Multiple Signals)

### 1. Zero-Configuration Topology Expansion
> **The Target-List Limitation:** Most command-line scanners report reachable hosts and services on targets explicitly provided by the user. If you have downstream routers, secondary guest APs, or isolated switch management subnets, discovering them typically requires manually configuring multiple scans.
>
> **The idNX Approach:** idNX starts with the active interface, harvests OS kernel routing tables and gateways, probes candidate adjacent subnets across RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and recursively traverses discovered subnets—reconstructing the true multi-tier topology in a single run.

### 2. Rogue Device & Shadow Infrastructure Detection
> **The Visibility Gap:** In corporate, campus, and lab environments, unmanaged Wi-Fi access points, travel routers, or desktop switches are often plugged into office Ethernet ports. Standard endpoint scanners see only an IP responding and cannot explain what is running behind it.
>
> **The idNX Approach:** idNX synthesizes **Layer 2 wire sniffing (LLDP/CDP/MNDP)**, **UPnP hardware XML descriptors**, **ASUS discovery**, **SNMP MIB-II route/ARP harvesting**, and **adjacent gateway sweeps** to uncover hidden downstream networks, identify switch ports, and highlight infrastructure relationships.

---

## 🏗️ How idNX Maps the Network

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                          idNX Discovery Engine                              │
└──────┬──────────────────┬─────────────────┬──────────────────┬──────────────┘
       │                  │                 │                  │
(1) L2 Sniffer     (2) Dual DNS      (3) UPnP / ASUS    (4) Routing Tables &
    LLDP/CDP/MNDP      mDNS + Unicast    Device Hardware    Adjacent Subnet Probes
       │                  │                 │                  │
       ▼                  ▼                 ▼                  ▼
┌──────────────┐   ┌──────────────┐  ┌──────────────┐   ┌─────────────────────┐
│ Switch Ports │   │ Hostnames &  │  │ Model, Serial│   │ Cascaded & Adjacent │
│ & Topologies │   │ IoT Roles    │  │ & Mfg Data   │   │ Subnets Traversed   │
└──────────────┘   └──────────────┘  └──────────────┘   └─────────────────────┘
```

1. **Auto-Detects Local Network & Link Speed:** Immediately detects the active interface, subnet CIDR, and real-time physical link speed (e.g. `10 Gbps Full-Duplex` or `2.16 Gbps Wi-Fi 6E 160MHz`).
2. **Passive & Active Layer 2 Hardware Discovery:** Decodes IEEE 802.1AB **LLDP**, Cisco **CDP**, and MikroTik **MNDP** frames off the wire to map physical switch chassis, port IDs, native VLANs, and RouterOS boards.
3. **Dual-Mode Name Synthesis:** Queries local Multicast DNS (RFC 6762) for `.local` names **and** sends RFC 1035 Unicast DNS PTR queries directly to gateway DNS servers (e.g. dnsmasq) to extract hostnames across routed subnets.
4. **Evidence-Graded Adjacent Subnet Traversal:** Derives adjacent networks from OS routing tables, the DHCP lease, LLDP/CDP management addresses, UPnP responders and SNMP MIB-II tables, then queues them for bounded recursive exploration. Every network is reported with the source that produced it and a confidence grade (`verified`, `advertised`, `user-supplied`, `inferred`), so an assumed network can never be mistaken for an observed one.
5. **Multi-Signal Host Discovery:** Combines ARP, ICMP echo, and TCP SYN probes to maximize coverage of endpoints across different operating systems and firewall profiles.
6. **Hardware Fingerprinting:** Resolves IEEE registered OUIs, flags IEEE 802 randomized private MAC addresses, interrogates UPnP/SSDP XML descriptors, and grabs SSH/HTTP server banners.

---

## ✨ Core Features

- **⚡ Lightning-Fast Asynchronous Engine:** Powered by `tokio` for massive concurrency across wide CIDR blocks.
- **🔌 Multi-Protocol L2 Decoders:**
  - **LLDP (IEEE 802.1AB):** Chassis ID, Port ID, System Name, System Description, Capabilities.
  - **Cisco CDP:** Device ID, Port ID, Platform/Hardware Model, Software Version, Native VLAN.
  - **MikroTik MNDP:** RouterOS Identity, Board Name (e.g. `RB5009`, `hEX`), Version, MAC.
- **🛰️ UPnP / SSDP Hardware Interrogation:** Extracts manufacturer, model name, and descriptions from consumer and enterprise gateways.
- **🔍 Link Negotiation Detection:** Reports real-time physical link speed (Gbps / Mbps / Wi-Fi generation, frequency, and channel width).
- **🤖 AI Agent & LLM Runtime Fingerprinting:** Interrogates local inference engines (Ollama, LM Studio, vLLM, LocalAI), extracts active model catalogues (`/v1/models`, `/api/tags`), detects Model Context Protocol (MCP) servers, and maps AgentPin identities (`.well-known/agent-identity.json`).
- **🌳 Unified Topology Tree & Table:** Synchronized hierarchical view showing Gateways, AI Agents & LLMs, Workstations, Smart Devices, and Cascaded Subnets.
- **💾 Multi-Format Export:** Export complete network inventories to **JSON**, **YAML**, **XML**, **CSV**, or formatted plain **Text** with automatic `idnx_YYYYMMDD.<ext>` timestamping.
- **📦 Dual Library + CLI Binary:** Use as a standalone CLI or embed as a Rust crate in custom automation and future UI applications.

---

## 🛠️ Installation & Build

Ensure Rust is installed:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone and build:
```bash
git clone https://github.com/marirs/idnx.git
cd idnx
cargo build --release
```

Install binary globally:
```bash
sudo cp target/release/idnx /usr/local/bin/
```

---

## 🚀 Usage & Example Commands

`idnx` is designed to work with zero configuration out of the box, while offering granular controls for enterprise auditing and custom sweeps.

### 1. Zero-Config Instant Network Scan
Auto-detects your primary active network interface, discovers your local subnet, inspects link speed, and automatically finds adjacent cascaded subnets:
```bash
idnx
```
> **What it does:** Runs an unprivileged multi-threaded scan on your active interface, identifies live hosts using TCP SYN and ICMP echo fallbacks, queries mDNS and gateway DNS PTR records for hostnames, and interrogates the routers it has evidence for — starting with your OS default gateway — over SNMP to learn what else they are attached to.
>
> **What it does not do:** invent networks. Reaching devices behind a router requires that router (or an adjacent one) to disclose them via SNMP, LLDP/CDP, DHCP or UPnP. Most consumer routers ship with SNMP disabled, in which case idNX reports your local subnet and whatever your kernel routes already cover. Brute-force subnet guessing is available behind `--heuristic-sweep` and everything it produces is graded `inferred`.

### 2. Full Privileged Discovery (Recommended for Switches)
Unlocks raw socket packet capture (BPF on macOS, `AF_PACKET` on Linux) to capture wire-level Layer 2 switch advertisements:
```bash
sudo idnx
```
> **What it does:** Everything in (1), plus listens for IEEE 802.1AB **LLDP** and Cisco **CDP** frames. Identifies connected switch chassis MACs, physical port numbers (e.g. `GigabitEthernet0/1`), native VLANs, and MikroTik **MNDP** identities.

### 3. Multi-Format Asset Inventory Export
Export complete scan results to disk for spreadsheets, SIEM ingestion, or asset databases:
```bash
# Export to JSON (auto-saved as idnx_YYYYMMDD.json)
idnx --output json

# Export to CSV (perfect for Excel / Google Sheets)
idnx --output csv

# Export to YAML or XML
idnx --output yaml
idnx --output xml

# Export to formatted plain text table (without terminal ANSI codes)
idnx --output text

# Export an interactive HTML topology graph (standalone, zero-dependency force-directed map)
idnx --export-graph topology.html

# Export to a custom destination file
sudo idnx --output json --output-file /tmp/datacenter_inventory.json
```
> **What it does:** Dumps every discovered device across all local and cascaded networks—including IP, hostname, MAC address, manufacturer OUI, open ports, status, and round-trip latency—into your chosen format, or visualizes it as an interactive force-directed web graph.

### 4. Targeting a Specific Subnet & Interface
Scan a specific corporate VLAN, secondary network card, or VPN tunnel:
```bash
# Scan a specific /24 subnet
idnx --scan 10.10.20.0/24

# Bind explicitly to a specific interface (e.g. eth1, en5, or utun2)
idnx --scan 192.168.10.0/24 --interface eth1
```
> **What it does:** Overrides the automatic interface detector and directs all probes exclusively across the specified subnet and network adapter.

### 5. High-Concurrency Custom Port Audit
Audit specific service and management ports across large subnets with custom timeouts:
```bash
idnx --scan 172.16.0.0/24 --ports 21,22,23,80,443,8080,8443,9000-9050 --concurrency 512 --timeout 300
```
> **What it does:** Expands the port list to include custom ranges and increases worker threads to 512 simultaneous probes with an aggressive 300ms connection timeout, completing a 254-host multi-port audit in seconds.

### 6. Deep Multi-Subnet Traversal with Physical Switch Documentation
Explicitly specify downstream subnets to explore while labeling physical unmanaged switches in the topology tree:
```bash
sudo idnx --subnets 192.168.50.0/24,192.168.70.0/24 --switches "UGREEN 6-Port PoE Switch, TP-Link TL-SG105"
```
> **What it does:** Traverses your primary network, explores the specified secondary subnets, and places your unmanaged switches directly into the ASCII topology tree hierarchy above their connected endpoints.

### 7. Dual-Stack IPv6 Neighbor Discovery (NDP)
`idnx` automatically discovers active IPv6 endpoints on the local Layer 2 broadcast domain using ICMPv6 all-nodes multicast (`ff02::1`) and cross-platform NDP table synthesis, unifying IPv4 and IPv6 addresses under single host cards:
```bash
# Standard scan automatically unifies dual-stack IPv4 & IPv6 hosts
idnx

# Disable IPv6 neighbor discovery if preferred
idnx --no-ipv6
```

### 8. Updatable 2-Tier IEEE OUI Engine
Download the authoritative IEEE OUI hardware vendor registry to keep local vendor resolutions completely up to date:
```bash
idnx --update-oui
```
> **What it does:** Downloads and compiles the latest IEEE OUI vendor registry to `~/.cache/idnx/oui.txt`, automatically overriding the built-in static table with tens of thousands of newly registered device manufacturers.

### 9. AI Agent & Local LLM Runtime Discovery
`idnx` automatically probes common local AI ports (`11434`, `1234`, `8000`, `8080`) to discover running inference engines, active model catalogues, Model Context Protocol (MCP) streaming endpoints, and AgentPin manifests:
```bash
# Standard scan automatically identifies Ollama, LM Studio, vLLM, and loaded models
idnx

# Targeted scan against local AI cluster nodes
idnx --scan 192.168.1.50-60 --ports 1234,11434,8000
```
> **Output:** Discovered AI hosts are highlighted under `🤖 AI Agents & LLM Runtimes` with active models displayed directly in the tree and table (e.g. `[Ollama v0.5.4] 🧠 Models: deepseek-r1:7b, llama3.2:latest`).

### 10. Interface & Network Inspection
Quickly inspect all detected network interfaces on the local host without scanning:
```bash
idnx --list-interfaces
```
> **What it does:** Displays all IPv4 and IPv6 network adapters, interface names, loopbacks, and associated CIDR network prefixes detected on the machine.

---

## 📦 Using idNX as a Rust Library

`idnx` is structured as a high-performance library (`lib.rs`) alongside the CLI binary (`main.rs`). Add it to your `Cargo.toml`:

```toml
[dependencies]
idnx = "0.2.2"
```

Use the ergonomic `ScannerBuilder` to configure and execute network scans:

```rust
use idnx::ScannerBuilder;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fluent builder pattern to configure scan parameters
    let scanner = ScannerBuilder::new()
        .target("192.168.1.0/24")?
        .ports(&[22, 80, 443, 445, 8080])
        .concurrency(256)
        .timeout(Duration::from_millis(500))
        .deep(true)
        .build()?;

    // 1. Run standard subnet discovery and port sweep
    let summary = scanner.scan().await;
    println!("Found {} active hosts:", summary.active_hosts.len());
    for host in &summary.active_hosts {
        println!(
            "Host: {:15} | Hostname: {:25?} | Vendor: {:?}",
            host.ip, host.hostname, host.vendor
        );
    }

    // 2. Or run full multi-tier infrastructure exploration (cascaded subnets & SNMP)
    let (summary, cascaded) = scanner.scan_deep().await;
    println!("Discovered {} downstream networks", cascaded.len());

    Ok(())
}
```

---

## 📚 Documentation

Deep-dive architectural documentation is in [`docs/`](docs/):

- [**Architecture & Design**](docs/architecture.md): Modular structure, crate layout, and concurrency model.
- [**Deep Exploration Engine**](docs/deep_exploration.md): Multi-tier traversal, control-plane vs. data-plane, and stealth host discovery.
- [**Supported Protocols & MIBs**](docs/protocols.md): LLDP, CDP, MNDP, UPnP, and SNMP OID specifications.
- [**Roadmap & Implementation Plan**](docs/roadmap.md): Current release status and upcoming milestones.

---

## 📜 License

Licensed under the [Apache License, Version 2.0](LICENSE).
