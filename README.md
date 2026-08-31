# idNX 🚀
### Network Identification & Deep eXploration Tool

```text
  _     _ _   _  __  __
 (_) __| | \ | | \ \/ /
 | |/ _` |  \| |  \  / 
 | | (_| | |\  |  /  \ 
 |_|\__,_|_| \_| /_/\_\  v0.1.0
```

**idNX** is a fast, asynchronous network discovery and deep infrastructure exploration utility written in Rust.

While traditional network scanners (like Nmap) focus primarily on data-plane port probing within directly reachable subnets, **idNX digs deeper into the control plane**. When it discovers routers, Layer 3 managed switches, or gateways, it interrogates their management protocols (SNMP, LLDP, CDP, UPnP/SSDP) to harvest hidden VLANs, routing tables, and remote ARP caches—mapping networks you couldn't otherwise see.

---

## ✨ Features

- **⚡ Lightning-Fast Asynchronous Sweeps:** Powered by `tokio` for massive concurrency across wide CIDR blocks.
- **🛰️ Deep Infrastructure Harvesting:**
  - **SNMP Route & Interface Walking:** Extracts all IP interfaces (`ipAddrTable`) and full routing tables (`ipRouteTable` / `inetCidrRouteTable`).
  - **ARP Cache Harvesting:** Dumps the router's active ARP cache (`ipNetToMediaTable`), uncovering live IP/MAC pairs across isolated VLANs without needing direct routing to them.
- **🔍 Layer 2 Discovery:**
  - Passive & active interrogation of LLDP (802.1AB), CDP (Cisco Discovery Protocol), and MNDP (MikroTik Neighbor Discovery Protocol).
  - Uncovers switch ports, neighbor topologies, and native VLAN IDs.
- **📡 UPnP / SSDP Gateway Interrogation:** Queries consumer/prosumer routers for external WAN IPs, gateway configs, and port-forwarding rules.
- **🔄 Recursive Pivot Exploration:** Automatically schedules secondary sweeps against newly discovered internal subnets.
- **🌳 Topology Tree Visualization:** Clean, colorized terminal hierarchy showing Switch ➔ VLAN ➔ Router ➔ Host relationships.
- **📊 Modern CLI & Export:** Rich terminal tables, interactive progress bars, and JSON/graph export options.

---

## 🏗️ Deep Exploration in Action

```
                  ┌──────────────────────────────────────────────┐
                  │                 idNX Scanner                 │
                  └───────┬──────────────┬──────────────┬────────┘
                          │              │              │
                    (1) SNMP       (2) L2 Discovery   (3) UPnP/SSDP
                    UDP 161        CDP/LLDP/MNDP      UDP 1900
                          │              │              │
                          ▼              ▼              ▼
           ┌────────────────────────────────────────────────────────────┐
           │                  Router / Managed Switch                   │
           │                                                            │
           │  • Interface Table    --> VLAN 10 (10.0.10.1), VLAN 20 ... │
           │  • Route Table        --> 10.0.10.0/24, 192.168.20.0/24... │
           │  • ARP Cache (L3)     --> 10.0.10.45 (MAC), 10.0.10.88 ... │
           │  • Bridge FDB (L2)    --> Port 4: MAC a4:b1:..., VLAN 10   │
           └────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Getting Started

### Prerequisites

Ensure the Rust toolchain is installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Installation & Build

```bash
git clone https://github.com/yourusername/idnx.git
cd idnx
cargo build --release
```

To install the binary globally:

```bash
sudo cp target/release/idnx /usr/local/bin/
```

---

## 🚀 Usage

### 1. Basic Host & Port Scan
Perform a high-speed sweep of a target subnet:

```bash
# Scan local subnet for common ports
idnx --scan 192.168.1.0/24 --ports 22,80,443,8080
```

### 2. Deep Infrastructure Exploration
Enable deep exploration to interrogate routers and switches:

```bash
# Deep scan with default SNMP communities ('public', 'private')
idnx --scan 192.168.1.0/24 --deep

# Deep scan with custom SNMP communities and recursive pivot
idnx --scan 10.0.0.0/24 --deep --snmp-communities public,mgmt_ro --recursive
```

### 3. Layer 2 Discovery Mode
Listen for and query LLDP/CDP/MNDP broadcast frames:

```bash
# Listen on interface en0 for switch broadcasts
idnx --discover-l2 --interface en0
```

### 4. JSON Output
Export full network topology and harvested host catalogs:

```bash
idnx --scan 192.168.1.0/24 --deep --json topology.json
```

---

## 📚 Documentation

Deep-dive documentation is available in the [`docs/`](docs/) directory:

- [**Architecture & Design**](docs/architecture.md): Overall modular structure, concurrency model, and data flow.
- [**Deep Exploration Engine**](docs/deep_exploration.md): How SNMP, ARP harvesting, and routing table extraction work under the hood.
- [**Supported Protocols & MIBs**](docs/protocols.md): OID references, Layer 2 packet specifications, and UPnP endpoints.
- [**Roadmap & Implementation Plan**](docs/roadmap.md): Milestones, crate ecosystem choices, and planned features.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
