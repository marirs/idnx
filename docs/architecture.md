# idNX Architecture & Design Specification

This document details the architectural design, concurrency model, modular crate structure, and data flow of **idNX**.

---

## 1. System Overview

idNX is architected as a high-performance, asynchronous Rust library (`idnx`) with a paired command-line interface (`idnx` binary).

```text
               ┌───────────────────────────────────────────┐
               │        CLI Binary (src/main.rs)           │
               │        - clap derive, args, banner        │
               │        - Link speed display, progress bar │
               └─────────────────────┬─────────────────────┘
                                     │
                                     ▼
               ┌───────────────────────────────────────────┐
               │        idNX Library (src/lib.rs)          │
               │      Public APIs & Module Pipeline        │
               └───────┬───────────────────────────┬───────┘
                       │                           │
      Stage 1: Primary │                           │ Stage 2: Deep Infrastructure
      Data-Plane Probe │                           │ Control-Plane Interrogation
                       ▼                           ▼
         ┌─────────────────────────┐   ┌───────────────────────────┐
         │ Fast Host & Port Engine │   │  Deep Exploration Engine  │
         │ • L2 ARP & Ping Sweep   │   │  • L2 Sniffer (LLDP/CDP)  │
         │ • Parallel TCP Connect  │   │  • MikroTik MNDP (UDP)    │
         │ • Dual mDNS & DNS PTR   │   │  • UPnP / SSDP XML Query  │
         │ • Banner Grabbing       │   │  • Gateway Explorer       │
         └─────────────┬───────────┘   └─────────────┬─────────────┘
                       │                             │
                       └───────────────┬─────────────┘
                                       ▼
               ┌───────────────────────────────────────────┐
               │         Topology & Output Engine          │
               │  - Device Role Classifier (classifier.rs) │
               │  - IEEE OUI Database (oui.rs)             │
               │  - Unified Topology Tree (tree.rs)        │
               │  - Terminal Results Table (terminal.rs)   │
               └───────────────────────────────────────────┘
```

---

## 2. Core Modules (`idnx::*`)

### 2.0 `topology` and `providers`

* **`topology::evidence`**: The single record every source emits. A provider cannot report a
  result any other way, which structurally prevents a working decoder from feeding nothing.
* **`topology::graph`**: Correlates evidence into nodes and relationships, owns device
  identity (addresses merge onto one device via MAC), and enforces two rules: a network node
  requires prefix-bearing evidence, and loopback/link-local/multicast ranges are not topology.
* **`topology::role`**: Scores device roles from corroborated behaviour with explicit
  weights. Manufacturer is never an input.
* **`providers`**: One trait for local, credential-free network, passive and optional
  amplifier sources. No vendor is privileged in the graph or the scheduler.


### 2.1 `engine`
* **`scanner`**: Data-plane probing used for *enrichment only*. Host sweeps, TCP connect probes and ICMP fallbacks validate and describe devices that discovery has already found; they are not a discovery mechanism.
* **`orchestrator`**: The automatic discovery engine. Runs every applicable provider to a fixed point over each discovered network and infrastructure device, under a bounded safety budget. Recursion is internal and always enabled; there is no depth or thread count to configure.

### 2.2 `probes`
* **`lldp`**: Berkeley Packet Filter (macOS `/dev/bpf*`) and raw packet socket (Linux `AF_PACKET`) frame listener that decodes IEEE 802.1AB LLDP TLVs (Chassis ID, Port ID, System Name, System Description, Capabilities).
* **`cdp`**: Cisco Discovery Protocol frame decoder for LLC/SNAP encapsulated packets (`01:00:0c:cc:cc:cc`, protocol `0x2000`). Extracts device hostname, hardware platform, port ID, and native VLAN.
* **`mndp`**: MikroTik Neighbor Discovery Protocol listener on UDP port 5678. Extracts RouterOS identity, software version, hardware board name, and MAC address.
* **`upnp`**: SSDP multicast (`239.255.255.250:1900`) discovery engine that fetches device XML descriptions to extract manufacturer and model details.
* **`asus`**: Probes ASUSWRT discovery protocol on UDP ports 9999 and 18017.

### 2.3 `net`
* **`interface`**: Cross-platform network interface enumeration and primary route detection (`get_if_addrs` + outbound routing probe).
* **`link_speed`**: Queries the operating system for real-time negotiated physical link speed (e.g. `10 Gbps Full-Duplex` or `1.81 Gbps Wi-Fi 6E 160MHz`).
* **`arp`**: Cross-platform OS kernel ARP table reader:
  * Linux: Reads directly from `/proc/net/arp` (works on minimal/container distros without external tools).
  * macOS: Parses Darwin `arp -a`.
  * Windows: Parses Windows `arp -a` with hyphenated MAC support.
* **`dns`**: High-performance zero-copy Unicast DNS reverse PTR resolver (RFC 1035) that queries subnet gateway DNS servers (e.g. dnsmasq) for hostnames across routed subnets.
* **`mdns`**: Asynchronous Multicast DNS (RFC 6762) reverse PTR resolver on `224.0.0.251:5353`.

### 2.4 `fingerprint`
* **`oui`**: Embedded, binary-searchable IEEE OUI vendor database. Automatically checks for IEEE 802 local/randomized MAC addresses (`mac[0] & 0x02 != 0`).
* **`topology::role`**: Assigns device roles by scoring corroborated behaviour with explicit weights. Manufacturer is never an input; the previous OUI-based classifier has been removed.
* **`tree`**: Renders the complete multi-tier network hierarchy in Unicode showing Gateway $\to$ Workstations $\to$ Smart Devices $\to$ Cascaded & Adjacent Networks.
* **`terminal`**: Renders a synchronized, formatted tabular overview (`comfy-table`) with network origin, IP, hostname, MAC/vendor, open ports, and latency.

---

## 3. Concurrency & Privileges

1. **Privilege Decoupling**:
   * **Unprivileged Mode (Non-Root)**: Uses standard POSIX sockets and ICMP sweeps without requiring `sudo`. Displays a prominent indicator informing the user that raw Layer 2 switch discovery is disabled.
   * **Privileged Mode (`sudo idnx`)**: Opens raw Berkeley Packet Filter (macOS) and `AF_PACKET` raw sockets (Linux) to capture wire-level LLDP and CDP frames.
2. **Resource Throttling**:
   * All network operations use `tokio::sync::Semaphore` to cap in-flight sockets and prevent file descriptor exhaustion or switch buffer overruns.
