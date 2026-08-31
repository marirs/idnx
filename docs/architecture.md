# idNX Architecture & Design Specification

This document details the architectural design, concurrency model, and data flow of **idNX**.

---

## 1. System Overview

idNX is architected around a multi-stage, event-driven pipeline written in asynchronous Rust on top of `tokio`.

```
               ┌───────────────────────────────┐
               │         CLI / Config          │
               │   (clap derive, args, opts)   │
               └───────────────┬───────────────┘
                               │
                               ▼
               ┌───────────────────────────────┐
               │       Scan Coordinator        │
               │  - Subnet Queue / Scheduler   │
               │  - Deduplication Cache        │
               └───────┬───────────────┬───────┘
                       │               │
      Stage 1: Primary │               │ Stage 2: Deep Infrastructure
      Data-Plane Probe │               │ Control-Plane Interrogation
                       ▼               ▼
         ┌───────────────────┐   ┌───────────────────────────┐
         │ Fast Host & Port  │   │  Deep Exploration Engine  │
         │ Discovery Worker  │   │  • SNMP Walker (MIB-II)   │
         │ • TCP SYN/Connect │   │  • UPnP/SSDP Interrogator │
         │ • ICMP / ARP Ping │   │  • L2 Sniffer (LLDP/CDP)  │
         └─────────┬─────────┘   └─────────────┬─────────────┘
                   │                           │
                   └───────────┬───────────────┘
                               ▼
               ┌───────────────────────────────┐
               │    Topology & Graph Store     │
               │  - Device Model (Role, OUI)   │
               │  - Interfaces & VLANs         │
               │  - Harvested Remote Hosts     │
               └───────────────┬───────────────┘
                               │
                               ▼
               ┌───────────────────────────────┐
               │        Output Formatter       │
               │  • ASCII / Colored Terminal   │
               │  • JSON / GraphViz DOT        │
               └───────────────────────────────┘
```

---

## 2. Core Modules

### 2.1 `engine`
- **`scanner`**: Responsible for driving the data-plane sweeps across given CIDR blocks. Uses bounded worker pools (semaphores) to ensure high concurrency without exhausting file descriptors or flooding local network buffers.
- **`coordinator`**: Manages the life cycle of discovered targets, preventing duplicate probes and feeding newly discovered subnets into the scheduler when running with `--recursive`.

### 2.2 `probes`
- **`tcp`**: High-speed asynchronous TCP connect and half-open SYN probes.
- **`snmp`**: Asynchronous SNMP v1/v2c client that walks IP-MIB, Route-MIB, and ARP tables using compact ASN.1 BER encoding.
- **`l2`**: Raw packet capture and broadcast parser for 802.1AB LLDP, Cisco CDP, and MikroTik MNDP.
- **`upnp`**: SSDP M-SEARCH multicast engine with XML descriptor parsing.

### 2.3 `fingerprint`
- **`oui`**: In-memory prefix tree / hash map of IEEE Organizationally Unique Identifiers (MAC vendors) to classify switch and router hardware (Cisco, Ubiquiti, Juniper, MikroTik, HP/Aruba, etc.).
- **`service`**: Identifies administrative interfaces (SSH, Telnet, HTTP/HTTPS WebFig/LuCI/pfSense, Winbox, SNMP).

### 2.4 `topology`
- Represents the network as an in-memory directed graph:
  - **Nodes**: Subnets, Routers, Switches, Hosts, Interfaces.
  - **Edges**: `routes_to`, `connected_to_port`, `member_of_vlan`, `discovered_via_arp`.

---

## 3. Concurrency & Resource Management

1. **File Descriptor Limits**:
   - `tokio::sync::Semaphore` caps the maximum number of concurrent in-flight sockets (e.g., default 512, configurable via `--concurrency`).
2. **Packet Rate Limiting**:
   - Token bucket / rate-limiter prevents triggering network intrusion detection or overwhelming intermediate switch buffers.
3. **Privilege Decoupling**:
   - **Unprivileged Mode (default)**: Operates using standard POSIX `TcpStream` and UDP sockets without requiring `sudo` / root.
   - **Raw Socket Mode (optional / `--raw`)**: Leverages `pnet` for raw ARP sweeps and L2 frame sniffing.
