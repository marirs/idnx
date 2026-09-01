# idNX Development Roadmap

This document outlines the milestones and release goals for the **idNX** project.

---

## 🎯 Release Milestones

### Milestone 1: Core Async Scanner Foundation -> [COMPLETED]
- [x] Initial Cargo project scaffolding & repository structure.
- [x] Dual Library (`src/lib.rs`) + CLI Binary (`src/main.rs`) crate architecture.
- [x] High-visibility ASCII art terminal banner integration.
- [x] CLI argument parsing (`clap` derive) for CIDR targets, ports, timeouts, concurrency.
- [x] Active local network & interface auto-detection with real-time Link Speed & PHY rate detection.
- [x] High-concurrency async TCP connect port scanner (`tokio`).
- [x] Active host discovery (TCP connect / RST alive detection + stealth ICMP echo sweep fallback).
- [x] Responsive terminal status output & formatted table (`indicatif` & `comfy-table`).
- [x] Multi-format export engine (`--output json|yaml|xml|csv|text`) with auto-timestamped naming (`idnx_YYYYMMDD.<ext>`).

### Milestone 2: Infrastructure Fingerprinting & UPnP -> [COMPLETED]
- [x] Gateway detection (detect default gateway via routing table/socket).
- [x] Embedded IEEE OUI vendor database with IEEE 802 randomized MAC identification.
- [x] Management port classifier (SSH 22, Telnet 23, HTTP 80/8080, HTTPS 443/8443, DNS 53).
- [x] Async UPnP / SSDP XML interrogation (extracting manufacturer, model name, and descriptions).
- [x] Dual-mode name synthesis (mDNS `.local` resolution + RFC 1035 Unicast Gateway DNS PTR queries).
- [x] SSH & HTTP application banner grabbing (extracting Linux distros and HTTP server engines).

### Milestone 4: Layer 2 Infrastructure Protocol Decoders -> [COMPLETED]
- [x] Passive & active Layer 2 frame listener on local network interface (macOS BPF + Linux `AF_PACKET`).
- [x] IEEE 802.1AB LLDP frame decoder (Chassis ID, Port ID, System Name, System Description, Capabilities).
- [x] Cisco Discovery Protocol (CDP) frame decoder (Device ID, Port ID, Platform, Version, Native VLAN).
- [x] MikroTik Neighbor Discovery Protocol (MNDP) UDP 5678 listener & parser (Identity, Board, Version).

---

### Milestone 3: Deep SNMP Harvester -> [ACTIVE - NEXT UP]
- [ ] Async SNMP v1/v2c client (compact UDP BER encoder/decoder).
- [ ] Community string sweep (`public`, `private`, user-defined lists).
- [ ] Interface IP Table (`ipAddrTable`) walking for multi-homed VLAN detection.
- [ ] Routing Table (`ipRouteTable` / `inetCidrRouteTable`) extraction to uncover remote subnets.
- [ ] Remote ARP Cache (`ipNetToMediaTable`) harvesting for silent / firewalled stealth devices.

---

### Milestone 5: Recursive Pivot & Visualization -> [PLANNED]
- [ ] Recursive exploration scheduler (`--recursive` flag to queue discovered subnets).
- [ ] Updatable 2-Tier OUI Engine (`idnx update-oui` fetching master OUI database to `~/.cache/idnx/oui.bin`).
- [ ] TLS X.509 Certificate Fingerprinting (Port 443 / 8443 Subject, Issuer, SAN extraction).
- [ ] Network topology graph export (`--format json`, `--export-graph topology.html` / SVG).

---

### Milestone 6: IPv6 Multi-Stack Engine & Neighbor Discovery -> [PLANNED]
- [ ] ICMPv6 Link-Local All-Nodes Multicast Echo Sweep (`ff02::1%<interface>`) for zero-config L2 IPv6 discovery.
- [ ] Cross-platform NDP (Neighbor Discovery Protocol) cache harvesting (`ndp -an` on macOS, `ip -6 neigh` on Linux, `GetIpNetTable2` on Windows).
- [ ] mDNS IPv6 resolution (`[ff02::fb]:5353`) for `AAAA` record extraction.
- [ ] Dual-stack host unification (merging IPv4 and IPv6 addresses under unified MAC-based device nodes).
- [ ] Router Advertisement (RA) prefix listener (`ICMPv6 type 134`) to detect local `/64` network prefixes and default gateways.

---

### Milestone 7: AI Agent & LLM Runtime Fingerprinting -> [PLANNED]
- [ ] Local LLM runtime detector (Ollama `11434`, LM Studio `1234`, vLLM `8000`, LocalAI `8080`, Text-generation-webui `5000`).
- [ ] Active model inventory extractor (`/v1/models` and `/api/tags` to identify loaded models like `llama3.2`, `deepseek-r1`).
- [ ] Model Context Protocol (MCP) server detector (JSON-RPC 2.0 / SSE endpoint discovery).
- [ ] AgentPin standard prober (`.well-known/agent-identity.json`).
- [ ] Dedicated topology category: `🤖 AI Agents & LLM Runtimes` in ASCII tree, tables, and JSON/YAML exports.
