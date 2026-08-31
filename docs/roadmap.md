# idNX Development Roadmap

This document outlines the milestones and release goals for the **idNX** project.

---

## 🎯 Release Milestones

### Milestone 1: Core Async Scanner Foundation
- [x] Initial Cargo project scaffolding & repository structure.
- [x] High-visibility ASCII art terminal banner integration.
- [x] CLI argument parsing (`clap` derive) for CIDR targets, ports, timeouts, concurrency.
- [ ] High-concurrency async TCP connect port scanner (`tokio`).
- [ ] Active host discovery (ICMP echo / TCP SYN-connect sweep).
- [ ] Responsive terminal status output (`indicatif` progress bars).

### Milestone 2: Infrastructure Fingerprinting & UPnP
- [ ] Gateway detection (detect default gateway via routing table/socket).
- [ ] OUI vendor database integration for MAC address classification.
- [ ] Management port classifier (SSH 22, Telnet 23, HTTP 80/8080, HTTPS 443/8443, SNMP 161, Winbox 8291).
- [ ] Async UPnP/SSDP interrogator (extract WAN IP and internal subnet configs).

### Milestone 3: Deep SNMP Harvester
- [ ] Async SNMP v1/v2c client (compact UDP BER encoder/decoder).
- [ ] Community string sweep (`public`, `private`, user-defined lists).
- [ ] Interface IP Table (`ipAddrTable`) walking for multi-homed VLAN detection.
- [ ] Routing Table (`ipRouteTable` / `inetCidrRouteTable`) extraction.
- [ ] ARP Cache (`ipNetToMediaTable`) harvesting for live remote host inventory.

### Milestone 4: Layer 2 Discovery (LLDP/CDP/MNDP)
- [ ] Passive L2 frame listener on local network interface.
- [ ] LLDP (802.1AB) frame decoder.
- [ ] Cisco CDP frame decoder.
- [ ] MikroTik MNDP UDP broadcast parser.

### Milestone 5: Recursive Pivot & Visualization
- [ ] Recursive exploration scheduler (`--recursive` flag to queue discovered subnets).
- [ ] Network topology graph model (directed graph connecting switches, routers, VLANs, and hosts).
- [ ] Rich ASCII / Unicode topology tree visualization in terminal.
- [ ] JSON and GraphViz DOT export for integration with SIEM/Asset Management tools.
