# Deep Infrastructure Exploration Guide

This document explains the technical mechanisms `idNX` uses to extract hidden networks, cascaded routers, managed switches, and silent devices.

---

## 1. The Core Problem: Multi-Tier Networks & The Perimeter Trap

Traditional network scanners query each IP individually on a single flat subnet. This approach fails in modern segmented and layered environments:

1. **Cascaded & Prosumer Routers**: Users and departments frequently attach downstream routers (e.g. Wi-Fi 6E/7 access points, travel routers, lab subnets). The primary router sees them as a single client IP, hiding all devices attached behind them.
2. **Enterprise Rogue Devices**: Employees or contractors plug unauthorized Wi-Fi routers or unmanaged switches into office wall jacks. Traditional scanners only see one IP responding, completely oblivious to the rogue secondary network behind it.
3. **WAN SPI Firewalls**: Many commercial and prosumer routers (like ASUSWRT) ship with aggressive WAN SPI firewalls enabled by default:
   * All inbound TCP connect attempts from outside the WAN are dropped (no `RST` reply).
   * ICMP echo requests from the WAN are dropped (`Respond to Ping from WAN = No`).
   * Broadcasts and multicast (ARP, mDNS) cannot cross the router boundary.

---

## 2. How idNX Synthesizes Multi-Tier Topology

`idNX` attacks this problem from four angles:

### 2.1 RFC 1918 Gateway Traversal
When deep exploration is active, `idNX` probes standard RFC 1918 gateway candidates (`192.168.x.1`, `10.x.x.1`, `172.16.x.1`). When a responsive gateway or managed switch is found (e.g. `192.168.1.1` or `192.168.70.1`), `idNX`:
1. Identifies the gateway type (router vs. managed switch).
2. Probes the management endpoints (HTTP/HTTPS, SSH, Telnet, SNMP).
3. Automatically queues the discovered subnet for recursive discovery.

### 2.2 Dual-Mode Name Synthesis (Overcoming Multicast Barriers)
* **Local Subnet**: `idNX` uses Multicast DNS (RFC 6762 on `224.0.0.251:5353`) to resolve Apple, Linux, and IoT `.local` names.
* **Cascaded / Routed Subnets**: Because mDNS packets cannot cross routers, `idNX` uses a custom zero-copy **RFC 1035 Unicast DNS PTR resolver**. It directs UDP reverse DNS queries directly to the subnet gateway's DNS daemon (e.g. dnsmasq on `192.168.1.1:53`), extracting device names (`507-Appt-Room`, `dmaker-fan`, `spark-48f8`, `Mac-mini`) across routing boundaries without root privileges.

### 2.3 Layer 2 Link-Layer Frame Capture (LLDP, CDP, MNDP)
In privileged mode (`sudo idnx`), `idNX` taps into the raw network interface using BPF (macOS) and `AF_PACKET` (Linux):
* **IEEE 802.1AB LLDP**: Intercepts advertisements on `01:80:c2:00:00:0e` to read switch chassis IDs, port numbers, and system descriptions.
* **Cisco CDP**: Decodes frames on `01:00:0c:cc:cc:cc` to discover Cisco, Ubiquiti UniFi, and TP-Link Omada switches, their model names, and native VLANs.
* **MikroTik MNDP**: Listens on UDP port 5678 for RouterOS broadcast beacons.

### 2.4 Stealth ICMP Echo Fallbacks
For devices on routed subnets that have no open TCP ports or drop SYN packets, `idNX` runs parallel ICMP echo sweeps with dynamic timeout clamping (`.clamp(300, 1500)`), capturing stealth endpoints that standard port scanners skip.

---

## 3. The Role of Milestone 3: Deep SNMP Harvesting

When a router has its WAN firewall in strict stealth mode (dropping both TCP and ICMP from the WAN, as observed with default ASUSWRT settings):
* The device is invisible to direct Layer 3 packets originating from upstream.
* **However, the upstream switch or gateway knows about it.**

### How SNMP Bridges the Gap:
1. **ARP Cache Walking (`ipNetToMediaTable` - `1.3.6.1.2.1.4.22`)**:
   The upstream managed switch (`192.168.70.1`) and gateway router (`192.168.1.1`) keep a live hardware ARP table of every MAC and IP address communicating across their ports. By querying this MIB table via SNMP, `idNX` extracts the stealth router's IP and MAC without needing the router itself to answer a single packet!
2. **Routing Table Extraction (`ipRouteTable` / `inetCidrRouteTable`)**:
   Extracting the router's routing table reveals downstream next-hop subnets (e.g. `192.168.50.0/24`) even if they are shielded behind a firewall.
