# Deep Infrastructure Exploration Guide

This document explains the technical mechanisms `idNX` uses to infer adjacent networks, cascaded routers, managed switches, and devices that ordinary endpoint probing does not explain.

> **Scope and honesty note.** An endpoint can only see what its own stack, its neighbours and cooperating infrastructure will tell it. idNX knows its directly connected subnets, its kernel routes, its ARP/NDP caches, local broadcast and multicast advertisements, and whatever a router will disclose over SNMP, LLDP/CDP, DHCP or UPnP. It cannot see through a router that discloses nothing. Every network idNX reports carries the evidence source and a confidence grade so you can tell what was observed from what was assumed.

---

## 1. The Core Problem: Multi-Tier Networks & The Perimeter Trap

Traditional network scanners query each IP individually on a single flat subnet. This approach fails in modern segmented and layered environments:

1. **Cascaded & Prosumer Routers**: Users and departments frequently attach downstream routers (e.g. Wi-Fi 6E/7 access points, travel routers, lab subnets). The primary router sees them as a single client IP, hiding all devices attached behind them.
2. **Enterprise Rogue Devices**: Employees or contractors plug unauthorized Wi-Fi routers or unmanaged switches into office wall jacks. An endpoint-only scan sees one IP responding and nothing about the secondary network behind it, unless some adjacent device discloses it.
3. **WAN SPI Firewalls**: Many commercial and prosumer routers (like ASUSWRT) ship with aggressive WAN SPI firewalls enabled by default:
   * All inbound TCP connect attempts from outside the WAN are dropped (no `RST` reply).
   * ICMP echo requests from the WAN are dropped (`Respond to Ping from WAN = No`).
   * Broadcasts and multicast (ARP, mDNS) cannot cross the router boundary.

---

## 2. How idNX Builds Multi-Tier Topology

### 2.1 Evidence Model: Routes and Pivots

Discovery distinguishes two things that are easy to conflate:

* A **route** is a network whose prefix is actually known.
* A **pivot** is a router address we have evidence for, whose attached networks are *not* yet known.

A traceroute hop, an LLDP/CDP management address, a DHCP option 3 router and a UPnP responder are all pivots. They prove a device exists; they say nothing about which prefixes hang off it. idNX interrogates pivots (SNMP) to turn them into routes. It does not widen a router address into an assumed `/24` unless you pass `--infer-hop-subnets`, and results obtained that way are labelled `inferred`.

Every reported network carries a confidence grade:

| Grade | Marker | Meaning |
| --- | --- | --- |
| `verified` | `*` | The local kernel holds a route for it, or we reached it ourselves. |
| `advertised` | `+` | A control-plane source asserted it (SNMP route/address table, LLDP/CDP, DHCP). We believe the device but have not reached the network. |
| `user-supplied` | `=` | You passed it via `--subnets`. |
| `inferred` | `~` | Derived by assumption, never by observation. Opt-in only. |

### 2.2 Gateway Interrogation Order

Deep exploration seeds from the OS default gateway first — it is the one router guaranteed to know what lies upstream — then interrogates every other pivot:

1. OS default gateway (kernel routing table).
2. Kernel routes with an off-subnet next hop.
3. DHCP option 3 routers, read from the lease the OS already holds.
4. LLDP/CDP management addresses from Layer 2 neighbours.
5. UPnP/SSDP responders outside the local subnet.
6. Upstream TTL hops.

Each pivot is queried over **UDP 161**. Candidate gateways are liveness-checked on TCP 80/443/53/22 *and* via a real SNMP exchange; a TCP probe of port 161 is not a valid SNMP check and is not used.

TTL hop discovery needs an off-link destination. idNX takes the first public nameserver from the system resolver configuration rather than shipping a hardcoded third-party address, and **skips hop discovery entirely** when every configured resolver is private. Override with `--trace-target`.

A brute-force `192.168.x.1/.254` sweep is available behind `--heuristic-sweep`. It is guessing, is confined to `192.168.0.0/16`, and everything it produces is graded `inferred`.

### 2.3 Dual-Mode Name Synthesis (Overcoming Multicast Barriers)
* **Local Subnet**: `idNX` uses Multicast DNS (RFC 6762 on `224.0.0.251:5353`) to resolve Apple, Linux, and IoT `.local` names.
* **Cascaded / Routed Subnets**: Because mDNS packets cannot cross routers, `idNX` uses a custom zero-copy **RFC 1035 Unicast DNS PTR resolver**. It directs UDP reverse DNS queries to the subnet's own gateway (typically dnsmasq on port 53), recovering device names across routing boundaries without root privileges. The resolver is chosen deterministically — the subnet gateway first, then the lowest-numbered host offering DNS — so repeated runs on an unchanged network produce identical output.

### 2.4 Layer 2 Link-Layer Frame Capture (LLDP, CDP, MNDP)
In privileged mode (`sudo idnx`), `idNX` taps into the raw network interface using BPF (macOS) and `AF_PACKET` (Linux):
* **IEEE 802.1AB LLDP**: Intercepts advertisements on `01:80:c2:00:00:0e` to read switch chassis IDs, port numbers, and system descriptions.
* **Cisco CDP**: Decodes frames on `01:00:0c:cc:cc:cc` to discover Cisco, Ubiquiti UniFi, and TP-Link Omada switches, their model names, and native VLANs.
* **MikroTik MNDP**: Listens on UDP port 5678 for RouterOS broadcast beacons.

Capture reveals the neighbours that advertise on the link idNX is bound to. That is the device on the other end of your cable plus anything else advertising in that broadcast domain — it is not a full switch-to-switch fabric reconstruction. Management addresses learned here are fed back into discovery as pivots.

### 2.5 Stealth ICMP Echo Fallbacks
For devices on routed subnets that have no open TCP ports or drop SYN packets, `idNX` runs parallel ICMP echo sweeps with dynamic timeout clamping (`.clamp(300, 1500)`), capturing stealth endpoints that standard port scanners skip.

---

## 3. The Role of Milestone 3: Deep SNMP Harvesting

When a router has its WAN firewall in strict stealth mode (dropping both TCP and ICMP from the WAN, as observed with default ASUSWRT settings):
* The device is invisible to direct Layer 3 packets originating from upstream.
* **However, the upstream switch or gateway knows about it.**

### How SNMP Bridges the Gap:
1. **ARP Cache Walking (`ipNetToMediaTable` — `1.3.6.1.2.1.4.22`)**:
   An upstream managed switch or gateway router keeps a live hardware ARP table of every MAC and IP communicating across its ports. Querying this MIB table extracts a silent device's IP and MAC without that device answering a packet itself. Hosts recovered this way are then actively probed for ports and services.
2. **Interface Address Table (`ipAddrTable` — `1.3.6.1.2.1.4.20`)**:
   The router's own interface addresses and masks. This is the strongest evidence of the networks it is *directly attached to*, and the router's exact address on each is known rather than guessed.
3. **Routing Table Extraction (`ipRouteTable` — `1.3.6.1.2.1.4.21`)**:
   Everything the router forwards toward, including networks reached via a further next hop. A zero next hop means the route is directly connected on the queried router.

Both tables are graded `advertised`, not `verified`: the device asserted them, and idNX has not yet reached them itself. Reaching a network during the subsequent scan is what promotes it to `verified`.

### Requirements and limits

SNMP is the mechanism that makes cascading real, and most consumer routers ship with it **disabled**. Where SNMP is off and no other control-plane source discloses anything, idNX will report the local subnet and whatever its kernel routes cover — which is the honest answer, not a failure. SNMPv3, BRIDGE-MIB forwarding tables and LLDP-MIB are not yet implemented; see the roadmap.
