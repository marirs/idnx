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

An LLDP/CDP management address, a DHCP option 3 router, an IPv6 router advertisement and a UPnP InternetGatewayDevice are all pivots. Each proves a device exists and behaves as infrastructure; none says which prefixes hang off it. idNX interrogates pivots to learn that, and never widens a router address into an assumed `/24`.

Every reported network carries a confidence grade:

| Grade | Marker | Meaning |
| --- | --- | --- |
| `observed` | `*` | Seen directly: a frame on the wire, a kernel table entry, or a live response. |
| `advertised` | `+` | A control-plane source asserted it (SNMP route/address table, LLDP/CDP, DHCP). We believe the device but have not reached the network. |
| `user-supplied` | `=` | You named it as the starting point (`idnx 10.20.0.0/16`). |
| `inferred` | `~` | Derived by assumption, never by observation. Opt-in only. |

### 2.1a What passive observation can and cannot establish

Passive capture is opportunistic and vantage-dependent. It reveals only traffic that
reaches the capture point:

| Signal | Establishes | Does not establish |
| --- | --- | --- |
| STP/RSTP BPDU | A bridge exists on this segment, and its claimed bridge/root identity | Routing behaviour, any subnet, or the full fabric beyond what is observed |
| 802.1Q / QinQ tag | The VLAN ID exists on this link | The VLAN's prefix, until DHCP, an RA or IP traffic supplies one |
| DHCP option 1 | A network prefix | Anything about networks the server did not mention |
| DHCP option 3 / 121 | A router, and explicit routes | A prefix for anything else |
| IPv6 RA | The sender is a router (observed) and its claimed prefixes (advertised) | That the prefixes are reachable from here |
| ARP / NDP | An address-to-MAC binding on this segment | Anything across a routing boundary |

A wireless station receives none of the wired link-layer signals. Traffic isolated behind
another router's boundary never arrives at this capture point at all, so listening on the
parent side cannot reveal what that router does not forward.

### 2.2 Unresolved Forwarding Interfaces

The most important thing idNX can report when it *cannot* enumerate what lies behind a
device is that the device is there and that it forwards. A downstream router presents itself
on the parent network as one ordinary client address among many; without an explicit report
it is indistinguishable from a printer.

An interface that forwarded our traffic, or that answered for itself at a gateway-candidate
address, is kept in its own category with the evidence that established it and a plain
statement that nothing disclosed a network behind it:

```
Forwarding interfaces (routing confirmed, ownership unknown) (1)
  ├── 192.168.70.1 [192.168.70.1]
  │     • observed forwarding traffic on a path
  │     downstream prefixes unresolved: no source disclosed a network behind this interface
```

Two things it deliberately does not say. It does not call the device a router: forwarding
one packet proves the interface forwards, and says nothing about who administers it — a
carrier's, a landlord's and the operator's own routers are indistinguishable by hop count.
And it does not call it a NAT boundary, which would be a claim about what lies behind it.

Manufacturer is never part of this. A vendor string identifies who built the hardware; an
ASUS, MikroTik or Ubiquiti OUI on a device that has disclosed nothing produces no boundary,
no router and no evidence of either.

Router evidence, all observed rather than assumed:

| Signal | Weight |
| --- | --- |
| Is this machine's default gateway | 100 |
| Reports IP forwarding over SNMP | 90 |
| Emits spanning-tree BPDUs (bridge, not router) | 90 |
| Advertises a UPnP InternetGatewayDevice | 80 |
| Acts as a DHCP router or server | 80 |
| Sends IPv6 router advertisements, or sets the RFC 4861 `isRouter` bit | 70 |
| LLDP/CDP capability bits | 70 |
| Observed forwarding traffic on a path | 60 |
| Serves DNS *and* a web management interface | 30 |

**Hardware vendor is not on this list and never contributes.** An OUI identifies the
manufacturer only. The threshold requires corroboration, so no single weak signal promotes
a device on its own.

The `isRouter` bit is read strictly from the `Flgs` column of the neighbour table. The
`St` (state) column also uses `R`, there meaning REACHABLE; conflating the two reports
every recently-contacted phone and laptop as network infrastructure.

### 2.3 How Infrastructure Is Interrogated

Discovery seeds from local OS state, then runs a fixed-point loop. Any device that shows
infrastructure behaviour becomes a pivot and is interrogated directly; whatever it discloses
is folded back into the graph, which may produce further networks and further pivots. The
loop ends when a pass adds nothing new, or when the safety budget is reached.

Pivot membership comes from observed behaviour only — being the default gateway, serving
DHCP, advertising as an IPv6 router, announcing a UPnP InternetGatewayDevice, reporting SNMP
forwarding, emitting BPDUs, or LLDP/CDP capability bits. A device is never queued because of
its manufacturer.

SNMP, where a community is available, is queried over **UDP 161**. A TCP probe of port 161 is
not a valid SNMP check and is not used. SNMP is one provider among several: when it does not
answer, every other provider continues and the outcome is reported rather than dropped.

Ordering is deterministic, so two runs over an unchanged network produce the same output.

### 2.4 Dual-Mode Name Synthesis (Overcoming Multicast Barriers)
* **Local Subnet**: `idNX` uses Multicast DNS (RFC 6762 on `224.0.0.251:5353`) to resolve Apple, Linux, and IoT `.local` names.
* **Cascaded / Routed Subnets**: Because mDNS packets cannot cross routers, `idNX` uses a custom zero-copy **RFC 1035 Unicast DNS PTR resolver**. It directs UDP reverse DNS queries to the subnet's own gateway (typically dnsmasq on port 53), recovering device names across routing boundaries without root privileges. The resolver is chosen deterministically — the subnet gateway first, then the lowest-numbered host offering DNS — so repeated runs on an unchanged network produce identical output.

### 2.5 Layer 2 Link-Layer Frame Capture (LLDP, CDP, MNDP)
In privileged mode (`sudo idnx`), `idNX` taps into the raw network interface using BPF (macOS) and `AF_PACKET` (Linux):
* **IEEE 802.1AB LLDP**: Intercepts advertisements on `01:80:c2:00:00:0e` to read switch chassis IDs, port numbers, and system descriptions.
* **Cisco CDP**: Decodes frames on `01:00:0c:cc:cc:cc` to discover Cisco, Ubiquiti UniFi, and TP-Link Omada switches, their model names, and native VLANs.
* **MikroTik MNDP**: Listens on UDP port 5678 for RouterOS broadcast beacons.

**LLDP and CDP do not work over Wi-Fi.** They are link-local multicast frames, and access
points do not bridge them to wireless clients. A capture on a wireless interface finds no
switches regardless of how correct the decoder is, so idNX detects a wireless link and says
so rather than reporting an empty result that looks like "there are no switches". To map
managed switches, run idNX from a host with a wired connection.

Capture reveals the neighbours that advertise on the link idNX is bound to. That is the device on the other end of your cable plus anything else advertising in that broadcast domain — it is not a full switch-to-switch fabric reconstruction. Management addresses learned here are fed back into discovery as pivots.

### 2.6 Stealth ICMP Echo Fallbacks
For devices with no open TCP port, and for addresses the neighbour cache merely remembers,
`idNX` sends a correlated ICMP echo over an interface-bound socket. A reply counts only when
it comes from the address that was asked and carries this run's identifier and sequence; a
probe that could not be sent is recorded as unsent rather than as silence. It does not shell
out to the system `ping` command, which ignores the selected interface and cannot report
which of its probes actually left.

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

Both tables are graded `advertised`, not `observed`: the device asserted them, and idNX has not reached them itself.

### Requirements and limits

SNMP is one of several sources that can disclose a network beyond the attached link, and
most consumer routers ship with it **disabled**. The others carry no credentials at all: RA
prefix and route information options, DHCP option 121/249 classless static routes, passive
RIPv2/RIPng, OSPFv2/v3 and IS-IS, ICMP address mask replies, and bounded reachability
probing of gateway candidates. Cascading does not depend on SNMP, and a run with SNMP
unavailable is not a degraded mode.

Where every source is silent, the forwarding interface stays on the map with its downstream
prefixes recorded as unresolved, rather than being omitted or having a subnet invented for
it.

A downstream NAT router is also, by design, opaque from its WAN side: it will typically
drop inbound connections, expose its UPnP IGD only to its own LAN clients, and answer no
management port. Where no control-plane source discloses the networks behind it, they
cannot be enumerated from the parent network at all - the boundary report is the correct
and complete answer. To map behind it, enable SNMP on the device or run idNX from a host on its LAN. Where SNMP is off and no other control-plane source discloses anything, idNX will report the local subnet and whatever its kernel routes cover — which is the honest answer, not a failure. SNMPv3, BRIDGE-MIB forwarding tables and LLDP-MIB are not implemented; SNMPv1 is refused
rather than parsed. See the roadmap.
