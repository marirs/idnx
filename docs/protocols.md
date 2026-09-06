# Supported Protocols & MIB Reference

This document provides a reference for the network protocols, OIDs, and frame specifications utilized by `idNX`.

---

## 1. SNMP MIB OID Reference

idNX targets standard RFC MIBs for maximum cross-vendor compatibility (Cisco, Juniper, HP/Aruba, MikroTik, Ubiquiti, pfSense, Fortinet).

Transport is **SNMP v2c over UDP 161** via a hand-written ASN.1 BER codec. v1 is neither
sent nor accepted — a response declaring version 0 is refused rather than parsed — and
SNMPv3 is not implemented.

Every exchange is validated before anything is read from it: the source address must be the
device asked, the community must match, the PDU must be a GetResponse carrying our
request-id, a GET's returned OID must equal the requested one, exactly one varbind is
accepted, and a datagram larger than the reader's bound is refused rather than truncated.
Container lengths are enforced against their parent, so a nested field cannot claim bytes
belonging to its siblings. Walks are bounded by a step limit, a total deadline and the
per-request timeout clamped to what remains of it; each table's completion is recorded and
reported, so a truncated table is never presented as an exhaustive one.

The **Status** column below is authoritative: ✅ means the OID is walked and its value consumed by the discovery engine today; 📋 means it is a planned target and is *not* currently queried. Do not read a listed OID as an implemented capability.

### 1.1 Interface & Address MIBs
| OID | Name | Status | Description |
|---|---|---|---|
| `1.3.6.1.2.1.1.1.0` | `sysDescr` | ✅ | System hardware and OS description string |
| `1.3.6.1.2.1.1.5.0` | `sysName` | ✅ | Hostname / FQDN of the device |
| `1.3.6.1.2.1.4.20.1.1` | `ipAdEntAddr` | ✅ | IP addresses configured on all interfaces |
| `1.3.6.1.2.1.4.20.1.3` | `ipAdEntNetMask` | ✅ | Subnet masks for each configured interface IP |
| `1.3.6.1.2.1.4.20.1.2` | `ipAdEntIfIndex` | 📋 | Interface index associated with each IP |

### 1.2 Routing Table MIBs
| OID | Name | Status | Description |
|---|---|---|---|
| `1.3.6.1.2.1.4.21.1.1` | `ipRouteDest` | ✅ | Destination IP address / network |
| `1.3.6.1.2.1.4.21.1.7` | `ipRouteNextHop` | ✅ | Next-hop IP address for the route |
| `1.3.6.1.2.1.4.21.1.11` | `ipRouteMask` | ✅ | Subnet mask for the destination network |
| `1.3.6.1.2.1.4.21.1.8` | `ipRouteType` | ✅ | Route type. `invalid(2)` creates nothing at all; `direct(3)` is attachment, `indirect(4)` is forwarding, and a row with no stated type keeps the weaker claim |
| `1.3.6.1.2.1.4.1.0` | `ipForwarding` | ✅ | Whether the device forwards. Required — with usable routing rows — before the SNMP forwarding role signal is emitted |
| `1.3.6.1.2.1.4.24.7.1` | `inetCidrRouteEntry` | ✅ | The version-neutral routing table (RFC 4292). IPv4 and IPv6, indexed by prefix length rather than mask |
| `1.3.6.1.2.1.4.24.4.1` | `ipCidrRouteEntry` | ❌ | The IPv4-only table RFC 4292 deprecated. Not walked: it describes no IPv6 route, so on a dual-stack device it shows half the forwarding state |

### 1.2a `inetCidrRouteTable` (RFC 4292)

Every field identifying a route is in the instance OID, not in a value: RFC 4292 makes the
six index objects not-accessible, so an agent returns only columns 7 upward and the index is
the sole source of the destination, prefix length, policy and next hop. Reading that index
wrongly does not fail loudly -- it produces a plausible route to a network nobody mentioned --
so it is parsed exactly and refused where it does not account for every subidentifier.

Index layout, each variable-length element preceded by its length (no `IMPLIED` element
exists in this table): destination type, destination, prefix length, policy OID, next-hop
type, next-hop address.

Address encodings are RFC 4001, with the length fixed by the type: `ipv4(1)` 4 octets,
`ipv6(2)` 16, `ipv4z(3)` 8 (address and a four-octet zone index), `ipv6z(4)` 20, `unknown(0)`
zero. `dns(16)` is refused, since a name in a routing table cannot be resolved to a route.

| Column | Name | Status | What it contributes |
|---|---|---|---|
| `.7` | `inetCidrRouteIfIndex` | ✅ | Retained in provenance |
| `.8` | `inetCidrRouteType` | ✅ | Decides what the row may state, below |
| `.9` | `inetCidrRouteProto` | ✅ | Retained in provenance |
| `.12` | `inetCidrRouteMetric1` | ✅ | Retained in provenance |
| `.17` | `inetCidrRouteStatus` | ✅ | An explicitly decoded `active(1)` is required before anything is promoted |

What each `inetCidrRouteType` is allowed to establish:

* `local(3)` -- attachment. The destination is on one of the device's own interfaces.
* `remote(4)` -- a route, with a next hop this crate can identify.
* `reject(2)` and `blackhole(5)` -- policy evidence only. Matching traffic is discarded, so
  no network, no attachment and no route: the prefix may not exist anywhere.
* `other(1)`, or no type returned -- a route with its directness unstated. It never claims
  attachment.
* A type outside the enumeration, or of the wrong syntax -- nothing. A value this code cannot
  interpret is a statement it failed to read, not one the agent declined to make, so it does
  not take the directness-unstated path.

`remote(4)`, `other(1)` and an absent type promote a route **only** where the next hop is an
address this crate can identify. A zoned, unknown or unspecified hop names nobody to relate
the network to, so the network stands on its own and the hop stays in provenance.

Absence is never consent. A walk over this table is column-major and bounded: a table larger
than the step limit, or an agent that stops answering, returns earlier columns for many rows
and the status column for none of them. Those rows are reported as rows whose status was not
established, and create no network, no relationship and no role evidence -- which is what
RowStatus is for.

A zoned address (`ipv4z`/`ipv6z`) carries an interface index belonging to the polled device.
This crate scopes an address by an interface name on the observing vantage, which is a
different namespace, so a zoned next hop creates no node and a zoned destination names no
network -- both are retained in the route's provenance instead.

Answering this table is not by itself router evidence. As with `ipRouteTable`, the role
signal needs `ipForwarding(1)` or a row that actually describes forwarding; a device's own
connected networks are not that. The two tables are walked independently and their
completion is reported separately, so an agent implementing one and not the other loses
nothing and is not reported as having no routing state.

### 1.3 ARP / Neighbor Cache MIBs
| OID | Name | Status | Description |
|---|---|---|---|
| `1.3.6.1.2.1.4.22.1.2` | `ipNetToMediaPhysAddress` | ✅ | MAC address of the connected neighbor host |
| `1.3.6.1.2.1.4.22.1.3` | `ipNetToMediaNetAddress` | ✅ | IP address of the connected neighbor host |
| `1.3.6.1.2.1.4.22.1.4` | `ipNetToMediaType` | 📋 | ARP entry type (3=dynamic, 4=static) |

### 1.4 Switch Port & VLAN MIBs

**None of the following are implemented yet.** The SNMP harvester currently walks system
information, the ARP cache, the routing table and the interface address table only. Switch
port mapping — the evidence needed to say "this device is on switch port 7" — requires the
BRIDGE-MIB below and is tracked on the roadmap.

| OID | Name | Status | Description |
|---|---|---|---|
| `1.3.6.1.2.1.17.4.3.1.1` | `dot1dTpFdbAddress` | 📋 | Learned MAC address in switch bridge table |
| `1.3.6.1.2.1.17.4.3.1.2` | `dot1dTpFdbPort` | 📋 | Switch port number for learned MAC |
| `1.3.6.1.2.1.31.1.1.1.1` | `ifName` | 📋 | Interface name (e.g., `Gi0/1`, `vlan10`, `ether1`) |
| `1.0.8802.1.1.2.1.4` | `lldpRemTable` (LLDP-MIB) | 📋 | Neighbour table read from a switch over SNMP |

---

> **What an interface address states.** `ipAddrTable` proves the device is *on* that network
> and nothing more; it is emitted as attachment, never as gateway status. Every interface
> address belongs to the polled device, so a router with four interfaces is one node rather
> than four. Masks must be contiguous: `255.0.255.0` is refused rather than counted into a
> `/16` that nobody described.

---

## 1a. Routing & Prefix Protocols

Decoded passively where they ride the link, and never answered.

| Protocol | Transport | Status | What it contributes |
|---|---|---|---|
| RIPv2 | UDP 520 | ✅ | Advertised prefixes, and withdrawals (metric 16) read as withdrawals |
| RIPng | UDP 521 | ✅ | The same for IPv6 |
| OSPFv2 | IP proto 89 | ✅ | Router identity and areas from hellos; prefixes only from checksum-valid, current advertisements |
| OSPFv3 | IP proto 89 | ✅ | Prefix LSAs; MaxAge withdraws |
| IS-IS | 802.2 LLC SAP `0xFE` | ✅ | System identity, areas, and reachability TLVs |
| ICMPv6 RA | IP proto 58 | ✅ | Prefix information (on-link vs address-formation-only) and route information options, hop limit 255 enforced |
| DHCPv4 | UDP 67/68 | ✅ | Option 1 (mask), option 3 (routers), option 121 (classless static routes). Server replies only: a BOOTREQUEST carrying ACK-shaped options is refused |
| ICMP address mask | ICMP type 17/18 | ✅ | A reached interface's own prefix, correlated to the request |
| BGP | TCP 179 | 📋 | Deferred until there is representative traffic to test against |
| EIGRP | IP proto 88 | 📋 | Deferred for the same reason |

---

## 2. Layer 2 Discovery Reference

### 2.0a Spanning tree

| Form | Destination | Encapsulation | Status |
|---|---|---|---|
| IEEE STP / RSTP | `01:80:c2:00:00:00` | 802.2 LLC, SAP `0x42` | ✅ |
| Cisco PVST+ / Rapid PVST+ | `01:00:0c:cc:cc:cd` | SNAP, OUI `00:00:0c`, PID `0x010b` | ✅ |

A Cisco switch sends one BPDU per VLAN to the second address; only VLAN 1 uses the first.
All four conditions are required before a PVST+ frame is read -- the destination, the OUI,
the protocol id and a structurally valid BPDU -- because three other Cisco protocols share
that OUI and CDP's address differs by one bit.

A per-VLAN BPDU may establish two things: that the sender bridges, and, where the trailing
originating-VLAN TLV (type `0x0000`, length `0x0002`) carries one, that the VLAN exists in
this switched domain. It never creates a network and never binds a VLAN to a prefix; a
spanning tree describes a topology, not an address space.

### 2.1 LLDP (IEEE 802.1AB)
- **Destination MAC**: `01:80:c2:00:00:0e`
- **EtherType**: `0x88CC`
- **Key TLVs**:
  - TLV 1: Chassis ID (Switch MAC/IP)
  - TLV 2: Port ID (Interface number/name)
  - TLV 3: Time to Live
  - TLV 4: Port Description
  - TLV 5: System Name
  - TLV 6: System Description
  - TLV 7: System Capabilities (Bridge, Router)
  - TLV 8: Management Address (Primary management IP) — fed into topology discovery as a pivot to interrogate

> **Capture scope.** LLDP and CDP reveal the neighbours advertising on the link idNX is bound to. That is the device on the other end of the cable plus anything else advertising in that broadcast domain. It is not a reconstruction of every switch-to-switch relationship in the fabric; that requires reading LLDP-MIB or BRIDGE-MIB off each switch over SNMP.

### 2.2 CDP (Cisco Discovery Protocol)
- **Destination MAC**: `01:00:0c:cc:cc:cc`
- **LLC / SNAP**: `0xAAAA03`, OUI `0x00000C`, Protocol `0x2000`
- CDP has no distinguishing EtherType, so capture matches the destination MAC. On Linux the
  capture socket binds `ETH_P_ALL` with a kernel packet filter for exactly this reason:
  a socket bound to `ETH_P_LLDP` (`0x88CC`) never receives a CDP frame.
- **Key TLVs**:
  - Device-ID (Hostname)
  - Address (Management IPv4/IPv6)
  - Port-ID (Connected port)
  - Native VLAN ID

### 2.3 MNDP (MikroTik Neighbor Discovery)
- **Transport**: UDP port 5678 (broadcast to `255.255.255.255`)
- **Key Fields**:
  - MAC Address
  - Identity (Router hostname)
  - Version (RouterOS version)
  - Platform / Hardware model
  - Interface IP addresses

---

## 3. UPnP / SSDP Specifications

- **Multicast Group**: `239.255.255.250:1900`
- **Search Target (ST)**:
  - `urn:schemas-upnp-org:device:InternetGatewayDevice:1`
  - `urn:schemas-upnp-org:service:WANIPConnection:1`
  - `ssdp:all`
