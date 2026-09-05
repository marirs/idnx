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
| `1.3.6.1.2.1.4.24.4.1` | `inetCidrRouteTable` | 📋 | Modern CIDR routing table (supports IPv4 & IPv6) |

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
