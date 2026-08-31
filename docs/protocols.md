# Supported Protocols & MIB Reference

This document provides a reference for the network protocols, OIDs, and frame specifications utilized by `idNX`.

---

## 1. SNMP MIB OID Reference

idNX targets standard RFC MIBs for maximum cross-vendor compatibility (Cisco, Juniper, HP/Aruba, MikroTik, Ubiquiti, pfSense, Fortinet).

### 1.1 Interface & Address MIBs
| OID | Name | Description |
|---|---|---|
| `1.3.6.1.2.1.1.1.0` | `sysDescr` | System hardware and OS description string |
| `1.3.6.1.2.1.1.5.0` | `sysName` | Hostname / FQDN of the device |
| `1.3.6.1.2.1.4.20.1.1` | `ipAdEntAddr` | IP addresses configured on all interfaces |
| `1.3.6.1.2.1.4.20.1.3` | `ipAdEntNetMask` | Subnet masks for each configured interface IP |
| `1.3.6.1.2.1.4.20.1.2` | `ipAdEntIfIndex` | Interface index associated with each IP |

### 1.2 Routing Table MIBs
| OID | Name | Description |
|---|---|---|
| `1.3.6.1.2.1.4.21.1.1` | `ipRouteDest` | Destination IP address / network |
| `1.3.6.1.2.1.4.21.1.7` | `ipRouteNextHop` | Next-hop IP address for the route |
| `1.3.6.1.2.1.4.21.1.11` | `ipRouteMask` | Subnet mask for the destination network |
| `1.3.6.1.2.1.4.21.1.8` | `ipRouteType` | Route type (1=other, 2=invalid, 3=direct, 4=indirect) |
| `1.3.6.1.2.1.4.24.4.1` | `inetCidrRouteTable` | Modern CIDR routing table (supports IPv4 & IPv6) |

### 1.3 ARP / Neighbor Cache MIBs
| OID | Name | Description |
|---|---|---|
| `1.3.6.1.2.1.4.22.1.2` | `ipNetToMediaPhysAddress` | MAC address of the connected neighbor host |
| `1.3.6.1.2.1.4.22.1.3` | `ipNetToMediaNetAddress` | IP address of the connected neighbor host |
| `1.3.6.1.2.1.4.22.1.4` | `ipNetToMediaType` | ARP entry type (3=dynamic, 4=static) |

### 1.4 Switch Port & VLAN MIBs
| OID | Name | Description |
|---|---|---|
| `1.3.6.1.2.1.17.4.3.1.1` | `dot1dTpFdbAddress` | Learned MAC address in switch bridge table |
| `1.3.6.1.2.1.17.4.3.1.2` | `dot1dTpFdbPort` | Switch port number for learned MAC |
| `1.3.6.1.2.1.31.1.1.1.1` | `ifName` | Interface name (e.g., `Gi0/1`, `vlan10`, `ether1`) |

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
  - TLV 8: Management Address (Primary management IP)

### 2.2 CDP (Cisco Discovery Protocol)
- **Destination MAC**: `01:00:0c:cc:cc:cc`
- **LLC / SNAP**: `0xAAAA03`, OUI `0x00000C`, Protocol `0x2000`
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
