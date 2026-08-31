# Deep Infrastructure Exploration Guide

This document explains the technical mechanisms `idNX` uses to extract hidden networks, VLANs, routing tables, and remote host IPs from routers and managed switches.

---

## 1. The Core Problem: Data Plane vs. Control Plane

Traditional network scanners query each IP individually on target ports. This approach fails in modern segmented environments:

1. **VLAN Segmentation**: Routers isolate traffic between subnets (e.g., VLAN 10 for Corporate, VLAN 20 for IoT).
2. **Access Control Lists (ACLs) & Firewalls**: Even if routing exists, firewalls on the router block traffic originating from untrusted subnets.

### The idNX Advantage
Routers and Layer 3 managed switches must know about all connected networks to function. They store this state in memory:
- **Routing tables**
- **ARP tables (Neighbor caches)**
- **Interface definitions & IP addresses**
- **Bridge forwarding databases (FDB)**

By querying these management structures, idNX maps the entire network footprint **from the control plane**.

---

## 2. Extraction Techniques

### 2.1 SNMP MIB Walking (The Primary Deep Probe)
When idNX detects an infrastructure host or when `--deep` is enabled:
1. It sends an SNMP `GetRequest` or `GetNextRequest` / `GetBulkRequest` (v2c) on UDP port 161 with targeted community strings (e.g., `public`, `private`).
2. It walks three critical MIB tables:

#### A. Interface Addresses (`ipAddrTable` - `1.3.6.1.2.1.4.20`)
- **What it returns**: All IP addresses assigned to every physical port, virtual interface, and VLAN on the router.
- **Value**: Instantly reveals other internal gateway IPs (e.g., `10.0.10.1`, `10.0.20.1`, `172.16.50.1`).

#### B. Routing Table (`ipRouteTable` - `1.3.6.1.2.1.4.21` / `inetCidrRouteTable` - `1.3.6.1.2.1.4.24`)
- **What it returns**: Complete list of destination CIDR blocks, subnet masks, next-hop gateways, and route types (direct, indirect).
- **Value**: Discovers all routable subnets, including multi-hop corporate networks and branch office tunnels.

#### C. ARP Cache Table (`ipNetToMediaTable` - `1.3.6.1.2.1.4.22`)
- **What it returns**: The router's ARP table: IP address to MAC address mappings across **all** attached subnets.
- **Value**: **This is the biggest win.** Even if idNX cannot route a single packet into VLAN 30, the router's ARP table lists the IP and MAC address of every device that has transmitted packets on VLAN 30!

---

### 2.2 Layer 2 Discovery (LLDP, CDP, MNDP)
Managed switches and enterprise routers broadcast discovery packets:
- **LLDP (802.1AB)**: Standardized neighbor discovery sent to multicast MAC `01:80:c2:00:00:0e`.
- **CDP**: Cisco proprietary discovery sent to `01:00:0c:cc:cc:cc`.
- **MNDP**: MikroTik Neighbor Discovery Protocol over UDP 5678.

**Payload extracted**:
- Switch chassis ID, hostname, and management IP.
- Port ID and port description (e.g., `GigabitEthernet0/12 - Uplink to Core`).
- Native VLAN and enabled capabilities (Bridge, Router, WLAN).

---

### 2.3 UPnP / SSDP (Consumer & Edge Gateways)
1. idNX broadcasts an `M-SEARCH` UDP packet to `239.255.255.250:1900`:
   ```http
   M-SEARCH * HTTP/1.1
   HOST: 239.255.255.250:1900
   MAN: "ssdp:discover"
   MX: 2
   ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1
   ```
2. The gateway returns its XML descriptor URL.
3. idNX parses the descriptor to obtain:
   - External WAN IP and status.
   - Internal LAN subnets.
   - Active UPnP port mappings.

---

## 3. Recursive Exploration Workflow

When `--recursive` is enabled alongside `--deep`:

```
[Start Sweep: 192.168.1.0/24]
        │
        ▼
[Find Router: 192.168.1.1]
        │
        ├─► [Harvest ARP Table] ────────► Discovered 48 remote IPs
        │
        └─► [Harvest Routing Table]
                    │
                    ├── Subnet A: 10.0.10.0/24 (Directly Connected)
                    ├── Subnet B: 10.0.20.0/24 (VLAN 20)
                    └── Subnet C: 172.16.0.0/16 (Corporate VPN)
                            │
                            ▼
           [Test Reachability / Add to Queue]
                            │
                            ▼
           [Recursive Sweep: 10.0.10.0/24]
```
