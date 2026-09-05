# idNX Architecture & Design Specification

This document details the architectural design, concurrency model, modular crate structure, and data flow of **idNX**.

---

## 1. System Overview

idNX is architected as a high-performance, asynchronous Rust library (`idnx`) with a paired command-line interface (`idnx` binary).

```text
        ┌────────────────────────────────────────────────────────────┐
        │ CLI (src/main.rs) — one workflow, no discovery mechanics    │
        │ resolves the starting vantage, then hands over to the engine │
        └───────────────────────────────┬────────────────────────────┘
                                        ▼
        ┌────────────────────────────────────────────────────────────┐
        │ engine::orchestrator — automatic fixed-point work queue      │
        │ seed pass → scope passes → device interrogation → converge   │
        └───────┬─────────────────────────────────────────┬──────────┘
                │                                         │
      providers │ (one trait, one evidence type)          │ continuous sources
                ▼                                         ▼
    ┌───────────────────────────┐            ┌───────────────────────────┐
    │ local     kernel routes,  │            │ passive capture (BPF /    │
    │           interfaces,     │            │ AF_PACKET), drained before │
    │           leases, caches  │            │ every convergence decision │
    │ network   RA/DHCP/SNMP/   │            │ and finished exactly once  │
    │           ICMP/ARP/NDP,   │            └───────────────┬───────────┘
    │           reachability    │                            │
    └─────────────┬─────────────┘                            │
                  └───────────────┬────────────────────────-─┘
                                  ▼
        ┌────────────────────────────────────────────────────────────┐
        │ topology::graph — one node per device, typed relationships,  │
        │ evidence and confidence on every fact, realm-scoped identity │
        └───────────────────────────────┬────────────────────────────┘
                                        ▼
        ┌────────────────────────────────────────────────────────────┐
        │ output — terminal view, JSON/YAML/XML/CSV/text, HTML page    │
        │ all rendered from the same graph and the same run record     │
        └────────────────────────────────────────────────────────────┘
```

Two channels leave a provider, and only one of them reaches the graph. `TopologyEvidence` is
topology; `ProviderOutput` also carries what was *attempted* — notes, and structured
per-network reachability — because an empty evidence list otherwise became the claim "no
response", which is only true when something was actually sent.


---

## 2. Core Modules (`idnx::*`)

### 2.0 `topology` and `providers`

* **`topology::evidence`**: The single record every source emits. A provider cannot report a
  result any other way, which structurally prevents a working decoder from feeding nothing.
* **`topology::graph`**: Correlates evidence into nodes and relationships, owns device
  identity (addresses merge onto one device via MAC), and enforces two rules: a network node
  requires prefix-bearing evidence, and loopback/link-local/multicast ranges are not topology.
* **`topology::role`**: Scores device roles from corroborated behaviour with explicit
  weights. Manufacturer is never an input.
* **`providers`**: One trait for local, credential-free network, passive and optional
  amplifier sources. No vendor is privileged in the graph or the scheduler.


### 2.1 `engine`
* **`scanner`**: Data-plane probing used for *enrichment only*. Host sweeps, TCP connect
  probes and the ICMP fallback validate and describe devices that discovery has already
  found; they are not a discovery mechanism. Every probe reports whether it actually left
  this machine, and each host records whether this run *heard from it* or merely found it in
  the neighbour cache — the two are different claims, and only the first is reachability.
  The ICMP fallback uses the interface-bound correlated echo path; it does not shell out to
  `ping`.
* **`enrich`**: Per-device interrogation, concurrent on the run-wide probe budget, with a
  coverage record per device so a silent device is distinguishable from an unasked one.
* **`orchestrator`**: The automatic discovery engine. Runs every applicable provider to a fixed point over each discovered network and infrastructure device, under a bounded safety budget. Recursion is internal and always enabled; there is no depth or thread count to configure.

### 2.1a Attempt and reachability model

* **`probes::attempt::AttemptOutcome`**: six states — unavailable, not applicable, not sent,
  no response, invalid response, answered — because collapsing them loses exactly the
  distinctions an operator needs. Only `Answered` carries a result, so a probe with no
  validated reply has no way to report one.
* **`providers::NetworkReachability`**: what a pass established about one network, keyed by
  `NetworkRef` (prefix *and* observation domain, since two peers can each hold a
  10.0.0.0/24). It holds the responders, the set of addresses actually probed, the count of
  probes that never left, each prober's account, and — separately — how the network came to
  be known. The state is *derived* from that evidence rather than asserted beside it, and
  merging unions the address sets: counts cannot merge truthfully, since two passes over 127
  addresses each may have covered 254 or 127.

### 2.2 `probes`
* **`lldp`**: Berkeley Packet Filter (macOS `/dev/bpf*`) and raw packet socket (Linux `AF_PACKET`) frame listener that decodes IEEE 802.1AB LLDP TLVs (Chassis ID, Port ID, System Name, System Description, Capabilities).
* **`cdp`**: Cisco Discovery Protocol frame decoder for LLC/SNAP encapsulated packets (`01:00:0c:cc:cc:cc`, protocol `0x2000`). Extracts device hostname, hardware platform, port ID, and native VLAN.
* **`mndp`**: MikroTik Neighbor Discovery Protocol listener on UDP port 5678. Extracts RouterOS identity, software version, hardware board name, and MAC address.
* **`upnp`**: SSDP multicast (`239.255.255.250:1900`) discovery engine that fetches device XML descriptions to extract manufacturer and model details.
* **`asus`**: ASUSWRT discovery on UDP 9999/18017. Currently reported as unavailable
  pending a framing audit, rather than sending bytes whose format has not been verified.
* **`arp` / `ndp`**: Validated active liveness on the attached link. A reply counts only when
  it correlates to a request this run transmitted; requests the raw channel accepted are
  reported as diagnostics and never as proof that a frame reached the medium.
* **`ra`**: IPv6 router solicitation, with prefix and route information options read
  separately — an on-link prefix and a route through the router are different claims.
* **`rip` / `ospf` / `isis`**: Passive routing decoders. Heard, never answered; withdrawals
  are read as withdrawals.
* **`icmp_mask`**, **`dhcp_inform`**, **`reach`**, **`path`**: the bounded active prefix and
  reachability sources, each interface-bound and each reporting an `AttemptOutcome`.
* **`snmp`**: SNMPv2c only, over a hand-written BER codec whose reader carries the bounds of
  every enclosing TLV. Responses are correlated to their request, walks are bounded three
  ways, and per-table completion is carried into the run's coverage.

### 2.3 `net`
* **`interface`**: Cross-platform network interface enumeration and primary route detection (`get_if_addrs` + outbound routing probe).
* **`link_speed`**: Queries the operating system for real-time negotiated physical link speed (e.g. `10 Gbps Full-Duplex` or `1.81 Gbps Wi-Fi 6E 160MHz`).
* **`arp`**: Cross-platform OS kernel ARP table reader:
  * Linux: Reads directly from `/proc/net/arp` (works on minimal/container distros without external tools).
  * macOS: Parses Darwin `arp -a`.
  * Windows: Parses Windows `arp -a` with hyphenated MAC support.
* **`dns`**: High-performance zero-copy Unicast DNS reverse PTR resolver (RFC 1035) that queries subnet gateway DNS servers (e.g. dnsmasq) for hostnames across routed subnets.
* **`mdns`**: Asynchronous Multicast DNS (RFC 6762) reverse PTR resolver on `224.0.0.251:5353`.

### 2.4 `fingerprint`
* **`oui`**: Embedded, binary-searchable IEEE OUI vendor database. Automatically checks for IEEE 802 local/randomized MAC addresses (`mac[0] & 0x02 != 0`).
* **`topology::role`**: Assigns device roles by scoring corroborated behaviour with explicit weights. Manufacturer is never an input; the previous OUI-based classifier has been removed.
### 2.5 `output`
* **`topology_view`**: The terminal rendering, written into a sink rather than to stdout, so
  the operator-facing view is capturable and covered by a golden snapshot.
* **`export`**: JSON, YAML, XML, CSV and text from one serialisable view of the graph. CSV is
  a typed-record export, not a device inventory.
* **`graph`**: The self-contained interactive HTML page, built from the same graph and
  carrying each network's reachability state and coverage.

---

## 3. Concurrency & Privileges

1. **Privilege Decoupling**:
   * **Unprivileged Mode (Non-Root)**: Standard POSIX sockets, unprivileged ICMP datagram
     sockets, and everything the OS already knows. Reports which sources were unavailable
     rather than reporting their absence as network silence.
   * **Privileged Mode (`sudo idnx`)**: Adds raw Berkeley Packet Filter (macOS) and
     `AF_PACKET` (Linux) capture, and raw ARP/NDP transmission. Privileges only ever add
     sources; the workflow and its scope are identical.
2. **Resource Throttling**:
   * All network operations use `tokio::sync::Semaphore` to cap in-flight sockets and prevent file descriptor exhaustion or switch buffer overruns.
