# idNX Development Roadmap

This document outlines the milestones and release goals for the **idNX** project.

---

## 🎯 Release Milestones

### Milestone 1: Core Async Scanner Foundation -> [COMPLETED]
- [x] Initial Cargo project scaffolding & repository structure.
- [x] Dual Library (`src/lib.rs`) + CLI Binary (`src/main.rs`) crate architecture.
- [x] High-visibility ASCII art terminal banner integration.
- [x] CLI argument parsing (`clap` derive). The surface has since narrowed deliberately: a
  positional interface or network, output format and path, graph export, per-probe timeout,
  SNMP community, `--list-interfaces` and `--update-oui`. Ports, concurrency, recursion and
  depth are the engine's decisions and have no flags -- `--help` is the authority.
- [x] Active local network & interface auto-detection with real-time Link Speed & PHY rate detection.
- [x] High-concurrency async TCP connect port scanner (`tokio`).
- [x] Active host discovery: TCP connect and RST liveness, with an ICMP fallback for hosts
  that answer neither. The fallback is now the interface-bound correlated echo path -- it
  reports which probes actually left this machine, and does not shell out to `ping`.
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

### Milestone 3: Deep SNMP Harvester -> [COMPLETED]
- [x] Async SNMP v2c client (compact UDP BER encoder/decoder, bounded reader, correlated responses). v1 is refused rather than parsed.
- [x] Community handling: the anonymous default (`public`) when the operator supplies none,
  and the supplied list *instead of* it when they do. There is no sweep through a built-in
  guess list, and no community is ever named in a diagnostic or an export.
- [x] Interface IP Table (`ipAddrTable`) walking for multi-homed VLAN detection.
- [x] Routing Table (`ipRouteTable`, OID `1.3.6.1.2.1.4.21.1`) extraction to uncover remote subnets.
- [ ] `inetCidrRouteTable` (OID `1.3.6.1.2.1.4.24.4.1`) — the modern CIDR/IPv6 routing table. Not implemented; only the legacy `ipRouteTable` is walked today.
- [x] Remote ARP Cache (`ipNetToMediaTable`) harvesting for silent / firewalled stealth devices.

---

### Milestone 5: Recursive Pivot & Deep Fingerprinting -> [COMPLETED]
- [x] Library embedding. The fluent `ScannerBuilder` this shipped with no longer exists:
  embedding goes through `DiscoveryEngine` with a provider list, which is the same path the
  binary takes, so an embedder cannot get a different discovery than the CLI performs.
- [x] Clean-Room Protocol Probes (targeted handshake triggers: TLS ClientHello for X.509 cert extraction, SMB Negotiate for Windows domain/hostname).
- [x] Interactive Network Topology Graph Export (`--export-graph topology.html` standalone force-directed visualization).
- [x] Recursive exploration scheduler queueing discovered subnets. (The `--recursive` and `--max-depth` flags this shipped with were removed in Milestone 10: recursion is automatic and has no depth to choose.)
- [x] Updatable 2-Tier OUI Engine (`idnx --update-oui` fetching master OUI database to `~/.cache/idnx/oui.txt`).

---

### Milestone 6: IPv6 Multi-Stack Engine & Neighbor Discovery -> [COMPLETED]
- [x] ICMPv6 Link-Local All-Nodes Multicast Echo Sweep (`ff02::1%<interface>`) for zero-config L2 IPv6 discovery.
- [x] Cross-platform NDP (Neighbor Discovery Protocol) cache harvesting (`ndp -an` on macOS, `ip -6 neigh` on Linux, `netsh` on Windows).
- [x] mDNS IPv6 PTR resolution (`[ff02::fb]:5353` for `ip6.arpa` name resolution).
- [x] Dual-stack host unification (merging IPv4 and IPv6 addresses under unified MAC-based device nodes).
- [x] Multi-format IPv6 reporting (terminal table, ASCII topology tree, JSON/YAML/XML/CSV exports, and interactive HTML graph).

---

### Milestone 7: AI Agent & LLM Runtime Fingerprinting (v0.2.2) -> [COMPLETED]
- [x] Local LLM runtime detector (Ollama `11434`, LM Studio `1234`, vLLM `8000`, LocalAI `8080`, Text-generation-webui `5000`).
- [x] Active model inventory extractor (`/v1/models` and `/api/tags` to identify loaded models like `llama3.2`, `deepseek-r1`, `qwen2.5-coder`).
- [x] Model Context Protocol (MCP) server detector (JSON-RPC 2.0 / SSE endpoint discovery on `/sse`).
- [ ] AgentPin standard prober (`.well-known/agent-identity.json`) — **partial**. The endpoint is fetched, but the parser accepts essentially any JSON object containing a `name` field. Until the manifest schema and its identity signature are validated, a response cannot be treated as a confirmed AgentPin identity; an unsigned or malformed manifest must make the device a candidate, not a confirmation.
- [x] Dedicated topology category: `🤖 AI Agents & LLM Runtimes` in ASCII tree, tables, HTML graph, and JSON/YAML/XML/CSV exports.

---

### Milestone 8: Evidence-Graded Topology Model -> [COMPLETED]
- [x] Split discovery into **routes** (networks whose prefix is known) and **pivots** (routers whose networks are not yet known), so a router address is never widened into a network by assumption.
- [x] Confidence grading on every network, surfaced in the topology view, HTML graph and every export format. (The grade names settled as `observed`, `advertised`, `inferred` and `user-supplied` in Milestone 9.)
- [x] Default gateway seeded as the first topology pivot; SNMP checked over UDP 161 rather than by probing TCP 161.
- [x] `ipAddrTable` consumed as directly-attached-network evidence, with the router's real interface address as the gateway.
- [x] DHCP option 3 routers ingested from the OS lease (`ipconfig getoption` on macOS, dhclient leases on Linux, `ipconfig /all` on Windows).
- [x] LLDP/CDP management addresses fed back into discovery as pivots instead of being printed and discarded.
- [x] Removed the hardcoded traceroute target. TTL-limited probing itself is still in use and
  produces the egress path: each hop that answers is recorded as a forwarding interface with
  its distance, in its own section. What was retired is inferring *prefixes* from hops -- a
  hop proves a router interface on one path and nothing about any network behind it.
- [x] Auto-discovered networks bounded by an internal safety budget so a `/16` VM bridge in the kernel table cannot stall a run. (Originally the `--max-sweep-hosts` flag; removed in Milestone 10, when discovery depth stopped being an operator decision.)
- [x] Deterministic resolver selection and deterministic route/pivot ordering, so repeated runs on an unchanged network produce identical output.

---

### Milestone 9: Vendor-Neutral Evidence Graph -> [COMPLETED]
- [x] One `TopologyEvidence` record emitted by every source; providers cannot report results any other way.
- [x] `TopologyGraph` with Interface, Network, VLAN, Router, Switch, Host, Service and OpaqueBoundary nodes and typed relationships.
- [x] Role scoring from corroborated behaviour with explicit weights; the rule that classified every ASUS/Linksys/MikroTik/Ubiquiti OUI as a router is removed.
- [x] Network nodes only from prefix-bearing evidence; a VLAN tag yields the VLAN ID and never a prefix.
- [x] Automatic fixed-point work queue with a bounded safety budget. Recursion always on; no user-facing depth, thread or provider flags.
- [x] Passive link-layer observation as an opportunistic provider: Ethernet II, LLC/SNAP, 802.1Q/QinQ, STP/RSTP, LLDP, CDP, ARP, DHCPv4 (options 1/3/121), IPv6 RA and NDP, MNDP — with byte-level fixtures.
- [x] Vantage classification and explicit visibility reporting; an empty capture is distinguished from an absent one.
- [x] Virtual and VPN networks classified by the interface they are reached through, never by address range.
- [x] Per-scope and per-pivot provider outcomes reported, including providers that returned nothing.
- [x] Every export format and the interactive HTML graph rebuilt on the graph, preserving kinds, relationships, evidence, confidence and coverage.

---

### Milestone 10a: Prefix-Bearing Discovery & Proof -> [COMPLETED]
- [x] Prefix-bearing sources beyond the attached link: RA prefix and route information options, DHCP option 121/249, passive RIPv2/RIPng, passive OSPFv2/OSPFv3 and IS-IS, ICMP address mask replies, and bounded reachability probing of gateway candidates.
- [x] Validated active liveness: raw ARP and IPv6 neighbour discovery, with replies counted only when correlated to a request this run transmitted.
- [x] Six-state `AttemptOutcome` on every probe, so "unavailable", "not sent", "no response" and "invalid response" stop being one empty result.
- [x] Structured per-network reachability (`reachable`, `probed_unreachable`, `not_enumerated`) keyed by observation domain, carrying responders, the addresses actually probed, probes that never left, and — separately — how the network was discovered.
- [x] Layer-3 switch as its own role, node kind, category and count: a device that bridges and routes keeps both kinds of evidence on one node.
- [x] VLAN-to-prefix binding as an evidence-carrying relationship, emitted only where one frame states both (tagged, client-facing, unrelayed DHCP ACK with option 1).
- [x] Synthetic PCAP byte fixtures for every passive decoder, including malformed captures and the relayed-DHCP negative case.
- [x] Scripted SNMP agent on loopback covering the walk lifecycle: end-of-view, subtree exit, agent error, non-advancing OID, wrong request-id/community/PDU type, malformed and oversized responses, and the total deadline.
- [x] Acceptance test through the real `DiscoveryEngine`: a disclosed subnet moves the frontier, examining it finds its devices, those devices disclose further subnets, and convergence is declared only after the whole frontier is exhausted.
- [x] Byte-for-byte golden snapshots of the terminal view, JSON, YAML, XML, CSV, text and HTML, with determinism arranged structurally rather than by masking output.
- [ ] Privileged Linux validation, and a run from a wired trunk or SPAN port. Hardware-dependent; not yet performed.

---

### Milestone 10: Switch Port Mapping & Change Detection -> [PLANNED]
- [ ] BRIDGE-MIB forwarding tables (`dot1dTpFdbAddress` / `dot1dTpFdbPort`) to place a device on a specific switch port.
- [ ] LLDP-MIB (`lldpRemTable`) read over SNMP to reconstruct switch-to-switch relationships beyond the local link.
- [ ] `ifName`, interface speed and operational state for named, typed uplinks.
- [ ] VLAN and trunk relationships.
- [ ] SNMPv3 (authentication and privacy).
- [ ] Snapshot save/diff (`idnx snapshot save`, `idnx snapshot diff`) — new device, new subnet, changed switch port, disappeared host, newly exposed service.
- [ ] An MNDP PCAP fixture. LLDP, CDP, STP/RSTP, ARP/NDP, DHCP, RA, RIP, OSPFv2/v3 and IS-IS
  fixtures exist (`tests/fixtures/pcap/`), and SNMP is covered by a scripted agent on
  loopback rather than by recorded responses; MikroTik MNDP is the remaining decoder with no
  byte-level fixture.

---

### Milestone 11: Container & Orchestrator Topology Mapping -> [PLANNED]
- [ ] Docker, Podman, and containerd runtime socket / port detection.
- [ ] Kubernetes Node & Kubelet (`10250`, `10255`) infrastructure probing.
- [ ] Virtualized container bridge subnet identification (`cni0`, `docker0`).
- [ ] Cloud metadata instance identity probing (AWS/GCP/Azure/DigitalOcean link-local `169.254.169.254`).

---

## 🛡️ Code Origin & Licensing Integrity
All features and components in `idnx` are 100% original, clean-room, handwritten Rust code licensed under **Apache-2.0**. We strictly reject copying or vendoring code from copyleft/GPL projects, guaranteeing a permissive, commercially safe foundation for the open-source community and enterprise users.

