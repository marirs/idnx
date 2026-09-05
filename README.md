# idNX 🚀
### Network Topology Discovery

[![CI](https://github.com/marirs/idnx/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/idnx/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-windows%20|%20macos%20|%20linux-blue?logo=gnubash&logoColor=white)

**idNX** maps the network topology observable from a chosen vantage point, tells you how it
knows each thing, and states plainly what it could not see.

It is not a port scanner. Port sweeping happens last, to enrich and validate devices
discovery has already found; it never finds them.

Active *topology* probing is a different thing and does discover: a bounded, ordered set of
gateway-candidate addresses is asked to answer for itself, and an address that does answer
becomes a forwarding interface on the map. What it does not become is a network — a
responding address is an address, and only a stated prefix (an address mask reply, a route,
an interrogation of the interface) creates one.

---

## What makes it different

Most command-line tools report reachable hosts and open ports on targets you supply. idNX
starts from a vantage point, gathers evidence from every source available without
credentials, correlates it into one topology graph, and grades every fact:

| Grade | Meaning |
| --- | --- |
| `observed` | Seen directly — a frame on the wire, a kernel table entry, a live response |
| `advertised` | A device asserted it — an RA prefix, an LLDP name, an SNMP route entry |
| `inferred` | Derived by assumption. Always labelled, never silent |
| `user-supplied` | You provided it |

The distinction is enforced, not decorative. Observing a router advertisement is `observed`
evidence that a device sent it; the prefix inside is `advertised`, because the device said
so and idNX did not verify it.

**Roles come from behaviour, never from manufacturer.** A device is a router because it is
your default gateway, hands out DHCP leases, sends router advertisements, advertises a UPnP
InternetGatewayDevice, or reports IP forwarding over SNMP. A device that both bridges and
routes — spanning-tree participation *and* forwarding evidence — is reported as a layer-3
switch, in its own category, with both kinds of evidence retained on one node. An OUI
identifies who built the hardware and says nothing about what it does.

An interface that forwarded our traffic but identified nothing about itself is a
*forwarding interface (ownership unknown)*, not a router: a hop count cannot tell the
operator's router from a carrier's.

**Nothing is invented.** A network node requires prefix-bearing evidence — an interface
mask, a kernel route, DHCP option 1 or 121, an RA prefix option, a RIP/OSPF/IS-IS
advertisement, or an ICMP address mask reply. An observed VLAN tag produces
`VLAN 20 observed; prefix unknown`, never a guessed `192.168.20.0/24`. Router addresses are
never widened into assumed `/24`s.

A VLAN gains a prefix only when a *single observation* states both — a client-facing,
untagged-by-no-relay DHCP ACK carrying the client's address and option 1, on a frame with
exactly one tag. A tag seen in one frame and a prefix seen in another are two observations,
and pairing them would be inference presented as capture. The binding is a relationship in
the graph carrying the frame that produced it, so it can be checked rather than taken.

**Reachability is a separate question from topology.** Whether anything answered inside a
network says nothing about whether the network exists, so the two are recorded apart. Each
network carries one of three states, with the coverage behind it:

| State | Meaning |
| --- | --- |
| `reachable` | Something in it answered *during this run* — a TCP response or refusal, a correlated ICMP reply, a fresh ARP reply |
| `probed_unreachable` | Probes reached the wire and nothing answered |
| `not_enumerated` | Nothing was probed: too large to enumerate, or every socket refused to send |

A neighbour-cache entry is never a responder — the kernel remembers stations long after they
are gone. An advertised network nothing answers on stays on the map with its failed
reachability recorded; how it was discovered is kept separately, because a silent sweep says
nothing about whether a router advertised the prefix.

---

## Usage

```bash
idnx                    # start from the interface carrying the default route
sudo idnx               # same workflow, plus privileged link-layer observation
idnx eth1               # start from a named interface
idnx 10.20.0.0/16       # start from a named network
```

There is one workflow. Naming an interface or network moves the **starting point** and
nothing else — it never selects a reduced mode. Every network discovered along the way
receives the same provider pipeline as the first.

Recursion, provider selection, observation lifetime, worker count and stopping conditions
are the engine's responsibility. There is no `--recursive`, `--threads`,
`--listen-seconds`, `--heuristic-sweep` or `--no-deep` to get wrong. Worker threads come
from `available_parallelism()`.

### Options

| Option | Purpose |
| --- | --- |
| `-o, --output <FORMAT>` | Export as `json`, `yaml`, `xml`, `csv` or `text` |
| `--output-file <PATH>` | Write the export somewhere other than `idnx_YYYYMMDD.<ext>` |
| `--export-graph <PATH>` | Write a standalone interactive HTML topology page |
| `-t, --timeout <MS>` | Per-probe timeout (default 800) |
| `--snmp-community <S>` | SNMP community to try, when you have one. Repeatable |
| `--list-interfaces` | List local interfaces with their vantage kind |
| `--update-oui` | Refresh the IEEE OUI registry |

`sudo` adds sources; it never changes scope. Running unprivileged is fully supported and
reports which sources were unavailable.

---

## Evidence sources

All of these run automatically and concurrently. Each is optional: one returning nothing
never stops the others, and every outcome is reported.

**Local** (no privileges, no cooperation from anything) — interface addresses and prefixes,
kernel routing tables, default gateway, the DHCP lease the OS already holds including
options 1, 3 and 121, ARP and IPv6 neighbour caches.

**Credential-free network** — SSDP/UPnP descriptors and announced device types, mDNS and
unicast DNS/PTR naming, MikroTik MNDP, vendor discovery broadcasts, service fingerprinting,
and the prefix-bearing active sources: IPv6 router solicitation (prefix and route
information options), DHCP INFORM, ICMP address mask requests, and bounded reachability
probing of gateway candidates. Every active probe is bound to the selected interface — ICMP
included — so an answer is never attributed to a vantage that did not carry it.

**Passive link-layer observation** (privileged, opportunistic) — opens at startup on the
selected interface and runs concurrently until discovery converges. No listening flag, no
fixed delay, nothing waits on it. Decodes Ethernet II, 802.3 LLC/SNAP, 802.1Q and QinQ,
STP/RSTP BPDUs, LLDP, CDP, ARP, DHCPv4 (options 1, 3 and 121), IPv6 router advertisements
and neighbour discovery, MNDP, RIPv2 and RIPng, OSPFv2 and OSPFv3, and IS-IS. Routing
updates are read, never answered. If capture cannot start, everything else is unaffected —
and "no routing protocol on this link" is reported differently from "the decoder never
ran".

**Optional amplifier** — SNMP v2c over UDP 161 with a community you supply (v1 and v3 are
not spoken; a v1 response is refused rather than parsed). One source among many, not a
prerequisite. Most consumer routers ship with SNMP disabled, and discovery proceeds
normally without it. Every response is bounded and correlated: the returned OID must match
the request, exactly one varbind is accepted, oversized datagrams are refused rather than
truncated, and each walk reports whether the table it read was complete — a truncated table
is never presented as an exhaustive one.

---

## What idNX cannot do

Stated plainly, because a partial map presented as complete is worse than no map.

- **A NAT boundary is opaque without cooperation.** A downstream router rewrites every
  packet from its LAN to one source address. Nothing passive sees those devices and nothing
  active reaches them. Where a device forwards traffic and no source states a prefix behind
  it, idNX keeps it as a *forwarding interface (ownership unknown)* and says the downstream
  prefixes are unresolved — it neither invents a subnet nor drops the interface. Nothing in
  the default build asserts a NAT boundary: that would be a claim about what is behind the
  device, which is exactly what could not be established.
- **Passive capture only sees what reaches the capture point.** A wireless station receives
  no wired STP, LLDP or trunk VLAN tags, and no switched unicast between other hosts. An
  access port sees its own broadcast domain; observing every VLAN generally needs a trunk or
  mirror port. Absence of captured frames is never proof that switches or devices do not
  exist, and idNX distinguishes "capture active, no frames observed" from "capture never
  started".
- **A BPDU proves a bridge, nothing more.** It is not router evidence and implies no hidden
  subnet.
- **A VLAN tag proves only the VLAN ID.** Its prefix stays unknown until one observation
  states both. A relayed DHCP reply does not: it was captured on the relay's link, so its
  tag is not the client's VLAN.
- **Unmanaged switches are transparent** by design: no management address, no agent, no
  advertisement.

Switch-port mapping (BRIDGE-MIB forwarding tables), LLDP-MIB neighbour tables read over
SNMP, and VLAN/trunk relationships are **not implemented**. See `docs/roadmap.md`.

---

## Output

The default view shows the vantage and why it was selected, what it cannot observe,
networks separated into physical and virtual/VPN, VLANs including prefix-unknown ones,
routers and switches with the behaviour that classified each, hosts, opaque boundaries, and
per-scope and per-pivot provider coverage — including providers that returned nothing.

```
Vantage: en0 (wireless station) — carries the default route
    Not visible from here: wired STP/BPDU, LLDP/CDP from wired switches, trunk VLAN tags
    Unavailable: raw link-layer capture requires elevated privileges

Networks
  ├── 192.168.1.0/24
  │     via en0
  │     reachable; 12 of 254 address(es) probed answered
  ├── 198.18.0.0/24
  │     254 address(es) probed, none answered (advertised by 192.168.1.1)

VLANs carrying a known prefix
  ├── VLAN 77 192.0.2.0/24 (from DHCP lease)

VLANs
  ├── VLAN 42 observed; prefix unknown

Routers & gateways
  ├── myrouter [192.168.1.1, fe80::7612:13ff:fe14:75dc] (Linksys Velop 6SP)
  │     • acts as a DHCP router or server
  │     • advertises a UPnP InternetGatewayDevice
  │     • advertises itself as an IPv6 router (RFC 4861)
  │     • is this machine's default gateway

Layer-3 switches (bridging and routing)
  ├── 10.0.0.2 [10.0.0.2]
  │     • emits spanning-tree BPDUs
  │     • SNMP reports IP forwarding

Forwarding interfaces (routing confirmed, ownership unknown) (1)
  ├── 10.100.136.62
  │     downstream prefixes unresolved: no source disclosed a network behind this interface

Discovery coverage
  192.168.1.0/24
    ssdp-upnp          2 facts
    mndp               no response
    host-enrichment    64 facts
```

Virtual and VPN networks are separated by the interface they are reached through, never by
address range: `10.0.0.0/8` is as legitimate for a corporate LAN as for a container bridge.
RFC 1918 is not treated as the only valid internal space — public, CGNAT, IPv6 global and
ULA prefixes are all preserved.

Every export format carries the same information as the terminal view: node kinds,
relationships, evidence, confidence, reachability, coverage and opaque boundaries. CSV is a
typed-record export — one row per network, VLAN, device, relationship and coverage record,
each naming its type in the first column — rather than a device inventory. The HTML page is
self-contained and opens with no network access.

Every format is covered by a byte-for-byte golden snapshot of one scripted discovery run
(`tests/goldens/`), so a change to what an operator or a downstream consumer is told shows
up as a diff rather than as a surprise.

---

## Installation

```bash
git clone https://github.com/marirs/idnx.git
cd idnx
cargo build --release
sudo cp target/release/idnx /usr/local/bin/
```

---

## Architecture

```
resolve starting scope
  → collect evidence from every applicable provider, concurrently
  → correlate into one topology graph
  → recursively process every discovered network and infrastructure device
  → enrich discovered devices by probing
  → stop when the graph converges
  → render the observable topology
```

Every source implements one trait and returns one evidence type. A provider cannot report a
result any other way, which is what stops a working decoder from silently feeding nothing.

- `topology/` — the evidence model, the graph, and behavioural role scoring
- `providers/` — local, network and passive evidence sources behind one interface
- `engine/orchestrator.rs` — the automatic fixed-point work queue and safety budget
- `probes/` — protocol decoders, each testable from byte fixtures
- `output/` — terminal, serialised and HTML renderings of the same graph

Correctness is proven where it can be: synthetic PCAP byte fixtures for every decoder, a
scripted SNMP agent on loopback for the walk lifecycle, an acceptance test that drives the
real orchestrator and proves a newly disclosed network moves the frontier and causes another
pass, and golden snapshots of every output format. What cannot be proven from a laptop —
privileged Linux capture, and a wired trunk or SPAN port — is stated as untested rather than
assumed.

See `docs/architecture.md`, `docs/deep_exploration.md` and `docs/protocols.md`; the protocol
tables there mark implemented versus planned explicitly.

---

## License

Apache-2.0. All code is original and clean-room; no copyleft code is vendored.
