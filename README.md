# idNX 🚀
### Network Topology Discovery

[![CI](https://github.com/marirs/idnx/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/idnx/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-windows%20|%20macos%20|%20linux-blue?logo=gnubash&logoColor=white)

**idNX** maps the network topology observable from a chosen vantage point, tells you how it
knows each thing, and states plainly what it could not see.

It is not a port scanner. Scanning happens last, to enrich and validate what discovery
already found; it is never the thing that finds it.

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
InternetGatewayDevice, or reports IP forwarding over SNMP. An OUI identifies who built the
hardware and says nothing about what it does.

**Nothing is invented.** A network node requires prefix-bearing evidence — an interface
mask, a kernel route, DHCP option 1 or 121, or an RA prefix option. An observed VLAN tag
produces `VLAN 20 observed; prefix unknown`, never a guessed `192.168.20.0/24`. Router
addresses are never widened into assumed `/24`s.

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
unicast DNS/PTR naming, MikroTik MNDP, vendor discovery broadcasts, ICMP and TCP
reachability, service fingerprinting.

**Passive link-layer observation** (privileged, opportunistic) — opens at startup on the
selected interface and runs concurrently until discovery converges. No listening flag, no
fixed delay, nothing waits on it. Decodes Ethernet II, 802.3 LLC/SNAP, 802.1Q and QinQ,
STP/RSTP BPDUs, LLDP, CDP, ARP, DHCPv4, IPv6 router advertisements and neighbour discovery,
and MNDP. If it cannot start, everything else is unaffected.

**Optional amplifier** — SNMP v1/v2c over UDP 161 with a community you supply. One source
among many, not a prerequisite. Most consumer routers ship with SNMP disabled, and
discovery proceeds normally without it.

---

## What idNX cannot do

Stated plainly, because a partial map presented as complete is worse than no map.

- **A NAT boundary is opaque without cooperation.** A downstream router rewrites every
  packet from its LAN to one source address. Nothing passive sees those devices and nothing
  active reaches them. Where a router discloses no downstream prefix, idNX reports an opaque
  boundary rather than inventing a subnet or omitting the router.
- **Passive capture only sees what reaches the capture point.** A wireless station receives
  no wired STP, LLDP or trunk VLAN tags, and no switched unicast between other hosts. An
  access port sees its own broadcast domain; observing every VLAN generally needs a trunk or
  mirror port. Absence of captured frames is never proof that switches or devices do not
  exist, and idNX distinguishes "capture active, no frames observed" from "capture never
  started".
- **A BPDU proves a bridge, nothing more.** It is not router evidence and implies no hidden
  subnet.
- **A VLAN tag proves only the VLAN ID.** Its prefix stays unknown until DHCP, an RA or IP
  traffic supplies one.
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

Virtual & VPN networks (local to this machine)
  ├── 10.242.0.0/16 via feth466

Routers & gateways
  ├── myrouter [192.168.1.1, fe80::7612:13ff:fe14:75dc] (Linksys Velop 6SP)
  │     • acts as a DHCP router or server
  │     • advertises a UPnP InternetGatewayDevice
  │     • advertises itself as an IPv6 router (RFC 4861)
  │     • is this machine's default gateway
  │     • serves DNS and a web management interface

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
relationships, evidence, confidence, coverage and opaque boundaries. The HTML page is
self-contained and opens with no network access.

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

See `docs/architecture.md`, `docs/deep_exploration.md` and `docs/protocols.md`; the protocol
tables there mark implemented versus planned explicitly.

---

## License

Apache-2.0. All code is original and clean-room; no copyleft code is vendored.
