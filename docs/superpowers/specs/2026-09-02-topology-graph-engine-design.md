# idNX Topology Graph Engine — Design Specification

Date: 2026-09-02
Status: Approved, implementation in progress

## Purpose

Make idNX a zero-configuration, vendor-neutral network topology discovery tool. It must
not be another target/port scanner, and it must not ask the operator to configure internal
discovery mechanics.

## CLI contract

The normal command is `idnx`. It selects the interface carrying the default route,
determines its IPv4 and IPv6 networks, and performs the complete topology-discovery
workflow. `sudo idnx` runs the same workflow and automatically enables privileged
providers such as raw Layer-2 observation. Privileges enhance discovery; they never
change its scope or require another mode.

A positional argument selects the starting scope:

```
idnx                 default-route interface
sudo idnx            same, plus privileged providers
idnx eth1            that interface as the vantage
idnx 10.20.0.0/16    that network as the starting scope
idnx invalid0        fails clearly and lists valid interfaces
```

Retained options express operator intent only: interface or network selection, output
format and destination, probe timeout, and an SNMP community when the operator has one.

Removed, because they are engine responsibilities: `--recursive`, `--listen-seconds`,
`--threads`, `--heuristic-sweep`, `--infer-hop-subnets`, `--no-deep`, `--scan`. No
deprecated aliases are preserved.

### Selected-scope rule

Whatever starting scope is resolved receives the complete deep-topology workflow.
Interface or subnet selection changes only the starting point; it never selects a reduced
mode. There is exactly one workflow:

```
resolve starting scope
  -> collect all available topology evidence
  -> identify networks and infrastructure
  -> recursively process every discovered network and pivot
  -> enrich discovered devices
  -> stop when the evidence graph converges
  -> render the complete observable topology
```

Every discovered subnet becomes a full discovery scope itself and receives the same
provider pipeline as the initial subnet, not merely an ICMP/TCP host sweep.

## Architecture

One vendor-neutral `TopologyGraph`.

Node kinds: `Interface`, `Network`, `Vlan`, `Router`, `Switch`, `Host`, `Service`,
`OpaqueBoundary`.

Relationship kinds: `AttachedTo`, `RoutesTo`, `GatewayFor`, `Advertises`, `ObservedBehind`,
`PossibleUplink`, `NatBoundary`, `ResolvedAs`.

Every fact carries: evidence source, vantage, timestamp, confidence, and
protocol-specific supporting data.

### Confidence taxonomy

One per-fact taxonomy: `Observed`, `Advertised`, `Inferred`, `UserSupplied`.

A captured advertisement is not direct verification of its contents. Observing an RA
packet is `Observed` evidence that a device sent it; the prefix inside it is `Advertised`.

## Provider orchestration

All applicable providers run automatically and concurrently behind one interface:

```rust
trait DiscoveryProvider {
    async fn discover(&self, context: &DiscoveryContext) -> Vec<TopologyEvidence>;
}
```

Local providers: interface addresses and prefixes, kernel routing tables, default gateway,
DHCP subnet mask/router/classless routes, ARP and NDP caches, resolver configuration.

Credential-free network providers: ARP/NDP, IPv6 RA and prefix discovery, ICMP reachability
and path discovery, DHCP evidence, mDNS, unicast DNS/PTR, SSDP/UPnP, NBNS, LLMNR, MNDP,
LLDP/CDP where available, protocol and service capability fingerprints.

Optional amplifiers: anonymous or configured SNMP, vendor-specific discovery protocols, and
future controller/IPAM and distributed idNX observations.

A provider returning no evidence must never stop other providers. No vendor is privileged
in the graph or the scheduler; ASUS and similar mechanisms sit behind the common provider
interface like any other.

## Packet capture

Capture is an optional, opportunistic provider, not the architecture and not a
prerequisite. Where privileges and platform permit, the interface capture opens
automatically at startup, observes concurrently with the rest of discovery, and closes when
the engine converges. There is no fixed listening delay.

When capture is unavailable or sees nothing, every other path continues. Absence of
captured frames is never proof that devices or switches do not exist; the visibility
limitation is reported concisely. An enterprise access port, Wi-Fi station or restricted
endpoint may expose almost no useful passive traffic, and the engine must remain fully
functional without capture.

## Recursive traversal

Recursion is always enabled internally.

1. Seed the graph from the selected scope and associated OS evidence.
2. Add every positively evidenced router, switch, gateway, network and VLAN.
3. Place infrastructure candidates into a deduplicated work queue.
4. Run all applicable providers against each candidate.
5. Add newly learned networks, devices and relationships.
6. Continue until fixed point or an internal safety budget is reached.
7. Use visited sets to prevent cycles.
8. Size CPU workers automatically from `available_parallelism()`.
9. Use bounded asynchronous I/O and parsing queues.

A router must never depend on SNMP to become a pivot.

## Role determination

An OUI identifies a manufacturer only. It must never independently classify a device as a
router or switch. The existing rule that treats every ASUS MAC as a router is removed.

Roles come from corroborated behaviour, combined through explicit scoring: selected or
default gateway, DHCP router/server behaviour, IPv6 router advertisements, LLDP/CDP
capabilities, UPnP InternetGatewayDevice type, SNMP forwarding state, routing
advertisements, observed forwarding or path behaviour, and weaker fingerprints in
combination.

## Subnet and VLAN correctness

A `Network` node is created only from prefix-bearing evidence: interface address and mask,
kernel route, DHCP subnet mask, DHCP classless route, IPv6 RA Prefix Information Option,
explicit route or interface advertisement, or a user-supplied network.

An observed VLAN tag proves only the VLAN ID. It yields `Vlan { id: 20, subnet: None }`,
rendered as `VLAN 20 observed; prefix unknown`. Never synthesize `192.168.20.0/24` from
VLAN 20, and never widen router addresses or traceroute hops into assumed `/24` networks.

## Address-space neutrality

RFC 1918 is not the only valid internal address space. Kernel-reachable public prefixes,
CGNAT ranges, IPv6 global and ULA prefixes, VPN routes and overlapping domains are
preserved and classified safely.

## NAT and visibility boundaries

Every applicable credential-free provider is attempted automatically. When a router
exposes no downstream prefix and NAT prevents direct reachability, an explicit
`OpaqueBoundary` node is created rather than silently omitting it or inventing a subnet.
Discovery continues for every other reachable or observable part of the topology.

A single endpoint cannot reconstruct topology that no forwarding, control, management or
passive evidence exposes. The program states that boundary once, precisely, and does not
present the partial map as complete.

## Output

Default output shows: the selected interface and why it was selected; local physical, VPN
and virtual networks separately; routers and gateways; routed networks; VLANs including
prefix-unknown ones; switches and observed relationships; hosts beneath the strongest
supported parent relationship; opaque boundaries; and discovery coverage with visibility
limitations.

Local VM and container bridges are not labelled as cascaded physical networks.

Pivot processing is exposed rather than silently dropped:

```
192.168.1.1
  Evidence: default gateway
  SNMP: no response
  UPnP: InternetGatewayDevice
  Routes learned: ...
  Status: processed
```

The final summary distinguishes observed topology, advertised topology, inferred facts,
opaque boundaries, and providers unavailable from this vantage.

## Implementation order

1. Audit README and identify every claimed feature that is print-only, disconnected or
   unimplemented.
2. Introduce the common evidence model and topology graph.
3. Connect kernel routes, interface data, DHCP, ARP/NDP and default gateways.
4. Connect existing LLDP/CDP, MNDP, UPnP and ASUS modules as generic providers.
5. Remove vendor-OUI role assumptions.
6. Implement the automatic fixed-point work queue.
7. Separate topology discovery from active host enrichment.
8. Add concise per-pivot diagnostics and visibility reporting.
9. Correct virtual-network classification.
10. Update every renderer and export to consume the graph.
11. Update README so every statement matches tested behaviour.
12. Add deterministic fixtures for every provider and an end-to-end multi-network topology.

## Acceptance scenarios

- `idnx` selects the default-route interface automatically, runs the complete workflow, and
  requires no discovery flags.
- `sudo idnx` performs the same workflow, automatically adds privileged observations where
  available, and does not wait for an arbitrary capture duration.
- `idnx eth1` uses only eth1 as the initial vantage, derives its prefixes and routes
  automatically, and recursively processes topology learned from it.
- `idnx invalid0` fails clearly and lists valid interfaces.
- An SNMP-disabled network continues through all other providers and does not silently
  terminate recursion.
- An enterprise access port maps everything supported by OS, routing, neighbour, service and
  available control-plane evidence, and does not assume capture provides fabric-wide
  visibility.
- A VLAN tag without prefix evidence produces a VLAN node with an unknown prefix and never
  an invented subnet.
- A NAT router with no disclosed downstream information appears as an opaque boundary and
  produces no guessed networks or invisible hosts.

## Quality requirements

Preserve the ARP performance fix, OUI caching, bounded work queues and deterministic
output. `cargo fmt --check`, `cargo test`, and `cargo clippy --all-targets --all-features
-D warnings` must pass, along with Linux and Windows cross-checks. No AI trailers on
commits.
