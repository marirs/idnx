//! Credential-free network providers.
//!
//! These send packets but never authenticate. Each is optional and independent: a provider
//! that finds nothing records that it ran and never halts the others. No vendor is
//! privileged — a proprietary discovery protocol sits beside DHCP and LLDP as one source
//! among many.

use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;

use super::{DiscoveryContext, DiscoveryProvider, ProviderFuture};
use crate::topology::TopologyEvidence;
use crate::topology::evidence::{
    Capability, Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal,
};

/// SSDP/UPnP discovery.
///
/// A device advertising the InternetGatewayDevice profile is declaring that it routes.
/// That is behavioural role evidence obtainable with no credentials, and it works against
/// routers that answer no SNMP.
pub struct SsdpProvider;

impl DiscoveryProvider for SsdpProvider {
    fn name(&self) -> &'static str {
        "ssdp-upnp"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        // SSDP is link-local multicast: it only reaches the segment we are attached to.
        context.target.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let mut out = Vec::new();
            let vantage = &context.vantage.interface;
            // SSDP replies trickle in: each responder answers after a random delay up to
            // the MX value, and each descriptor then needs an HTTP fetch. A sub-second
            // window silently misses gateways that are present and answering.
            let devices = crate::probes::upnp::discover_upnp_devices(
                &context.binding,
                context.timeout.max(Duration::from_millis(2500)),
            )
            .await;

            for dev in devices {
                let addr = IpAddr::V4(dev.ip);
                if let Some(scope) = context.scope
                    && !scope.contains(&addr)
                {
                    continue;
                }

                let device = DeviceKey::Address(addr);
                out.push(TopologyEvidence::new(
                    Fact::DeviceAddress {
                        device: device.clone(),
                        address: addr,
                    },
                    EvidenceSource::Ssdp,
                    Confidence::Observed,
                    vantage,
                ));

                if let Some(name) = dev.friendly_name.clone() {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceHostname {
                            device: device.clone(),
                            hostname: name,
                        },
                        EvidenceSource::Ssdp,
                        // The device asserted this name; we did not verify it.
                        Confidence::Advertised,
                        vantage,
                    ));
                }

                let described = [dev.manufacturer.clone(), dev.model_name.clone()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ");
                if !described.is_empty() {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceDescription {
                            device: device.clone(),
                            text: described,
                        },
                        EvidenceSource::Ssdp,
                        Confidence::Advertised,
                        vantage,
                    ));
                }

                if dev.is_internet_gateway() {
                    out.push(
                        TopologyEvidence::new(
                            Fact::DeviceRoleSignal {
                                device,
                                signal: RoleSignal::InternetGatewayDevice,
                            },
                            EvidenceSource::Ssdp,
                            Confidence::Advertised,
                            vantage,
                        )
                        .with_detail(
                            dev.device_type
                                .clone()
                                .unwrap_or_else(|| "InternetGatewayDevice".to_string()),
                        ),
                    );
                    out.push(TopologyEvidence::new(
                        Fact::DeviceCapability {
                            device: DeviceKey::Address(addr),
                            capability: Capability::NatGateway,
                            detail: Some("UPnP InternetGatewayDevice".to_string()),
                        },
                        EvidenceSource::Ssdp,
                        Confidence::Advertised,
                        vantage,
                    ));
                }
            }

            out
        })
    }
}

/// MikroTik Neighbor Discovery Protocol.
///
/// Previously printed and discarded. A RouterOS beacon identifies infrastructure by its own
/// announcement, which is exactly the kind of evidence the graph exists to hold.
pub struct MndpProvider;

impl DiscoveryProvider for MndpProvider {
    fn name(&self) -> &'static str {
        "mndp"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        context.target.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let mut out = Vec::new();
            let vantage = &context.vantage.interface;

            for n in crate::probes::mndp::listen_mndp_neighbors(
                &context.binding,
                Duration::from_millis(600),
            )
            .await
            {
                let device = DeviceKey::mac(&n.mac_address);

                out.push(TopologyEvidence::new(
                    Fact::DeviceHostname {
                        device: device.clone(),
                        hostname: n.identity.clone(),
                    },
                    EvidenceSource::Mndp,
                    Confidence::Advertised,
                    vantage,
                ));

                if let Some(board) = n.board_name.clone() {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceDescription {
                            device: device.clone(),
                            text: board,
                        },
                        EvidenceSource::Mndp,
                        Confidence::Advertised,
                        vantage,
                    ));
                }

                // A RouterOS device announcing itself on the segment is infrastructure by
                // its own declaration, not by its manufacturer.
                out.push(
                    TopologyEvidence::new(
                        Fact::DeviceRoleSignal {
                            device,
                            signal: RoleSignal::LinkLayerCapability("Router"),
                        },
                        EvidenceSource::Mndp,
                        Confidence::Advertised,
                        vantage,
                    )
                    .with_detail("announces itself via MikroTik MNDP"),
                );
            }

            out
        })
    }
}

/// Vendor-proprietary discovery broadcasts.
///
/// A thin shell over the vendor broadcast registry, so that no manufacturer is privileged
/// in the graph or the scheduler: adding one means adding an entry to that registry, not a
/// branch here. Whether any broadcast answers never affects recursion.
pub struct VendorDiscoveryProvider;

impl DiscoveryProvider for VendorDiscoveryProvider {
    fn name(&self) -> &'static str {
        "vendor-discovery"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        context.target.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            crate::providers::vendor::run_broadcasts(
                &context.vantage.interface,
                &context.binding,
                context.timeout.max(Duration::from_millis(600)),
            )
            .await
        })
    }
}

/// Router interfaces beyond the first hop.
///
/// The kernel routing table names exactly one router: the default gateway. Every other
/// router on the way out is invisible to every provider that reads local state -- and yet
/// they are real, frequently reachable, and often the only devices that know the prefixes
/// of the networks behind them. On the network this was written against, the second hop is
/// a router with an open management interface that nothing else here ever saw.
///
/// A hop is a device, never a prefix. A router answering from one of its interfaces proves
/// that it forwards; it says nothing about the size or shape of the network that address
/// belongs to, and deriving one would be inventing topology. So each hop enters the graph
/// as a device with observed forwarding behaviour, which makes it a pivot -- and the staged
/// interrogation that follows is what may legitimately extract a prefix from it.
pub struct PathDiscoveryProvider;

impl DiscoveryProvider for PathDiscoveryProvider {
    fn name(&self) -> &'static str {
        "path-discovery"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        // Not aimed at a single device. The path out belongs to the vantage rather than to
        // any one scope, and absorbing the same hops twice is idempotent, so running it
        // per scope costs a few packets and keeps the provider free of run-level state.
        context.target.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let mut out = Vec::new();
            let vantage = &context.vantage.interface;

            let hops = crate::probes::path::discover_path(
                &context.binding,
                context.timeout.max(Duration::from_millis(600)),
                crate::probes::path::MAX_HOPS,
            )
            .await;

            for hop in hops {
                let device = DeviceKey::Address(hop.address);

                out.push(TopologyEvidence::new(
                    Fact::DeviceAddress {
                        device: device.clone(),
                        address: hop.address,
                    },
                    EvidenceSource::IcmpProbe,
                    Confidence::Observed,
                    vantage,
                ));

                // Behaviour, not manufacture: this device decremented our packet's hop
                // count and said so. That is what a router does.
                out.push(
                    TopologyEvidence::new(
                        Fact::DeviceRoleSignal {
                            device: device.clone(),
                            signal: RoleSignal::ObservedForwarding,
                        },
                        EvidenceSource::IcmpProbe,
                        Confidence::Observed,
                        vantage,
                    )
                    .with_detail(format!("forwarded a probe at hop {}", hop.distance)),
                );

                out.push(TopologyEvidence::new(
                    Fact::DeviceCapability {
                        device: device.clone(),
                        capability: Capability::Ipv4Forwarding,
                        detail: Some(format!("hop {} on the path out", hop.distance)),
                    },
                    EvidenceSource::IcmpProbe,
                    Confidence::Observed,
                    vantage,
                ));

                // Beyond the first hop the router is upstream of this vantage's own
                // gateway, so whatever it serves is not on any link reachable from here
                // until the device itself discloses it. Recorded as an unresolved boundary
                // rather than omitted, and never as a synthesised prefix.
                if hop.distance > 1 {
                    out.push(
                        TopologyEvidence::new(
                            Fact::OpaqueBoundary {
                                device,
                                why: format!(
                                    "upstream router at hop {}; forwards traffic but has \
                                     disclosed no prefix for what lies behind it",
                                    hop.distance
                                ),
                            },
                            EvidenceSource::IcmpProbe,
                            Confidence::Observed,
                            vantage,
                        )
                        .with_detail("interrogated for routing evidence; nothing yet disclosed"),
                    );
                }
            }

            out
        })
    }
}

/// SNMP, as one amplifier among many rather than the gatekeeper of topology.
///
/// When available it is the richest single source, contributing routing tables, interface
/// prefixes and remote ARP caches. When unavailable — the common case on consumer gear —
/// every other provider continues unaffected.
pub struct SnmpProvider;

impl SnmpProvider {
    fn communities(context: &DiscoveryContext) -> Vec<String> {
        if context.snmp_communities.is_empty() {
            vec!["public".to_string()]
        } else {
            context.snmp_communities.clone()
        }
    }
}

impl DiscoveryProvider for SnmpProvider {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        context.target.is_some()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let mut out = Vec::new();
            let Some(IpAddr::V4(target)) = context.target else {
                return out;
            };
            let vantage = &context.vantage.interface;

            let mut info = None;
            for community in Self::communities(context) {
                if let Some(found) = crate::probes::snmp::harvest_snmp_device(
                    target,
                    161,
                    &community,
                    &context.binding,
                    context.timeout.max(Duration::from_millis(350)),
                )
                .await
                {
                    info = Some(found);
                    break;
                }
            }

            let Some(info) = info else {
                return out;
            };
            let device = DeviceKey::Address(IpAddr::V4(target));

            out.push(
                TopologyEvidence::new(
                    Fact::DeviceRoleSignal {
                        device: device.clone(),
                        signal: RoleSignal::SnmpForwarding,
                    },
                    EvidenceSource::Snmp,
                    Confidence::Advertised,
                    vantage,
                )
                .with_detail("returned MIB-II routing state"),
            );

            if let Some(name) = info.sys_name.clone() {
                out.push(TopologyEvidence::new(
                    Fact::DeviceHostname {
                        device: device.clone(),
                        hostname: name,
                    },
                    EvidenceSource::Snmp,
                    Confidence::Advertised,
                    vantage,
                ));
            }

            // ipAddrTable: networks this router is directly attached to, with its exact
            // interface address on each. Prefix-bearing, so these become real networks.
            for (addr, mask) in &info.local_ips {
                let prefix_len = u32::from(*mask).count_ones() as u8;
                if !(1..=30).contains(&prefix_len) {
                    continue;
                }
                let Ok(net) = ipnet::Ipv4Net::new(*addr, prefix_len) else {
                    continue;
                };
                let network = IpNet::V4(net.trunc());
                out.push(TopologyEvidence::new(
                    Fact::Network { prefix: network },
                    EvidenceSource::Snmp,
                    Confidence::Advertised,
                    vantage,
                ));
                out.push(TopologyEvidence::new(
                    Fact::GatewayFor {
                        device: DeviceKey::Address(IpAddr::V4(*addr)),
                        network,
                    },
                    EvidenceSource::Snmp,
                    Confidence::Advertised,
                    vantage,
                ));
            }

            // ipRouteTable: everything it forwards toward.
            for entry in &info.routes {
                let prefix_len = u32::from(entry.mask).count_ones() as u8;
                if !(1..=30).contains(&prefix_len) || entry.dest_network.is_unspecified() {
                    continue;
                }
                let Ok(net) = ipnet::Ipv4Net::new(entry.dest_network, prefix_len) else {
                    continue;
                };
                let network = IpNet::V4(net.trunc());
                let next_hop = if entry.next_hop.is_unspecified() {
                    None
                } else {
                    Some(IpAddr::V4(entry.next_hop))
                };
                out.push(TopologyEvidence::new(
                    Fact::Network { prefix: network },
                    EvidenceSource::Snmp,
                    Confidence::Advertised,
                    vantage,
                ));
                out.push(TopologyEvidence::new(
                    Fact::RoutesTo {
                        device: device.clone(),
                        network,
                        next_hop,
                    },
                    EvidenceSource::Snmp,
                    Confidence::Advertised,
                    vantage,
                ));
            }

            // The router's ARP cache lists devices that answered it even if they answer
            // nothing of ours.
            for entry in &info.arp_cache {
                out.push(TopologyEvidence::new(
                    Fact::DeviceAddress {
                        device: DeviceKey::mac(&entry.mac),
                        address: IpAddr::V4(entry.ip),
                    },
                    EvidenceSource::Snmp,
                    Confidence::Advertised,
                    vantage,
                ));
            }

            out
        })
    }
}

/// Active host enrichment for a discovered network.
///
/// This runs *after* topology discovery and only against networks the graph already knows
/// exist. Scanning validates and enriches what discovery found; it is no longer the thing
/// that finds it. Oversized networks are skipped, since enumerating a /16 belonging to a
/// container bridge costs minutes and yields nothing.
pub struct HostEnrichmentProvider {
    pub ports: Vec<u16>,
    pub max_enumerable_hosts: usize,
}

impl Default for HostEnrichmentProvider {
    fn default() -> Self {
        Self {
            // Liveness only. Every other port belongs to the per-device queue, which
            // probes a far wider set once and attributes the result to one device;
            // sweeping the same seventeen ports here as well probed each host twice.
            // These three are kept because a host that ignores ICMP and has no ARP entry
            // is otherwise invisible, and they are the ports most likely to answer.
            ports: vec![22, 80, 443],
            max_enumerable_hosts: crate::engine::orchestrator::Budget::default()
                .max_enumerable_hosts,
        }
    }
}

impl DiscoveryProvider for HostEnrichmentProvider {
    fn name(&self) -> &'static str {
        "host-enrichment"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        let Some(scope) = context.scope else {
            return false;
        };
        // IPv4 only: IPv6 host space is never swept, and its hosts arrive from neighbour
        // discovery instead.
        matches!(scope, IpNet::V4(_))
            && crate::engine::orchestrator::enumerable_host_count(&scope)
                <= self.max_enumerable_hosts
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let mut out = Vec::new();
            let Some(IpNet::V4(scope)) = context.scope else {
                return out;
            };
            let vantage = &context.vantage.interface;

            let summary = crate::engine::scanner::scan_subnet_ext(
                scope,
                &self.ports,
                Some(&context.vantage.interface),
                &context.probe_channel(),
                context.timeout,
                None,
                true,
            )
            .await;

            for host in summary.active_hosts {
                // Prefer the MAC as identity so a host merges with whatever the neighbour
                // cache and other providers already recorded for the same device.
                let device = match &host.mac_address {
                    Some(mac) => DeviceKey::mac(mac),
                    None if !host.ip.is_unspecified() => DeviceKey::Address(IpAddr::V4(host.ip)),
                    None => continue,
                };

                if !host.ip.is_unspecified() {
                    // Attribute the address to how it was actually established. Labelling
                    // every host as an ICMP result was simply false for the many found via
                    // ARP or a TCP response, and it made the evidence trail useless.
                    let source = match (&host.mac_address, host.open_ports.is_empty()) {
                        (Some(_), _) => EvidenceSource::ArpCache,
                        (None, false) => EvidenceSource::TcpProbe,
                        (None, true) => EvidenceSource::IcmpProbe,
                    };
                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: device.clone(),
                            address: IpAddr::V4(host.ip),
                        },
                        source,
                        Confidence::Observed,
                        vantage,
                    ));
                }

                for v6 in &host.ipv6_addrs {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: device.clone(),
                            address: IpAddr::V6(*v6),
                        },
                        EvidenceSource::NdpCache,
                        Confidence::Observed,
                        vantage,
                    ));
                }

                // The scanner uses bracketed placeholders where it has no real name.
                // Passing one through would present "[IPv6 Only]" as a hostname.
                if let Some(name) = host
                    .hostname
                    .clone()
                    .filter(|n| !n.starts_with('[') && !n.trim().is_empty())
                {
                    // A `.local` name is mDNS; anything else came from unicast PTR. Marking
                    // every name as mDNS misattributed the resolver that actually answered.
                    let source = if name.ends_with(".local") || name.ends_with(".local.") {
                        EvidenceSource::Mdns
                    } else {
                        EvidenceSource::UnicastDns
                    };
                    out.push(TopologyEvidence::new(
                        Fact::DeviceHostname {
                            device: device.clone(),
                            hostname: name,
                        },
                        source,
                        Confidence::Observed,
                        vantage,
                    ));
                }

                if let Some(vendor) = host.vendor.clone() {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceVendor {
                            device: device.clone(),
                            vendor,
                        },
                        EvidenceSource::ArpCache,
                        Confidence::Observed,
                        vantage,
                    ));
                }

                // Liveness discovery only. Services and capabilities belong to the
                // per-device pipeline, which confirms a protocol by speaking it.
                //
                // What stood here derived capabilities from port numbers: TCP 53 open
                // became a DNS server, an open HTTP port became a management interface,
                // and the two together emitted a role signal. None of that had been
                // confirmed -- an open port is reachability, not a protocol -- and the
                // combination promoted ordinary hosts on the strength of two open ports.
            }

            out
        })
    }
}

/// Providers that examine a network scope or a specific device.
pub fn network_providers() -> Vec<Box<dyn DiscoveryProvider>> {
    vec![
        Box::new(SsdpProvider),
        Box::new(MndpProvider),
        Box::new(VendorDiscoveryProvider),
        Box::new(PathDiscoveryProvider),
        Box::new(SnmpProvider),
        Box::new(HostEnrichmentProvider::default()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{Vantage, VantageKind};

    fn ctx(kind: VantageKind, capture: bool) -> DiscoveryContext {
        DiscoveryContext::seed(
            Vantage {
                interface: "test0".to_string(),
                kind,
                index: 0,
                capture_available: capture,
            },
            Duration::from_millis(200),
            16,
        )
    }

    #[test]
    fn no_network_provider_opens_a_capture_device() {
        // Capture belongs solely to the continuous passive source. A second provider
        // opening its own device competed for BPF devices on macOS and reintroduced the
        // fixed listening delay this design removed.
        let names: Vec<&str> = network_providers().iter().map(|p| p.name()).collect();
        assert!(!names.contains(&"lldp-cdp"));
        assert!(!names.contains(&"passive-capture"));
    }

    #[test]
    fn snmp_only_applies_to_a_specific_target() {
        // SNMP interrogates a device; it is not a segment-wide sweep.
        let seeded = ctx(VantageKind::Wired, true);
        assert!(!SnmpProvider.applies(&seeded));

        let targeted = seeded.for_target("10.0.0.1".parse().unwrap());
        assert!(SnmpProvider.applies(&targeted));
    }

    #[test]
    fn snmp_defaults_to_the_anonymous_community() {
        let c = ctx(VantageKind::Wired, true);
        assert_eq!(SnmpProvider::communities(&c), vec!["public".to_string()]);
    }

    #[test]
    fn snmp_honours_operator_supplied_communities() {
        let mut c = ctx(VantageKind::Wired, true);
        c.snmp_communities = vec!["private".to_string(), "ro".to_string()];
        assert_eq!(SnmpProvider::communities(&c).len(), 2);
    }

    #[test]
    fn multicast_providers_do_not_run_against_a_remote_target() {
        // SSDP and MNDP are link-local; aiming them at a routed device would be pointless
        // work and a misleading diagnostic.
        let targeted = ctx(VantageKind::Wired, true).for_target("10.0.0.1".parse().unwrap());
        assert!(!SsdpProvider.applies(&targeted));
        assert!(!MndpProvider.applies(&targeted));
    }
}
