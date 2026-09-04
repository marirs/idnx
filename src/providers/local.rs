//! Providers backed by local operating-system state.
//!
//! These need no privileges and no cooperation from anything on the network. They are the
//! seed of every discovery run and the reason the engine still produces a useful map on a
//! network where nothing answers SNMP.

use std::net::{IpAddr, Ipv4Addr};

use super::{DiscoveryContext, DiscoveryProvider, ProviderFuture};
use crate::topology::TopologyEvidence;
use crate::topology::evidence::{
    Capability, Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal,
};

/// IPv4 addresses configured on the selected interface.
///
/// Needed because Windows `route print` reports the interface by its address where the
/// Unix tools report a name, so route matching has to accept both forms.
fn selected_interface_addresses(name: &str) -> Vec<Ipv4Addr> {
    crate::net::interface::list_ipv4_interfaces()
        .map(|list| {
            list.into_iter()
                .filter(|i| i.interface_name.eq_ignore_ascii_case(name))
                .map(|i| i.ip)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a kernel route belongs to the selected interface.
///
/// Selecting an interface has to change what is discovered, not merely what the output is
/// labelled: importing every interface's routes would put unrelated networks — a second NIC,
/// a VPN tunnel, a container bridge — into the recursive queue regardless of the choice.
///
/// A route whose interface is unknown is excluded. Guessing that it belongs to the selected
/// link is the same class of assumption this engine refuses everywhere else.
pub fn route_belongs_to_interface(
    route_interface: Option<&str>,
    selected: &str,
    selected_addresses: &[Ipv4Addr],
) -> bool {
    let Some(found) = route_interface else {
        return false;
    };
    if found.eq_ignore_ascii_case(selected) {
        return true;
    }
    // Windows form: the "interface" column holds an address.
    found
        .parse::<Ipv4Addr>()
        .map(|addr| selected_addresses.contains(&addr))
        .unwrap_or(false)
}

/// Local interface addresses and their prefixes.
///
/// The prefix here is authoritative: it comes from the interface configuration, which is
/// exactly the prefix-bearing evidence a `Network` node requires.
pub struct InterfaceProvider;

impl DiscoveryProvider for InterfaceProvider {
    fn name(&self) -> &'static str {
        "interface-addresses"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        // Only contributes when seeding; it describes this machine, not a remote scope.
        context.scope.is_none() && context.target.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(crate::providers::attempted(async move {
            let mut out = Vec::new();
            // Dual-stack: an IPv6-only prefix on this link is as real as the IPv4 one, and
            // enumerating a single family hides half the attached topology.
            let interfaces = crate::net::interface::list_interface_addresses();

            for iface in interfaces {
                // Only the selected vantage. Emitting every interface's network would make
                // `idnx eth1` discover eth0's and every tunnel's topology too.
                if !iface
                    .interface_name
                    .eq_ignore_ascii_case(&context.vantage.interface)
                {
                    continue;
                }

                let prefix = iface.cidr;
                out.push(
                    TopologyEvidence::new(
                        Fact::Network { prefix },
                        EvidenceSource::InterfaceAddress,
                        Confidence::Observed,
                        &context.vantage.interface,
                    )
                    .with_detail(format!(
                        "configured on {} as {}/{}",
                        iface.interface_name,
                        iface.ip,
                        iface.cidr.prefix_len()
                    )),
                );

                out.push(TopologyEvidence::new(
                    Fact::InterfaceNetwork {
                        interface: iface.interface_name.clone(),
                        prefix,
                    },
                    EvidenceSource::InterfaceAddress,
                    Confidence::Observed,
                    &context.vantage.interface,
                ));

                let device = DeviceKey::scoped_address(iface.ip, Some(&iface.interface_name));
                out.push(TopologyEvidence::new(
                    Fact::DeviceAddress {
                        device: device.clone(),
                        address: iface.ip,
                    },
                    EvidenceSource::InterfaceAddress,
                    Confidence::Observed,
                    &context.vantage.interface,
                ));
                out.push(TopologyEvidence::new(
                    Fact::AttachedTo {
                        device,
                        network: prefix,
                    },
                    EvidenceSource::InterfaceAddress,
                    Confidence::Observed,
                    &context.vantage.interface,
                ));
            }

            out
        }))
    }
}

/// Kernel routing table, including the default gateway.
///
/// Address-space neutral: every routed prefix is preserved, whether RFC 1918, CGNAT,
/// public, or IPv6. Classification of what a prefix *means* happens at render time, not by
/// discarding it here.
pub struct KernelRouteProvider;

impl DiscoveryProvider for KernelRouteProvider {
    fn name(&self) -> &'static str {
        "kernel-routes"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        context.scope.is_none() && context.target.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(crate::providers::attempted(async move {
            let mut out = Vec::new();
            let vantage = &context.vantage.interface;
            let selected_addresses = selected_interface_addresses(vantage);

            for route in crate::net::routes::harvest_kernel_routes().await {
                if !route_belongs_to_interface(
                    route.interface.as_deref(),
                    vantage,
                    &selected_addresses,
                ) {
                    continue;
                }

                let prefix = route.destination;
                let prefix_len = prefix.prefix_len();
                let host_bits = if prefix.addr().is_ipv4() { 32 } else { 128 };

                // A default route carries no network of its own, but its gateway is the
                // most important single device on the machine. A host route (/32 or /128)
                // is a neighbour entry rather than a network.
                let is_default = route.is_default();
                let is_network = !is_default && prefix_len < host_bits;

                if is_network {
                    out.push(
                        TopologyEvidence::new(
                            Fact::Network { prefix },
                            EvidenceSource::KernelRoute,
                            Confidence::Observed,
                            vantage,
                        )
                        .with_detail(format!(
                            "kernel route on {}",
                            route
                                .interface
                                .clone()
                                .unwrap_or_else(|| "unknown interface".to_string())
                        )),
                    );
                }

                if let Some(addr) = route.gateway {
                    // A link-local next hop is only meaningful within its zone, so identity
                    // carries it: without that, fe80::1 on two links would be one device.
                    let device = DeviceKey::scoped_address(addr, route.gateway_zone.as_deref());

                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: device.clone(),
                            address: addr,
                        },
                        EvidenceSource::KernelRoute,
                        Confidence::Observed,
                        vantage,
                    ));

                    if is_default {
                        out.push(TopologyEvidence::new(
                            Fact::DeviceRoleSignal {
                                device: device.clone(),
                                signal: RoleSignal::DefaultGateway,
                            },
                            EvidenceSource::DefaultGateway,
                            Confidence::Observed,
                            vantage,
                        ));
                        out.push(TopologyEvidence::new(
                            Fact::DeviceCapability {
                                device,
                                capability: Capability::DefaultGateway,
                                detail: None,
                            },
                            EvidenceSource::DefaultGateway,
                            Confidence::Observed,
                            vantage,
                        ));
                    } else if is_network {
                        // The routed network and the router that reaches it. This is the
                        // relationship that exposes a subnet one hop away — including an
                        // IPv6-only one, which the IPv4-only harvester never saw.
                        out.push(
                            TopologyEvidence::new(
                                Fact::RoutesTo {
                                    device: device.clone(),
                                    network: prefix,
                                    next_hop: Some(addr),
                                },
                                EvidenceSource::KernelRoute,
                                Confidence::Observed,
                                vantage,
                            )
                            .with_detail(format!("kernel route to {prefix} via {addr}")),
                        );

                        // Being the next hop is itself forwarding evidence. Without this a
                        // router that had left the neighbour table still showed its route
                        // but was no longer recognised as a router at all.
                        out.push(TopologyEvidence::new(
                            Fact::DeviceRoleSignal {
                                device: device.clone(),
                                signal: RoleSignal::KernelNextHop,
                            },
                            EvidenceSource::KernelRoute,
                            Confidence::Observed,
                            vantage,
                        ));
                        out.push(TopologyEvidence::new(
                            Fact::DeviceCapability {
                                device,
                                capability: if prefix.addr().is_ipv6() {
                                    Capability::Ipv6Router
                                } else {
                                    Capability::Ipv4Forwarding
                                },
                                detail: Some(format!("next hop for {prefix}")),
                            },
                            EvidenceSource::KernelRoute,
                            Confidence::Observed,
                            vantage,
                        ));
                    }
                }
            }

            out
        }))
    }
}

/// DHCP lease state already held by the OS.
///
/// Reads the lease rather than emitting a DHCP packet, so it needs no privileges and
/// cannot perturb the network. Option 3 identifies a router by behaviour, which is real
/// role evidence rather than a guess from its manufacturer.
pub struct DhcpLeaseProvider;

impl DiscoveryProvider for DhcpLeaseProvider {
    fn name(&self) -> &'static str {
        "dhcp-lease"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        context.scope.is_none() && context.target.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(crate::providers::attempted(async move {
            let mut out = Vec::new();
            let vantage = &context.vantage.interface;

            for router in
                crate::net::routes::harvest_dhcp_routers(Some(&context.vantage.interface)).await
            {
                let addr = IpAddr::V4(router);
                let device = DeviceKey::Address(addr);

                out.push(TopologyEvidence::new(
                    Fact::DeviceAddress {
                        device: device.clone(),
                        address: addr,
                    },
                    EvidenceSource::DhcpLease,
                    Confidence::Observed,
                    vantage,
                ));
                out.push(
                    TopologyEvidence::new(
                        Fact::DeviceRoleSignal {
                            device,
                            signal: RoleSignal::DhcpRouter,
                        },
                        EvidenceSource::DhcpLease,
                        Confidence::Observed,
                        vantage,
                    )
                    .with_detail("named as router in the OS DHCP lease (option 3)"),
                );
            }

            out
        }))
    }
}

/// ARP and IPv6 neighbour caches.
///
/// The neighbour cache is the single richest credential-free source on a local segment: it
/// lists devices that have communicated even when they answer no probe, and the IPv6
/// isRouter bit is a device's own declaration that it routes.
pub struct NeighborCacheProvider;

impl DiscoveryProvider for NeighborCacheProvider {
    fn name(&self) -> &'static str {
        "neighbor-cache"
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(crate::providers::attempted(async move {
            let mut out = Vec::new();
            let vantage = &context.vantage.interface;
            let iface = Some(context.vantage.interface.as_str());

            for entry in crate::net::arp::read_system_arp_table(iface) {
                let addr = IpAddr::V4(entry.ip);
                if let Some(scope) = context.scope
                    && !scope.contains(&addr)
                {
                    continue;
                }

                let device = DeviceKey::mac(&entry.mac);
                out.push(TopologyEvidence::new(
                    Fact::DeviceAddress {
                        device: device.clone(),
                        address: addr,
                    },
                    EvidenceSource::ArpCache,
                    Confidence::Observed,
                    vantage,
                ));

                if let Some(vendor) = entry.vendor.clone() {
                    // Descriptive only. Vendor never feeds role scoring.
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

                if let Some(hostname) = entry.hostname.clone() {
                    out.push(TopologyEvidence::new(
                        Fact::DeviceHostname { device, hostname },
                        EvidenceSource::ArpCache,
                        Confidence::Observed,
                        vantage,
                    ));
                }
            }

            for entry in crate::net::ipv6::harvest_ndp_cache(iface).await {
                let addr = IpAddr::V6(entry.ip);
                let device = DeviceKey::mac(&entry.mac);

                out.push(TopologyEvidence::new(
                    Fact::DeviceAddress {
                        device: device.clone(),
                        address: addr,
                    },
                    EvidenceSource::NdpCache,
                    Confidence::Observed,
                    vantage,
                ));

                if entry.is_router {
                    out.push(
                        TopologyEvidence::new(
                            Fact::DeviceRoleSignal {
                                device,
                                signal: RoleSignal::RouterAdvertisement,
                            },
                            EvidenceSource::NdpCache,
                            Confidence::Observed,
                            vantage,
                        )
                        .with_detail("isRouter flag set in the IPv6 neighbour table (RFC 4861)"),
                    );
                }
            }

            out
        }))
    }
}

/// All local providers, in the order they seed the graph.
pub fn local_providers() -> Vec<Box<dyn DiscoveryProvider>> {
    vec![
        Box::new(InterfaceProvider),
        Box::new(KernelRouteProvider),
        Box::new(DhcpLeaseProvider),
        Box::new(NeighborCacheProvider),
        // Runs after the cache read, and deliberately so: it re-asks what the cache
        // remembers, and a validated answer takes the address from a stale entry.
        Box::new(crate::providers::network::NdpLivenessProvider),
        // Seed-time, because a router's disclosures describe this link and may name
        // networks beyond it -- which is what puts new scopes into the traversal.
        Box::new(crate::providers::network::RouterDiscoveryProvider),
        // The IPv4 counterpart: option 121 is one of the few mechanisms that can name a
        // prefix this machine is not attached to.
        Box::new(crate::providers::network::DhcpInformProvider),
        // Last of the seed providers: it asks only where the disclosing sources have
        // already been asked, and it creates a network only when an interface states one.
        Box::new(crate::providers::network::BoundedReachabilityProvider::default()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{Vantage, VantageKind};
    use crate::topology::TopologyEvidence;
    use crate::topology::evidence::Capability;
    use std::time::Duration;

    fn ctx() -> DiscoveryContext {
        DiscoveryContext::seed(
            Vantage {
                interface: "test0".to_string(),
                kind: VantageKind::Wired,
                index: 0,
                capture_available: false,
            },
            Duration::from_millis(200),
            16,
        )
    }

    #[test]
    fn seed_only_providers_do_not_apply_to_a_remote_scope() {
        // Interface and route data describe this machine. Re-emitting them while examining
        // a discovered subnet would attach local facts to a remote network.
        let scoped = ctx().for_scope("10.0.0.0/24".parse().unwrap());
        assert!(!InterfaceProvider.applies(&scoped));
        assert!(!KernelRouteProvider.applies(&scoped));
        assert!(!DhcpLeaseProvider.applies(&scoped));

        // The neighbour cache does apply per-scope: it is filtered by the scope itself.
        assert!(NeighborCacheProvider.applies(&scoped));
    }

    #[test]
    fn routes_on_other_interfaces_are_excluded() {
        // `idnx eth1` must change what is discovered, not just the label. Importing eth0's
        // or a container bridge's routes would put unrelated networks into the queue.
        let addrs = [Ipv4Addr::new(10, 0, 0, 5)];

        assert!(route_belongs_to_interface(Some("eth1"), "eth1", &addrs));
        assert!(route_belongs_to_interface(Some("ETH1"), "eth1", &addrs));

        assert!(!route_belongs_to_interface(Some("eth0"), "eth1", &addrs));
        assert!(!route_belongs_to_interface(Some("feth466"), "eth1", &addrs));
        assert!(!route_belongs_to_interface(Some("utun3"), "eth1", &addrs));
        assert!(!route_belongs_to_interface(Some("docker0"), "eth1", &addrs));
    }

    #[test]
    fn windows_routes_match_by_interface_address() {
        // `route print` names the interface by its address rather than a device name.
        let addrs = [Ipv4Addr::new(10, 0, 0, 5)];
        assert!(route_belongs_to_interface(Some("10.0.0.5"), "eth1", &addrs));
        assert!(!route_belongs_to_interface(
            Some("10.0.0.9"),
            "eth1",
            &addrs
        ));
    }

    #[test]
    fn a_route_with_no_known_interface_is_not_assumed_to_be_ours() {
        // Guessing that an unattributed route belongs to the selected link is the same
        // class of assumption the engine refuses everywhere else.
        assert!(!route_belongs_to_interface(None, "eth1", &[]));
    }

    #[test]
    fn a_scoped_ipv6_next_hop_survives_without_a_neighbour_entry() {
        // Reproduces the live case end to end, from parsed route to graph relationship.
        // The device owning fe80::1812:faa5:e4ee:1b9 left the neighbour table while its
        // route remained; without this the network kept its route but the gateway stopped
        // being recognised as routing at all.
        use crate::topology::TopologyGraph;
        use crate::topology::graph::{NodeId, Relationship};

        let sample = "\
Routing tables

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
fd84:3bfe:bf84::/64                     fe80::1812:faa5:e4ee:1b9%en0            UGc                   en0
";
        let routes = crate::net::routes::parse_netstat_routes(sample);
        let route = routes.first().expect("the routed prefix parses");

        // Exactly what KernelRouteProvider emits for such a route.
        let gateway = route.gateway.expect("scoped next hop");
        let device = DeviceKey::scoped_address(gateway, route.gateway_zone.as_deref());
        let network = route.destination;

        let mut graph = TopologyGraph::new();
        for fact in [
            Fact::Network { prefix: network },
            Fact::DeviceAddress {
                device: device.clone(),
                address: gateway,
            },
            Fact::RoutesTo {
                device: device.clone(),
                network,
                next_hop: Some(gateway),
            },
            Fact::DeviceRoleSignal {
                device: device.clone(),
                signal: RoleSignal::KernelNextHop,
            },
            Fact::DeviceCapability {
                device: device.clone(),
                capability: Capability::Ipv6Router,
                detail: Some(format!("next hop for {network}")),
            },
        ] {
            graph.absorb(TopologyEvidence::new(
                fact,
                EvidenceSource::KernelRoute,
                Confidence::Observed,
                "en0",
            ));
        }
        graph.finalize_roles();

        // The network exists.
        assert!(graph.networks().contains(&network));

        // The gateway is a router, from the route alone and with no NDP entry present.
        let node = graph
            .node(&NodeId::Device(device.clone()))
            .expect("gateway node");
        assert_eq!(node.kind, crate::topology::graph::NodeKind::Router);
        assert!(
            node.capabilities.iter().any(|c| c.contains("IPv6 router")),
            "capability must name IPv6 routing specifically"
        );
        assert!(
            !node
                .capabilities
                .iter()
                .any(|c| c.contains("default gateway")),
            "a routed prefix must never imply the Internet gateway"
        );

        // And it is attached to the prefix it routes to.
        assert!(
            graph.edges().any(|e| {
                e.relationship == Relationship::RoutesTo
                    && e.from == NodeId::Device(device.clone())
                    && matches!(&e.to, crate::topology::NodeId::Network(net, _) if *net == network)
            }),
            "the routed prefix must remain attached to its next hop"
        );
    }

    #[test]
    fn seed_providers_apply_when_seeding() {
        let seed = ctx();
        assert!(InterfaceProvider.applies(&seed));
        assert!(KernelRouteProvider.applies(&seed));
    }

    #[tokio::test]
    async fn interface_provider_emits_prefix_bearing_networks() {
        // Runs against the real host; assert on shape rather than on a specific network so
        // the test is stable anywhere.
        let produced = InterfaceProvider.discover(&ctx()).await;
        for ev in &produced.evidence {
            if let Fact::Network { prefix } = &ev.fact {
                assert!(
                    prefix.prefix_len() > 0,
                    "a network must carry a real prefix, never a placeholder"
                );
                assert_eq!(ev.confidence, Confidence::Observed);
            }
        }
    }
}
