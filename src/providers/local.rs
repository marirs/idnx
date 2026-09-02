//! Providers backed by local operating-system state.
//!
//! These need no privileges and no cooperation from anything on the network. They are the
//! seed of every discovery run and the reason the engine still produces a useful map on a
//! network where nothing answers SNMP.

use std::net::IpAddr;

use ipnet::IpNet;

use super::{DiscoveryContext, DiscoveryProvider, ProviderFuture};
use crate::topology::TopologyEvidence;
use crate::topology::evidence::{Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal};

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
        Box::pin(async move {
            let mut out = Vec::new();
            let Ok(interfaces) = crate::net::interface::list_ipv4_interfaces() else {
                return out;
            };

            for iface in interfaces {
                let prefix = IpNet::V4(iface.cidr);
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

                let device = DeviceKey::Address(IpAddr::V4(iface.ip));
                out.push(TopologyEvidence::new(
                    Fact::DeviceAddress {
                        device: device.clone(),
                        address: IpAddr::V4(iface.ip),
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
        })
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
        Box::pin(async move {
            let mut out = Vec::new();
            let vantage = &context.vantage.interface;

            for route in crate::net::routes::harvest_kernel_routes().await {
                let prefix_len = route.destination.prefix_len();

                // A default route carries no network of its own, but its gateway is the
                // most important single device on the machine.
                let is_default = prefix_len == 0;

                if !is_default && prefix_len < 32 {
                    let prefix = IpNet::V4(route.destination);
                    out.push(
                        TopologyEvidence::new(
                            Fact::Network { prefix },
                            EvidenceSource::KernelRoute,
                            Confidence::Observed,
                            vantage,
                        )
                        .with_detail(format!(
                            "kernel route via {}",
                            route
                                .interface
                                .clone()
                                .unwrap_or_else(|| "unknown interface".to_string())
                        )),
                    );
                }

                if let Some(gw) = route.gateway {
                    let addr = IpAddr::V4(gw);
                    let device = DeviceKey::Address(addr);

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
                    } else if prefix_len < 32 {
                        out.push(TopologyEvidence::new(
                            Fact::RoutesTo {
                                device,
                                network: IpNet::V4(route.destination),
                                next_hop: Some(addr),
                            },
                            EvidenceSource::KernelRoute,
                            Confidence::Observed,
                            vantage,
                        ));
                    }
                }
            }

            out
        })
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
        Box::pin(async move {
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
        })
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
        Box::pin(async move {
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
        })
    }
}

/// All local providers, in the order they seed the graph.
pub fn local_providers() -> Vec<Box<dyn DiscoveryProvider>> {
    vec![
        Box::new(InterfaceProvider),
        Box::new(KernelRouteProvider),
        Box::new(DhcpLeaseProvider),
        Box::new(NeighborCacheProvider),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{Vantage, VantageKind};
    use std::time::Duration;

    fn ctx() -> DiscoveryContext {
        DiscoveryContext::seed(
            Vantage {
                interface: "test0".to_string(),
                kind: VantageKind::Wired,
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
    fn seed_providers_apply_when_seeding() {
        let seed = ctx();
        assert!(InterfaceProvider.applies(&seed));
        assert!(KernelRouteProvider.applies(&seed));
    }

    #[tokio::test]
    async fn interface_provider_emits_prefix_bearing_networks() {
        // Runs against the real host; assert on shape rather than on a specific network so
        // the test is stable anywhere.
        let evidence = InterfaceProvider.discover(&ctx()).await;
        for ev in &evidence {
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
