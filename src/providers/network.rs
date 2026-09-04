//! Credential-free network providers.
//!
//! These send packets but never authenticate. Each is optional and independent: a provider
//! that finds nothing records that it ran and never halts the others. No vendor is
//! privileged — a proprietary discovery protocol sits beside DHCP and LLDP as one source
//! among many.

use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;

use super::{DiscoveryContext, DiscoveryProvider, ProviderFuture, ProviderOutput};
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
        Box::pin(crate::providers::attempted(async move {
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
        }))
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
        Box::pin(crate::providers::attempted(async move {
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
        }))
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
            let run = crate::providers::vendor::run_broadcasts(
                &context.vantage.interface,
                &context.binding,
                context.timeout.max(Duration::from_millis(600)),
            )
            .await;
            // Only evidence enters the graph. The outcomes travel beside it so that a
            // broadcast whose framing is unverified is reported as unavailable rather than
            // disappearing into an empty result the engine would then call "no response".
            ProviderOutput {
                evidence: run.evidence,
                notes: run.outcomes,
                attempted: run.transmitted,
            }
        })
    }
}

/// Router interfaces on the default egress path.
///
/// The kernel routing table names exactly one router: the default gateway. The routers
/// beyond it are invisible to every provider that reads local state, and yet they are real
/// and frequently reachable -- on the network this was written against, the second hop has
/// telnet, DNS and HTTP open and nothing else here had ever seen it.
///
/// What this establishes, and only this: an interface at that address forwarded one packet,
/// at that distance, toward one destination, from this vantage. Not a prefix -- the address
/// says nothing about the network it belongs to. Not opacity -- a router that forwards is
/// not thereby hiding anything, and calling every hop a boundary asserted a NAT nobody had
/// observed. Not ownership -- hop count is not an administrative boundary, and a router a
/// few hops out is as likely to be a carrier's as the operator's.
///
/// The value is that each hop becomes a device with observed forwarding behaviour, which
/// makes it a pivot. Interrogating it is what may legitimately produce a prefix, and a
/// prefix is the only thing that creates a network.
pub struct PathDiscoveryProvider;

impl DiscoveryProvider for PathDiscoveryProvider {
    fn name(&self) -> &'static str {
        "egress-path"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        // Not aimed at a single device. The path out belongs to the vantage rather than to
        // any one scope, and absorbing the same hops twice is idempotent.
        context.target.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(crate::providers::attempted(async move {
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

                // Behaviour, not manufacture: this interface decremented our packet's hop
                // count and said so. That is what forwarding is.
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
                    .with_detail(format!(
                        "answered a TTL-expired probe at hop {} toward {}",
                        hop.distance, hop.toward
                    )),
                );

                out.push(TopologyEvidence::new(
                    Fact::DeviceCapability {
                        device: device.clone(),
                        capability: Capability::Ipv4Forwarding,
                        detail: Some(format!(
                            "hop {} on the egress path toward {}",
                            hop.distance, hop.toward
                        )),
                    },
                    EvidenceSource::IcmpProbe,
                    Confidence::Observed,
                    vantage,
                ));

                // The path itself, with everything needed to reproduce the finding. No
                // boundary is asserted: that would need separate evidence of a NAT, a
                // firewall, or topology being withheld.
                out.push(TopologyEvidence::new(
                    Fact::ForwardsToward {
                        device,
                        toward: hop.toward,
                        distance: hop.distance,
                        previous: hop.previous.map(DeviceKey::Address),
                    },
                    EvidenceSource::IcmpProbe,
                    Confidence::Observed,
                    vantage,
                ));
            }

            out
        }))
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
        Box::pin(crate::providers::attempted(async move {
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
        }))
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
                return ProviderOutput::default();
            };
            let vantage = &context.vantage.interface;

            // ARP resolution is not this provider's decision to make. arp-liveness owns the
            // whole sequence -- raw sweep, and the kernel-ARP fallback when nothing was
            // transmitted -- so that two providers cannot reach contradictory conclusions
            // about whether the link has already been asked.
            let mut notes =
                vec!["port sweep only; ARP resolution belongs to arp-liveness".to_string()];

            let summary = crate::engine::scanner::scan_subnet_ext(
                scope,
                &self.ports,
                Some(&context.vantage.interface),
                &context.probe_channel(),
                context.timeout,
                None,
                true,
                false,
            )
            .await;
            let summary_hosts = summary.active_hosts.len();

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

            notes.push(format!("{} host(s) answered something", summary_hosts));
            ProviderOutput {
                evidence: out,
                notes,
                attempted: true,
            }
        })
    }
}

/// Active liveness confirmation on the attached link.
///
/// Everything else that establishes a device is either a memory (the kernel's neighbour
/// cache, which keeps entries long after the host is gone) or a side effect of some other
/// probe. This asks the question directly and validates the answer against it, which is the
/// only way to say a station was answering at the moment it was asked.
///
/// It runs only for the prefix this interface is actually attached to. ARP resolves nothing
/// beyond the link, and broadcasting for an off-link address would record whichever router
/// proxied as that address's own hardware identity.
pub struct ArpLivenessProvider {
    pub max_enumerable_hosts: usize,
}

impl Default for ArpLivenessProvider {
    fn default() -> Self {
        Self {
            max_enumerable_hosts: crate::engine::orchestrator::Budget::default()
                .max_enumerable_hosts,
        }
    }
}

impl DiscoveryProvider for ArpLivenessProvider {
    fn name(&self) -> &'static str {
        "arp-liveness"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        context.target.is_none()
            && context.scope.is_some_and(|scope| {
                matches!(scope, IpNet::V4(_))
                    && crate::engine::orchestrator::enumerable_host_count(&scope)
                        <= self.max_enumerable_hosts
            })
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let Some(IpNet::V4(scope)) = context.scope else {
                return ProviderOutput::default();
            };
            let vantage = &context.vantage.interface;

            // The interface's own address is both the sender field and the proof that this
            // prefix is on-link. Without it there is nothing to put in the request.
            let attached = match crate::net::interface::get_interface_by_name(vantage) {
                Ok(local) if local.cidr == scope.trunc() => local,
                Ok(local) => {
                    return ProviderOutput::not_applicable(format!(
                        "{scope} is not the prefix {vantage} is attached to ({}); ARP resolves \
                         nothing beyond the link",
                        local.cidr
                    ));
                }
                Err(reason) => {
                    return ProviderOutput::unavailable(format!(
                        "{vantage} has no IPv4 address to ask from: {reason}"
                    ));
                }
            };

            let targets: Vec<std::net::Ipv4Addr> = scope.hosts().collect();
            let outcome = crate::probes::arp::sweep_liveness(
                vantage,
                scope.trunc(),
                attached.ip,
                targets,
                context.timeout.max(Duration::from_millis(1500)),
            )
            .await;

            let attempted = outcome.transmitted();
            let mut notes = vec![outcome.describe(self.name())];
            let mut out = Vec::new();

            // What the outcome means for the rest of address resolution on this link, and
            // the fallback run here rather than by a second provider working from a
            // preflight that cannot see whether anything was actually sent.
            let resolution = crate::probes::arp::resolve_sweep(&outcome);
            if let crate::probes::arp::ArpResolution::Fallback { .. } = &resolution {
                crate::net::arp::trigger_kernel_arp_sweep(scope.trunc(), &context.probe_channel())
                    .await;

                // Context, bounded by what can actually be established from here. The
                // sweep's own observation says whether the request entered this host's
                // egress path; nothing on this machine can say whether it was modulated
                // onto the medium, and a wireless vantage is a reason to read the
                // observation carefully rather than a reason to stop asking.
                // Only where something was actually attempted: on an unprivileged run
                // nothing was sent, and the medium is not the question.
                if attempted && context.vantage.kind == crate::providers::VantageKind::Wireless {
                    notes.push(
                        "note: this vantage is a wireless station; an observed outbound \
                         request proves it reached the local egress path, and only a capture \
                         point off this machine could prove it reached the medium"
                            .to_string(),
                    );
                }
            }
            notes.push(describe_resolution(&resolution));

            if let Some(sweep) = outcome.result() {
                notes.push(format!(
                    "{} reply/replies from {} asked; the other {} are not confirmed, which is \
                     not the same as absent",
                    sweep.replies.len(),
                    sweep.asked.len(),
                    sweep.unconfirmed().len()
                ));
                for (address, macs) in sweep.contested() {
                    let answering: Vec<String> = macs
                        .iter()
                        .map(|mac| {
                            mac.iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<Vec<_>>()
                                .join(":")
                        })
                        .collect();
                    notes.push(format!(
                        "{address} was answered for by {} stations ({}); neither is recorded \
                         as holding it",
                        answering.len(),
                        answering.join(", ")
                    ));
                }

                for reply in sweep.replies {
                    let device = DeviceKey::mac(&reply.mac_text());
                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: device.clone(),
                            address: IpAddr::V4(reply.address),
                        },
                        EvidenceSource::ArpProbe,
                        Confidence::Observed,
                        vantage,
                    ));

                    // Descriptive only. A manufacturer never establishes a role.
                    if let Some(vendor) = crate::net::arp::lookup_vendor(&reply.mac_text()) {
                        out.push(TopologyEvidence::new(
                            Fact::DeviceVendor { device, vendor },
                            EvidenceSource::ArpProbe,
                            Confidence::Observed,
                            vantage,
                        ));
                    }

                    // A tag seen on a frame we received is a tag that exists in this
                    // switched domain. It never becomes a network on its own.
                    if let Some(id) = reply.vlan {
                        out.push(TopologyEvidence::new(
                            Fact::Vlan { id },
                            EvidenceSource::ArpProbe,
                            Confidence::Observed,
                            vantage,
                        ));
                    }
                }
            }

            ProviderOutput {
                evidence: out,
                notes,
                attempted,
            }
        })
    }
}

/// How an ARP resolution decision is reported, in words that match what was done.
///
/// Pure so it can be tested without a link: the wording is the part that was wrong before.
/// Nothing here may say the raw sweep handled the link unless a reply was correlated to a
/// request. Two earlier versions got this wrong: a preflight declared raw access available
/// and the sends then failed, and afterwards a successful `write` was read as proof that a
/// frame reached the medium. Only an answer proves the exchange.
fn describe_resolution(resolution: &crate::probes::arp::ArpResolution) -> String {
    use crate::probes::arp::ArpResolution;
    match resolution {
        ArpResolution::Confirmed { replies } => format!(
            "kernel ARP provocation skipped: {replies} raw reply/replies were correlated to \
             requests we sent"
        ),
        ArpResolution::Fallback { reason } => format!(
            "kernel fallback used ({reason}); its results are cache reads rather than fresh \
             confirmations"
        ),
        ArpResolution::Skip { reason } => {
            format!("no ARP resolution attempted here: {reason}")
        }
    }
}

/// Router discovery: soliciting advertisements and recording what they disclose.
///
/// The first provider that can establish a network nobody here is attached to. Everything
/// before it works outward from addresses this machine already holds, so it can only ever
/// find the link it is standing on. A Route Information option names a prefix reachable
/// *through* the router, which is how a cascaded subnet becomes visible without guessing at
/// one.
///
/// Every fact is the router's own claim and is recorded as advertised. What is verified is
/// that the claim came from a router on this link: hop limit 255, a checksum over the real
/// pseudo-header, a link-local source, and arrival on the interface we solicited from.
pub struct RouterDiscoveryProvider;

impl DiscoveryProvider for RouterDiscoveryProvider {
    fn name(&self) -> &'static str {
        "router-discovery"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        // Link-scoped: the solicitation goes to ff02::2 and describes this link only.
        context.target.is_none() && context.scope.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let vantage = &context.vantage.interface;
            let outcome = crate::probes::ra::solicit(
                vantage,
                context.vantage.index,
                // Routers answer a solicitation quickly, but RFC 4861 lets them delay up to
                // half a second, and several routers answer independently.
                context.timeout.max(Duration::from_millis(2000)),
            )
            .await;

            let attempted = outcome.transmitted();
            let mut notes = vec![outcome.describe(self.name())];
            let mut out = Vec::new();

            if let Some(advertisements) = outcome.result() {
                for advertisement in &advertisements {
                    // What the advertisement contained, counted by class. An RA with no
                    // options at all and one carrying prefixes are both "answered", and
                    // only the enumeration says which happened.
                    notes.push(format!(
                        "router-discovery answered from {}:",
                        advertisement.router
                    ));
                    notes.push(format!(
                        "  PIO on-link: {}",
                        advertisement.on_link_prefixes().count()
                    ));
                    notes.push(format!(
                        "  PIO address-formation only: {}",
                        advertisement
                            .prefixes
                            .iter()
                            .filter(|prefix| !prefix.on_link)
                            .count()
                    ));
                    notes.push(format!(
                        "  RIO routes: {}",
                        advertisement.usable_routes().count()
                    ));
                }

                for advertisement in advertisements {
                    // The router is keyed by its link-layer address when it disclosed one,
                    // and by its link-local address otherwise -- scoped to this vantage,
                    // since fe80:: addresses name different devices on different links.
                    let device = match advertisement.mac_text() {
                        Some(mac) => DeviceKey::mac(&mac),
                        None => DeviceKey::scoped_address(
                            IpAddr::V6(advertisement.router),
                            Some(vantage.as_str()),
                        ),
                    };

                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: device.clone(),
                            address: IpAddr::V6(advertisement.router),
                        },
                        EvidenceSource::RouterAdvertisement,
                        Confidence::Observed,
                        vantage,
                    ));
                    out.push(
                        TopologyEvidence::new(
                            Fact::DeviceRoleSignal {
                                device: device.clone(),
                                signal: RoleSignal::RouterAdvertisement,
                            },
                            EvidenceSource::RouterAdvertisement,
                            Confidence::Observed,
                            vantage,
                        )
                        .with_detail("answered a router solicitation"),
                    );

                    // A prefix the router says is on this link. The L flag is what makes it
                    // a statement about the link; without it the router is saying only that
                    // addresses may be formed from the prefix, which attaches nothing.
                    for prefix in advertisement.on_link_prefixes() {
                        let network = IpNet::V6(prefix.prefix);
                        out.push(TopologyEvidence::new(
                            Fact::Network { prefix: network },
                            EvidenceSource::RouterAdvertisement,
                            Confidence::Advertised,
                            vantage,
                        ));
                        out.push(TopologyEvidence::new(
                            Fact::InterfaceNetwork {
                                interface: vantage.clone(),
                                prefix: network,
                            },
                            EvidenceSource::RouterAdvertisement,
                            Confidence::Advertised,
                            vantage,
                        ));
                        out.push(TopologyEvidence::new(
                            Fact::AttachedTo {
                                device: device.clone(),
                                network,
                            },
                            EvidenceSource::RouterAdvertisement,
                            Confidence::Advertised,
                            vantage,
                        ));
                    }

                    // A prefix reachable through this router: the disclosure that extends
                    // the map past this link.
                    for route in advertisement.usable_routes() {
                        let network = IpNet::V6(route.prefix);
                        out.push(TopologyEvidence::new(
                            Fact::Network { prefix: network },
                            EvidenceSource::RouterAdvertisement,
                            Confidence::Advertised,
                            vantage,
                        ));
                        out.push(
                            TopologyEvidence::new(
                                Fact::RoutesTo {
                                    device: device.clone(),
                                    network,
                                    next_hop: Some(IpAddr::V6(advertisement.router)),
                                },
                                EvidenceSource::RouterAdvertisement,
                                Confidence::Advertised,
                                vantage,
                            )
                            .with_detail(format!(
                                "route information option, {} preference, {}s",
                                route.preference.label(),
                                route.lifetime
                            )),
                        );
                    }

                    if advertisement.router_lifetime > 0 {
                        out.push(
                            TopologyEvidence::new(
                                Fact::DeviceRoleSignal {
                                    device,
                                    signal: RoleSignal::DefaultGateway,
                                },
                                EvidenceSource::RouterAdvertisement,
                                Confidence::Advertised,
                                vantage,
                            )
                            .with_detail(format!(
                                "offers itself as a default router for {}s",
                                advertisement.router_lifetime
                            )),
                        );
                    }
                }
            }

            ProviderOutput {
                evidence: out,
                notes,
                attempted,
            }
        })
    }
}

/// DHCPINFORM: the operator's own description of this link, from the server that holds it.
///
/// Runs once for the selected IPv4 vantage. An INFORM asks about the address this client
/// already has, so it is asked once per link and never per device -- and it claims no lease,
/// so the server's bookkeeping and this host's configuration are both untouched. Nothing
/// received is applied.
///
/// What each option may establish is the whole point:
///
///   * Option 1 (mask) creates exactly one network: this interface's own prefix, from the
///     mask combined with an address this machine holds.
///   * Option 3 (routers) creates devices. A router's address says nothing about the
///     prefixes behind it, and a /24 drawn around one would be invented.
///   * Options 121 and 249 create routed prefixes and the relationships to reach them,
///     because they carry prefix lengths and next hops outright.
pub struct DhcpInformProvider;

impl DiscoveryProvider for DhcpInformProvider {
    fn name(&self) -> &'static str {
        "dhcp-inform"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        context.target.is_none() && context.scope.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let vantage = &context.vantage.interface;
            let Ok(local) = crate::net::interface::get_interface_by_name(vantage) else {
                return ProviderOutput::not_applicable(format!(
                    "{vantage} has no IPv4 address, and an INFORM asks about one this client \
                     already holds"
                ));
            };
            let Some(mac) = crate::net::linklayer::interface_mac(vantage) else {
                return ProviderOutput::not_applicable(format!(
                    "{vantage} has no hardware address to identify this client by"
                ));
            };

            let outcome = crate::probes::dhcp_inform::ask(
                vantage,
                &context.binding,
                local.ip,
                mac,
                context.timeout.max(Duration::from_millis(2000)),
            )
            .await;

            let attempted = outcome.transmitted();
            let mut notes = vec![outcome.describe(self.name())];
            let mut out = Vec::new();

            if let Some(disclosures) = outcome.result() {
                for disclosure in disclosures {
                    // Every option that was asked for, present or absent. "Answered" says
                    // nothing about what the answer contained, and an absent option 121 is
                    // exactly as much of a finding as a present one -- it is why no prefix
                    // beyond this link was disclosed.
                    notes.push(format!("dhcp-inform answered from {}:", disclosure.server));
                    notes.push(format!(
                        "  option 1: {}",
                        disclosure
                            .subnet_mask
                            .map(|mask| mask.to_string())
                            .unwrap_or_else(|| "absent".to_string())
                    ));
                    notes.push(format!(
                        "  option 3: {}",
                        if disclosure.routers.is_empty() {
                            "absent".to_string()
                        } else {
                            disclosure
                                .routers
                                .iter()
                                .map(|router| router.to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        }
                    ));
                    for option in [121u8, 249] {
                        let named: Vec<String> = disclosure
                            .classless_routes
                            .iter()
                            .filter(|route| route.option == option)
                            .map(|route| {
                                format!(
                                    "{} via {}",
                                    route.prefix,
                                    if route.next_hop.is_unspecified() {
                                        "this link".to_string()
                                    } else {
                                        route.next_hop.to_string()
                                    }
                                )
                            })
                            .collect();
                        notes.push(format!(
                            "  option {option}: {}",
                            if named.is_empty() {
                                "absent".to_string()
                            } else {
                                named.join(", ")
                            }
                        ));
                    }

                    let server = DeviceKey::Address(IpAddr::V4(disclosure.server));
                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: server.clone(),
                            address: IpAddr::V4(disclosure.server),
                        },
                        EvidenceSource::DhcpLease,
                        Confidence::Observed,
                        vantage,
                    ));

                    // Option 1, and only for this interface's own address.
                    if let Some(prefix) = disclosure.attached_prefix(local.ip) {
                        let network = IpNet::V4(prefix);
                        out.push(
                            TopologyEvidence::new(
                                Fact::Network { prefix: network },
                                EvidenceSource::DhcpLease,
                                Confidence::Advertised,
                                vantage,
                            )
                            .with_detail(format!(
                                "DHCP option 1 mask {} applied to {}",
                                disclosure.subnet_mask.expect("a prefix came from a mask"),
                                local.ip
                            )),
                        );
                        out.push(TopologyEvidence::new(
                            Fact::InterfaceNetwork {
                                interface: vantage.clone(),
                                prefix: network,
                            },
                            EvidenceSource::DhcpLease,
                            Confidence::Advertised,
                            vantage,
                        ));
                    }

                    // Option 3: devices that route, and nothing about what is behind them.
                    let superseded = disclosure.classless_routes_supersede_router_option();
                    for router in &disclosure.routers {
                        let device = DeviceKey::Address(IpAddr::V4(*router));
                        out.push(TopologyEvidence::new(
                            Fact::DeviceAddress {
                                device: device.clone(),
                                address: IpAddr::V4(*router),
                            },
                            EvidenceSource::DhcpLease,
                            Confidence::Advertised,
                            vantage,
                        ));
                        out.push(
                            TopologyEvidence::new(
                                Fact::DeviceRoleSignal {
                                    device,
                                    signal: RoleSignal::DhcpRouter,
                                },
                                EvidenceSource::DhcpLease,
                                Confidence::Advertised,
                                vantage,
                            )
                            .with_detail(if superseded {
                                // RFC 3442 §6: a client receiving both MUST ignore the
                                // router option, so this router is named but is not the
                                // effective default.
                                "named in DHCP option 3, superseded by the classless static \
                                 routes in option 121/249"
                                    .to_string()
                            } else {
                                "named as a router in DHCP option 3".to_string()
                            }),
                        );
                    }
                    if superseded {
                        notes.push(
                            "option 3 is not the effective default route: RFC 3442 gives the \
                             classless static routes precedence"
                                .to_string(),
                        );
                    }

                    // Options 121 and 249: prefixes with next hops, stated outright.
                    for route in &disclosure.classless_routes {
                        let network = IpNet::V4(route.prefix);
                        let next_hop = IpAddr::V4(route.next_hop);
                        // The device the route points at, which is the next hop when there
                        // is one and the server itself when the destination is on-link.
                        let via = if route.next_hop.is_unspecified() {
                            server.clone()
                        } else {
                            DeviceKey::Address(next_hop)
                        };

                        if !route.is_default() {
                            out.push(
                                TopologyEvidence::new(
                                    Fact::Network { prefix: network },
                                    EvidenceSource::DhcpLease,
                                    Confidence::Advertised,
                                    vantage,
                                )
                                .with_detail(format!(
                                    "DHCP option {} entry {}",
                                    route.option,
                                    route.evidence()
                                )),
                            );
                        }
                        out.push(
                            TopologyEvidence::new(
                                Fact::RoutesTo {
                                    device: via,
                                    network,
                                    next_hop: (!route.next_hop.is_unspecified())
                                        .then_some(next_hop),
                                },
                                EvidenceSource::DhcpLease,
                                Confidence::Advertised,
                                vantage,
                            )
                            .with_detail(format!(
                                "DHCP option {} from {}, entry {}",
                                route.option,
                                disclosure.server,
                                route.evidence()
                            )),
                        );
                    }
                }
            }

            ProviderOutput {
                evidence: out,
                notes,
                attempted,
            }
        })
    }
}

/// What a responding candidate turned out to be.
///
/// Isolated from the probing so the rule can be tested without a network: an address that
/// answered is a device, and it becomes a network only when something states a prefix for
/// it. A responding 192.168.51.1 with no mask and no route is an unresolved interface, and
/// saying anything more about it would be inventing the /24 around it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachedInterface {
    /// The address answered and stated its own mask: a network, attached to the interface.
    Resolved {
        address: std::net::Ipv4Addr,
        prefix: IpNet,
        mask: std::net::Ipv4Addr,
    },
    /// The address answered and nothing states its prefix.
    Unresolved { address: std::net::Ipv4Addr },
}

impl ReachedInterface {
    /// Reads a mask outcome into the decision, which is the whole of the rule.
    pub fn from_mask(
        address: std::net::Ipv4Addr,
        mask: &crate::probes::icmp_mask::MaskOutcome,
    ) -> Self {
        match mask {
            crate::probes::attempt::AttemptOutcome::Answered { result, .. } => {
                ReachedInterface::Resolved {
                    address,
                    prefix: IpNet::V4(result.prefix),
                    mask: result.mask,
                }
            }
            // Every other outcome -- no reply, an invalid mask, no ICMP socket -- leaves the
            // interface exactly as reachability found it: an address.
            _ => ReachedInterface::Unresolved { address },
        }
    }
}

/// Bounded reachability probing for router interfaces nobody disclosed.
///
/// Runs when the disclosing sources have all been asked and none named a network beyond
/// this link. It probes a small, ordered set of gateway candidates in private space, and it
/// is active work on the same interface-bound channel, shared permit pool and run-wide
/// budget as everything else -- not a second scanner with its own limits.
///
/// The rules it holds to are what separate it from a sweep. Only gateway addresses are
/// asked. Only the exact target answering for itself creates a device. And a device becomes
/// a network only when a prefix is stated: an address mask reply here, or a route or
/// interrogation elsewhere. Recursion follows the network, never the address.
pub struct BoundedReachabilityProvider {
    /// Hard bound on candidates per run.
    pub max_candidates: usize,
}

impl Default for BoundedReachabilityProvider {
    fn default() -> Self {
        // Two addresses per /24 across roughly a class-B worth of subnets: enough to reach
        // a cascaded network in the same private block, small enough that the run stays
        // bounded on any link.
        Self {
            max_candidates: 512,
        }
    }
}

impl DiscoveryProvider for BoundedReachabilityProvider {
    fn name(&self) -> &'static str {
        "bounded-reachability"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        context.target.is_none() && context.scope.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let vantage = &context.vantage.interface;
            let Ok(local) = crate::net::interface::get_interface_by_name(vantage) else {
                return ProviderOutput::not_applicable(format!(
                    "{vantage} has no IPv4 address to probe from"
                ));
            };
            if crate::probes::reach::enclosing_private_block(local.ip).is_none() {
                return ProviderOutput::not_applicable(format!(
                    "{} is not in private address space, which is the only space this probes",
                    local.ip
                ));
            }

            // Addresses this vantage has already established, so none is asked twice.
            let known: std::collections::BTreeSet<std::net::Ipv4Addr> =
                crate::net::arp::read_system_arp_table(Some(vantage.as_str()))
                    .into_iter()
                    .map(|entry| entry.ip)
                    .chain(std::iter::once(local.ip))
                    .collect();

            // Neighbourhoods are seeded from what this vantage has actually seen -- its own
            // address, its neighbours, and the gateways the kernel names -- so the search
            // starts where a cascaded network is most likely to sit.
            let mut observed = vec![local.ip];
            observed.extend(known.iter().copied().filter(|address| *address != local.ip));
            if let Some(gateway) = local.default_gateway {
                observed.insert(1.min(observed.len()), gateway);
            }

            let (candidates, coverage) = crate::probes::reach::candidates_with_coverage(
                &observed,
                &known,
                self.max_candidates,
            );
            if candidates.is_empty() {
                return ProviderOutput::not_applicable(
                    "no gateway candidate remained after excluding what is already known"
                        .to_string(),
                );
            }

            // One identifier for the run, a sequence per candidate: that pair is what makes
            // a reply attributable to the address it was sent to.
            let identifier = std::process::id() as u16;
            let per_probe = context.timeout.min(Duration::from_millis(400));
            let channel = context.probe_channel();
            // Everything already scheduled, so an expansion never re-asks an address.
            let mut queued: std::collections::BTreeSet<std::net::Ipv4Addr> =
                candidates.iter().copied().collect();
            let mut sweep = crate::probes::reach::ReachabilitySweep {
                budget_exhausted: candidates.len() >= self.max_candidates,
                ..Default::default()
            };
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let mut unresolved: Vec<std::net::Ipv4Addr> = Vec::new();
            let mut resolved: Vec<String> = Vec::new();

            // Concurrent, on the run-wide permit pool. Asked one at a time, a budget of 512
            // candidates times seven questions each is a run measured in tens of minutes;
            // the pool is what bounds this against everything else, so the work belongs in
            // it rather than in a sequential loop beside it.
            let mut wave: Vec<std::net::Ipv4Addr> = candidates;
            let mut answers: Vec<(std::net::Ipv4Addr, crate::probes::reach::ResponseSignal)> =
                Vec::new();

            while !wave.is_empty() && sweep.asked.len() < self.max_candidates {
                let mut asking: tokio::task::JoinSet<(
                    std::net::Ipv4Addr,
                    Option<crate::probes::reach::ResponseSignal>,
                )> = tokio::task::JoinSet::new();

                for target in wave.drain(..) {
                    if sweep.asked.len() >= self.max_candidates {
                        sweep.budget_exhausted = true;
                        break;
                    }
                    sweep.asked.push(target);
                    let channel = channel.clone();
                    // Derived from the address, so a reply is attributable to the candidate
                    // it was sent to even with every probe in flight at once.
                    let sequence = (u32::from(target) & 0xffff) as u16;
                    asking.spawn(async move {
                        let Ok(_permit) = channel.permits.clone().acquire_owned().await else {
                            return (target, None);
                        };
                        let signal = crate::probes::reach::probe_signals(
                            target, identifier, sequence, &channel, per_probe,
                        )
                        .await;
                        (target, signal)
                    });
                }

                let mut responded_this_wave = Vec::new();
                while let Some(joined) = asking.join_next().await {
                    // A panicking probe loses that one candidate, not the pass.
                    let Ok((target, Some(signal))) = joined else {
                        continue;
                    };
                    sweep.responded.push(target);
                    answers.push((target, signal.clone()));
                    responded_this_wave.push(target);

                    // It answered for itself, so it exists. That is a device and nothing
                    // more until something states a prefix.
                    out.push(
                        TopologyEvidence::new(
                            Fact::DeviceAddress {
                                device: DeviceKey::Address(IpAddr::V4(target)),
                                address: IpAddr::V4(target),
                            },
                            // Attributed to what actually answered rather than to ICMP for
                            // everything: a device found by a TCP reset was not found by
                            // ping.
                            match signal {
                                crate::probes::reach::ResponseSignal::Icmp => {
                                    EvidenceSource::IcmpProbe
                                }
                                crate::probes::reach::ResponseSignal::Dns => {
                                    EvidenceSource::UnicastDns
                                }
                                crate::probes::reach::ResponseSignal::NatPmp => {
                                    EvidenceSource::NatPmp
                                }
                                _ => EvidenceSource::TcpProbe,
                            },
                            Confidence::Observed,
                            vantage,
                        )
                        .with_detail(signal.label()),
                    );
                }

                // Networks are provisioned in runs, so the /24s beside a live interface are
                // asked next, still inside the same budget.
                for target in responded_this_wave {
                    for neighbour in crate::probes::reach::expand_around(target) {
                        if !known.contains(&neighbour) && queued.insert(neighbour) {
                            wave.push(neighbour);
                        }
                    }
                }
            }

            // Escalation happens only now, against addresses that answered: ask each
            // interface for its own mask, which is the one thing that can turn an address
            // into a network without anyone else disclosing it.
            for (target, _) in &answers {
                let mask = crate::probes::icmp_mask::ask(
                    *target,
                    identifier,
                    (u32::from(*target) & 0xffff) as u16,
                    &context.binding,
                    per_probe,
                )
                .await;

                match ReachedInterface::from_mask(*target, &mask) {
                    ReachedInterface::Resolved {
                        prefix,
                        mask: stated,
                        ..
                    } => {
                        out.push(
                            TopologyEvidence::new(
                                Fact::Network { prefix },
                                EvidenceSource::IcmpProbe,
                                // The device's own claim about its network.
                                Confidence::Advertised,
                                vantage,
                            )
                            .with_detail(format!(
                                "ICMP address mask reply from {target}: {stated}"
                            )),
                        );
                        out.push(TopologyEvidence::new(
                            Fact::AttachedTo {
                                device: DeviceKey::Address(IpAddr::V4(*target)),
                                network: prefix,
                            },
                            EvidenceSource::IcmpProbe,
                            Confidence::Advertised,
                            vantage,
                        ));
                        resolved.push(format!("{target} states {stated} -> {prefix}"));
                    }
                    ReachedInterface::Unresolved { address } => unresolved.push(address),
                }
            }

            notes.push(format!(
                "{} candidate(s) asked ({}), {} answered for themselves, {} produced no \
                 response to any probe",
                sweep.asked.len(),
                coverage.describe(),
                sweep.responded.len(),
                sweep.silent()
            ));
            // Named so "no response" is readable: it means these questions, not all
            // possible questions.
            notes.push(format!(
                "  probes attempted per candidate: {}",
                crate::probes::reach::probes_attempted()
            ));
            for (address, signal) in &answers {
                notes.push(format!("  {address} answered: {}", signal.label()));
            }
            for line in &resolved {
                notes.push(format!("  prefix disclosed: {line}"));
            }
            for address in &unresolved {
                // Named individually: each is a router interface that exists and whose
                // network nothing has stated.
                notes.push(format!(
                    "  unresolved interface: {address} answered; no mask or route states its \
                     prefix"
                ));
            }
            if sweep.budget_exhausted {
                notes.push(format!(
                    "candidate budget of {} exhausted; further gateway candidates were not \
                     asked",
                    self.max_candidates
                ));
            }

            ProviderOutput {
                evidence: out,
                notes,
                attempted: !sweep.asked.is_empty(),
            }
        })
    }
}

/// Active IPv6 liveness confirmation on the attached link.
///
/// There is no IPv6 host sweep and there cannot be one, so the addresses come from what
/// something already reported -- the kernel's neighbour cache for this interface. Re-asking
/// is the point: a cache entry says a MAC was learned at some time, and this says whether
/// the station is answering for the address now, with the reply validated against the
/// question.
pub struct NdpLivenessProvider;

impl DiscoveryProvider for NdpLivenessProvider {
    fn name(&self) -> &'static str {
        "ndp-liveness"
    }

    fn applies(&self, context: &DiscoveryContext) -> bool {
        // Seed-time only: the candidates are link-scoped, not scope-scoped, and soliciting
        // them again for every discovered network would repeat the same work.
        context.target.is_none() && context.scope.is_none()
    }

    fn discover<'a>(&'a self, context: &'a DiscoveryContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let vantage = &context.vantage.interface;
            let known: Vec<std::net::Ipv6Addr> =
                crate::net::ipv6::harvest_ndp_cache(Some(vantage.as_str()))
                    .await
                    .into_iter()
                    .map(|entry| entry.ip)
                    .collect();
            if known.is_empty() {
                // Not applicable: neighbour discovery is available here, nothing on this
                // link has been reported to solicit. Calling that "unavailable" would say
                // the platform cannot do it.
                return ProviderOutput::not_applicable(
                    "no IPv6 neighbour has been reported on this link to solicit".to_string(),
                );
            }

            let outcome = crate::probes::ndp::sweep_liveness(
                vantage,
                context.vantage.index,
                None,
                known,
                context.timeout.max(Duration::from_millis(1500)),
            )
            .await;

            let attempted = outcome.transmitted();
            let mut notes = vec![outcome.describe(self.name())];
            let mut out = Vec::new();

            if let Some(sweep) = outcome.result() {
                notes.push(format!(
                    "{} advertisement(s) from {} solicited; the other {} are not confirmed, \
                     which is not the same as absent",
                    sweep.advertisements.len(),
                    sweep.asked.len(),
                    sweep.unconfirmed().len()
                ));
                for (address, macs) in sweep.contested() {
                    notes.push(format!(
                        "{address} was advertised for by {} stations; neither is recorded as \
                         holding it",
                        macs.len()
                    ));
                }

                for found in sweep.advertisements {
                    // Without a link-layer option there is no identity to key on, and the
                    // address alone is what we already had. The zone is the vantage: a
                    // link-local address belongs to this link and no other.
                    let device = match found.mac {
                        Some(_) => {
                            DeviceKey::mac(&found.mac_text().expect("a MAC that was just matched"))
                        }
                        None => DeviceKey::scoped_address(
                            IpAddr::V6(found.address),
                            Some(vantage.as_str()),
                        ),
                    };
                    out.push(TopologyEvidence::new(
                        Fact::DeviceAddress {
                            device: device.clone(),
                            address: IpAddr::V6(found.address),
                        },
                        EvidenceSource::NdpProbe,
                        Confidence::Observed,
                        vantage,
                    ));

                    if let Some(mac) = found.mac_text()
                        && let Some(vendor) = crate::net::arp::lookup_vendor(&mac)
                    {
                        out.push(TopologyEvidence::new(
                            Fact::DeviceVendor {
                                device: device.clone(),
                                vendor,
                            },
                            EvidenceSource::NdpProbe,
                            Confidence::Observed,
                            vantage,
                        ));
                    }

                    // The R flag is the sender's own claim about itself, recorded as
                    // advertised rather than observed: nothing here saw it forward a packet.
                    if found.router {
                        out.push(TopologyEvidence::new(
                            Fact::DeviceRoleSignal {
                                device,
                                signal: RoleSignal::RouterAdvertisement,
                            },
                            EvidenceSource::NdpProbe,
                            Confidence::Advertised,
                            vantage,
                        ));
                    }
                }
            }

            ProviderOutput {
                evidence: out,
                notes,
                attempted,
            }
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
        Box::new(ArpLivenessProvider::default()),
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
    fn a_reached_interface_becomes_a_network_only_when_it_states_its_own_mask() {
        // The positive fixture. 192.168.51.1 answers for itself, and its address mask reply
        // advertises 255.255.255.0 -- which is what creates 192.168.51.0/24, attaches the
        // interface to it, and gives the engine a network to recurse into.
        use crate::probes::attempt::AttemptOutcome;
        use crate::probes::icmp_mask::MaskReply;

        let address = std::net::Ipv4Addr::new(192, 168, 51, 1);
        let answered = AttemptOutcome::Answered {
            sent: "ICMP address mask request to 192.168.51.1".to_string(),
            result: MaskReply {
                address,
                mask: std::net::Ipv4Addr::new(255, 255, 255, 0),
                prefix: "192.168.51.0/24".parse().unwrap(),
                raw: vec![18, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0],
            },
        };

        assert_eq!(
            ReachedInterface::from_mask(address, &answered),
            ReachedInterface::Resolved {
                address,
                prefix: "192.168.51.0/24".parse().unwrap(),
                mask: std::net::Ipv4Addr::new(255, 255, 255, 0),
            }
        );
    }

    #[test]
    fn a_reached_interface_with_no_stated_prefix_stops_at_the_interface() {
        // The negative fixture, and the more important one. The address answered, so the
        // interface exists; nothing states its prefix, so nothing may be said about the
        // network behind it. Assuming a /24 around a responding address is the invention
        // this whole path refuses.
        use crate::probes::attempt::AttemptOutcome;

        let address = std::net::Ipv4Addr::new(192, 168, 51, 1);
        let unresolved = ReachedInterface::Unresolved { address };

        for silent in [
            AttemptOutcome::NoResponse {
                sent: "ICMP address mask request to 192.168.51.1".to_string(),
            },
            AttemptOutcome::InvalidResponse {
                sent: "ICMP address mask request to 192.168.51.1".to_string(),
                rejected: 1,
            },
            AttemptOutcome::unavailable("an ICMP socket could not be opened"),
            AttemptOutcome::not_sent("the request could not be sent"),
            AttemptOutcome::not_applicable("nothing to ask"),
        ] {
            assert_eq!(
                ReachedInterface::from_mask(address, &silent),
                unresolved,
                "only a stated mask may resolve the interface: {silent:?}"
            );
        }
    }

    #[tokio::test]
    async fn bounded_reachability_probes_nothing_outside_private_space() {
        // It is bounded by address space as well as by count: probing outside RFC 1918 on a
        // guess would put traffic on addresses the operator does not hold.
        let seeded = ctx(VantageKind::Wired, true);
        let provider = BoundedReachabilityProvider::default();
        assert!(provider.applies(&seeded));
        assert_eq!(provider.max_candidates, 512);

        // test0 has no address, so the provider reports why rather than probing anything.
        let produced = provider.discover(&seeded).await;
        assert!(produced.evidence.is_empty());
        assert!(!produced.attempted);
        assert!(
            produced.notes[0].contains("not applicable"),
            "{:?}",
            produced.notes
        );
    }

    #[tokio::test]
    async fn arp_liveness_refuses_a_prefix_this_interface_is_not_attached_to() {
        // ARP resolves nothing beyond the link. Sweeping a routed network anyway would
        // record whichever router proxied as each address's own hardware identity -- and
        // reporting the silence as "no response" would blame the hosts for it.
        let scoped = ctx(VantageKind::Wired, true).for_scope("10.99.0.0/24".parse().unwrap());
        let provider = ArpLivenessProvider::default();
        assert!(provider.applies(&scoped));

        let produced = provider.discover(&scoped).await;
        assert!(produced.evidence.is_empty());
        assert!(!produced.attempted, "nothing may be sent off-link");
        assert_eq!(produced.notes.len(), 1);
        assert!(
            produced.notes[0].contains("no IPv4 address") || produced.notes[0].contains("attached"),
            "{:?}",
            produced.notes
        );
    }

    #[test]
    fn a_sweep_without_a_correlated_reply_falls_back_and_claims_no_transmission() {
        // The wording is the part that was wrong twice over: first "left to arp-liveness"
        // after the sends failed, then "raw requests reached the wire" after a successful
        // BPF write that produced no reply at all. Neither may be reachable.
        use crate::probes::arp::{ArpResolution, resolve_sweep};

        let accepted_then_silent =
            resolve_sweep(&crate::probes::attempt::AttemptOutcome::NoResponse {
                sent: "BPF accepted 254 ARP request(s) for 192.168.1.0/24; 0 frame(s) read"
                    .to_string(),
            });
        assert!(matches!(
            accepted_then_silent,
            ArpResolution::Fallback { .. }
        ));

        let note = describe_resolution(&accepted_then_silent);
        assert!(note.contains("kernel fallback used"), "{note}");
        assert!(note.contains("BPF accepted"), "{note}");
        assert!(note.contains("no correlated replies observed"), "{note}");
        assert!(
            note.contains("cache reads rather than fresh confirmations"),
            "{note}"
        );

        // Neither discredited phrase may come out of any decision.
        for resolution in [
            ArpResolution::Confirmed { replies: 2 },
            accepted_then_silent.clone(),
            ArpResolution::Fallback {
                reason: "needs root".to_string(),
            },
            ArpResolution::Skip {
                reason: "not the attached prefix".to_string(),
            },
        ] {
            let rendered = describe_resolution(&resolution);
            assert!(!rendered.contains("left to arp-liveness"), "{rendered}");
            assert!(!rendered.contains("reached the wire"), "{rendered}");
        }

        // Only a correlated reply may claim the sweep resolved the link.
        assert!(
            describe_resolution(&ArpResolution::Confirmed { replies: 2 })
                .contains("correlated to requests we sent")
        );
    }

    #[test]
    fn arp_liveness_never_sweeps_a_network_too_large_to_enumerate() {
        let provider = ArpLivenessProvider::default();
        let huge = ctx(VantageKind::Wired, true).for_scope("10.0.0.0/8".parse().unwrap());
        assert!(!provider.applies(&huge));

        // IPv6 host space is never enumerated; those neighbours arrive from solicitation.
        let v6 = ctx(VantageKind::Wired, true).for_scope("2001:db8::/64".parse().unwrap());
        assert!(!provider.applies(&v6));
    }

    #[test]
    fn liveness_providers_are_registered_where_their_evidence_is_link_scoped() {
        // The ARP sweep belongs to a network scope; the neighbour solicitation belongs to
        // the seed pass, because its candidates come from the link and not from a prefix.
        let scoped: Vec<&str> = network_providers().iter().map(|p| p.name()).collect();
        assert!(scoped.contains(&"arp-liveness"));

        let seeded: Vec<&str> = crate::providers::local::local_providers()
            .iter()
            .map(|p| p.name())
            .collect();
        assert!(seeded.contains(&"ndp-liveness"));
        assert!(
            seeded.iter().position(|name| *name == "neighbor-cache")
                < seeded.iter().position(|name| *name == "ndp-liveness"),
            "the cache is read first so a validated answer can displace a stale entry"
        );
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
