//! Vendor neutrality acceptance test.
//!
//! The core algorithm must not depend on recognising a manufacturer. These tests build the
//! same topology -- an upstream router and a downstream device behind it -- several times,
//! varying only the manufacturer string, and require the resulting graph to be identical in
//! structure. The unknown-vendor case includes a device with no manufacturer at all, which
//! is what a white-label MAC, a randomized MAC, or a software router on generic hardware
//! looks like from the outside.

use std::net::IpAddr;

use idnx::topology::evidence::{
    Capability, Confidence, DeviceKey, EvidenceSource, Fact, RoleSignal, TopologyEvidence,
};
use idnx::topology::graph::{DeviceCategory, TopologyGraph};

const VANTAGE: &str = "test0";

/// Structural summary of a graph: what it found, with no identity text in it.
///
/// Manufacturer names are deliberately excluded -- the point is that they must not change
/// the shape of the result.
#[derive(Debug, PartialEq, Eq)]
struct Structure {
    networks: Vec<String>,
    routers: Vec<String>,
    switches: Vec<String>,
    opaque_boundaries: Vec<String>,
    hosts: Vec<String>,
    node_count: usize,
    edge_count: usize,
}

fn summarize(graph: &TopologyGraph) -> Structure {
    let category = |c: DeviceCategory| {
        let mut names: Vec<String> = graph
            .devices_in(c)
            .iter()
            .map(|n| n.display_name())
            .collect();
        names.sort();
        names
    };

    let mut networks: Vec<String> = graph.networks().iter().map(|n| n.to_string()).collect();
    networks.sort();

    Structure {
        networks,
        routers: category(DeviceCategory::Router),
        switches: category(DeviceCategory::Switch),
        opaque_boundaries: category(DeviceCategory::OpaqueBoundary),
        hosts: category(DeviceCategory::Host),
        node_count: graph.node_count(),
        edge_count: graph.edges().count(),
    }
}

fn evidence(fact: Fact, source: EvidenceSource, confidence: Confidence) -> TopologyEvidence {
    TopologyEvidence::new(fact, source, confidence, VANTAGE)
}

/// Builds one identical scenario, differing only in the manufacturer attributed to each
/// device. `vendor` of `None` is the unknown / white-label / randomized-MAC case.
fn scenario(vendor: Option<&str>) -> TopologyGraph {
    let gateway_address: IpAddr = "10.42.0.1".parse().unwrap();
    let sensor_address: IpAddr = "10.42.0.57".parse().unwrap();
    let gateway = DeviceKey::Mac("02:00:5e:10:00:01".to_string());
    let sensor = DeviceKey::Mac("02:00:5e:10:00:57".to_string());
    let lan = "10.42.0.0/24".parse().unwrap();

    let mut graph = TopologyGraph::new();

    for (device, address) in [(&gateway, gateway_address), (&sensor, sensor_address)] {
        graph.absorb(evidence(
            Fact::DeviceAddress {
                device: device.clone(),
                address,
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
        if let Some(name) = vendor {
            graph.absorb(evidence(
                Fact::DeviceVendor {
                    device: device.clone(),
                    vendor: name.to_string(),
                },
                EvidenceSource::UserSupplied,
                Confidence::Inferred,
            ));
        }
        graph.absorb(evidence(
            Fact::AttachedTo {
                device: device.clone(),
                network: lan,
            },
            EvidenceSource::ArpCache,
            Confidence::Observed,
        ));
    }

    graph.absorb(evidence(
        Fact::Network { prefix: lan },
        EvidenceSource::KernelRoute,
        Confidence::Observed,
    ));

    // The only thing that establishes the gateway as a router: routing behaviour.
    graph.absorb(evidence(
        Fact::DeviceRoleSignal {
            device: gateway.clone(),
            signal: RoleSignal::DefaultGateway,
        },
        EvidenceSource::KernelRoute,
        Confidence::Observed,
    ));
    graph.absorb(evidence(
        Fact::DeviceCapability {
            device: gateway.clone(),
            capability: Capability::DefaultGateway,
            detail: None,
        },
        EvidenceSource::KernelRoute,
        Confidence::Observed,
    ));
    graph.absorb(evidence(
        Fact::GatewayFor {
            device: gateway,
            network: lan,
        },
        EvidenceSource::KernelRoute,
        Confidence::Observed,
    ));

    // The downstream device does nothing but answer, so it stays a host.
    graph.absorb(evidence(
        Fact::Service {
            address: sensor_address,
            port: 80,
            protocol: "tcp",
            detail: None,
        },
        EvidenceSource::TcpProbe,
        Confidence::Observed,
    ));

    graph.finalize_roles();
    graph
}

#[test]
fn an_unknown_vendor_topology_matches_every_recognised_vendor() {
    let unknown = summarize(&scenario(None));

    // Every one of these has, or could have, a vendor adapter. None of them may produce a
    // different graph than the device whose manufacturer is unknown entirely.
    for vendor in [
        "ASUSTek Computer",
        "Cisco Systems, Inc",
        "Fortinet, Inc.",
        "Ubiquiti Inc",
        "TP-LINK TECHNOLOGIES CO.,LTD.",
        "MikroTik",
        "Shenzhen Generic Electronics",
    ] {
        assert_eq!(
            summarize(&scenario(Some(vendor))),
            unknown,
            "vendor {vendor} changed the topology structure"
        );
    }
}

#[test]
fn routing_evidence_alone_establishes_the_router() {
    let graph = scenario(None);
    assert_eq!(graph.devices_in(DeviceCategory::Router).len(), 1);
    assert_eq!(graph.devices_in(DeviceCategory::Host).len(), 1);
}

#[test]
fn a_manufacturer_name_alone_never_establishes_a_router() {
    // A recognised router manufacturer with no routing behaviour behind it must stay a host.
    let mut graph = TopologyGraph::new();
    let address: IpAddr = "10.42.0.90".parse().unwrap();
    let device = DeviceKey::Mac("02:00:5e:10:00:90".to_string());

    graph.absorb(evidence(
        Fact::DeviceAddress {
            device: device.clone(),
            address,
        },
        EvidenceSource::ArpCache,
        Confidence::Observed,
    ));
    graph.absorb(evidence(
        Fact::DeviceVendor {
            device,
            vendor: "Cisco Systems, Inc".to_string(),
        },
        EvidenceSource::UserSupplied,
        Confidence::Inferred,
    ));
    graph.finalize_roles();

    assert!(graph.devices_in(DeviceCategory::Router).is_empty());
    assert_eq!(graph.devices_in(DeviceCategory::Host).len(), 1);
}
