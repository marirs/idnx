//! End-to-end capture fixtures: file bytes in, graph out.
//!
//! Every decoder in this crate has unit tests that hand it the bytes it expects. These
//! exercise what is between the file and the topology: the capture header and link type,
//! the frame decoder's dispatch, the conversion to evidence, and the graph's own rules
//! about what may become a network. A defect anywhere along that path is invisible to a
//! per-decoder test and visible here.
//!
//! These are synthetic PCAP byte fixtures, not independently captured device traffic. They
//! prove the complete file-to-graph pipeline against structurally valid frames; they do not
//! establish interoperability with what a particular vendor actually emits, and a passing
//! suite here should never be read as that claim.
//!
//! The captures are synthetic and sanitised. Addresses come from the documentation ranges
//! (RFC 5737 and RFC 3849), hardware addresses are locally administered, and no
//! credentials, community strings or authentication material appear in any of them.
//! tests/fixtures/pcap/generate.py builds them and recomputes every checksum, so the frames
//! are structurally valid rather than merely plausible.

use idnx::net::pcap;
use idnx::probes::passive::decode_frame;
use idnx::providers::passive::convert_unscoped;
use idnx::topology::TopologyGraph;
use idnx::topology::evidence::Fact;

const VANTAGE: &str = "test0";

/// Reads one fixture and runs it through the whole path.
fn absorb(name: &str) -> (TopologyGraph, Vec<idnx::topology::TopologyEvidence>) {
    let path = format!("{}/tests/fixtures/pcap/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let capture = pcap::read(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(capture.link_type, pcap::LINKTYPE_ETHERNET);

    let mut facts = Vec::new();
    for frame in &capture.frames {
        facts.extend(decode_frame(frame));
    }
    let evidence = convert_unscoped(&facts, VANTAGE);

    let mut graph = TopologyGraph::new();
    for item in evidence.clone() {
        graph.absorb(item);
    }
    graph.finalize_roles();
    (graph, evidence)
}

/// Every network the graph holds, as text.
fn networks(graph: &TopologyGraph) -> Vec<String> {
    let mut out: Vec<String> = graph
        .network_refs()
        .into_iter()
        .map(|net| net.prefix.to_string())
        .collect();
    out.sort();
    out
}

#[test]
fn a_dhcp_ack_creates_a_network_only_from_option_121() {
    // Option 121 carries a prefix and a next hop outright. Options 1 and 3 describe this
    // client's own link and the routers on it, and neither names a network beyond it.
    let (graph, _) = absorb("dhcp_ack_option121.pcap");
    assert!(
        networks(&graph).contains(&"198.51.100.0/24".to_string()),
        "the classless static route names a network beyond this link: {:?}",
        networks(&graph)
    );

    let (bare, _) = absorb("dhcp_ack_no_routes.pcap");
    assert!(
        !networks(&bare).contains(&"198.51.100.0/24".to_string()),
        "options 1 and 3 alone disclose no network beyond the link: {:?}",
        networks(&bare)
    );
}

#[test]
fn a_router_advertisement_separates_on_link_prefixes_from_routes() {
    // The L flag makes a prefix a statement about this link; without it the router is only
    // saying addresses may be formed from it. A route information option names a prefix
    // reachable through the router, which is the disclosure that extends the map.
    let (graph, evidence) = absorb("ra_pio_rio.pcap");
    let found = networks(&graph);

    assert!(found.contains(&"2001:db8:1::/64".to_string()), "{found:?}");
    assert!(
        found.contains(&"2001:db8:51::/48".to_string()),
        "the route information option must name the prefix beyond the link: {found:?}"
    );
    assert!(
        !found.contains(&"2001:db8:2::/64".to_string()),
        "a prefix without the on-link flag attaches nothing: {found:?}"
    );

    // Reaching it is a route, not an attachment.
    assert!(
        evidence.iter().any(|e| matches!(
            &e.fact,
            Fact::RoutesTo { network, .. } if network.to_string() == "2001:db8:51::/48"
        )),
        "the router is named as the way there"
    );
}

#[test]
fn a_rip_update_names_a_network_and_a_withdrawal_names_none() {
    // Metric 16 says the sender can no longer reach the prefix. Recording it as a network
    // would put one on the map on the strength of an advertisement that it is gone.
    let (graph, evidence) = absorb("rip_update_and_withdrawal.pcap");
    let found = networks(&graph);

    assert!(found.contains(&"198.51.100.0/24".to_string()), "{found:?}");
    assert!(
        !found.contains(&"203.0.113.0/24".to_string()),
        "a withdrawn prefix must not become a current network: {found:?}"
    );

    // The withdrawal is still evidence, kept against the router that stated it.
    assert!(
        evidence.iter().any(|e| matches!(
            &e.fact,
            Fact::DeviceDescription { text, .. } if text.contains("withdrew 203.0.113.0/24")
        )),
        "the withdrawal is retained as evidence about the router's table"
    );
    assert!(
        !evidence.iter().any(|e| matches!(
            &e.fact,
            Fact::RoutesTo { network, .. } if network.to_string() == "203.0.113.0/24"
        )),
        "and never as a route to reach it"
    );
}

#[test]
fn a_rip_request_advertises_nothing_and_is_not_a_failure() {
    // This is the shape idnx's own table request takes, which the capture sees leaving the
    // interface. It asks a neighbour for its table; it is neither an update nor a defect.
    let (graph, evidence) = absorb("rip_request.pcap");
    assert!(networks(&graph).is_empty(), "{:?}", networks(&graph));
    assert!(
        evidence.is_empty(),
        "a request establishes no device and no network: {evidence:?}"
    );
}

#[test]
fn ospf_summary_lsas_name_networks_and_maxage_withdraws_one() {
    let (graph, evidence) = absorb("ospf_v2_update.pcap");
    let found = networks(&graph);

    assert!(found.contains(&"198.51.100.0/24".to_string()), "{found:?}");
    assert!(
        !found.contains(&"203.0.113.0/24".to_string()),
        "an LSA at MaxAge is being withdrawn from the domain: {found:?}"
    );
    assert!(
        evidence.iter().any(|e| matches!(
            &e.fact,
            Fact::DeviceDescription { text, .. } if text.contains("203.0.113.0/24") && text.contains("MaxAge")
        )),
        "the withdrawal is reported against the router that sent it"
    );
}

#[test]
fn an_ospf_hello_identifies_a_router_and_creates_no_network() {
    // A router-id is not an address space and an area is not a subnet.
    let (graph, evidence) = absorb("ospf_v2_hello.pcap");
    assert!(networks(&graph).is_empty(), "{:?}", networks(&graph));
    assert!(
        evidence
            .iter()
            .any(|e| matches!(&e.fact, Fact::DeviceRoleSignal { .. })),
        "speaking OSPF at all is observed router behaviour"
    );
}

#[test]
fn an_isis_lsp_names_a_network_from_its_reachability_tlv() {
    let (graph, evidence) = absorb("isis_lsp.pcap");
    assert!(
        networks(&graph).contains(&"198.51.100.0/24".to_string()),
        "{:?}",
        networks(&graph)
    );
    assert!(
        evidence
            .iter()
            .any(|e| matches!(&e.fact, Fact::DeviceRoleSignal { .. })),
        "advertising a table is router behaviour this vantage observed"
    );
}

#[test]
fn an_lldp_neighbour_is_a_device_and_not_a_network() {
    let (graph, evidence) = absorb("lldp_neighbor.pcap");
    assert!(
        networks(&graph).is_empty(),
        "a neighbour announcement carries no prefix: {:?}",
        networks(&graph)
    );
    assert!(
        evidence
            .iter()
            .any(|e| matches!(&e.fact, Fact::DeviceHostname { hostname, .. } if hostname == "test-switch")),
        "the switch named itself"
    );
}

#[test]
fn a_vlan_tag_alone_stays_prefixless() {
    // A tag proves the VLAN exists in this switched domain and nothing more. Synthesising
    // a prefix for it is the fabrication this whole design refuses.
    let (graph, _) = absorb("vlan_tag_only.pcap");
    assert!(networks(&graph).is_empty(), "{:?}", networks(&graph));

    let vlans: Vec<u16> = graph.vlans_without_prefix().map(|vlan| vlan.id).collect();
    assert_eq!(vlans, vec![4], "the tag is recorded without a prefix");
}

#[test]
fn a_mixed_capture_merges_one_router_across_three_protocols() {
    // Ordering and cross-protocol identity in one file: the same hardware address appears
    // in a router advertisement, a RIP update and a DHCP reply, and must be one device.
    let (graph, _) = absorb("mixed_link.pcap");
    let found = networks(&graph);

    // Each disclosing protocol contributed what only it could.
    assert!(found.contains(&"2001:db8:1::/64".to_string()), "{found:?}");
    assert!(found.contains(&"2001:db8:51::/48".to_string()), "{found:?}");
    assert!(found.contains(&"198.51.100.0/24".to_string()), "{found:?}");

    let router = graph
        .nodes()
        .find(|node| format!("{:?}", node.id).contains("02:00:5e:00:00:01"))
        .expect("the router is one node, not three");
    assert!(
        router.role_signals.len() >= 2,
        "its behaviour was observed through more than one protocol: {:?}",
        router.role_signals
    );

    // The VLAN tag in the same capture still creates no network.
    let vlans: Vec<u16> = graph.vlans_without_prefix().map(|vlan| vlan.id).collect();
    assert_eq!(vlans, vec![4]);
}

#[test]
fn an_ospfv3_prefix_lsa_names_a_network_and_maxage_withdraws_one() {
    let (graph, evidence) = absorb("ospf_v3_update.pcap");
    let found = networks(&graph);

    assert!(found.contains(&"2001:db8:60::/48".to_string()), "{found:?}");
    assert!(
        !found.contains(&"2001:db8:61::/48".to_string()),
        "an LSA at MaxAge is being withdrawn from the flooding domain: {found:?}"
    );
    assert!(
        evidence.iter().any(|e| matches!(
            &e.fact,
            Fact::DeviceDescription { text, .. } if text.contains("2001:db8:61::/48") && text.contains("MaxAge")
        )),
        "the withdrawal stays evidence about the router's table"
    );
}

#[test]
fn a_cdp_neighbour_over_llc_snap_is_a_device_and_not_a_network() {
    // CDP rides 802.2 LLC with a SNAP header rather than its own ethertype, so it exercises
    // a different dispatch path from LLDP entirely.
    let (graph, evidence) = absorb("cdp_neighbor.pcap");
    assert!(
        networks(&graph).is_empty(),
        "a neighbour announcement carries no prefix: {:?}",
        networks(&graph)
    );
    assert!(
        evidence.iter().any(|e| matches!(
            &e.fact,
            Fact::DeviceHostname { hostname, .. } if hostname == "test-switch-cdp"
        )),
        "the switch named itself over CDP: {evidence:?}"
    );
}

#[test]
fn a_spanning_tree_bpdu_is_bridge_evidence_and_never_a_network() {
    // Only a bridge emits a BPDU, which is behaviour observed rather than claimed. It
    // describes a spanning tree, and a spanning tree is not an address space.
    for fixture in ["stp_bpdu.pcap", "rstp_bpdu.pcap"] {
        let (graph, evidence) = absorb(fixture);
        assert!(
            networks(&graph).is_empty(),
            "{fixture} must create no network: {:?}",
            networks(&graph)
        );
        assert!(
            evidence
                .iter()
                .any(|e| matches!(&e.fact, Fact::DeviceRoleSignal { .. })),
            "{fixture} establishes the sender as a bridge: {evidence:?}"
        );
    }
}

#[test]
fn a_tagged_frame_records_its_vlan_and_its_prefix_separately() {
    // Both facts come from one frame and neither implies the other: the tag says the VLAN
    // exists in this switched domain, and the option says a network is reachable through a
    // named next hop. Associating them would claim the prefix belongs to the VLAN, which
    // nothing in the frame states.
    let (graph, _) = absorb("vlan_tagged_dhcp.pcap");

    let vlans: Vec<u16> = graph.vlans_without_prefix().map(|vlan| vlan.id).collect();
    assert_eq!(
        vlans,
        vec![12],
        "the tag is recorded, still without a prefix"
    );
    assert!(
        networks(&graph).contains(&"198.51.100.0/24".to_string()),
        "the classless static route is independent evidence: {:?}",
        networks(&graph)
    );
}

#[test]
fn a_tagged_client_facing_ack_states_both_the_vlan_and_its_prefix() {
    // The positive case, and the only shape that earns it: one tag, a DHCP ACK, no relay,
    // the client's own address in yiaddr and its mask in option 1. One frame states both,
    // so the association is an observation rather than a pairing of two separate ones.
    let (graph, _) = absorb("vlan_tagged_dhcp_client_ack.pcap");

    let bound = graph.vlan_networks();
    assert_eq!(bound.len(), 1, "one binding, from one frame: {bound:?}");
    assert_eq!(bound[0].0.id, 30);
    assert_eq!(bound[0].1.to_string(), "203.0.113.0/24");
    assert!(
        !bound[0].2.is_empty(),
        "the binding carries the observation that made it"
    );
    assert!(
        !graph.vlans_without_prefix().any(|vlan| vlan.id == 30),
        "it is no longer a tag of unknown extent"
    );

    // The option 121 route in the same frame names a network reachable *through* this one.
    // It is evidence of that network and of nothing about the tag.
    assert!(
        networks(&graph).contains(&"198.51.100.0/24".to_string()),
        "the classless route is still its own evidence: {:?}",
        networks(&graph)
    );
    assert!(
        !bound
            .iter()
            .any(|(_, prefix, _)| prefix.to_string() == "198.51.100.0/24"),
        "a route reachable through the network is not a network riding on the tag"
    );
}

#[test]
fn a_relayed_ack_leaves_the_tag_unassociated() {
    // giaddr is set, so this reply was captured on the relay's link. The tag here belongs
    // to the relay's segment; joining it to the client's prefix would name a VLAN that
    // this capture never saw the client on.
    let (graph, _) = absorb("vlan_tagged_dhcp_relayed.pcap");

    assert!(
        graph.vlan_networks().is_empty(),
        "a relayed reply joins nothing: {:?}",
        graph.vlan_networks()
    );
    assert!(
        graph.vlans_without_prefix().any(|vlan| vlan.id == 31),
        "the tag itself was still observed"
    );
    assert!(
        networks(&graph).contains(&"203.0.113.0/24".to_string()),
        "and option 1 still names the client's network: {:?}",
        networks(&graph)
    );
}

#[test]
fn one_hardware_address_learned_two_ways_is_one_device() {
    // An ARP reply and a neighbour advertisement from the same station, in one capture.
    // Both address families must land on a single node: keying them apart would report one
    // router as two, and every fact about it would be split between them.
    let (graph, _) = absorb("arp_ndp_identity.pcap");

    let router = graph
        .nodes()
        .find(|node| format!("{:?}", node.id).contains("02:00:5e:00:00:01"))
        .expect("the router is one node");
    let addresses: Vec<String> = router.addresses.iter().map(|a| a.to_string()).collect();

    assert!(
        addresses.iter().any(|a| a == "192.0.2.1"),
        "the ARP reply bound its IPv4 address: {addresses:?}"
    );
    assert!(
        addresses.iter().any(|a| a == "fe80::1"),
        "the neighbour advertisement bound its IPv6 address: {addresses:?}"
    );
    assert!(networks(&graph).is_empty(), "{:?}", networks(&graph));
}

#[test]
fn malformed_captures_create_no_topology_at_all() {
    // A truncated advertisement, a packet whose checksum fails, a RIP datagram cut mid
    // entry and a DHCP option claiming more bytes than arrived. Each is structurally wrong
    // in one specific way, and none of them may produce a network.
    let (graph, evidence) = absorb("malformed.pcap");
    assert!(
        networks(&graph).is_empty(),
        "malformed input must not create topology: {:?}",
        networks(&graph)
    );
    assert!(
        !evidence
            .iter()
            .any(|e| matches!(&e.fact, Fact::Network { .. } | Fact::RoutesTo { .. })),
        "and must not create a route either: {evidence:?}"
    );
}

#[test]
fn a_capture_from_another_link_type_is_refused_before_decoding() {
    // The frames of an 802.11 capture have a different header; decoding them as Ethernet
    // would read arbitrary bytes as hardware addresses.
    let mut file = std::fs::read(format!(
        "{}/tests/fixtures/pcap/lldp_neighbor.pcap",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the fixture exists");
    file[20..24].copy_from_slice(&105u32.to_le_bytes());

    let refused = pcap::read(&file).expect_err("a non-Ethernet capture must be refused");
    assert!(refused.contains("link type 105"), "{refused}");
}
