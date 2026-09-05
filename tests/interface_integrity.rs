//! Interface integrity.
//!
//! Naming an interface is a claim about what is visible from one link. If a probe can leave
//! through another interface, every fact derived from its answer is attributed to a vantage
//! that never carried the traffic — and on a multi-homed host with overlapping addressing,
//! ordinary routing will do exactly that.
//!
//! These tests pin two properties: a socket originates from the interface it was created
//! for, and no discovery module can create one outside the socket abstraction.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use idnx::net::interface::InterfaceAddress;
use idnx::net::socket::{BindingMode, SocketBinding};

const ETH1_INDEX: u32 = 11;
const ETH2_INDEX: u32 = 22;

fn address(interface: &str, ip: &str, prefix: u8) -> InterfaceAddress {
    let ip: IpAddr = ip.parse().unwrap();
    InterfaceAddress {
        interface_name: interface.to_string(),
        ip,
        cidr: ipnet::IpNet::new(ip, prefix).unwrap(),
    }
}

/// Two interfaces on the *same* prefix, which is what defeats source-address reasoning
/// based on the routing table alone: both have a route to 10.0.0.0/24.
fn conflicting_interfaces() -> Vec<InterfaceAddress> {
    vec![
        address("eth1", "10.0.0.5", 24),
        address("eth1", "fd00::5", 64),
        address("eth1", "fe80::5", 64),
        address("eth2", "10.0.0.6", 24),
        address("eth2", "fd00::6", 64),
        address("eth2", "fe80::6", 64),
    ]
}

#[test]
fn a_probe_originates_from_the_interface_it_was_created_for() {
    let addresses = conflicting_interfaces();
    let eth1 = SocketBinding::for_interface("eth1", &addresses, ETH1_INDEX);
    let eth2 = SocketBinding::for_interface("eth2", &addresses, ETH2_INDEX);

    // Same destination, reachable through either interface. The source address must follow
    // the selected interface, not whichever route the kernel would have preferred.
    let destination: SocketAddr = "10.0.0.200:80".parse().unwrap();
    assert_eq!(
        eth1.local_address_for(&destination).map(|a| a.ip()),
        Some("10.0.0.5".parse().unwrap())
    );
    assert_eq!(
        eth2.local_address_for(&destination).map(|a| a.ip()),
        Some("10.0.0.6".parse().unwrap())
    );

    // The same holds for routable IPv6 on a shared prefix.
    let v6: SocketAddr = "[fd00::200]:80".parse().unwrap();
    assert_eq!(
        eth1.local_address_for(&v6).map(|a| a.ip()),
        Some("fd00::5".parse().unwrap())
    );
    assert_eq!(
        eth2.local_address_for(&v6).map(|a| a.ip()),
        Some("fd00::6".parse().unwrap())
    );
}

#[test]
fn a_link_local_destination_is_scoped_to_the_selected_link() {
    // fe80::200 exists on both links and is a different device on each. Without the scope
    // index the kernel cannot route to either, and with the wrong one it reaches the wrong
    // device while the evidence is filed under this vantage.
    let addresses = conflicting_interfaces();
    let destination: SocketAddr = "[fe80::200]:80".parse().unwrap();

    for (interface, index, expected_source) in [
        ("eth1", ETH1_INDEX, "fe80::5"),
        ("eth2", ETH2_INDEX, "fe80::6"),
    ] {
        let binding = SocketBinding::for_interface(interface, &addresses, index);
        let SocketAddr::V6(local) = binding
            .local_address_for(&destination)
            .expect("a source address")
        else {
            panic!("expected an IPv6 source");
        };
        assert_eq!(local.ip().to_string(), expected_source);
        assert_eq!(local.scope_id(), index, "{interface} scope index");
    }
}

#[tokio::test]
async fn a_family_the_interface_lacks_fails_instead_of_rerouting() {
    // The defect this prevents: an interface with no source in the destination's family
    // silently reverting to ordinary routing, so the packet leaves elsewhere and its
    // answer is still attributed here.
    let v4_only = SocketBinding::for_interface("eth1", &[address("eth1", "10.0.0.5", 24)], 1);

    assert!(v4_only.is_selected());
    assert!(!v4_only.can_reach(&"[fd00::1]:80".parse().unwrap()));

    let error = v4_only
        .tcp_connect("[fd00::1]:80".parse().unwrap(), Duration::from_millis(50))
        .await
        .expect_err("must not fall back to default routing");
    assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);

    let error = v4_only
        .udp_socket(&"[fd00::1]:53".parse().unwrap())
        .await
        .expect_err("must not fall back to default routing");
    assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
}

#[tokio::test]
async fn an_interface_with_no_address_at_all_still_refuses_to_reroute() {
    // Selection is recorded independently of what the interface is configured with.
    // Deriving "constrained" from "has a source address" meant precisely this case --
    // an interface that is up but unconfigured -- reverted to unbound routing.
    let unconfigured = SocketBinding::for_interface("eth9", &conflicting_interfaces(), 99);

    assert!(
        unconfigured.is_selected(),
        "the operator chose this interface"
    );
    assert!(unconfigured.v4_source.is_none());
    assert!(!unconfigured.can_reach(&"10.0.0.1:80".parse().unwrap()));

    for result in [
        unconfigured
            .tcp_connect("10.0.0.1:80".parse().unwrap(), Duration::from_millis(50))
            .await
            .err(),
        unconfigured.udp_broadcast().await.err(),
        unconfigured.udp_multicast_v4(0).await.err(),
    ] {
        assert_eq!(
            result.expect("must fail").kind(),
            io::ErrorKind::AddrNotAvailable
        );
    }
}

#[test]
fn the_binding_guarantee_is_reported_rather_than_assumed() {
    // Source binding is not the same guarantee as asking the kernel to use one interface.
    // Whichever holds, it is stated; neither is claimed when it does not.
    let addresses = conflicting_interfaces();
    let bound = SocketBinding::for_interface("eth1", &addresses, ETH1_INDEX);
    let destination: SocketAddr = "10.0.0.200:80".parse().unwrap();

    let mode = bound.mode(&destination);
    assert!(
        matches!(
            mode,
            BindingMode::NativeInterface | BindingMode::SourceAddress
        ),
        "a selected interface must constrain something: {mode:?}"
    );

    let unbound = SocketBinding::unbound();
    assert_eq!(unbound.mode(&destination), BindingMode::Unbound);
    assert!(!unbound.is_selected());
    // With no interface chosen, ordinary routing is correct and is not an error.
    assert!(unbound.can_reach(&destination));
}

#[test]
fn link_local_addresses_are_usable_as_sources_but_are_not_networks() {
    // Two different questions with different answers. A link-local address names no
    // routable network -- emitting it as a prefix would invent one -- but it is a perfectly
    // good source, and on many links the only IPv6 source a host has. Filtering it out
    // before binding left those interfaces with no IPv6 source at all.
    let sources = idnx::net::interface::list_socket_sources();
    let prefixes = idnx::net::interface::list_interface_addresses();

    let is_v6_link_local = |a: &InterfaceAddress| match a.ip {
        IpAddr::V6(v6) => idnx::net::endpoint::is_link_local(&v6),
        IpAddr::V4(_) => false,
    };

    assert!(
        !prefixes.iter().any(is_v6_link_local),
        "a link-local address must never be reported as an attached network"
    );
    assert!(
        sources.len() >= prefixes.len(),
        "sources are a superset of prefixes"
    );
}

/// No discovery module may create an active socket outside the socket abstraction.
///
/// This is a source-level guard rather than a runtime one because the failure it prevents
/// is silent: an unbound socket works perfectly, produces answers, and attributes them to
/// the wrong vantage. Nothing at runtime distinguishes that from a correct result.
///
/// `src/net/socket.rs` is the one place allowed to call these, because it is the
/// abstraction. Capture (`src/net/capture.rs`) opens raw link-layer devices by interface
/// already and does not go through it.
#[test]
fn no_discovery_module_opens_a_socket_directly() {
    const ABSTRACTION: &str = "src/net/socket.rs";
    const FORBIDDEN: &[&str] = &[
        "TcpStream::connect",
        "TcpSocket::new_v4",
        "TcpSocket::new_v6",
        "UdpSocket::bind",
        "TcpListener::bind",
    ];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offences: Vec<String> = Vec::new();

    for path in rust_sources(&root) {
        let relative = path
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if relative == ABSTRACTION {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Test-only code is exempt, and only test-only code: a scripted agent that binds a
        // loopback port to answer this crate's own probes is not discovery traffic, and
        // routing it through the interface binding would defeat the point of testing what
        // the binding does. Everything before the first `#[cfg(test)]` in a file is subject
        // to the rule, which is where discovery code lives.
        let productive = match text.find("#[cfg(test)]") {
            Some(at) => &text[..at],
            None => text.as_str(),
        };

        for (number, line) in productive.lines().enumerate() {
            // Doc comments and ordinary comments name these constructs while explaining
            // why they are not used; only real calls matter.
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for needle in FORBIDDEN {
                if code.contains(needle) {
                    offences.push(format!("{relative}:{}: {}", number + 1, code.trim()));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "these must go through crate::net::socket::SocketBinding so the selected \
         interface constrains the traffic:\n{}",
        offences.join("\n")
    );
}

fn rust_sources(directory: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Runtime code must never use the immediate-accept shortcut.
///
/// It advances the replay cursor before the evidence has an owner or the cursor is durable
/// -- the exact sequence that made a declined bundle unresendable. It stays public only
/// because integration tests are separate crates and cannot reach a `cfg(test)` item.
#[test]
fn no_runtime_code_commits_a_bundle_before_delivery() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offences = Vec::new();

    for path in rust_sources(&root) {
        let relative = path
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        // The definition and its own tests live here.
        if relative == "src/federation/ledger.rs" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if !code.starts_with("//") && code.contains("accept_immediately") {
                offences.push(format!("{relative}:{}: {}", number + 1, code.trim()));
            }
        }
    }

    assert!(
        offences.is_empty(),
        "runtime code must prepare, deliver, persist the cursor, then commit:\n{}",
        offences.join("\n")
    );
}
