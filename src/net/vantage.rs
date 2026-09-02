//! Resolving where discovery starts from, and what that vantage can see.
//!
//! The operator chooses a starting point — nothing, an interface, or a network. That
//! choice only ever moves the starting point; it never selects a reduced workflow.

use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net};

use crate::engine::orchestrator::is_virtual_interface;
use crate::providers::{Vantage, VantageKind};

/// Where a discovery run begins.
#[derive(Debug, Clone)]
pub struct StartingScope {
    pub vantage: Vantage,
    /// The first network to examine. `None` when the interface has no IPv4 address, in
    /// which case discovery still proceeds from local and neighbour evidence.
    pub network: Option<IpNet>,
    /// Why this vantage was chosen, shown to the operator.
    pub reason: String,
}

/// Classifies an interface so the engine can report what it is unable to observe.
pub fn classify_interface(name: &str) -> VantageKind {
    if name == "lo" || name == "lo0" {
        return VantageKind::Loopback;
    }
    if is_virtual_interface(name) {
        return VantageKind::Virtual;
    }
    if crate::net::interface::is_wireless_interface(name) {
        return VantageKind::Wireless;
    }
    VantageKind::Wired
}

/// Builds a vantage description for an interface.
///
/// `privileged` reflects whether the process can open a raw capture at all; the vantage
/// kind decides whether doing so would see anything useful.
pub fn vantage_for(name: &str, privileged: bool) -> Vantage {
    let kind = classify_interface(name);
    // Capture is only meaningful on a real link. On a virtual or loopback interface there
    // is no link-layer fabric to observe, so claiming capture availability would be
    // misleading even when the syscall would succeed.
    let capture_available =
        privileged && matches!(kind, VantageKind::Wired | VantageKind::Wireless);

    Vantage {
        interface: name.to_string(),
        kind,
        capture_available,
    }
}

/// Resolves the operator's starting argument into a vantage and first network.
///
/// Accepts an interface name, a CIDR, a bare IP address, or nothing at all. An
/// unrecognised argument is an error listing what is available, rather than a silent
/// fallback to some other interface.
pub fn resolve_starting_scope(
    argument: Option<&str>,
    privileged: bool,
) -> Result<StartingScope, String> {
    let interfaces = crate::net::interface::list_ipv4_interfaces()?;

    match argument {
        None => {
            let info = crate::net::interface::detect_local_network()?;
            Ok(StartingScope {
                vantage: vantage_for(&info.interface_name, privileged),
                network: Some(IpNet::V4(info.cidr)),
                reason: "carries the default route".to_string(),
            })
        }
        Some(arg) => {
            let arg = arg.trim();

            // 1. An interface name.
            if let Some(info) = interfaces
                .iter()
                .find(|i| i.interface_name.eq_ignore_ascii_case(arg))
            {
                return Ok(StartingScope {
                    vantage: vantage_for(&info.interface_name, privileged),
                    network: Some(IpNet::V4(info.cidr)),
                    reason: "selected on the command line".to_string(),
                });
            }

            // An interface that exists but has no IPv4 address is still a valid vantage:
            // neighbour discovery and link-layer observation work without one.
            if interface_exists(arg) {
                return Ok(StartingScope {
                    vantage: vantage_for(arg, privileged),
                    network: None,
                    reason: "selected on the command line (no IPv4 address configured)".to_string(),
                });
            }

            // 2. A network or a bare address.
            if let Some(network) = parse_network(arg) {
                // The vantage stays the machine's own default-route interface: the operator
                // named a scope to examine, not a link to observe from.
                let info = crate::net::interface::detect_local_network()?;
                return Ok(StartingScope {
                    vantage: vantage_for(&info.interface_name, privileged),
                    network: Some(network),
                    reason: format!("network {} selected on the command line", network),
                });
            }

            Err(format!(
                "'{}' is not a known interface, network or address.\nAvailable interfaces: {}",
                arg,
                available_interface_list()
            ))
        }
    }
}

/// Parses a CIDR or a bare address into a network.
///
/// A bare address becomes a host route rather than being widened into an assumed /24;
/// guessing a prefix is exactly the behaviour this rebuild removes.
pub fn parse_network(text: &str) -> Option<IpNet> {
    if let Ok(net) = IpNet::from_str(text) {
        return Some(net.trunc());
    }
    if let Ok(v4) = Ipv4Net::from_str(text) {
        return Some(IpNet::V4(v4.trunc()));
    }
    if let Ok(addr) = text.parse::<std::net::IpAddr>() {
        return IpNet::new(addr, if addr.is_ipv4() { 32 } else { 128 })
            .ok()
            .map(|n| n.trunc());
    }
    None
}

fn interface_exists(name: &str) -> bool {
    if_addrs::get_if_addrs()
        .map(|list| list.iter().any(|i| i.name.eq_ignore_ascii_case(name)))
        .unwrap_or(false)
}

/// Comma-separated list of interface names for error messages.
pub fn available_interface_list() -> String {
    match if_addrs::get_if_addrs() {
        Ok(list) => {
            let mut names: Vec<String> = list.into_iter().map(|i| i.name).collect();
            names.sort();
            names.dedup();
            names.join(", ")
        }
        Err(_) => "unavailable".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_virtual_interfaces_are_classified() {
        assert_eq!(classify_interface("lo0"), VantageKind::Loopback);
        assert_eq!(classify_interface("utun3"), VantageKind::Virtual);
        assert_eq!(classify_interface("docker0"), VantageKind::Virtual);
    }

    #[test]
    fn a_bare_address_becomes_a_host_route_not_a_guessed_subnet() {
        let net = parse_network("192.168.1.50").expect("parses");
        assert_eq!(net.prefix_len(), 32);
    }

    #[test]
    fn cidr_is_truncated_to_its_network_address() {
        let net = parse_network("192.168.1.50/24").expect("parses");
        assert_eq!(net.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn ipv6_networks_parse() {
        let net = parse_network("fd00::/64").expect("parses");
        assert_eq!(net.prefix_len(), 64);
    }

    #[test]
    fn nonsense_is_rejected() {
        assert!(parse_network("not-a-network").is_none());
    }

    #[test]
    fn unknown_interface_reports_the_available_ones() {
        let err = resolve_starting_scope(Some("definitely-not-real0"), false)
            .expect_err("must reject an unknown interface");
        assert!(err.contains("Available interfaces"));
    }

    #[test]
    fn virtual_vantage_never_claims_capture() {
        // Even as root there is no link-layer fabric on a tunnel interface.
        let v = vantage_for("utun3", true);
        assert!(!v.capture_available);
    }
}
