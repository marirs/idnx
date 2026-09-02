//! Role determination from corroborated behaviour.
//!
//! A device becomes a router or a switch because of what it was observed *doing*, never
//! because of who manufactured it. The previous implementation classified every ASUS,
//! Linksys, MikroTik and Ubiquiti MAC as a router, which mislabels access points, range
//! extenders, NAS boxes and laptops with those chipsets.

use std::collections::BTreeSet;

use super::evidence::RoleSignal;

/// The role a device plays in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRole {
    Router,
    Switch,
    Host,
}

/// Score at which a device is accepted as network infrastructure.
///
/// Set above the weight of any single weak signal so that a lone management surface, or a
/// lone hostname containing "router", cannot promote a device on its own. One strong
/// signal (being the default gateway, SNMP forwarding, spanning-tree participation) does
/// clear it, because those are not ambiguous.
const INFRASTRUCTURE_THRESHOLD: u32 = 70;

/// Decides a device's role from the set of behaviours observed for it.
pub fn score_role(signals: &BTreeSet<RoleSignal>) -> DeviceRole {
    if signals.is_empty() {
        return DeviceRole::Host;
    }

    let total: u32 = signals.iter().map(|s| s.weight()).sum();

    if total < INFRASTRUCTURE_THRESHOLD {
        return DeviceRole::Host;
    }

    // Spanning-tree participation is bridge behaviour. A device that both bridges and
    // routes is reported as a router, since routing is the more consequential role for
    // topology: it defines a boundary between networks.
    let routes = signals.iter().any(|s| {
        matches!(
            s,
            RoleSignal::DefaultGateway
                | RoleSignal::DhcpRouter
                | RoleSignal::RouterAdvertisement
                | RoleSignal::InternetGatewayDevice
                | RoleSignal::SnmpForwarding
                | RoleSignal::ObservedForwarding
        ) || matches!(s, RoleSignal::LinkLayerCapability(c) if c.contains("Router"))
    });

    if routes {
        return DeviceRole::Router;
    }

    let bridges = signals.iter().any(|s| {
        matches!(s, RoleSignal::SpanningTreeBridge)
            || matches!(s, RoleSignal::LinkLayerCapability(c) if c.contains("Bridge"))
    });

    if bridges {
        return DeviceRole::Switch;
    }

    DeviceRole::Host
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(items: &[RoleSignal]) -> BTreeSet<RoleSignal> {
        items.iter().cloned().collect()
    }

    #[test]
    fn no_signals_is_a_plain_host() {
        assert_eq!(score_role(&signals(&[])), DeviceRole::Host);
    }

    #[test]
    fn a_lone_management_surface_is_not_infrastructure() {
        // DNS plus a web UI describes a router, a NAS, a Pi-hole and a printer equally.
        assert_eq!(
            score_role(&signals(&[RoleSignal::ManagementSurface])),
            DeviceRole::Host
        );
    }

    #[test]
    fn default_gateway_alone_is_a_router() {
        assert_eq!(
            score_role(&signals(&[RoleSignal::DefaultGateway])),
            DeviceRole::Router
        );
    }

    #[test]
    fn weak_signals_corroborate_into_infrastructure() {
        // Neither alone clears the threshold; together they do.
        assert_eq!(
            score_role(&signals(&[
                RoleSignal::ManagementSurface,
                RoleSignal::ObservedForwarding,
            ])),
            DeviceRole::Router
        );
    }

    #[test]
    fn spanning_tree_participation_is_a_switch() {
        assert_eq!(
            score_role(&signals(&[RoleSignal::SpanningTreeBridge])),
            DeviceRole::Switch
        );
    }

    #[test]
    fn a_bridging_router_is_reported_as_a_router() {
        assert_eq!(
            score_role(&signals(&[
                RoleSignal::SpanningTreeBridge,
                RoleSignal::DefaultGateway,
            ])),
            DeviceRole::Router
        );
    }

    #[test]
    fn link_layer_bridge_capability_is_a_switch() {
        assert_eq!(
            score_role(&signals(&[RoleSignal::LinkLayerCapability(
                "Bridge/Switch"
            )])),
            DeviceRole::Switch
        );
    }
}
