//! Observation domains.
//!
//! An identifier is only unique inside some domain, and federation is where that stops
//! being academic. Two peers on unrelated networks routinely both have a device at
//! `fe80::1%eth0`, both run `10.0.0.0/24`, and both hold devices with locally administered
//! MACs. Keyed globally, those collide: two routers become one, two subnets become one, and
//! the resulting topology describes a network that does not exist.
//!
//! So each fact carries the domain it was observed in. Local observations are one domain;
//! each peer vantage is another. Identifiers that really are globally unique -- a public
//! address, a manufacturer-assigned MAC -- stay unqualified, because merging those *is*
//! correct and is how the same device seen by two peers becomes one node.
//!
//! Domains are never merged on similarity. Two devices in different domains are two devices
//! until something positive says otherwise.

use std::net::IpAddr;

use ipnet::IpNet;

use super::evidence::{DeviceKey, PeerOrigin};

/// The domain an identifier is unique within.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum Realm {
    /// Observed by this machine.
    #[default]
    Local,
    /// Observed by a peer, from one of its vantages.
    ///
    /// The vantage matters as much as the peer: one peer with two interfaces can see two
    /// different devices at the same link-local address.
    Peer { peer: String, vantage: String },
}

impl Realm {
    /// The domain a piece of evidence belongs to.
    pub fn of(origin: Option<&PeerOrigin>) -> Self {
        match origin {
            None => Realm::Local,
            Some(origin) => Realm::Peer {
                peer: origin.peer.clone(),
                vantage: origin.vantage.clone(),
            },
        }
    }

    pub fn is_local(&self) -> bool {
        matches!(self, Realm::Local)
    }

    /// Short form for display.
    pub fn label(&self) -> String {
        match self {
            Realm::Local => "local".to_string(),
            Realm::Peer { peer, vantage } => {
                let short: String = peer.chars().take(16).collect();
                format!("peer {short} via {vantage}")
            }
        }
    }

    /// Suffix that makes an identifier unique across domains.
    ///
    /// Uses the complete peer identity, never a short form. This suffix becomes part of a
    /// device or bridge key, and two peers sharing a 16-character prefix -- which an
    /// attacker can arrange, and chance eventually will -- would then have their devices
    /// merged. [`Realm::label`] is the short form, and it is for display only.
    ///
    /// Empty for the local domain, so local identity is unchanged and nothing about a
    /// single-machine run differs.
    pub fn suffix(&self) -> String {
        match self {
            Realm::Local => String::new(),
            Realm::Peer { peer, vantage } => format!("@{peer}/{vantage}"),
        }
    }
}

/// Splits a qualified zone back into its interface part and its domain.
///
/// The inverse of the qualification above, needed wherever a stored identity has to be
/// looked up: the domain must be known to make the lookup exact, and by then the only place
/// it survives is inside the zone. An interface name never contains `@`, so the split is
/// unambiguous.
pub fn split_qualified_zone(zone: &str) -> (Option<String>, Realm) {
    let Some((base, qualifier)) = zone.split_once('@') else {
        return ((!zone.is_empty()).then(|| zone.to_string()), Realm::Local);
    };
    let Some((peer, vantage)) = qualifier.split_once('/') else {
        return (Some(zone.to_string()), Realm::Local);
    };
    (
        (!base.is_empty()).then(|| base.to_string()),
        Realm::Peer {
            peer: peer.to_string(),
            vantage: vantage.to_string(),
        },
    )
}

/// The domain a stored device identity belongs to.
pub fn realm_of_key(key: &DeviceKey) -> Realm {
    match key {
        DeviceKey::ScopedAddress(_, zone) => split_qualified_zone(zone).1,
        // A MAC keeps its domain as a suffix, and a bare address is only ever local or
        // globally unique -- an ambiguous remote address becomes a scoped one above.
        DeviceKey::Mac(mac) => split_qualified_zone(mac).1,
        DeviceKey::Address(_) => Realm::Local,
    }
}

/// Whether an address is unique beyond the network it was seen on.
///
/// Private, link-local, unique-local and shared-address-space ranges are not: the same
/// address exists on countless networks, and two peers reporting one are almost never
/// reporting the same device.
pub fn is_globally_unique_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_loopback()
                && !v4.is_unspecified()
                && !v4.is_broadcast()
                // Documentation ranges are deliberately not excluded: they are globally
                // reserved, so the same address anywhere is the same range, and treating
                // them as ambiguous would split fixtures that use them for exactly that
                // reason.
                // 100.64.0.0/10, carrier-grade NAT: as ambiguous as RFC 1918.
                && !(v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            // fc00::/7 unique-local is only *probably* unique and is used with fixed
            // prefixes often enough that it cannot be relied on.
            !crate::net::endpoint::is_link_local(v6)
                && (v6.segments()[0] & 0xfe00) != 0xfc00
                && !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
        }
    }
}

/// Whether a prefix names one network across the whole internet.
pub fn is_globally_unique_prefix(prefix: &IpNet) -> bool {
    is_globally_unique_address(&prefix.addr())
}

/// Whether a MAC identifies one device worldwide.
///
/// A manufacturer-assigned address does. A locally administered one -- the second-least
/// significant bit of the first octet set, which covers randomized privacy addresses and
/// most virtual interfaces -- identifies nothing beyond the link it is used on.
pub fn is_globally_unique_mac(mac: &str) -> bool {
    let Some(first) = mac.split(':').next() else {
        return false;
    };
    let Ok(octet) = u8::from_str_radix(first, 16) else {
        return false;
    };
    octet & 0b0000_0010 == 0
}

/// Qualifies a device identity with the domain it was observed in.
///
/// Globally unique identities are returned unchanged, so a device two peers both see is one
/// node. Everything else is namespaced, so two peers' `fe80::1%eth0` stay two devices.
pub fn qualify_device(key: DeviceKey, realm: &Realm) -> DeviceKey {
    if realm.is_local() {
        return key;
    }

    match key {
        DeviceKey::Mac(mac) if is_globally_unique_mac(&mac) => DeviceKey::Mac(mac),
        DeviceKey::Mac(mac) => DeviceKey::Mac(format!("{mac}{}", realm.suffix())),
        DeviceKey::Address(address) if is_globally_unique_address(&address) => {
            DeviceKey::Address(address)
        }
        // An ambiguous address becomes a scoped one, with the domain as its zone: that is
        // exactly what a zone is for, and it keeps the address itself intact for display.
        // The suffix keeps its `@`, so the domain can be split back out unambiguously --
        // an interface name never contains one.
        DeviceKey::Address(address) => DeviceKey::ScopedAddress(address, realm.suffix()),
        DeviceKey::ScopedAddress(address, zone) => {
            // The peer's interface name means nothing here; two peers both say "eth0".
            DeviceKey::ScopedAddress(address, format!("{zone}{}", realm.suffix()))
        }
    }
}

/// The domain a network's *identity* belongs to.
///
/// A public prefix names the same network wherever it is seen, so it shares one identity
/// and peers can corroborate each other about it. A private one does not.
///
/// This is a statement about naming and nothing else. It does not mean the network is
/// reachable from here: a public prefix reported only by a peer is globally identified and
/// still unreachable, and traversal must decide from evidence of local observation, never
/// from this. Conflating the two would have this machine sweep a peer's uplink.
pub fn network_realm(prefix: &IpNet, realm: &Realm) -> Realm {
    if is_globally_unique_prefix(prefix) {
        Realm::Local
    } else {
        realm.clone()
    }
}

/// The domain an address's identity belongs to.
///
/// Same rule and same caveat as [`network_realm`]: globally unique addresses share one
/// identity so two peers seeing one host produce one node.
pub fn address_realm(address: &IpAddr, realm: &Realm) -> Realm {
    if is_globally_unique_address(address) {
        Realm::Local
    } else {
        realm.clone()
    }
}

/// The domain a purely local name belongs to.
///
/// Interface names and VLAN identifiers are unique only within the machine or the switched
/// domain that uses them. Every peer has an `eth0`, and VLAN 20 on two unrelated sites is
/// two VLANs. There is no globally unique case to exempt.
pub fn scoped_realm(realm: &Realm) -> Realm {
    realm.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_realm(peer: &str, vantage: &str) -> Realm {
        Realm::Peer {
            peer: peer.to_string(),
            vantage: vantage.to_string(),
        }
    }

    #[test]
    fn two_peers_link_local_routers_stay_two_devices() {
        // Both peers have a router at fe80::1 on an interface they both call eth0. Keyed
        // globally, they are one node, and the topology claims one router serves two
        // unrelated networks.
        let address = "fe80::1".parse().unwrap();
        let a = qualify_device(
            DeviceKey::ScopedAddress(address, "eth0".to_string()),
            &peer_realm("aaaa1111", "eth0"),
        );
        let b = qualify_device(
            DeviceKey::ScopedAddress(address, "eth0".to_string()),
            &peer_realm("bbbb2222", "eth0"),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn one_peer_with_two_interfaces_keeps_them_apart() {
        // The vantage is part of the domain: fe80::1 on the peer's eth0 and on its eth1 are
        // different devices on different links.
        let address = "fe80::1".parse().unwrap();
        let first = qualify_device(
            DeviceKey::ScopedAddress(address, "eth0".to_string()),
            &peer_realm("aaaa1111", "eth0"),
        );
        let second = qualify_device(
            DeviceKey::ScopedAddress(address, "eth1".to_string()),
            &peer_realm("aaaa1111", "eth1"),
        );
        assert_ne!(first, second);
    }

    #[test]
    fn private_addresses_from_different_peers_do_not_merge() {
        let address: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!is_globally_unique_address(&address));

        let a = qualify_device(DeviceKey::Address(address), &peer_realm("aaaa1111", "eth0"));
        let b = qualify_device(DeviceKey::Address(address), &peer_realm("bbbb2222", "eth0"));
        assert_ne!(a, b);
        // The address survives for display; only the domain is added.
        assert_eq!(a.address(), Some(address));
    }

    #[test]
    fn a_public_address_seen_by_two_peers_is_one_device() {
        // This is the case where merging is right: the same host, observed from two
        // vantages, must not become two nodes.
        let address: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(is_globally_unique_address(&address));

        let a = qualify_device(DeviceKey::Address(address), &peer_realm("aaaa1111", "eth0"));
        let b = qualify_device(DeviceKey::Address(address), &peer_realm("bbbb2222", "eth1"));
        assert_eq!(a, b);
    }

    #[test]
    fn a_manufacturer_mac_merges_and_a_randomized_one_does_not() {
        // An OUI address is unique worldwide, which is the whole point of the registry. A
        // locally administered one identifies nothing beyond its own link, and two peers
        // both holding 02:00:5e:00:00:01 is unremarkable.
        assert!(is_globally_unique_mac("74:12:13:14:75:dc"));
        assert!(!is_globally_unique_mac("02:00:5e:00:00:01"));
        assert!(!is_globally_unique_mac("5e:8e:44:c6:c7:da"));

        let global = DeviceKey::Mac("74:12:13:14:75:dc".to_string());
        assert_eq!(
            qualify_device(global.clone(), &peer_realm("aaaa1111", "eth0")),
            qualify_device(global, &peer_realm("bbbb2222", "eth1"))
        );

        let local = DeviceKey::Mac("02:00:5e:00:00:01".to_string());
        assert_ne!(
            qualify_device(local.clone(), &peer_realm("aaaa1111", "eth0")),
            qualify_device(local, &peer_realm("bbbb2222", "eth1"))
        );
    }

    #[test]
    fn overlapping_private_prefixes_are_different_networks() {
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        assert!(!is_globally_unique_prefix(&prefix));

        let a = network_realm(&prefix, &peer_realm("aaaa1111", "eth0"));
        let b = network_realm(&prefix, &peer_realm("bbbb2222", "eth0"));
        assert_ne!(a, b);
    }

    #[test]
    fn a_public_prefix_is_the_same_network_everywhere() {
        let prefix: IpNet = "203.0.113.0/24".parse().unwrap();
        assert!(is_globally_unique_prefix(&prefix));
        assert_eq!(
            network_realm(&prefix, &peer_realm("aaaa1111", "eth0")),
            Realm::Local
        );
    }

    #[test]
    fn a_globally_identified_network_can_still_be_remotely_observed() {
        // Identity and reachability are different questions. A public prefix a peer
        // reported shares an identity with one this machine might also see -- that is what
        // lets them corroborate -- but it says nothing about whether this vantage can reach
        // it, and traversal must not read it that way.
        let prefix: IpNet = "203.0.113.0/24".parse().unwrap();
        let remote = peer_realm("aaaa1111", "eth0");

        assert_eq!(
            network_realm(&prefix, &remote),
            Realm::Local,
            "one identity, so two peers can corroborate"
        );
        assert!(
            !remote.is_local(),
            "the observation is still remote; only the name is shared"
        );
    }

    #[test]
    fn interface_and_vlan_names_are_never_globally_unique() {
        // Every peer has an eth0, and VLAN 20 at two sites is two VLANs.
        let remote = peer_realm("aaaa1111", "eth0");
        assert_eq!(scoped_realm(&remote), remote);
        assert_eq!(scoped_realm(&Realm::Local), Realm::Local);
    }

    #[test]
    fn qualification_uses_the_whole_peer_identity() {
        // Two peers sharing a display prefix must not share a namespace: an attacker can
        // grind out a matching 16-character prefix, and their devices would merge.
        let shared = "a".repeat(16);
        let first = Realm::Peer {
            peer: format!("{shared}1111111111111111111111111111111111111111111111111"),
            vantage: "eth0".to_string(),
        };
        let second = Realm::Peer {
            peer: format!("{shared}2222222222222222222222222222222222222222222222222"),
            vantage: "eth0".to_string(),
        };

        assert_eq!(
            first.label(),
            second.label(),
            "display truncates, as intended"
        );
        assert_ne!(first.suffix(), second.suffix(), "identity does not");

        let key = DeviceKey::Mac("02:00:5e:00:00:01".to_string());
        assert_ne!(
            qualify_device(key.clone(), &first),
            qualify_device(key, &second)
        );
    }

    #[test]
    fn a_qualified_zone_splits_back_into_its_parts() {
        // The domain has to be recoverable from a stored identity, or every later lookup
        // has to guess which peer it belonged to.
        let realm = peer_realm("aaaa1111bbbb2222", "eth7");
        let qualified = qualify_device(
            DeviceKey::ScopedAddress("fe80::1".parse().unwrap(), "eth0".to_string()),
            &realm,
        );
        let DeviceKey::ScopedAddress(_, zone) = &qualified else {
            panic!("expected a scoped address");
        };
        assert_eq!(
            split_qualified_zone(zone),
            (Some("eth0".to_string()), realm.clone())
        );
        assert_eq!(realm_of_key(&qualified), realm);

        // A bare ambiguous address becomes scoped with no interface part.
        let bare = qualify_device(DeviceKey::Address("10.0.0.1".parse().unwrap()), &realm);
        assert_eq!(realm_of_key(&bare), realm);

        // Local identities split to the local domain.
        assert_eq!(
            split_qualified_zone("en0"),
            (Some("en0".to_string()), Realm::Local)
        );
        assert_eq!(
            realm_of_key(&DeviceKey::ScopedAddress(
                "fe80::1".parse().unwrap(),
                "en0".to_string()
            )),
            Realm::Local
        );
    }

    #[test]
    fn local_observation_is_never_qualified() {
        // A run with no peers must produce exactly the identities it always did.
        for key in [
            DeviceKey::Mac("02:00:5e:00:00:01".to_string()),
            DeviceKey::Address("10.0.0.1".parse().unwrap()),
            DeviceKey::ScopedAddress("fe80::1".parse().unwrap(), "en0".to_string()),
        ] {
            assert_eq!(qualify_device(key.clone(), &Realm::Local), key);
        }
        assert!(Realm::Local.suffix().is_empty());
    }

    #[test]
    fn carrier_grade_nat_is_as_ambiguous_as_rfc1918() {
        assert!(!is_globally_unique_address(&"100.64.0.1".parse().unwrap()));
        assert!(!is_globally_unique_address(
            &"100.127.255.1".parse().unwrap()
        ));
        // 100.128.0.0 is outside the shared range and is ordinary public space.
        assert!(is_globally_unique_address(&"100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn unique_local_ipv6_is_not_treated_as_globally_unique() {
        // fd00::/8 is only probably unique, and fd00::1 in particular is a common default.
        assert!(!is_globally_unique_address(&"fd00::1".parse().unwrap()));
        assert!(is_globally_unique_address(&"2001:db8::1".parse().unwrap()));
    }
}
