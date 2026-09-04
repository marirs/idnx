//! Router discovery: soliciting router advertisements and reading what they disclose
//! (RFC 4861 §4.1–4.2, §4.6.2; RFC 4191 §2.3).
//!
//! This is the first probe in the crate that can establish a network nobody is attached to.
//! A Prefix Information option says "this prefix is on this link"; a Route Information
//! option says "reach *that* prefix through me" -- and the second is how a router discloses
//! a subnet that exists somewhere beyond the link, which no amount of sweeping the local
//! address space can find.
//!
//! Both are the router's own claims, recorded as advertised rather than observed. What is
//! verified here is that the claim genuinely came from a router on this link: hop limit 255
//! (RFC 4861 §11.2, which is what stops an off-link station forging router discovery), a
//! checksum computed over the real IPv6 pseudo-header, and arrival on the interface we
//! solicited from.
//!
//! Nothing is synthesised. A prefix reaches the graph only when the advertisement carried
//! its bytes, and an option whose length field disagrees with its contents is discarded
//! rather than repaired.

use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use ipnet::Ipv6Net;

use crate::net::icmpv6::{IcmpV6Socket, REQUIRED_HOP_LIMIT};
use crate::net::linklayer::interface_mac;
use crate::probes::attempt::AttemptOutcome;
use crate::probes::ndp::icmpv6_checksum;

/// ICMPv6 types for router discovery.
const ROUTER_SOLICITATION: u8 = 133;
const ROUTER_ADVERTISEMENT: u8 = 134;

/// Neighbour discovery option types this probe reads.
const OPTION_SOURCE_LINK_LAYER: u8 = 1;
const OPTION_PREFIX_INFORMATION: u8 = 3;
const OPTION_MTU: u8 = 5;
const OPTION_ROUTE_INFORMATION: u8 = 24;

/// `ff02::2`, the all-routers link-local multicast group.
pub fn all_routers() -> Ipv6Addr {
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2)
}

/// A prefix the router says is on this link (RFC 4861 §4.6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixInformation {
    pub prefix: Ipv6Net,
    /// The L flag: this prefix is on-link. Without it the prefix says nothing about
    /// reachability on this link, only that addresses may be formed from it.
    pub on_link: bool,
    /// The A flag: hosts may autoconfigure addresses from this prefix.
    pub autonomous: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
}

/// A route the router says it can reach (RFC 4191 §2.3).
///
/// The disclosure that matters for topology: a prefix that is *not* on this link, named by
/// a router offering to carry traffic to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInformation {
    pub prefix: Ipv6Net,
    /// Router preference, as the two-bit field encodes it: high, medium, low or reserved.
    pub preference: RoutePreference,
    /// Seconds this route remains valid. Zero withdraws it.
    pub lifetime: u32,
}

/// The Prf field of a Route Information option (RFC 4191 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePreference {
    High,
    Medium,
    Low,
    /// The reserved encoding. RFC 4191 §2.3 says an option carrying it must be ignored, so
    /// it is parsed, named and then discarded rather than being treated as medium.
    Reserved,
}

impl RoutePreference {
    fn from_flags(flags: u8) -> Self {
        match (flags >> 3) & 0b11 {
            0b01 => RoutePreference::High,
            0b00 => RoutePreference::Medium,
            0b11 => RoutePreference::Low,
            _ => RoutePreference::Reserved,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            RoutePreference::High => "high",
            RoutePreference::Medium => "medium",
            RoutePreference::Low => "low",
            RoutePreference::Reserved => "reserved",
        }
    }
}

/// One validated router advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAdvertisement {
    /// The address it came from, which is the router's link-local address.
    pub router: Ipv6Addr,
    /// Its link-layer address, when the advertisement carried the option.
    pub mac: Option<[u8; 6]>,
    /// Seconds this router offers itself as a default router. Zero means it is not one,
    /// which is a real statement and not an absence.
    pub router_lifetime: u16,
    /// The M flag: addresses come from DHCPv6.
    pub managed: bool,
    /// The O flag: other configuration comes from DHCPv6.
    pub other_config: bool,
    /// Link MTU, when advertised.
    pub mtu: Option<u32>,
    pub prefixes: Vec<PrefixInformation>,
    pub routes: Vec<RouteInformation>,
    /// The bytes every fact above came from.
    pub raw: Vec<u8>,
}

impl RouterAdvertisement {
    pub fn mac_text(&self) -> Option<String> {
        self.mac.map(|mac| {
            mac.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        })
    }

    /// Prefixes the router says are on this link.
    pub fn on_link_prefixes(&self) -> impl Iterator<Item = &PrefixInformation> {
        self.prefixes.iter().filter(|prefix| prefix.on_link)
    }

    /// Routes worth acting on: a usable preference and a lifetime that has not expired.
    pub fn usable_routes(&self) -> impl Iterator<Item = &RouteInformation> {
        self.routes
            .iter()
            .filter(|route| route.preference != RoutePreference::Reserved && route.lifetime > 0)
    }
}

/// The outcome of one router solicitation.
pub type RouterOutcome = AttemptOutcome<Vec<RouterAdvertisement>>;

/// Builds a router solicitation carrying this station's link-layer address.
pub fn solicitation(sender_mac: [u8; 6]) -> Vec<u8> {
    let mut message = Vec::with_capacity(16);
    message.push(ROUTER_SOLICITATION);
    message.push(0); // code
    message.extend_from_slice(&[0, 0]); // checksum, computed by the kernel
    message.extend_from_slice(&[0, 0, 0, 0]); // reserved
    message.push(OPTION_SOURCE_LINK_LAYER);
    message.push(1); // option length, in units of 8 bytes
    message.extend_from_slice(&sender_mac);
    message
}

/// Whether a message is a router advertisement that arrived on the interface we asked from.
///
/// A raw ICMPv6 socket receives every ICMPv6 message on the host. Unrelated ones are not
/// failed advertisements and must not be counted as such.
pub fn is_candidate(message: &[u8], arrived_on: u32, selected_interface: u32) -> bool {
    arrived_on == selected_interface
        && message.len() >= 16
        && message[0] == ROUTER_ADVERTISEMENT
        && message[1] == 0
}

/// Validates and decodes a router advertisement.
///
/// `hop_limit` and `destination` come from the receiving socket's ancillary data. Hop limit
/// 255 is what confines router discovery to this link: a router would have decremented it,
/// so anything less was injected from somewhere else.
pub fn parse_advertisement(
    message: &[u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    hop_limit: u8,
) -> Option<RouterAdvertisement> {
    if hop_limit != REQUIRED_HOP_LIMIT || message.len() < 16 {
        return None;
    }
    if message[0] != ROUTER_ADVERTISEMENT || message[1] != 0 {
        return None;
    }
    // A verifying checksum is zero over the message with its checksum field in place, and
    // the pseudo-header is what binds it to the addresses it travelled between.
    if icmpv6_checksum(source, destination, message) != 0 {
        return None;
    }
    // Router discovery describes the link it was sent on, and a router's link-local address
    // is what a host installs as its next hop. A global source would be describing
    // something else.
    if (source.segments()[0] & 0xffc0) != 0xfe80 {
        return None;
    }

    let flags = message[5];
    let mut advertisement = RouterAdvertisement {
        router: source,
        mac: None,
        router_lifetime: u16::from_be_bytes([message[6], message[7]]),
        managed: flags & 0x80 != 0,
        other_config: flags & 0x40 != 0,
        mtu: None,
        prefixes: Vec::new(),
        routes: Vec::new(),
        raw: message.to_vec(),
    };

    let mut cursor = 16;
    while cursor + 2 <= message.len() {
        let kind = message[cursor];
        let units = message[cursor + 1] as usize;
        if units == 0 {
            // RFC 4861 §4.6 forbids a zero length, and honouring it would loop forever.
            return None;
        }
        let end = cursor + units * 8;
        if end > message.len() {
            // An option claiming more bytes than arrived: the message is malformed, and
            // guessing at the remainder would invent topology.
            return None;
        }
        let option = &message[cursor..end];

        match kind {
            OPTION_SOURCE_LINK_LAYER if units == 1 => {
                let address: [u8; 6] = option[2..8].try_into().ok()?;
                // A group address is not a station's own hardware address.
                if address[0] & 0x01 == 0 && address != [0u8; 6] {
                    advertisement.mac = Some(address);
                }
            }
            OPTION_MTU if units == 1 => {
                advertisement.mtu = Some(u32::from_be_bytes([
                    option[4], option[5], option[6], option[7],
                ]));
            }
            OPTION_PREFIX_INFORMATION if units == 4 => {
                if let Some(prefix) = parse_prefix_information(option) {
                    advertisement.prefixes.push(prefix);
                }
            }
            OPTION_ROUTE_INFORMATION => {
                if let Some(route) = parse_route_information(option) {
                    advertisement.routes.push(route);
                }
            }
            _ => {}
        }
        cursor = end;
    }

    Some(advertisement)
}

/// Prefix Information (RFC 4861 §4.6.2): fixed at four 8-byte units.
fn parse_prefix_information(option: &[u8]) -> Option<PrefixInformation> {
    if option.len() != 32 {
        return None;
    }
    let prefix_len = option[2];
    if prefix_len > 128 {
        return None;
    }
    let flags = option[3];
    let raw: [u8; 16] = option[16..32].try_into().ok()?;
    // Truncated to its own prefix length: a router that leaves host bits set is describing
    // the same network, and keeping them would produce a prefix that matches nothing.
    let prefix = Ipv6Net::new(Ipv6Addr::from(raw), prefix_len).ok()?.trunc();

    Some(PrefixInformation {
        prefix,
        on_link: flags & 0x80 != 0,
        autonomous: flags & 0x40 != 0,
        valid_lifetime: u32::from_be_bytes([option[4], option[5], option[6], option[7]]),
        preferred_lifetime: u32::from_be_bytes([option[8], option[9], option[10], option[11]]),
    })
}

/// Route Information (RFC 4191 §2.3): one, two or three 8-byte units, carrying 0, 8 or 16
/// bytes of prefix respectively.
///
/// The length must agree with the prefix length it declares. An option claiming a /64 in a
/// single unit carries no prefix bytes at all, and reading the zeros that follow as a
/// prefix would invent `::/64` out of a malformed option.
fn parse_route_information(option: &[u8]) -> Option<RouteInformation> {
    let units = option.len() / 8;
    if !(1..=3).contains(&units) || !option.len().is_multiple_of(8) {
        return None;
    }
    let prefix_len = option[2];
    if prefix_len > 128 {
        return None;
    }
    let carried_bits = match units {
        1 => 0,
        2 => 64,
        _ => 128,
    };
    if prefix_len as usize > carried_bits {
        return None;
    }

    let mut raw = [0u8; 16];
    let available = option.len() - 8;
    raw[..available].copy_from_slice(&option[8..8 + available]);
    let prefix = Ipv6Net::new(Ipv6Addr::from(raw), prefix_len).ok()?.trunc();

    Some(RouteInformation {
        prefix,
        preference: RoutePreference::from_flags(option[3]),
        lifetime: u32::from_be_bytes([option[4], option[5], option[6], option[7]]),
    })
}

/// Solicits router advertisements on one interface and collects what answers.
///
/// A solicitation rather than a wait: unsolicited advertisements arrive on the router's own
/// schedule, which RFC 4861 allows to be up to 1800 seconds apart. Asking turns a
/// half-hour wait into a bounded one.
pub async fn solicit(interface: &str, scope_index: u32, budget: Duration) -> RouterOutcome {
    let interface = interface.to_string();
    tokio::task::spawn_blocking(move || {
        let sender_mac = match interface_mac(&interface) {
            Some(mac) => mac,
            None => {
                return AttemptOutcome::not_sent(format!(
                    "{interface} has no hardware address to send from"
                ));
            }
        };
        let socket = match IcmpV6Socket::open(scope_index) {
            Ok(socket) => socket,
            Err(reason) => return AttemptOutcome::unavailable(reason),
        };

        let sent = format!("ICMPv6 router solicitation to {}", all_routers());
        if let Err(reason) = socket.send_to(&solicitation(sender_mac), all_routers(), scope_index) {
            return AttemptOutcome::not_sent(reason);
        }

        let deadline = Instant::now() + budget;
        let mut advertisements: Vec<RouterAdvertisement> = Vec::new();
        let mut rejected = 0usize;

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Some(received) = socket.recv(remaining) else {
                continue;
            };
            if !is_candidate(&received.message, received.interface_index, scope_index) {
                continue;
            }
            match parse_advertisement(
                &received.message,
                received.source,
                received.destination,
                received.hop_limit,
            ) {
                // One advertisement per router: a router answering the solicitation and
                // then sending its periodic one within the window is one router.
                Some(found) => {
                    if !advertisements
                        .iter()
                        .any(|seen| seen.router == found.router)
                    {
                        advertisements.push(found);
                    }
                }
                None => rejected += 1,
            }
        }

        if !advertisements.is_empty() {
            return AttemptOutcome::Answered {
                sent,
                result: advertisements,
            };
        }
        if rejected > 0 {
            return AttemptOutcome::InvalidResponse { sent, rejected };
        }
        AttemptOutcome::NoResponse { sent }
    })
    .await
    .unwrap_or_else(|error| {
        AttemptOutcome::not_sent(format!(
            "the router solicitation task did not complete: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0212, 0x34ff, 0xfe56, 0x7890);
    const US: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

    /// Assembles an advertisement with a verifying checksum.
    fn advertisement(flags: u8, lifetime: u16, options: &[Vec<u8>]) -> Vec<u8> {
        let mut message = vec![ROUTER_ADVERTISEMENT, 0, 0, 0, 64, flags];
        message.extend_from_slice(&lifetime.to_be_bytes());
        message.extend_from_slice(&[0, 0, 0, 0]); // reachable time
        message.extend_from_slice(&[0, 0, 0, 0]); // retransmit timer
        for option in options {
            message.extend_from_slice(option);
        }
        let checksum = icmpv6_checksum(ROUTER, US, &message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());
        message
    }

    fn prefix_option(prefix: Ipv6Addr, len: u8, flags: u8) -> Vec<u8> {
        let mut option = vec![OPTION_PREFIX_INFORMATION, 4, len, flags];
        option.extend_from_slice(&2592000u32.to_be_bytes()); // valid lifetime
        option.extend_from_slice(&604800u32.to_be_bytes()); // preferred lifetime
        option.extend_from_slice(&[0, 0, 0, 0]); // reserved
        option.extend_from_slice(&prefix.octets());
        option
    }

    fn route_option(prefix: Ipv6Addr, len: u8, units: u8, flags: u8, lifetime: u32) -> Vec<u8> {
        let mut option = vec![OPTION_ROUTE_INFORMATION, units, len, flags];
        option.extend_from_slice(&lifetime.to_be_bytes());
        let carried = (units as usize - 1) * 8;
        option.extend_from_slice(&prefix.octets()[..carried]);
        option
    }

    #[test]
    fn a_solicitation_names_this_station_and_goes_to_all_routers() {
        assert_eq!(all_routers(), "ff02::2".parse::<Ipv6Addr>().unwrap());

        let mac = [0x02, 0x99, 0x88, 0x77, 0x66, 0x55];
        let message = solicitation(mac);
        assert_eq!(message[0], ROUTER_SOLICITATION);
        assert_eq!(message[1], 0);
        assert_eq!(&message[2..4], &[0, 0], "the kernel computes the checksum");
        assert_eq!(message[8], OPTION_SOURCE_LINK_LAYER);
        assert_eq!(message[9], 1);
        assert_eq!(&message[10..16], &mac);
    }

    #[test]
    fn an_on_link_prefix_is_distinguished_from_one_that_is_merely_autoconfigurable() {
        // The L flag is what makes a prefix a statement about this link. Without it the
        // router is saying only that addresses may be formed from it.
        let on_link = prefix_option("2001:db8:1::".parse().unwrap(), 64, 0xc0);
        let addresses_only = prefix_option("2001:db8:2::".parse().unwrap(), 64, 0x40);
        let message = advertisement(0, 1800, &[on_link, addresses_only]);

        let parsed = parse_advertisement(&message, ROUTER, US, 255).expect("valid");
        assert_eq!(parsed.prefixes.len(), 2);
        assert!(parsed.prefixes[0].on_link && parsed.prefixes[0].autonomous);
        assert!(!parsed.prefixes[1].on_link && parsed.prefixes[1].autonomous);

        let on_link: Vec<Ipv6Net> = parsed.on_link_prefixes().map(|p| p.prefix).collect();
        assert_eq!(on_link, vec!["2001:db8:1::/64".parse::<Ipv6Net>().unwrap()]);
        assert_eq!(parsed.prefixes[0].valid_lifetime, 2592000);
        assert_eq!(parsed.prefixes[0].preferred_lifetime, 604800);
    }

    #[test]
    fn a_route_information_option_discloses_a_prefix_beyond_this_link() {
        // The reason this probe exists. A cascaded subnet cannot be found by sweeping the
        // local address space; a router offering to carry traffic to it says so outright.
        let route = route_option("2001:db8:51::".parse().unwrap(), 48, 2, 0x08, 1800);
        let message = advertisement(0, 1800, &[route]);

        let parsed = parse_advertisement(&message, ROUTER, US, 255).expect("valid");
        assert_eq!(parsed.routes.len(), 1);
        assert_eq!(
            parsed.routes[0].prefix,
            "2001:db8:51::/48".parse::<Ipv6Net>().unwrap()
        );
        assert_eq!(parsed.routes[0].preference, RoutePreference::High);
        assert_eq!(parsed.routes[0].lifetime, 1800);
        assert_eq!(parsed.usable_routes().count(), 1);
    }

    #[test]
    fn route_preferences_decode_to_their_own_meanings() {
        for (flags, expected) in [
            (0x08, RoutePreference::High),
            (0x00, RoutePreference::Medium),
            (0x18, RoutePreference::Low),
            (0x10, RoutePreference::Reserved),
        ] {
            let message = advertisement(
                0,
                1800,
                &[route_option(
                    "2001:db8:7::".parse().unwrap(),
                    48,
                    2,
                    flags,
                    600,
                )],
            );
            let parsed = parse_advertisement(&message, ROUTER, US, 255).expect("valid");
            assert_eq!(parsed.routes[0].preference, expected);
        }

        // RFC 4191 §2.3: the reserved encoding must be ignored, not read as medium.
        let reserved = advertisement(
            0,
            1800,
            &[route_option(
                "2001:db8:7::".parse().unwrap(),
                48,
                2,
                0x10,
                600,
            )],
        );
        let parsed = parse_advertisement(&reserved, ROUTER, US, 255).expect("valid");
        assert_eq!(parsed.usable_routes().count(), 0);

        // A withdrawn route is not a route either.
        let withdrawn = advertisement(
            0,
            1800,
            &[route_option(
                "2001:db8:7::".parse().unwrap(),
                48,
                2,
                0x08,
                0,
            )],
        );
        let parsed = parse_advertisement(&withdrawn, ROUTER, US, 255).expect("valid");
        assert_eq!(parsed.usable_routes().count(), 0);
    }

    #[test]
    fn a_route_option_shorter_than_its_prefix_length_is_discarded() {
        // A single-unit option carries no prefix bytes. Reading the zeros after it as a
        // prefix would invent ::/64 from a malformed option.
        let lying = route_option("2001:db8:9::".parse().unwrap(), 64, 1, 0x08, 600);
        let message = advertisement(0, 1800, &[lying]);
        let parsed = parse_advertisement(&message, ROUTER, US, 255).expect("the RA is still valid");
        assert!(
            parsed.routes.is_empty(),
            "a prefix length the option cannot carry establishes nothing"
        );
    }

    #[test]
    fn the_header_flags_and_options_are_recorded_as_the_router_stated_them() {
        let mut mtu = vec![OPTION_MTU, 1, 0, 0];
        mtu.extend_from_slice(&1500u32.to_be_bytes());
        let mut source_mac = vec![OPTION_SOURCE_LINK_LAYER, 1];
        source_mac.extend_from_slice(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);

        let message = advertisement(0xc0, 0, &[mtu, source_mac]);
        let parsed = parse_advertisement(&message, ROUTER, US, 255).expect("valid");
        assert!(parsed.managed && parsed.other_config);
        assert_eq!(parsed.mtu, Some(1500));
        assert_eq!(parsed.mac_text().as_deref(), Some("00:1a:2b:3c:4d:5e"));
        // Lifetime zero is a statement: this router is not offering itself as a default.
        assert_eq!(parsed.router_lifetime, 0);
        assert_eq!(parsed.raw, message);
    }

    #[test]
    fn an_advertisement_that_could_not_have_come_from_this_link_is_refused() {
        let message = advertisement(
            0,
            1800,
            &[prefix_option("2001:db8::".parse().unwrap(), 64, 0xc0)],
        );

        // Hop limit below 255 has crossed a router (RFC 4861 §11.2).
        for hop_limit in [0u8, 1, 64, 254] {
            assert!(parse_advertisement(&message, ROUTER, US, hop_limit).is_none());
        }
        // A checksum that does not verify over the real pseudo-header.
        let elsewhere = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1234);
        assert!(parse_advertisement(&message, elsewhere, US, 255).is_none());
        // A global source is not describing this link's router.
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let from_global = {
            let mut message = advertisement(0, 1800, &[]);
            let checksum = icmpv6_checksum(global, US, &message);
            message[2..4].copy_from_slice(&checksum.to_be_bytes());
            message
        };
        assert!(parse_advertisement(&from_global, global, US, 255).is_none());
    }

    #[test]
    fn malformed_options_are_refused_rather_than_looped_or_read_past() {
        let mut zero_length = advertisement(
            0,
            1800,
            &[prefix_option("2001:db8::".parse().unwrap(), 64, 0xc0)],
        );
        zero_length[17] = 0; // an option length of zero would never advance
        zero_length[2..4].copy_from_slice(&[0, 0]);
        let checksum = icmpv6_checksum(ROUTER, US, &zero_length);
        zero_length[2..4].copy_from_slice(&checksum.to_be_bytes());
        assert!(parse_advertisement(&zero_length, ROUTER, US, 255).is_none());

        let mut overrun = advertisement(
            0,
            1800,
            &[prefix_option("2001:db8::".parse().unwrap(), 64, 0xc0)],
        );
        overrun[17] = 8; // claims 64 bytes where 32 arrived
        overrun[2..4].copy_from_slice(&[0, 0]);
        let checksum = icmpv6_checksum(ROUTER, US, &overrun);
        overrun[2..4].copy_from_slice(&checksum.to_be_bytes());
        assert!(parse_advertisement(&overrun, ROUTER, US, 255).is_none());

        let full = advertisement(
            0,
            1800,
            &[prefix_option("2001:db8::".parse().unwrap(), 64, 0xc0)],
        );
        for length in 0..full.len() {
            assert!(parse_advertisement(&full[..length], ROUTER, US, 255).is_none());
        }
    }

    #[test]
    fn unrelated_icmpv6_is_not_a_candidate_advertisement() {
        let message = advertisement(0, 1800, &[]);
        assert!(is_candidate(&message, 4, 4));
        // Arrived on another interface: it describes another link.
        assert!(!is_candidate(&message, 7, 4));

        let mut solicitation = message.clone();
        solicitation[0] = ROUTER_SOLICITATION;
        assert!(!is_candidate(&solicitation, 4, 4));

        let neighbour_advertisement = {
            let mut message = message.clone();
            message[0] = 136;
            message
        };
        assert!(!is_candidate(&neighbour_advertisement, 4, 4));
    }
}
