//! The version-neutral routing table: `inetCidrRouteTable` (RFC 4292).
//!
//! MIB-II's `ipRouteTable` is IPv4-only and expresses a mask rather than a prefix length; it
//! cannot describe an IPv6 route at all, and on a dual-stack device it describes half the
//! forwarding state. This table replaces it, and this module reads the part of it that is
//! hardest to get right: the index.
//!
//! Every field that identifies a route lives *in the OID*, not in a value. One row's
//! instance identifier carries the destination's address family, the destination, the prefix
//! length, the routing policy that produced the row, and the next hop's family and address --
//! all encoded as subidentifiers, with each variable-length element preceded by its length
//! (RFC 4292 declares no `IMPLIED` index element, so none may be read as running to the end).
//!
//! Reading that wrong does not produce a parse error; it produces a plausible-looking route
//! to the wrong network. So the parser here is exact about lengths and refuses anything it
//! cannot account for, rather than taking what it recognises and ignoring the rest.
//!
//! Address encodings are RFC 4001 `InetAddressType` / `InetAddress`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::snmp::Oid;

/// `InetAddressType`, as it appears in an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InetAddressType {
    /// `unknown(0)`: no address. The only length that may follow is zero.
    Unknown,
    Ipv4,
    Ipv6,
    /// `ipv4z(3)`: an IPv4 address followed by a four-octet zone index.
    Ipv4z,
    /// `ipv6z(4)`: an IPv6 address followed by a four-octet zone index.
    Ipv6z,
}

impl InetAddressType {
    fn from_subid(subid: u32) -> Option<Self> {
        match subid {
            0 => Some(InetAddressType::Unknown),
            1 => Some(InetAddressType::Ipv4),
            2 => Some(InetAddressType::Ipv6),
            3 => Some(InetAddressType::Ipv4z),
            4 => Some(InetAddressType::Ipv6z),
            // dns(16) names a host rather than an address, and cannot be resolved from a
            // routing table row. Anything else is not a type this reads.
            _ => None,
        }
    }

    /// The exact octet count RFC 4001 defines for this type. Not a minimum: a length that
    /// disagrees means the index was not encoded the way it was read.
    fn address_len(&self) -> usize {
        match self {
            InetAddressType::Unknown => 0,
            InetAddressType::Ipv4 => 4,
            InetAddressType::Ipv6 => 16,
            InetAddressType::Ipv4z => 8,
            InetAddressType::Ipv6z => 20,
        }
    }

    /// The largest prefix length this family admits.
    fn max_prefix_len(&self) -> u8 {
        match self {
            InetAddressType::Unknown => 0,
            InetAddressType::Ipv4 | InetAddressType::Ipv4z => 32,
            InetAddressType::Ipv6 | InetAddressType::Ipv6z => 128,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            InetAddressType::Unknown => "unknown",
            InetAddressType::Ipv4 => "ipv4",
            InetAddressType::Ipv6 => "ipv6",
            InetAddressType::Ipv4z => "ipv4z",
            InetAddressType::Ipv6z => "ipv6z",
        }
    }
}

/// One address out of an index, with the zone where the type carries one.
///
/// The zone is kept apart from the address because it is not part of it: it is a local
/// interface index on the *device being polled*, meaningless anywhere else, and an address
/// that needs one is not usable as an identity without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InetAddress {
    pub family: InetAddressType,
    pub address: Option<IpAddr>,
    pub zone: Option<u32>,
}

impl InetAddress {
    /// Whether this address can stand on its own as an identity.
    ///
    /// A zoned address cannot: the zone is an interface index on the polled device, and this
    /// crate identifies a scoped address by an interface *name* on the observing vantage.
    /// The two are not the same namespace, and inventing a mapping between them would attach
    /// facts to whatever happens to hold that address here.
    pub fn usable_as_identity(&self) -> bool {
        self.address.is_some() && self.zone.is_none()
    }

    pub fn describe(&self) -> String {
        match (self.address, self.zone) {
            (Some(address), Some(zone)) => {
                format!("{address} zone {zone} ({})", self.family.label())
            }
            (Some(address), None) => address.to_string(),
            (None, _) => self.family.label().to_string(),
        }
    }
}

/// The composite index of one `inetCidrRouteEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InetRouteIndex {
    pub destination: InetAddress,
    pub prefix_len: u8,
    /// `inetCidrRoutePolicy`: the OID of the mechanism that produced this row. Two rows to
    /// the same prefix under different policies are two routes, not a duplicate.
    pub policy: Oid,
    pub next_hop: InetAddress,
}

impl InetRouteIndex {
    /// The prefix this row is about, where the destination is a plain address.
    pub fn prefix(&self) -> Option<ipnet::IpNet> {
        let address = self.destination.address?;
        // A zoned destination describes a prefix inside one interface's scope on the polled
        // device. It is a real route there and names no network reachable from here.
        if self.destination.zone.is_some() {
            return None;
        }
        ipnet::IpNet::new(address, self.prefix_len)
            .ok()
            .map(|net| net.trunc())
    }
}

/// Reads the index subidentifiers that follow a column's OID.
///
/// Layout, in order, with no element permitted to run past its declared length:
/// destination type, destination length and octets, prefix length, policy length and
/// subidentifiers, next-hop type, next-hop length and octets. The whole index must be
/// consumed exactly -- trailing subidentifiers mean this is not the row it was read as.
pub fn parse_index(subids: &[u32]) -> Option<InetRouteIndex> {
    let mut at = 0usize;

    let destination = read_address(subids, &mut at)?;

    let prefix_len = u8::try_from(*subids.get(at)?).ok()?;
    at += 1;
    if prefix_len > destination.family.max_prefix_len() {
        return None;
    }

    // The policy OID, length-prefixed like every other variable element here.
    let policy_len = *subids.get(at)? as usize;
    at += 1;
    let policy = subids.get(at..at + policy_len)?;
    at += policy_len;

    let next_hop = read_address(subids, &mut at)?;

    // Exactly consumed. Anything left over means the index was longer than this reading of
    // it, and a row read against the wrong layout describes the wrong route.
    if at != subids.len() {
        return None;
    }

    Some(InetRouteIndex {
        destination,
        prefix_len,
        policy: Oid::new(policy.to_vec()),
        next_hop,
    })
}

/// Reads one type-length-value address out of the index.
fn read_address(subids: &[u32], at: &mut usize) -> Option<InetAddress> {
    let family = InetAddressType::from_subid(*subids.get(*at)?)?;
    *at += 1;

    let declared = *subids.get(*at)? as usize;
    *at += 1;
    // The length is fixed by the type. A row declaring any other length was not encoded the
    // way this reads it, whatever the octets happen to contain.
    if declared != family.address_len() {
        return None;
    }

    let octets = subids.get(*at..*at + declared)?;
    *at += declared;
    // Index subidentifiers holding octets must each fit in one.
    let bytes: Vec<u8> = octets
        .iter()
        .map(|subid| u8::try_from(*subid))
        .collect::<Result<_, _>>()
        .ok()?;

    let (address, zone) = match family {
        InetAddressType::Unknown => (None, None),
        InetAddressType::Ipv4 => (
            Some(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            ))),
            None,
        ),
        InetAddressType::Ipv6 => {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&bytes);
            (Some(IpAddr::V6(Ipv6Addr::from(raw))), None)
        }
        InetAddressType::Ipv4z => {
            let address = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            let zone = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            (Some(IpAddr::V4(address)), Some(zone))
        }
        InetAddressType::Ipv6z => {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&bytes[..16]);
            let zone = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
            (Some(IpAddr::V6(Ipv6Addr::from(raw))), Some(zone))
        }
    };

    Some(InetAddress {
        family,
        address,
        zone,
    })
}

/// A column that may be absent, present and readable, or present and not.
///
/// Three states, because two lose the distinction that matters most here. A walk over this
/// table is column-major and bounded: it collects column 7 for every row, then column 8, and
/// so on. A table larger than the step limit, or one whose agent stops answering, therefore
/// yields rows that have an ifIndex and no status at all. Reading "absent" as "active" turns
/// an unfinished walk into topology, which is exactly what RowStatus exists to prevent.
///
/// `Invalid` is kept apart from `Missing` for the same reason in the other direction: a
/// value this code cannot interpret is a statement it failed to read, not a statement the
/// agent did not make, and neither may be promoted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Column<T> {
    Missing,
    Valid(T),
    Invalid(String),
}

impl<T> Column<T> {
    pub fn valid(&self) -> Option<&T> {
        match self {
            Column::Valid(value) => Some(value),
            _ => None,
        }
    }

    pub fn describe(&self, name: &str) -> String {
        match self {
            Column::Missing => format!("{name} not returned"),
            Column::Valid(_) => String::new(),
            Column::Invalid(reason) => format!("{name} unreadable: {reason}"),
        }
    }
}

/// `inetCidrRouteType`, which says what the device does with matching traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteType {
    /// `other(1)`: none of the below. A route, with nothing said about directness.
    Other,
    /// `reject(2)`: matching traffic is discarded with an unreachable indication.
    Reject,
    /// `local(3)`: the destination is on an interface of this device.
    Local,
    /// `remote(4)`: forwarded to the next hop.
    Remote,
    /// `blackhole(5)`: discarded silently.
    Blackhole,
}

impl RouteType {
    pub fn from_value(value: i64) -> Option<Self> {
        match value {
            1 => Some(RouteType::Other),
            2 => Some(RouteType::Reject),
            3 => Some(RouteType::Local),
            4 => Some(RouteType::Remote),
            5 => Some(RouteType::Blackhole),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            RouteType::Other => "other(1)",
            RouteType::Reject => "reject(2)",
            RouteType::Local => "local(3)",
            RouteType::Remote => "remote(4)",
            RouteType::Blackhole => "blackhole(5)",
        }
    }

    /// Whether traffic matching this row is discarded rather than delivered anywhere.
    ///
    /// Such a row is a real statement about the device's policy and no statement about
    /// topology: nothing is attached, nothing is reached, and the prefix it names may not
    /// exist at all.
    pub fn discards(&self) -> bool {
        matches!(self, RouteType::Reject | RouteType::Blackhole)
    }
}

/// One row of the table, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InetRoute {
    pub index: InetRouteIndex,
    /// The instance OID this row was read from, kept verbatim so a claim can be traced back
    /// to the exact object that carried it.
    pub instance: Oid,
    pub if_index: Option<i64>,
    /// `inetCidrRouteType`. Missing and unreadable are different states: only a row whose
    /// type was genuinely not returned may take the directness-unstated path, and a value
    /// outside the enumeration is a row this code could not read rather than one the agent
    /// left unsaid.
    pub route_type: Column<RouteType>,
    /// `inetCidrRouteProto`, the mechanism that installed the row (RFC 4292 IANAipRouteProtocol).
    pub proto: Option<i64>,
    pub metric: Option<i64>,
    /// `inetCidrRouteStatus`, a RowStatus. Only `active(1)` is a row in force.
    pub status: Column<i64>,
}

impl InetRoute {
    /// Whether the row is in force, stated explicitly by the agent.
    ///
    /// Requires a decoded `active(1)`. Absence is not consent: a walk over this table is
    /// column-major, so a bounded or truncated walk collects earlier columns for many rows
    /// and reaches the status column for none of them. Treating those as active would let an
    /// enterprise routing table too large to finish manufacture topology out of half-read
    /// rows -- and a row being created, destroyed or held out of service describes no
    /// forwarding whatsoever.
    ///
    /// Rows failing this are not discarded; they are reported as what they are, and create
    /// nothing.
    pub fn active(&self) -> bool {
        matches!(self.status, Column::Valid(1))
    }

    /// The next hop, where it is one this crate can identify.
    pub fn usable_next_hop(&self) -> Option<IpAddr> {
        if !self.index.next_hop.usable_as_identity() {
            return None;
        }
        let address = self.index.next_hop.address?;
        // An unspecified next hop is how a directly connected row says "no next hop", not an
        // address anything can be attributed to.
        (!is_unspecified(&address)).then_some(address)
    }

    /// One line naming everything the row stated, for provenance.
    pub fn describe(&self) -> String {
        let mut parts = vec![format!(
            "inetCidrRoute {}/{} via {}",
            self.index.destination.describe(),
            self.index.prefix_len,
            self.index.next_hop.describe()
        )];
        if !self.index.policy.0.is_empty() {
            parts.push(format!("policy {}", self.index.policy));
        }
        match &self.route_type {
            Column::Valid(kind) => parts.push(format!("type {}", kind.label())),
            other => parts.push(other.describe("type")),
        }
        if let Some(proto) = self.proto {
            parts.push(format!("proto {proto}"));
        }
        if let Some(if_index) = self.if_index {
            parts.push(format!("ifIndex {if_index}"));
        }
        if let Some(metric) = self.metric {
            parts.push(format!("metric {metric}"));
        }
        match &self.status {
            Column::Valid(status) => parts.push(format!("status {status}")),
            other => parts.push(other.describe("status")),
        }
        parts.push(format!("instance {}", self.instance));
        parts.join(", ")
    }
}

fn is_unspecified(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds index subidentifiers the way an agent encodes them.
    fn index(
        dest_type: u32,
        dest: &[u32],
        prefix_len: u32,
        policy: &[u32],
        hop_type: u32,
        hop: &[u32],
    ) -> Vec<u32> {
        let mut out = vec![dest_type, dest.len() as u32];
        out.extend_from_slice(dest);
        out.push(prefix_len);
        out.push(policy.len() as u32);
        out.extend_from_slice(policy);
        out.push(hop_type);
        out.push(hop.len() as u32);
        out.extend_from_slice(hop);
        out
    }

    #[test]
    fn an_ipv4_index_decodes_every_element() {
        let subids = index(1, &[198, 51, 100, 0], 24, &[0], 1, &[192, 0, 2, 254]);
        let parsed = parse_index(&subids).expect("a well-formed index");

        assert_eq!(parsed.destination.family, InetAddressType::Ipv4);
        assert_eq!(
            parsed.destination.address,
            Some("198.51.100.0".parse().unwrap())
        );
        assert_eq!(parsed.prefix_len, 24);
        assert_eq!(parsed.policy, Oid::new(vec![0]));
        assert_eq!(
            parsed.next_hop.address,
            Some("192.0.2.254".parse().unwrap())
        );
        assert_eq!(parsed.prefix().unwrap().to_string(), "198.51.100.0/24");
    }

    #[test]
    fn an_ipv6_index_decodes_every_element() {
        let mut destination = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0];
        destination.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let mut hop = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0];
        hop.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);

        let subids = index(2, &destination, 64, &[1, 3, 6, 1], 2, &hop);
        let parsed = parse_index(&subids).expect("a well-formed index");

        assert_eq!(parsed.destination.family, InetAddressType::Ipv6);
        assert_eq!(parsed.prefix_len, 64);
        assert_eq!(parsed.policy, Oid::new(vec![1, 3, 6, 1]));
        assert_eq!(parsed.prefix().unwrap().to_string(), "2001:db8::/64");
        assert_eq!(
            parsed.next_hop.address,
            Some("2001:db8::1".parse::<std::net::IpAddr>().unwrap())
        );
    }

    #[test]
    fn zoned_addresses_carry_their_zone_and_name_no_network() {
        // ipv4z is four address octets and four zone octets; ipv6z is sixteen and four. The
        // zone is an interface index on the polled device, so it is kept and never merged
        // into the address.
        let subids = index(
            3,
            &[10, 0, 0, 0, 0, 0, 0, 7],
            8,
            &[0],
            3,
            &[10, 0, 0, 1, 0, 0, 0, 7],
        );
        let parsed = parse_index(&subids).expect("a well-formed ipv4z index");
        assert_eq!(parsed.destination.zone, Some(7));
        assert_eq!(parsed.next_hop.zone, Some(7));
        assert!(
            parsed.prefix().is_none(),
            "a zoned destination names no network reachable from here"
        );
        assert!(!parsed.next_hop.usable_as_identity());

        let mut destination = vec![0xfe, 0x80];
        destination.extend(std::iter::repeat_n(0, 14));
        destination.extend_from_slice(&[0, 0, 0, 5]);
        let subids = index(4, &destination, 10, &[0], 0, &[]);
        let parsed = parse_index(&subids).expect("a well-formed ipv6z index");
        assert_eq!(parsed.destination.zone, Some(5));
        assert_eq!(parsed.next_hop.family, InetAddressType::Unknown);
    }

    #[test]
    fn a_length_that_disagrees_with_its_type_is_refused() {
        // The failure this prevents is not a parse error: reading four octets where sixteen
        // were encoded produces a plausible route to a network nobody mentioned.
        for (kind, address) in [
            (1u32, vec![198, 51, 100]),    // ipv4 with three octets
            (1, vec![198, 51, 100, 0, 0]), // ipv4 with five
            (2, vec![0x20, 0x01]),         // ipv6 with two
            (3, vec![10, 0, 0, 1]),        // ipv4z without its zone
            (4, vec![0xfe, 0x80, 0, 0]),   // ipv6z far too short
            (0, vec![1]),                  // unknown with an address
        ] {
            let subids = index(kind, &address, 24, &[0], 0, &[]);
            assert!(
                parse_index(&subids).is_none(),
                "type {kind} with {} octet(s) must be refused",
                address.len()
            );
        }
    }

    #[test]
    fn an_impossible_prefix_length_is_refused() {
        assert!(parse_index(&index(1, &[10, 0, 0, 0], 33, &[0], 0, &[])).is_none());
        assert!(parse_index(&index(2, &[0; 16], 129, &[0], 0, &[])).is_none());
        // And the boundaries themselves are accepted, since /32 and /128 are real rows even
        // where this crate declines to treat them as networks.
        assert!(parse_index(&index(1, &[10, 0, 0, 1], 32, &[0], 0, &[])).is_some());
        assert!(parse_index(&index(2, &[0; 16], 128, &[0], 0, &[])).is_some());
    }

    #[test]
    fn a_truncated_or_overlong_index_is_refused() {
        let complete = index(1, &[198, 51, 100, 0], 24, &[0], 1, &[192, 0, 2, 254]);
        for cut in 1..complete.len() {
            assert!(
                parse_index(&complete[..cut]).is_none(),
                "an index cut at {cut} subid(s) is not a row"
            );
        }
        // Trailing subidentifiers mean the index was not the shape it was read as.
        let mut overlong = complete.clone();
        overlong.push(1);
        assert!(parse_index(&overlong).is_none());
    }

    #[test]
    fn an_octet_that_cannot_be_an_octet_is_refused() {
        // Subidentifiers are 32-bit; the ones carrying address octets must each fit in one.
        let subids = index(1, &[198, 51, 100, 300], 24, &[0], 0, &[]);
        assert!(parse_index(&subids).is_none());
    }

    #[test]
    fn policy_distinguishes_two_routes_to_one_prefix() {
        let first = parse_index(&index(1, &[198, 51, 100, 0], 24, &[0], 1, &[192, 0, 2, 1]))
            .expect("a row");
        let second = parse_index(&index(
            1,
            &[198, 51, 100, 0],
            24,
            &[1, 3, 6, 1, 4, 1, 9],
            1,
            &[192, 0, 2, 1],
        ))
        .expect("a row");

        assert_eq!(first.prefix(), second.prefix());
        assert_ne!(first, second, "different policies are different rows");
    }

    #[test]
    fn a_row_is_in_force_only_when_it_says_so() {
        use super::Column;

        let row = |status: Column<i64>| InetRoute {
            index: parse_index(&index(1, &[198, 51, 100, 0], 24, &[0], 0, &[])).expect("a row"),
            instance: Oid::new(vec![1, 3, 6]),
            if_index: None,
            route_type: Column::Valid(RouteType::Local),
            proto: None,
            metric: None,
            status,
        };

        assert!(row(Column::Valid(1)).active(), "active(1) is in force");
        for status in [
            Column::Missing,
            Column::Invalid("not an integer".to_string()),
            Column::Valid(2), // notInService
            Column::Valid(3), // notReady
            Column::Valid(6), // destroy
        ] {
            assert!(
                !row(status.clone()).active(),
                "{status:?} is not a row in force"
            );
        }
    }

    #[test]
    fn a_discarding_row_is_policy_and_not_topology() {
        assert!(RouteType::Reject.discards());
        assert!(RouteType::Blackhole.discards());
        assert!(!RouteType::Local.discards());
        assert!(!RouteType::Remote.discards());
        assert!(!RouteType::Other.discards());
        assert_eq!(RouteType::from_value(9), None);
    }
}
