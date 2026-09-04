//! DHCPINFORM: asking the DHCP server what it knows about this link (RFC 2131 §3.4,
//! RFC 3442, and Microsoft's option 249).
//!
//! A DHCP server holds the operator's own description of the network -- the mask of the
//! attached prefix, the routers, and, where classless static routes are configured, explicit
//! prefixes reachable through named next hops. Option 121 is one of the few IPv4 mechanisms
//! that can name a subnet this machine is not attached to, which is why it is here.
//!
//! Two rules govern what any of it establishes.
//!
//! A router address is not a network. Option 3 names devices that route; it says nothing
//! about the prefixes behind them, and treating a router's address as evidence of a /24
//! around it would invent a network from an address. Only option 1 -- combined with this
//! interface's own address -- and options 121/249, which carry prefix lengths outright, may
//! create one.
//!
//! And nothing here is applied. This is an INFORM, which asks for configuration without
//! requesting a lease; the answer is recorded as evidence and never written to the host's
//! routing table, resolver or lease database.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use ipnet::Ipv4Net;

use crate::net::socket::SocketBinding;
use crate::probes::attempt::AttemptOutcome;

/// BOOTP operation codes.
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;

/// The DHCP magic cookie that precedes the options (RFC 2131 §3).
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Fixed BOOTP header length, before the cookie.
const BOOTP_HEADER_LEN: usize = 236;

/// DHCP options this probe reads or sets.
const OPTION_SUBNET_MASK: u8 = 1;
const OPTION_ROUTER: u8 = 3;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_PARAMETER_REQUEST: u8 = 55;
const OPTION_CLIENT_IDENTIFIER: u8 = 61;
const OPTION_CLASSLESS_ROUTE: u8 = 121;
/// Microsoft's pre-standard encoding of the same thing, still emitted by many servers.
const OPTION_MS_CLASSLESS_ROUTE: u8 = 249;
const OPTION_END: u8 = 255;

/// DHCP message types.
const DHCPINFORM: u8 = 8;
const DHCPACK: u8 = 5;

const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;

/// One classless static route, exactly as the server encoded it (RFC 3442).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClasslessRoute {
    pub prefix: Ipv4Net,
    /// The next hop the server named. `0.0.0.0` means the destination is on-link.
    pub next_hop: Ipv4Addr,
    /// Which option carried it: 121, or Microsoft's 249.
    pub option: u8,
    /// The bytes of this entry, so the prefix can be traced to the field that stated it.
    pub raw_entry: Vec<u8>,
}

impl ClasslessRoute {
    pub fn evidence(&self) -> String {
        self.raw_entry
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Whether this is the default route rather than a specific prefix.
    pub fn is_default(&self) -> bool {
        self.prefix.prefix_len() == 0
    }
}

/// What a server disclosed in reply to the INFORM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpDisclosure {
    /// The server that answered.
    pub server: Ipv4Addr,
    /// Option 1. Combined with this interface's address, and with nothing else.
    pub subnet_mask: Option<Ipv4Addr>,
    /// Option 3. Routers, which are devices and not networks.
    pub routers: Vec<Ipv4Addr>,
    /// Options 121 and 249, in the order the server listed them.
    pub classless_routes: Vec<ClasslessRoute>,
    /// The whole reply, so every fact keeps its supporting bytes.
    pub raw: Vec<u8>,
}

impl DhcpDisclosure {
    /// The prefix this interface is attached to, from the advertised mask and our own
    /// address -- the only network option 1 can establish.
    pub fn attached_prefix(&self, address: Ipv4Addr) -> Option<Ipv4Net> {
        let mask = self.subnet_mask?;
        let bits = u32::from(mask);
        // A mask must be contiguous. Anything else is not a prefix, and deriving one from
        // it would mean choosing which bits the server meant.
        if bits.leading_ones() + bits.trailing_zeros() != 32 {
            return None;
        }
        Ipv4Net::new(address, bits.leading_ones() as u8)
            .ok()
            .map(|net| net.trunc())
    }

    /// Whether the classless routes supersede option 3 (RFC 3442 §6).
    ///
    /// "If the DHCP server returns both a Classless Static Routes option and a Router
    /// option, the DHCP client MUST ignore the Router option." Reporting both as effective
    /// default routes would describe a forwarding decision the client never makes.
    pub fn classless_routes_supersede_router_option(&self) -> bool {
        !self.classless_routes.is_empty() && !self.routers.is_empty()
    }
}

/// The outcome of one INFORM.
pub type DhcpOutcome = AttemptOutcome<Vec<DhcpDisclosure>>;

/// Builds a DHCPINFORM for this client.
///
/// INFORM rather than DISCOVER or REQUEST: it asks for configuration for an address the
/// client already has, so no lease is offered, none is claimed, and the server's own
/// bookkeeping is untouched.
pub fn inform(transaction: u32, client: Ipv4Addr, mac: [u8; 6]) -> Vec<u8> {
    let mut message = vec![0u8; BOOTP_HEADER_LEN];
    message[0] = BOOTREQUEST;
    message[1] = 1; // htype: Ethernet
    message[2] = 6; // hlen
    message[3] = 0; // hops
    message[4..8].copy_from_slice(&transaction.to_be_bytes());
    // secs and flags stay zero: a unicast reply is wanted, and this client is not booting.
    message[12..16].copy_from_slice(&client.octets()); // ciaddr: required for INFORM
    message[28..34].copy_from_slice(&mac);

    message.extend_from_slice(&MAGIC_COOKIE);
    message.extend_from_slice(&[OPTION_MESSAGE_TYPE, 1, DHCPINFORM]);
    // The client identifier is the hardware type and address, which is what the server
    // correlates its reply against.
    message.push(OPTION_CLIENT_IDENTIFIER);
    message.push(7);
    message.push(1);
    message.extend_from_slice(&mac);
    message.extend_from_slice(&[
        OPTION_PARAMETER_REQUEST,
        4,
        OPTION_SUBNET_MASK,
        OPTION_ROUTER,
        OPTION_CLASSLESS_ROUTE,
        OPTION_MS_CLASSLESS_ROUTE,
    ]);
    message.push(OPTION_END);
    message
}

/// Validates a reply as the answer to our INFORM and decodes what it disclosed.
///
/// Correlation is by transaction id, client hardware address and message type together. Any
/// one of them alone would accept another client's exchange on a link where several are
/// running: DHCP replies are frequently broadcast.
pub fn parse_reply(
    datagram: &[u8],
    transaction: u32,
    mac: [u8; 6],
    server: Ipv4Addr,
) -> Option<DhcpDisclosure> {
    if datagram.len() < BOOTP_HEADER_LEN + 4 {
        return None;
    }
    if datagram[0] != BOOTREPLY {
        return None;
    }
    if u32::from_be_bytes(datagram[4..8].try_into().ok()?) != transaction {
        return None;
    }
    if datagram[28..34] != mac {
        return None;
    }
    if datagram[BOOTP_HEADER_LEN..BOOTP_HEADER_LEN + 4] != MAGIC_COOKIE {
        return None;
    }

    let mut disclosure = DhcpDisclosure {
        server,
        subnet_mask: None,
        routers: Vec::new(),
        classless_routes: Vec::new(),
        raw: datagram.to_vec(),
    };
    let mut message_type = None;

    let options = &datagram[BOOTP_HEADER_LEN + 4..];
    let mut cursor = 0;
    while cursor < options.len() {
        let code = options[cursor];
        if code == OPTION_END {
            break;
        }
        // Pad option, which carries no length byte.
        if code == 0 {
            cursor += 1;
            continue;
        }
        let length = *options.get(cursor + 1)?;
        let start = cursor + 2;
        let end = start + length as usize;
        if end > options.len() {
            // An option claiming more bytes than arrived: the datagram is truncated, and
            // reading past it would take facts from whatever follows.
            return None;
        }
        let value = &options[start..end];

        match code {
            OPTION_MESSAGE_TYPE if length == 1 => message_type = Some(value[0]),
            OPTION_SUBNET_MASK if length == 4 => {
                disclosure.subnet_mask =
                    Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            OPTION_ROUTER => {
                for router in value.as_chunks::<4>().0 {
                    let address = Ipv4Addr::new(router[0], router[1], router[2], router[3]);
                    if !address.is_unspecified() {
                        disclosure.routers.push(address);
                    }
                }
            }
            OPTION_CLASSLESS_ROUTE | OPTION_MS_CLASSLESS_ROUTE => {
                disclosure
                    .classless_routes
                    .extend(parse_classless_routes(value, code)?);
            }
            _ => {}
        }
        cursor = end;
    }

    // Only an ACK answers an INFORM. A NAK or an offer to some other client is not an
    // answer to this question.
    if message_type != Some(DHCPACK) {
        return None;
    }
    Some(disclosure)
}

/// Decodes the RFC 3442 destination descriptors in options 121 and 249.
///
/// Each entry is a mask width, then only the significant octets of the destination, then a
/// four-byte gateway. The whole option is refused when any entry is short: a partial parse
/// would report some of the operator's routes and silently drop the rest.
pub fn parse_classless_routes(value: &[u8], option: u8) -> Option<Vec<ClasslessRoute>> {
    let mut routes = Vec::new();
    let mut cursor = 0;

    while cursor < value.len() {
        let width = value[cursor];
        if width > 32 {
            return None;
        }
        let significant = width.div_ceil(8) as usize;
        let end = cursor + 1 + significant + 4;
        if end > value.len() {
            return None;
        }

        let mut destination = [0u8; 4];
        destination[..significant].copy_from_slice(&value[cursor + 1..cursor + 1 + significant]);
        let gateway = &value[cursor + 1 + significant..end];

        let prefix = Ipv4Net::new(Ipv4Addr::from(destination), width)
            .ok()?
            .trunc();
        routes.push(ClasslessRoute {
            prefix,
            next_hop: Ipv4Addr::new(gateway[0], gateway[1], gateway[2], gateway[3]),
            option,
            raw_entry: value[cursor..end].to_vec(),
        });
        cursor = end;
    }

    Some(routes)
}

/// Sends one DHCPINFORM from the selected interface and collects the replies.
///
/// Once per vantage, not once per device: an INFORM asks about this client's own link, and
/// asking repeatedly would put the same question to the same servers.
pub async fn ask(
    interface: &str,
    binding: &SocketBinding,
    client: Ipv4Addr,
    mac: [u8; 6],
    budget: Duration,
) -> DhcpOutcome {
    // Derived from the client's own identity and the clock, so two runs do not reuse one
    // transaction and a reply cannot be correlated to the wrong exchange.
    let transaction = {
        let seed = Instant::now().elapsed().as_nanos() as u32;
        let from_mac = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
        let from_clock = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.subsec_nanos())
            .unwrap_or(0);
        from_mac ^ from_clock ^ seed
    };

    let socket = match binding.udp_bound_v4(CLIENT_PORT).await {
        Ok(socket) => socket,
        Err(error) => {
            return AttemptOutcome::unavailable(format!(
                "UDP {CLIENT_PORT} could not be bound on {interface}: {error}"
            ));
        }
    };
    if let Err(error) = socket.set_broadcast(true) {
        return AttemptOutcome::not_sent(format!("broadcast could not be enabled: {error}"));
    }

    let message = inform(transaction, client, mac);
    let destination = SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT);
    if let Err(error) = socket.send_to(&message, destination).await {
        return AttemptOutcome::not_sent(format!("the INFORM could not be transmitted: {error}"));
    }

    let sent = format!(
        "DHCPINFORM from {client} requesting options {OPTION_SUBNET_MASK}, {OPTION_ROUTER}, \
         {OPTION_CLASSLESS_ROUTE}, {OPTION_MS_CLASSLESS_ROUTE}"
    );
    let deadline = tokio::time::Instant::now() + budget;
    let mut disclosures: Vec<DhcpDisclosure> = Vec::new();
    let mut rejected = 0usize;
    let mut buffer = vec![0u8; 1500];

    // Several servers may answer, and each answer is its own disclosure.
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let received = tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await;
        let Ok(Ok((length, from))) = received else {
            continue;
        };
        let std::net::SocketAddr::V4(from) = from else {
            continue;
        };

        match parse_reply(&buffer[..length], transaction, mac, *from.ip()) {
            Some(disclosure) => {
                if !disclosures
                    .iter()
                    .any(|seen| seen.server == disclosure.server)
                {
                    disclosures.push(disclosure);
                }
            }
            None => rejected += 1,
        }
    }

    if !disclosures.is_empty() {
        return AttemptOutcome::Answered {
            sent,
            result: disclosures,
        };
    }
    if rejected > 0 {
        return AttemptOutcome::InvalidResponse { sent, rejected };
    }
    AttemptOutcome::NoResponse { sent }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 119);
    const MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    fn reply(transaction: u32, mac: [u8; 6], options: &[u8]) -> Vec<u8> {
        let mut message = vec![0u8; BOOTP_HEADER_LEN];
        message[0] = BOOTREPLY;
        message[1] = 1;
        message[2] = 6;
        message[4..8].copy_from_slice(&transaction.to_be_bytes());
        message[28..34].copy_from_slice(&mac);
        message.extend_from_slice(&MAGIC_COOKIE);
        message.extend_from_slice(&[OPTION_MESSAGE_TYPE, 1, DHCPACK]);
        message.extend_from_slice(options);
        message.push(OPTION_END);
        message
    }

    #[test]
    fn the_inform_asks_for_the_four_options_and_claims_no_lease() {
        let message = inform(0x1234_5678, CLIENT, MAC);
        assert_eq!(message[0], BOOTREQUEST);
        assert_eq!(&message[4..8], &0x1234_5678u32.to_be_bytes());
        // ciaddr carries the address we already hold, which is what makes this an INFORM
        // rather than a request for one.
        assert_eq!(&message[12..16], &CLIENT.octets());
        assert_eq!(&message[28..34], &MAC);

        let options = &message[BOOTP_HEADER_LEN..];
        assert_eq!(&options[..4], &MAGIC_COOKIE);
        assert!(
            options
                .windows(3)
                .any(|w| w == [OPTION_MESSAGE_TYPE, 1, DHCPINFORM]),
            "the message type must be INFORM, which asks for configuration without a lease"
        );
        assert!(options.windows(6).any(|w| w
            == [
                OPTION_PARAMETER_REQUEST,
                4,
                OPTION_SUBNET_MASK,
                OPTION_ROUTER,
                OPTION_CLASSLESS_ROUTE,
                OPTION_MS_CLASSLESS_ROUTE
            ]));
    }

    #[test]
    fn a_mask_establishes_only_this_interfaces_own_prefix() {
        // Option 1 says how wide this link is. Combined with an address this machine holds,
        // that is one network; combined with anything else it is a guess.
        let message = reply(7, MAC, &[OPTION_SUBNET_MASK, 4, 255, 255, 255, 0]);
        let parsed = parse_reply(&message, 7, MAC, SERVER).expect("an ACK for our INFORM");
        assert_eq!(parsed.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(
            parsed.attached_prefix(CLIENT),
            Some("192.168.1.0/24".parse().unwrap())
        );

        // A non-contiguous mask is not a prefix, and choosing which bits were meant would
        // be inventing one.
        let broken = reply(7, MAC, &[OPTION_SUBNET_MASK, 4, 255, 0, 255, 0]);
        let parsed = parse_reply(&broken, 7, MAC, SERVER).expect("still an ACK");
        assert_eq!(parsed.attached_prefix(CLIENT), None);
    }

    #[test]
    fn a_router_address_is_a_device_and_never_a_network() {
        // The rule this encodes: option 3 names devices that route. Nothing about the
        // prefixes behind them is stated, and a /24 around a router's address would be
        // invented rather than disclosed.
        let message = reply(9, MAC, &[OPTION_ROUTER, 8, 192, 168, 1, 1, 192, 168, 1, 2]);
        let parsed = parse_reply(&message, 9, MAC, SERVER).expect("an ACK");
        assert_eq!(
            parsed.routers,
            vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)]
        );
        assert!(parsed.classless_routes.is_empty());
        assert!(parsed.subnet_mask.is_none());
        assert_eq!(
            parsed.attached_prefix(CLIENT),
            None,
            "a router option establishes no prefix at all"
        );
    }

    #[test]
    fn classless_routes_name_prefixes_beyond_this_link() {
        // 192.168.51.0/24 via 192.168.1.1, and the default route, in RFC 3442 form: mask
        // width, then only the significant destination octets, then the gateway.
        let value = [
            24, 192, 168, 51, 192, 168, 1, 1, // 192.168.51.0/24 via 192.168.1.1
            0, 192, 168, 1, 1, // 0.0.0.0/0 via 192.168.1.1
        ];
        let mut options = vec![OPTION_CLASSLESS_ROUTE, value.len() as u8];
        options.extend_from_slice(&value);
        let message = reply(11, MAC, &options);

        let parsed = parse_reply(&message, 11, MAC, SERVER).expect("an ACK");
        assert_eq!(parsed.classless_routes.len(), 2);

        let route = &parsed.classless_routes[0];
        assert_eq!(route.prefix, "192.168.51.0/24".parse::<Ipv4Net>().unwrap());
        assert_eq!(route.next_hop, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(route.option, OPTION_CLASSLESS_ROUTE);
        assert!(!route.is_default());
        // The bytes that stated it, kept so the prefix can be traced to the field.
        assert_eq!(route.evidence(), "18 c0 a8 33 c0 a8 01 01");

        assert!(parsed.classless_routes[1].is_default());
        assert_eq!(
            parsed.classless_routes[1].prefix,
            "0.0.0.0/0".parse::<Ipv4Net>().unwrap()
        );
    }

    #[test]
    fn microsofts_option_carries_the_same_encoding_and_is_labelled_as_its_own() {
        let value = [16, 10, 2, 10, 0, 0, 1];
        let mut options = vec![OPTION_MS_CLASSLESS_ROUTE, value.len() as u8];
        options.extend_from_slice(&value);
        let parsed = parse_reply(&reply(13, MAC, &options), 13, MAC, SERVER).expect("an ACK");

        assert_eq!(parsed.classless_routes.len(), 1);
        assert_eq!(
            parsed.classless_routes[0].prefix,
            "10.2.0.0/16".parse::<Ipv4Net>().unwrap()
        );
        assert_eq!(parsed.classless_routes[0].option, OPTION_MS_CLASSLESS_ROUTE);
    }

    #[test]
    fn classless_routes_supersede_the_router_option() {
        // RFC 3442 §6: a client receiving both MUST ignore the router option. Presenting
        // both as effective default routes would describe a decision no client makes.
        let mut options = vec![OPTION_ROUTER, 4, 192, 168, 1, 254];
        let value = [0u8, 192, 168, 1, 1];
        options.push(OPTION_CLASSLESS_ROUTE);
        options.push(value.len() as u8);
        options.extend_from_slice(&value);

        let parsed = parse_reply(&reply(15, MAC, &options), 15, MAC, SERVER).expect("an ACK");
        assert!(parsed.classless_routes_supersede_router_option());
        // Both are still recorded: what the server said is preserved, and only the
        // interpretation is constrained.
        assert_eq!(parsed.routers, vec![Ipv4Addr::new(192, 168, 1, 254)]);
        assert_eq!(parsed.classless_routes.len(), 1);

        let routers_only = parse_reply(
            &reply(16, MAC, &[OPTION_ROUTER, 4, 192, 168, 1, 254]),
            16,
            MAC,
            SERVER,
        )
        .expect("an ACK");
        assert!(!routers_only.classless_routes_supersede_router_option());
    }

    #[test]
    fn a_reply_to_another_exchange_is_not_our_answer() {
        let options = [OPTION_SUBNET_MASK, 4, 255, 255, 255, 0];
        let message = reply(21, MAC, &options);

        // Another client's transaction.
        assert!(parse_reply(&message, 22, MAC, SERVER).is_none());
        // Another client's hardware address: DHCP replies are frequently broadcast, so this
        // is the ordinary case on a busy link rather than an exotic one.
        assert!(parse_reply(&message, 21, [0x02, 0, 0, 0, 0, 0x99], SERVER).is_none());

        // A request looped back is not a reply.
        let mut request = message.clone();
        request[0] = BOOTREQUEST;
        assert!(parse_reply(&request, 21, MAC, SERVER).is_none());

        // Only an ACK answers an INFORM.
        let mut nak = vec![0u8; BOOTP_HEADER_LEN];
        nak[0] = BOOTREPLY;
        nak[4..8].copy_from_slice(&21u32.to_be_bytes());
        nak[28..34].copy_from_slice(&MAC);
        nak.extend_from_slice(&MAGIC_COOKIE);
        nak.extend_from_slice(&[OPTION_MESSAGE_TYPE, 1, 6]); // DHCPNAK
        nak.push(OPTION_END);
        assert!(parse_reply(&nak, 21, MAC, SERVER).is_none());
    }

    #[test]
    fn a_truncated_or_lying_option_discards_the_message_rather_than_half_of_it() {
        // A partial parse would report some of the operator's routes and drop the rest,
        // which is worse than reporting none: the map would look complete.
        let mut options = vec![OPTION_CLASSLESS_ROUTE, 8, 24, 192, 168, 51]; // gateway missing
        options.extend_from_slice(&[192, 168]);
        assert!(parse_reply(&reply(31, MAC, &options), 31, MAC, SERVER).is_none());

        // An option claiming more bytes than arrived.
        let overrun = vec![OPTION_SUBNET_MASK, 8, 255, 255];
        assert!(parse_reply(&reply(32, MAC, &overrun), 32, MAC, SERVER).is_none());

        // A prefix width beyond /32.
        assert!(
            parse_classless_routes(&[33, 10, 0, 0, 1, 0, 0, 0], OPTION_CLASSLESS_ROUTE).is_none()
        );

        // Truncated at every length, the message never parses into something usable.
        let full = reply(33, MAC, &[OPTION_SUBNET_MASK, 4, 255, 255, 255, 0]);
        for length in 0..full.len() {
            let _ = parse_reply(&full[..length], 33, MAC, SERVER);
        }
    }
}
