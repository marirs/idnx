//! Plaintext HTTP identity probe.
//!
//! An open port on 80 or 8080 says only that something accepted a connection. What the
//! server puts in its status line, `Server` header, `WWW-Authenticate` challenge and page
//! title is the device describing itself, and it is often the only identity a consumer
//! router or an appliance discloses without credentials.
//!
//! Deliberately plaintext only. There is no TLS client here, and pretending to have probed
//! an HTTPS port would report coverage that never happened; TLS ports are identified from
//! their certificate instead.

use std::time::Duration;

use crate::net::endpoint::Endpoint;
use crate::net::socket::SocketBinding;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Ports worth asking for an HTTP response.
pub const HTTP_PORTS: &[u16] = &[80, 81, 8000, 8008, 8080, 8081, 8123, 8181, 8888, 10000];

/// What a server disclosed about itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpIdentity {
    /// Status code from the response line.
    pub status: u16,
    /// `Server` header, when sent.
    pub server: Option<String>,
    /// `WWW-Authenticate` challenge, when the server demanded credentials.
    pub authenticate: Option<String>,
    /// Contents of `<title>`, when the body carried one.
    pub title: Option<String>,
    /// Prefixes found in the body, each with the semantics the page gave it.
    ///
    /// A candidate is not a network. Only those the page labelled as its own addressing
    /// may be promoted, and the rest are reported as candidates and left alone.
    pub prefixes: Vec<PrefixCandidate>,
    /// Where this response redirected, if it did. Overwritten on each hop by design: it
    /// describes *this* response, and the chain is kept separately.
    pub redirect_target: Option<String>,
    /// Every redirect followed to reach this response, in order.
    ///
    /// Tracked apart from `redirect_target`, which the final response clears -- so a
    /// successfully followed redirect was being reported as though none had happened.
    pub redirect_chain: Vec<String>,
    /// Links the document published, as written.
    ///
    /// Kept so a bounded audit can read what the device offers rather than guessing at
    /// paths. They are raw attribute values here: whether any of them is same-origin, and
    /// whether it is read-only, is decided by the caller and not by this parser.
    pub links: Vec<String>,
    /// A redirect that was not followed, and why.
    ///
    /// An HTTPS target is the common case: same origin includes the scheme, and following
    /// it over plaintext would be talking a different protocol to a different port and
    /// calling the result the same page.
    pub redirect_declined: Option<String>,
}

impl HttpIdentity {
    /// Whether the server refused without credentials.
    ///
    /// Distinguishing this from silence matters: an authenticated management interface is
    /// a positive finding about the device, not an absence of one.
    pub fn requires_authentication(&self) -> bool {
        self.status == 401 || self.status == 407 || self.authenticate.is_some()
    }

    /// A one-line summary, or `None` when the server disclosed nothing beyond a status.
    pub fn description(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(server) = &self.server {
            parts.push(format!("server {server}"));
        }
        if let Some(title) = &self.title {
            parts.push(format!("title \"{title}\""));
        }
        if self.requires_authentication() {
            parts.push("authentication required".to_string());
        }
        (!parts.is_empty()).then(|| format!("HTTP {}: {}", self.status, parts.join(", ")))
    }
}

/// What a page's own structure says a prefix is.
///
/// The distinction that decides whether a network may be created. A CIDR appearing
/// somewhere in HTML or JavaScript is not topology: it is as likely to be example text, an
/// access list, a VPN pool, a validation constant or a stale form default. Only a page that
/// labels the value as its own addressing has stated a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixSemantics {
    /// An interface or LAN address together with its mask, in one structured field.
    ///
    /// Proves the device is attached to that network. It says nothing about routing.
    InterfaceAddress,
    /// A route destination and mask, in a routing-table row.
    ///
    /// Proves the device routes toward the network.
    RouteDestination,
    /// A prefix with no semantics the page attached to it.
    ///
    /// Recorded as a candidate and never promoted. This is where a documentation literal
    /// such as `192.168.51.0/24` ends up, and turning one into a network would fabricate
    /// exactly the topology this tool exists to avoid inventing.
    Unlabelled,
}

impl PrefixSemantics {
    /// Whether this is enough to create a network node.
    pub fn establishes_network(&self) -> bool {
        matches!(
            self,
            PrefixSemantics::InterfaceAddress | PrefixSemantics::RouteDestination
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            PrefixSemantics::InterfaceAddress => "interface address and mask",
            PrefixSemantics::RouteDestination => "route destination and mask",
            PrefixSemantics::Unlabelled => "unlabelled prefix (candidate only)",
        }
    }
}

/// A prefix found in a response, with what the page said about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixCandidate {
    pub prefix: ipnet::IpNet,
    pub semantics: PrefixSemantics,
    /// The structured unit it was found in -- one table row, one object, one element --
    /// clipped for display. Kept so a promotion can be argued with rather than trusted.
    pub context: String,
    /// The exact text that produced the prefix.
    pub source_text: String,
}

impl PrefixCandidate {
    /// One line for the evidence trail.
    pub fn evidence(&self) -> String {
        format!(
            "{}: {:?} in {:?}",
            self.semantics.label(),
            crate::text::clip(&self.source_text, 60),
            crate::text::clip(&self.context, 160)
        )
    }
}

/// Words a page uses when it is describing its own attached addressing.
const INTERFACE_LABELS: &[&str] = &[
    "lan subnet",
    "lan network",
    "lan ip",
    "lan address",
    "interface address",
    "ip address",
    "ipaddr",
    "inet addr",
    "local address",
];

/// Words that identify a mask field.
const MASK_LABELS: &[&str] = &[
    "netmask",
    "subnet mask",
    "subnetmask",
    "subnet_mask",
    "prefix length",
    "prefixlen",
];

/// The field that names what a route is *for*.
///
/// Necessary and nowhere near sufficient. An access list, a firewall rule and a NAT policy
/// all have a destination, and a row reading "Destination 10.0.0.0/8 -- Deny" describes
/// traffic being dropped rather than a network being routed to.
const DESTINATION_LABELS: &[&str] = &["destination", "dest network", "dest addr", "dest ip"];

/// Words that place a destination in a routing table specifically.
///
/// A routing table names where traffic goes next. A filter table names what happens to it.
/// Both have destinations, and only the first is topology.
const ROUTE_CONTEXT: &[&str] = &[
    "routing table",
    "route table",
    "route entry",
    "static route",
    "next hop",
    "nexthop",
    "gateway",
    "metric",
];

/// Contexts in which a destination is a rule about traffic, not a route to a network.
///
/// Promotion is refused outright here, even where routing words also appear: a firewall
/// page mentioning a gateway does not turn its deny list into a routing table, and the cost
/// of being wrong is a fabricated network.
const POLICY_CONTEXT: &[&str] = &[
    "acl",
    "access list",
    "access-list",
    "firewall",
    "policy",
    "filter",
    "nat",
    "port forward",
    "vpn",
    "tunnel",
    "deny",
    "permit",
    "allow",
    "block",
    "rule",
];

/// Words that mark text as illustrative rather than a statement about this device.
const EXAMPLE_MARKERS: &[&str] = &[
    "example",
    "e g",
    "for instance",
    "such as",
    "placeholder",
    "default is",
    "defaults to",
    "sample",
    "must be in the form",
    "in the form",
    "format",
    "enter a",
    "enter the",
];

/// Extracts prefix candidates from a response body, with the semantics the page gave them.
///
/// Generic parsing only. Scripts, styles and comments are removed first: a value inside
/// them is a program's constant, not a rendered statement about this device, and the router
/// this was written against keeps its own address in a `<script>` variable precisely
/// because it is not page content. A vendor adapter that knows a documented configuration
/// format may parse these; nothing generic should.
pub fn prefix_candidates(body: &str) -> Vec<PrefixCandidate> {
    let visible = strip_non_content(body);
    let mut out: Vec<PrefixCandidate> = Vec::new();

    for unit in structured_units(&visible) {
        if is_illustrative(&unit) {
            continue;
        }
        for candidate in candidates_in_unit(&unit) {
            push_unique(&mut out, candidate);
        }
    }

    out
}

/// Removes everything that is not rendered content.
fn strip_non_content(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let lowered = body.to_ascii_lowercase();
    let mut index = 0usize;

    while index < body.len() {
        // Comments and the two element bodies that are code rather than text.
        let skip_to = [
            ("<!--", "-->"),
            ("<script", "</script>"),
            ("<style", "</style>"),
        ]
        .iter()
        .find_map(|(open, close)| {
            lowered[index..].starts_with(open).then(|| {
                lowered[index..]
                    .find(close)
                    .map(|end| index + end + close.len())
                    .unwrap_or(body.len())
            })
        });

        if let Some(end) = skip_to {
            // Replaced by a separator, so removing a block cannot join two unrelated
            // fields into one apparent unit.
            out.push('\n');
            index = end;
            continue;
        }

        let ch = body[index..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

/// Splits content into the units a value and its label can share.
///
/// A table row, a JSON or XML object, a form field, or failing those a line. The unit is
/// the whole basis for pairing: a mask two hundred characters away from an address is not
/// in the same field, and treating a sliding window as one let unrelated values be married
/// into a network nobody described.
fn structured_units(content: &str) -> Vec<String> {
    let lowered = content.to_ascii_lowercase();
    let mut units: Vec<String> = Vec::new();
    // Regions already claimed by a structured unit. Line splitting must skip them: a
    // document whose rows are all on one line was being treated as a single field, which
    // paired an address in one row with a mask in the next.
    let mut claimed: Vec<(usize, usize)> = Vec::new();

    // Table rows first, since that is how nearly every appliance renders a status page.
    let mut index = 0usize;
    while let Some(found) = lowered[index..].find("<tr") {
        let start = index + found;
        let end = lowered[start..]
            .find("</tr>")
            .map(|e| start + e + 5)
            .unwrap_or(content.len());
        units.push(content[start..end].to_string());
        claimed.push((start, end));
        index = end;
        if index >= content.len() {
            break;
        }
    }

    // Shallow JSON and XML objects.
    for (start, end, text) in balanced_units(content, '{', '}') {
        units.push(text);
        claimed.push((start, end));
    }

    // Whatever is left, by line. A line is a unit in plain-text and form-encoded output,
    // but only the part of it no structured unit already covers.
    let mut offset = 0usize;
    for line in content.split_inclusive('\n') {
        let (start, end) = (offset, offset + line.len());
        offset = end;
        if claimed.iter().any(|(from, to)| *from < end && start < *to) {
            continue;
        }
        units.push(line.to_string());
    }
    units
}

/// Extracts balanced, non-nested regions between two delimiters.
fn balanced_units(content: &str, open: char, close: char) -> Vec<(usize, usize, String)> {
    let mut units = Vec::new();
    let mut start: Option<usize> = None;
    let mut depth = 0usize;

    for (index, ch) in content.char_indices() {
        if ch == open {
            if depth == 0 {
                start = Some(index);
            }
            depth += 1;
        } else if ch == close && depth > 0 {
            depth -= 1;
            if depth == 0
                && let Some(from) = start.take()
                && let Some(text) = content.get(from..index + close.len_utf8())
                // Bounded: a whole document wrapped in braces is not one field.
                && text.len() <= 512
            {
                units.push((from, index + close.len_utf8(), text.to_string()));
            }
        }
    }
    units
}

/// Whether a sequence of whole words appears in order.
///
/// A phrase matches only at word boundaries. Substring matching is wrong here in both
/// directions: "destination" contains "nat", and "netmasks" should still match "netmask".
/// The second is handled by comparing word stems rather than by widening the match.
fn contains_phrase(words: &[&str], phrase: &str) -> bool {
    let needle: Vec<&str> = phrase.split_whitespace().collect();
    if needle.is_empty() {
        return false;
    }
    words.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(word, target)| word_matches(word, target))
    })
}

/// Whether one word is the label, allowing for a trailing plural.
///
/// The text has already been reduced to words of letters and digits, so no trimming is
/// needed here -- only "netmasks" matching "netmask".
fn word_matches(word: &str, target: &str) -> bool {
    word == target || word.strip_suffix('s') == Some(target)
}

/// Normalises a unit for label matching.
///
/// Field names arrive as `lan_ip`, `lan-ip`, `LanIP` and `LAN IP` and all mean the same
/// thing, so separators become spaces and camel case is split. Matching the raw text missed
/// every form but one, which meant a JSON body naming its own LAN address went unrecognised.
fn label_form(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let mut previous_alnum = false;
    // Whether the previous character was lowercase *before* being folded. Deciding this
    // from the folded output split every acronym: `IP` became `i p`, so "ip address" could
    // never match.
    let mut previous_lower = false;
    let mut in_tag = false;

    for ch in text.chars() {
        // Markup separates fields; it does not join them.
        if ch == '<' {
            in_tag = true;
        }
        if in_tag {
            if ch == '>' {
                in_tag = false;
            }
            if previous_alnum {
                out.push(' ');
            }
            previous_alnum = false;
            previous_lower = false;
            continue;
        }

        // Everything that is not a letter or a digit is a separator: quotes, colons,
        // underscores and dots all divide fields, and leaving any of them attached meant no
        // whole-word label could match.
        if !ch.is_ascii_alphanumeric() {
            if previous_alnum {
                out.push(' ');
            }
            previous_alnum = false;
            previous_lower = false;
            continue;
        }

        // camelCase is two words: `lanIp` names the same field as `lan_ip`.
        if ch.is_ascii_uppercase() && previous_lower {
            out.push(' ');
        }
        out.push(ch.to_ascii_lowercase());
        previous_alnum = true;
        previous_lower = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }
    out
}
/// Whether a unit is illustrating a format rather than stating this device's addressing.
fn is_illustrative(unit: &str) -> bool {
    let lowered = label_form(unit);
    EXAMPLE_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

/// Finds prefixes inside one structured unit and decides what the unit says about them.
fn candidates_in_unit(unit: &str) -> Vec<PrefixCandidate> {
    let text = unescape_hex(unit);
    let lowered = label_form(&text);
    let mut out = Vec::new();

    // Word boundaries, not substrings. "destination" contains "nat", so raw substring
    // matching classified every routing table as a NAT policy and refused to promote any
    // of it -- and the same trap catches "allow" in "allowed", "rule" in "ruleset" and so
    // on. Labels are phrases of whole words.
    let words: Vec<&str> = lowered.split_whitespace().collect();
    let has = |labels: &[&str]| labels.iter().any(|label| contains_phrase(&words, label));

    // A mask label is not a claim about anything. It says a field holds a mask, not what
    // the address beside it is -- so on its own it decides nothing, and treating it as
    // evidence of attachment promoted any unit that happened to mention one.
    let mask_labelled = has(MASK_LABELS);

    // A rule about traffic is never a route to a network, whatever else the page says.
    let policy = has(POLICY_CONTEXT);

    let interface_labelled = has(INTERFACE_LABELS) && !policy;
    // Both halves, and neither is enough alone: a destination field, and something placing
    // it in a routing table rather than a filter table.
    let route_labelled = has(DESTINATION_LABELS) && has(ROUTE_CONTEXT) && !policy;

    // A CIDR literal in a unit that names what it is.
    for token in tokens(&text) {
        if !token.contains('/') {
            continue;
        }
        let Ok(network) = token.parse::<ipnet::IpNet>() else {
            continue;
        };
        if network.prefix_len() == network.max_prefix_len() {
            continue;
        }
        let semantics = if interface_labelled {
            PrefixSemantics::InterfaceAddress
        } else if route_labelled {
            PrefixSemantics::RouteDestination
        } else {
            // Including every uncertain case. A prefix whose meaning the page did not state
            // is kept as a candidate rather than guessed at.
            PrefixSemantics::Unlabelled
        };
        out.push(PrefixCandidate {
            prefix: network.trunc(),
            semantics,
            context: text.clone(),
            source_text: token.to_string(),
        });
    }

    // An address and a mask in the same unit. The mask lets a prefix be computed; what the
    // prefix *means* still comes from the unit's own labels, and where it says neither the
    // result is a candidate.
    if mask_labelled {
        let semantics = if interface_labelled {
            PrefixSemantics::InterfaceAddress
        } else if route_labelled {
            PrefixSemantics::RouteDestination
        } else {
            PrefixSemantics::Unlabelled
        };
        if let Some(candidate) = address_and_mask(&text, semantics) {
            out.push(candidate);
        }
    }

    out
}

/// Pairs an address with a mask inside one unit, under semantics the caller decided.
fn address_and_mask(text: &str, semantics: PrefixSemantics) -> Option<PrefixCandidate> {
    let quads: Vec<std::net::Ipv4Addr> = tokens(text)
        .iter()
        .filter_map(|t| t.parse::<std::net::Ipv4Addr>().ok())
        .collect();

    let mask = quads.iter().copied().find(is_contiguous_mask)?;
    let address = quads.iter().copied().find(|a| !is_contiguous_mask(a))?;
    let length = u32::from_be_bytes(mask.octets()).leading_ones() as u8;
    let network = ipnet::Ipv4Net::new(address, length).ok()?;

    Some(PrefixCandidate {
        prefix: ipnet::IpNet::V4(network.trunc()),
        semantics,
        context: text.to_string(),
        source_text: format!("{address} mask {mask}"),
    })
}

/// Splits text into address-shaped tokens.
///
/// Hexadecimal digits and colons are included, without which no IPv6 literal could ever be
/// extracted -- the earlier tokenizer made IPv6 prefixes impossible to find at all.
fn tokens(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':' || c == '/'))
        .filter(|t| !t.is_empty())
        .collect()
}

fn push_unique(out: &mut Vec<PrefixCandidate>, candidate: PrefixCandidate) {
    match out
        .iter_mut()
        .find(|existing| existing.prefix == candidate.prefix)
    {
        // The strongest statement about a prefix wins: a page may mention it in passing and
        // also state it properly, and the proper statement is the one that counts.
        Some(existing) => {
            if candidate.semantics.establishes_network()
                && !existing.semantics.establishes_network()
            {
                *existing = candidate;
            }
        }
        None => out.push(candidate),
    }
}

/// Whether a dotted quad is a contiguous netmask.
fn is_contiguous_mask(address: &std::net::Ipv4Addr) -> bool {
    let bits = u32::from_be_bytes(address.octets());
    // 0.0.0.0 is a legal mask but is also every unset field on a page, so it is not taken
    // as one.
    bits != 0 && bits.leading_ones() + bits.trailing_zeros() == 32
}

/// Undoes `\xNN` escaping, which web interfaces use to keep addresses out of page source.
fn unescape_hex(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'\\'
            && bytes.get(index + 1) == Some(&b'x')
            && let Some(pair) = text.get(index + 2..index + 4)
            && let Ok(byte) = u8::from_str_radix(pair, 16)
            && byte.is_ascii()
        {
            out.push(byte as char);
            index += 4;
            continue;
        }
        let ch = text[index..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

/// Parses a response far enough to identify the server.
///
/// Tolerant by design: appliance web servers are frequently non-conformant, and a malformed
/// header must lose only that header rather than the whole response.
pub fn parse_http_identity(response: &str) -> Option<HttpIdentity> {
    let mut lines = response.split("\r\n");
    let status_line = lines.next()?;
    if !status_line.starts_with("HTTP/") {
        return None;
    }
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut identity = HttpIdentity {
        status,
        ..Default::default()
    };

    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }
        match name.trim().to_ascii_lowercase().as_str() {
            "server" => identity.server = Some(value),
            "www-authenticate" => identity.authenticate = Some(value),
            "location" => identity.redirect_target = Some(value),
            _ => {}
        }
    }

    identity.title = extract_title(response);
    identity.links = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| document_links(body))
        .unwrap_or_default();
    // Only the body: a header value is never a topology statement, and scanning them would
    // read a Content-Security-Policy or a cookie path as addressing.
    identity.prefixes = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| prefix_candidates(body))
        .unwrap_or_default();
    Some(identity)
}

/// Every `href` and `src` value a document carries, in the order it wrote them.
///
/// Deliberately dumb: it extracts, and decides nothing. Whether a link is on this origin,
/// whether it is safe to fetch, and whether it is worth fetching are the auditor's
/// decisions, and keeping them out of here means the extraction cannot quietly widen.
pub fn document_links(body: &str) -> Vec<String> {
    let mut links = Vec::new();
    let lower = body.to_ascii_lowercase();

    for attribute in ["href=", "src="] {
        let mut at = 0;
        while let Some(found) = lower[at..].find(attribute) {
            let start = at + found + attribute.len();
            at = start;
            let rest = &body[start.min(body.len())..];
            let Some(quote) = rest.chars().next() else {
                break;
            };
            // Unquoted attribute values are ambiguous to delimit; skipping one loses a
            // link, and mis-delimiting one invents a URL.
            if quote != '"' && quote != '\'' {
                continue;
            }
            let Some(end) = rest[1..].find(quote) else {
                continue;
            };
            let value = rest[1..1 + end].trim();
            if !value.is_empty() && links.len() < 200 {
                links.push(value.to_string());
            }
            at = start + 1 + end;
        }
    }

    links
}

/// Extracts `<title>` from a body, if any.
fn extract_title(response: &str) -> Option<String> {
    let lower = response.to_ascii_lowercase();
    let open = lower.find("<title")?;
    let start = lower[open..].find('>')? + open + 1;
    let end = lower[start..].find("</title>")? + start;
    let title = response[start..end].trim();
    // Long or empty titles are markup accidents rather than a device name.
    (!title.is_empty() && title.len() <= 120).then(|| title.to_string())
}

/// Asks one plaintext HTTP port to identify itself.
pub async fn probe_http(
    target: &Endpoint,
    port: u16,
    binding: &SocketBinding,
    timeout_duration: Duration,
) -> Option<HttpIdentity> {
    probe_http_path(target, port, "/", binding, timeout_duration).await
}

/// Reads one path.
pub async fn probe_http_path(
    target: &Endpoint,
    port: u16,
    path: &str,
    binding: &SocketBinding,
    timeout_duration: Duration,
) -> Option<HttpIdentity> {
    let mut stream = binding
        .tcp_connect(target.socket_addr(port), timeout_duration)
        .await
        .ok()?;

    // HEAD would skip the body, and with it the page title that most often carries the
    // model name. `Connection: close` keeps the read from waiting on keep-alive.
    // An IPv6 literal must be bracketed in a Host header, and the zone must not appear in
    // it: a server parsing "fe80::1%en0" as a host name rejects the request.
    let host = target.host_literal();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: idnx\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    timeout(timeout_duration, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    // Bounded: enough for headers and a title, never enough for a page to exhaust memory.
    let mut buf = vec![0u8; 8192];
    let mut filled = 0usize;
    while filled < buf.len() {
        let read = match timeout(timeout_duration, stream.read(&mut buf[filled..])).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break,
        };
        filled += read;
    }
    if filled == 0 {
        return None;
    }

    parse_http_identity(&String::from_utf8_lossy(&buf[..filled]))
}

/// How many redirects to follow.
///
/// Appliances redirect `/` to a login page once, occasionally twice. More than that is a
/// loop or a device sending us somewhere we did not ask to go.
const MAX_REDIRECTS: usize = 3;

/// Reads a device's HTTP identity, following redirects that stay on the same origin.
///
/// Same-origin only, and by path. A redirect to another host is the device pointing at
/// something else -- possibly a name that resolves anywhere at all -- and following it would
/// mean probing a machine this run never discovered and attributing the answer to one it
/// did.
pub async fn identify(
    target: &Endpoint,
    port: u16,
    binding: &SocketBinding,
    timeout_duration: Duration,
) -> Option<HttpIdentity> {
    let mut path = "/".to_string();
    let mut identity = probe_http_path(target, port, &path, binding, timeout_duration).await?;
    let mut chain: Vec<String> = Vec::new();
    let mut declined: Option<String> = None;

    for _ in 0..MAX_REDIRECTS {
        let Some(next) = identity.redirect_target.clone() else {
            break;
        };
        match same_origin_path(&next, target, port) {
            Ok(next_path) => {
                if next_path == path {
                    break;
                }
                let Some(followed) =
                    probe_http_path(target, port, &next_path, binding, timeout_duration).await
                else {
                    break;
                };
                chain.push(next_path.clone());
                path = next_path;
                identity = followed;
            }
            Err(reason) => {
                declined = Some(format!("{next}: {reason}"));
                break;
            }
        }
    }

    identity.redirect_chain = chain;
    identity.redirect_declined = declined;
    Some(identity)
}

/// The path a redirect points to, when it stays on this origin.
///
/// Same origin means scheme, host and port. The scheme matters as much as the host: this
/// probe speaks plaintext HTTP, and following an `https://` redirect over it would be
/// talking a different protocol to a different port and calling the result the same page.
/// Such a redirect is reported instead, with the reason.
pub fn same_origin_path(
    location: &str,
    target: &Endpoint,
    port: u16,
) -> Result<String, &'static str> {
    let location = location.trim();
    if location.is_empty() {
        return Err("empty Location");
    }
    // A protocol-relative URL looks like a path and is not one: `//host/path` names
    // another host, and treating it as relative would follow the device anywhere.
    if location.starts_with("//") {
        return Err("protocol-relative, names another origin");
    }
    // A genuinely relative redirect is by definition on this origin and scheme.
    if location.starts_with('/') {
        return Ok(location.to_string());
    }

    if location.starts_with("https://") {
        return Err("HTTPS, not followed by a plaintext probe");
    }
    let rest = location
        .strip_prefix("http://")
        .ok_or("not an absolute HTTP URL")?;

    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    // Strip any credentials the device put in the URL; they are not ours to send anywhere.
    let authority = authority.rsplit('@').next().unwrap_or(authority);

    let expected_host = target.host_literal();
    let matches = authority == expected_host
        || authority == format!("{expected_host}:{port}")
        || authority == format!("{}", target.address)
        || authority == format!("{}:{port}", target.address);

    if matches {
        Ok(path)
    } else {
        Err("different host or port")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_header_and_title_identify_the_device() {
        let response = "HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.39\r\nContent-Type: text/html\r\n\r\n<html><head><title>RT-AX88U Login</title></head></html>";
        let identity = parse_http_identity(response).expect("parsed");
        assert_eq!(identity.status, 200);
        assert_eq!(identity.server.as_deref(), Some("lighttpd/1.4.39"));
        assert_eq!(identity.title.as_deref(), Some("RT-AX88U Login"));
        assert!(!identity.requires_authentication());
    }

    #[test]
    fn an_authentication_challenge_is_a_positive_finding() {
        // A management interface that demands credentials tells us more than silence does.
        let response =
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"index\"\r\n\r\n";
        let identity = parse_http_identity(response).expect("parsed");
        assert_eq!(identity.status, 401);
        assert!(identity.requires_authentication());
        assert!(
            identity
                .description()
                .expect("described")
                .contains("authentication required")
        );
    }

    #[test]
    fn a_response_disclosing_nothing_has_no_description() {
        let identity = parse_http_identity("HTTP/1.0 200 OK\r\n\r\n").expect("parsed");
        assert_eq!(identity.status, 200);
        assert!(identity.description().is_none());
    }

    #[test]
    fn a_redirect_is_followed_only_within_the_same_origin() {
        // Origin includes the scheme. This probe speaks plaintext, so following an HTTPS
        // redirect over it would be talking a different protocol to a different port and
        // calling the result the same page.
        let target = Endpoint::global("192.168.70.1".parse().unwrap());

        assert_eq!(
            same_origin_path("/login.html", &target, 80),
            Ok("/login.html".to_string())
        );
        assert_eq!(
            same_origin_path("http://192.168.70.1/index.html", &target, 80),
            Ok("/index.html".to_string())
        );

        // Elsewhere, in every disguise.
        assert!(same_origin_path("https://192.168.70.1/", &target, 80).is_err());
        assert!(same_origin_path("http://evil.example/", &target, 80).is_err());
        assert!(same_origin_path("http://192.168.70.2/", &target, 80).is_err());
        assert!(same_origin_path("http://192.168.70.1@evil.example/", &target, 80).is_err());
        assert!(same_origin_path("//evil.example/", &target, 80).is_err());
        assert!(same_origin_path("", &target, 80).is_err());
    }

    #[test]
    fn a_prefix_is_taken_from_the_body_and_not_from_headers() {
        // A Content-Security-Policy or a cookie path is not a topology statement.
        let response = "HTTP/1.1 200 OK\r\nX-Net: 10.9.0.0/16\r\n\r\n<tr><td>LAN Subnet</td><td>192.168.51.0/24</td></tr>";
        let identity = parse_http_identity(response).expect("parsed");
        assert_eq!(identity.prefixes.len(), 1);
        assert_eq!(identity.prefixes[0].prefix.to_string(), "192.168.51.0/24");
    }

    #[test]
    fn a_prefix_with_no_semantics_is_a_candidate_and_never_a_network() {
        // The whole point. A CIDR in a page could be example text, an access list, a VPN
        // pool, a validation constant or a stale form default. Promoting one would
        // fabricate a network -- and 192.168.51.0/24 is precisely the literal that must not
        // become real by appearing in someone's documentation.
        for body in [
            "<p>Enter a network in the form 192.168.51.0/24</p>",
            "<td>Allowed clients</td><td>10.8.0.0/24</td>",
            "<li>VPN pool 172.16.9.0/24</li>",
        ] {
            for candidate in prefix_candidates(body) {
                assert!(
                    !candidate.semantics.establishes_network(),
                    "{body} promoted {:?}",
                    candidate
                );
            }
        }
    }

    #[test]
    fn illustrative_text_is_not_read_as_a_statement() {
        for body in [
            "<tr><td>LAN Subnet</td><td>for example 192.168.51.0/24</td></tr>",
            "<tr><td>Netmask</td><td>e.g. 255.255.255.0 with 192.168.51.1</td></tr>",
            "<tr><td>IP Address</td><td>default is 192.168.51.1, netmask 255.255.255.0</td></tr>",
        ] {
            assert!(prefix_candidates(body).is_empty(), "{body}");
        }
    }

    #[test]
    fn an_interface_address_and_mask_prove_attachment_not_routing() {
        // Two different claims. Emitting a route for every prefix a page mentions asserted
        // routing the device never described.
        let body = "<tr><td>IP Address</td><td>192.168.51.1</td><td>Subnet Mask</td><td>255.255.255.0</td></tr>";
        let found = prefix_candidates(body);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].prefix.to_string(), "192.168.51.0/24");
        assert_eq!(found[0].semantics, PrefixSemantics::InterfaceAddress);
        assert!(found[0].semantics.establishes_network());
    }

    #[test]
    fn a_routing_table_row_proves_routing() {
        // A real routing table names where traffic goes next. A destination alone does not:
        // every filter table has one too.
        let body = "<tr><td>Destination</td><td>10.9.0.0</td><td>Netmask</td><td>255.255.0.0</td><td>Gateway</td><td>192.168.70.2</td><td>Metric</td><td>1</td></tr>";
        let routed: Vec<_> = prefix_candidates(body)
            .into_iter()
            .filter(|c| c.semantics == PrefixSemantics::RouteDestination)
            .collect();
        assert_eq!(routed.len(), 1, "{routed:?}");
        assert_eq!(routed[0].prefix.to_string(), "10.9.0.0/16");
    }

    #[test]
    fn a_destination_without_routing_context_is_not_a_route() {
        // The hole this closes. A destination field appears in access lists, firewall
        // rules, NAT policies and port forwards, and none of them routes to a network.
        let body =
            "<tr><td>Destination</td><td>10.9.0.0</td><td>Netmask</td><td>255.255.0.0</td></tr>";
        for candidate in prefix_candidates(body) {
            assert!(!candidate.semantics.establishes_network(), "{candidate:?}");
        }
    }

    #[test]
    fn a_mask_and_an_address_must_share_a_structured_field() {
        // A sliding window married unrelated values into a network nobody described. The
        // unit is a table row, an object, or a line -- and two separate rows are two
        // separate statements.
        let separate = "<tr><td>WAN IP</td><td>192.168.70.1</td></tr><tr><td>Netmask</td><td>255.255.255.0</td></tr>";
        let found = prefix_candidates(separate);
        assert!(
            found.iter().all(|c| !c.semantics.establishes_network()),
            "{found:?}"
        );
    }

    #[test]
    fn scripts_styles_and_comments_are_not_page_content() {
        // The router this was written against keeps its own address in a script variable
        // precisely because it is not rendered content. A value there is a program's
        // constant, and only a vendor adapter that knows the format may read it.
        for body in [
            r"<script>var lan ='192\x2e168\x2e51\x2e0/24'; var mask='255.255.255.0';</script>",
            "<style>/* LAN Subnet 192.168.51.0/24 */</style>",
            "<!-- IP Address 192.168.51.1 Subnet Mask 255.255.255.0 -->",
        ] {
            assert!(prefix_candidates(body).is_empty(), "{body}");
        }
    }

    #[test]
    fn removing_a_script_does_not_join_the_fields_around_it() {
        // Otherwise an address before a script and a mask after it become one apparent
        // field.
        let body = "192.168.51.1<script>var x=1;</script>Netmask 255.255.255.0";
        let found = prefix_candidates(body);
        assert!(
            found.iter().all(|c| !c.semantics.establishes_network()),
            "{found:?}"
        );
    }

    #[test]
    fn a_json_object_is_one_structured_field() {
        let body = r#"{"lan_ip":"192.168.51.1","netmask":"255.255.255.0"}"#;
        let found = prefix_candidates(body);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].prefix.to_string(), "192.168.51.0/24");
        assert!(found[0].semantics.establishes_network());
    }

    #[test]
    fn ipv6_prefixes_can_be_extracted_at_all() {
        // The earlier tokenizer excluded colons and hex digits, which made every IPv6
        // literal invisible -- the parser could not have found one if a device had stated it.
        let body = "<tr><td>LAN Subnet</td><td>fd84:3bfe:bf84::/64</td></tr>";
        let found = prefix_candidates(body);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].prefix.to_string(), "fd84:3bfe:bf84::/64");
        assert!(found[0].semantics.establishes_network());
    }

    #[test]
    fn a_host_route_is_not_a_network() {
        // /32 and /128 name one address. Recording them would fill the topology with a node
        // per host.
        assert!(
            prefix_candidates("<tr><td>LAN Subnet</td><td>192.168.51.7/32</td></tr>").is_empty()
        );
        assert!(prefix_candidates("<tr><td>LAN Subnet</td><td>fd00::1/128</td></tr>").is_empty());
    }

    #[test]
    fn a_mask_that_is_not_contiguous_is_not_a_mask() {
        // 255.0.255.0 describes no CIDR block, and 0.0.0.0 is every unset field on a page.
        for body in [
            "<tr><td>IP Address</td><td>10.0.0.1</td><td>Netmask</td><td>255.0.255.0</td></tr>",
            "<tr><td>IP Address</td><td>10.0.0.1</td><td>Netmask</td><td>0.0.0.0</td></tr>",
        ] {
            let found = prefix_candidates(body);
            assert!(
                found.iter().all(|c| !c.semantics.establishes_network()),
                "{body} -> {found:?}"
            );
        }
    }

    #[test]
    fn the_strongest_statement_about_a_prefix_wins() {
        // A page may mention a network in passing and also state it properly.
        let body = "<li>see 10.9.0.0/16</li><tr><td>LAN Subnet</td><td>10.9.0.0/16</td></tr>";
        let found = prefix_candidates(body);
        assert_eq!(found.len(), 1);
        assert!(found[0].semantics.establishes_network());
    }

    #[test]
    fn extraction_does_not_panic_on_arbitrary_bytes() {
        // The body is whatever the device sent.
        for body in [
            "",
            "/",
            "//",
            "1.2.3.4/",
            "/24",
            r"\x",
            r"\xZZ",
            "999.999.999.999/24",
            "<tr",
            "{",
            "{{{{",
            ":::",
            "::/",
            "<script",
            "<!--",
        ] {
            let _ = prefix_candidates(body);
        }
    }

    #[test]
    fn non_http_traffic_is_not_parsed_as_a_response() {
        assert!(parse_http_identity("SSH-2.0-OpenSSH_9.0\r\n").is_none());
        assert!(parse_http_identity("").is_none());
        // A status line with no code is malformed, not a zero status.
        assert!(parse_http_identity("HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn a_malformed_header_loses_only_itself() {
        let response = "HTTP/1.1 200 OK\r\nthis-is-not-a-header\r\nServer: nginx\r\n\r\n";
        let identity = parse_http_identity(response).expect("parsed");
        assert_eq!(identity.server.as_deref(), Some("nginx"));
    }

    #[test]
    fn an_oversized_title_is_markup_not_a_name() {
        let long = "x".repeat(200);
        let response = format!("HTTP/1.1 200 OK\r\n\r\n<title>{long}</title>");
        assert!(
            parse_http_identity(&response)
                .expect("parsed")
                .title
                .is_none()
        );
    }
}
