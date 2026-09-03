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
    /// Prefixes the response stated explicitly. Never derived from a bare address.
    pub prefixes: Vec<StatedPrefix>,
    /// Where a redirect pointed, when it stayed on the same origin.
    pub redirected_to: Option<String>,
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

/// A prefix a device stated in its own response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatedPrefix {
    pub prefix: ipnet::IpNet,
    /// The exact text that produced it, so the network can be traced to what was said
    /// rather than to how it was parsed.
    pub source_text: String,
}

/// Extracts prefixes a device stated explicitly.
///
/// Only two forms count, and both are unambiguous statements of a network.
///
/// * A CIDR literal: `192.168.51.0/24`.
/// * An address and a dotted netmask together, where the mask is labelled as one.
///
/// A bare address is never enough. A router's status page is full of addresses -- its own,
/// its gateway's, its DNS servers' -- and none of them names a network. Deriving a prefix
/// from an address and an assumed mask is exactly the invention this refuses to do, so a
/// page that mentions 192.168.51.1 and no mask produces nothing.
///
/// Escaping is undone first: web interfaces routinely write addresses as `192\x2e168\x2e1`
/// to keep them out of the page source, and a device that hides its own addressing that way
/// is not thereby making a different statement.
pub fn stated_prefixes(body: &str) -> Vec<StatedPrefix> {
    let text = unescape_hex(body);
    let mut out: Vec<StatedPrefix> = Vec::new();

    for token in text.split(|c: char| !(c.is_ascii_digit() || c == '.' || c == '/')) {
        if !token.contains('/') {
            continue;
        }
        let Ok(network) = token.parse::<ipnet::IpNet>() else {
            continue;
        };
        // A single address written with a full-length prefix is an address, not a network.
        if network.prefix_len() == network.max_prefix_len() {
            continue;
        }
        push_unique(
            &mut out,
            StatedPrefix {
                prefix: network.trunc(),
                source_text: token.to_string(),
            },
        );
    }

    out.extend(masked_prefixes(&text));
    out
}

/// Finds an address paired with something the page itself calls a netmask.
///
/// The label is required. Two dotted quads near each other are usually an address and a
/// gateway, and pairing them would produce a network nobody described.
fn masked_prefixes(text: &str) -> Vec<StatedPrefix> {
    const LABELS: &[&str] = &["netmask", "subnet mask", "subnetmask", "mask"];

    let lowered = text.to_ascii_lowercase();
    let mut out: Vec<StatedPrefix> = Vec::new();

    for label in LABELS {
        let mut from = 0usize;
        while let Some(found) = lowered[from..].find(label) {
            let at = from + found;
            from = at + label.len();

            // The window either side of the label: an address before it and the mask after,
            // or both after. Bounded so a mask cannot be paired with an address elsewhere
            // on the page.
            let start = at.saturating_sub(120);
            let end = (from + 120).min(text.len());
            let Some(window) = text.get(start..end) else {
                continue;
            };

            let quads: Vec<&str> = window
                .split(|c: char| !(c.is_ascii_digit() || c == '.'))
                .filter(|t| t.parse::<std::net::Ipv4Addr>().is_ok())
                .collect();

            // The mask is whichever quad is a contiguous mask; the address is another quad
            // that is not.
            let Some(mask) = quads.iter().find_map(|t| {
                t.parse::<std::net::Ipv4Addr>()
                    .ok()
                    .filter(is_contiguous_mask)
            }) else {
                continue;
            };
            let Some(address) = quads.iter().find_map(|t| {
                t.parse::<std::net::Ipv4Addr>()
                    .ok()
                    .filter(|a| !is_contiguous_mask(a))
            }) else {
                continue;
            };

            let length = u32::from_be_bytes(mask.octets()).leading_ones() as u8;
            let Ok(network) = ipnet::Ipv4Net::new(address, length) else {
                continue;
            };
            push_unique(
                &mut out,
                StatedPrefix {
                    prefix: ipnet::IpNet::V4(network.trunc()),
                    source_text: format!("{address} {label} {mask}"),
                },
            );
        }
    }

    out
}

fn push_unique(out: &mut Vec<StatedPrefix>, candidate: StatedPrefix) {
    if !out
        .iter()
        .any(|existing| existing.prefix == candidate.prefix)
    {
        out.push(candidate);
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
        // Not an escape: copy the character whole, so multi-byte text survives.
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
            "location" => identity.redirected_to = Some(value),
            _ => {}
        }
    }

    identity.title = extract_title(response);
    // Only the body: a header value is never a topology statement, and scanning them would
    // read a Content-Security-Policy or a cookie path as addressing.
    identity.prefixes = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| stated_prefixes(body))
        .unwrap_or_default();
    Some(identity)
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

    for _ in 0..MAX_REDIRECTS {
        let Some(next) = identity.redirected_to.clone() else {
            break;
        };
        let Some(next_path) = same_origin_path(&next, target, port) else {
            break;
        };
        if next_path == path {
            break;
        }
        path = next_path;
        let Some(followed) = probe_http_path(target, port, &path, binding, timeout_duration).await
        else {
            break;
        };
        identity = followed;
    }

    Some(identity)
}

/// The path a redirect points to, when it stays on this origin.
///
/// Returns `None` for anything naming a different host or scheme, which is the device
/// sending us elsewhere rather than describing itself.
pub fn same_origin_path(location: &str, target: &Endpoint, port: u16) -> Option<String> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    // A protocol-relative URL looks like a path and is not one: `//host/path` names
    // another host, and treating it as relative would follow the device anywhere.
    if location.starts_with("//") {
        return None;
    }
    // A genuinely relative redirect is by definition on this origin.
    if location.starts_with('/') {
        return Some(location.to_string());
    }

    let rest = location
        .strip_prefix("http://")
        .or_else(|| location.strip_prefix("https://"))?;
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

    matches.then_some(path)
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
        // A redirect to another host is the device pointing somewhere else. Following it
        // would probe a machine this run never discovered and file the answer under one it
        // did.
        let target = Endpoint::global("192.168.70.1".parse().unwrap());

        assert_eq!(
            same_origin_path("/login.html", &target, 80),
            Some("/login.html".to_string())
        );
        assert_eq!(
            same_origin_path("http://192.168.70.1/index.html", &target, 80),
            Some("/index.html".to_string())
        );
        assert_eq!(
            same_origin_path("http://192.168.70.1:80/", &target, 80),
            Some("/".to_string())
        );

        // Elsewhere, in every disguise.
        assert!(same_origin_path("http://evil.example/", &target, 80).is_none());
        assert!(same_origin_path("http://192.168.70.2/", &target, 80).is_none());
        assert!(same_origin_path("http://192.168.70.1@evil.example/", &target, 80).is_none());
        assert!(same_origin_path("//evil.example/", &target, 80).is_none());
        assert!(same_origin_path("", &target, 80).is_none());
    }

    #[test]
    fn a_prefix_is_taken_from_the_body_and_not_from_headers() {
        // A Content-Security-Policy or a cookie path is not a topology statement.
        let response = "HTTP/1.1 200 OK\r\nX-Net: 10.9.0.0/16\r\n\r\n<p>LAN 192.168.51.0/24</p>";
        let identity = parse_http_identity(response).expect("parsed");
        assert_eq!(identity.prefixes.len(), 1);
        assert_eq!(identity.prefixes[0].prefix.to_string(), "192.168.51.0/24");
    }

    #[test]
    fn a_cidr_literal_states_a_network() {
        let found = stated_prefixes("LAN subnet is 192.168.51.0/24 (bridged)");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].prefix.to_string(), "192.168.51.0/24");
        assert_eq!(found[0].source_text, "192.168.51.0/24");
    }

    #[test]
    fn an_address_with_a_labelled_mask_states_a_network() {
        for text in [
            "IP Address: 192.168.51.1 Subnet Mask: 255.255.255.0",
            "netmask=255.255.0.0&ip=10.4.0.1",
            "<td>Subnetmask</td><td>255.255.255.128</td><td>172.20.5.3</td>",
        ] {
            let found = stated_prefixes(text);
            assert_eq!(found.len(), 1, "{text}");
            assert!(found[0].source_text.contains("mask"), "{:?}", found[0]);
        }
        assert_eq!(
            stated_prefixes("IP Address: 192.168.51.1 Subnet Mask: 255.255.255.0")[0]
                .prefix
                .to_string(),
            "192.168.51.0/24"
        );
    }

    #[test]
    fn a_bare_address_never_becomes_a_network() {
        // The failure this exists to prevent. A status page is full of addresses -- the
        // device's own, its gateway, its resolvers -- and none of them names a network.
        // Assuming a mask would invent the very prefix this tool must not invent.
        for text in [
            "SSLHostIp ='192.168.70.1'",
            "Gateway 192.168.1.1 DNS 192.168.1.1 8.8.8.8",
            "Connected to 10.0.0.5 and 10.0.0.6",
            "Default route via 192.168.51.1",
        ] {
            assert!(stated_prefixes(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn escaped_addresses_are_read_as_written() {
        // Web interfaces write addresses as \x2e-escaped text to keep them out of the page
        // source. A device hiding its own addressing that way is making the same statement.
        let found = stated_prefixes(r"var lan ='192.168.51.0/24';");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].prefix.to_string(), "192.168.51.0/24");

        // And an escaped bare address is still just an address.
        assert!(stated_prefixes(r"var ip ='192.168.70.1';").is_empty());
    }

    #[test]
    fn a_host_route_is_not_a_network() {
        // /32 and /128 name one address. Recording them as networks would fill the topology
        // with a node per host.
        assert!(stated_prefixes("route 192.168.51.7/32 via eth0").is_empty());
        assert!(stated_prefixes("fd00::1/128").is_empty());
    }

    #[test]
    fn a_mask_that_is_not_contiguous_is_not_a_mask() {
        // 255.0.255.0 describes no CIDR block, and 0.0.0.0 is every unset field on a page.
        assert!(stated_prefixes("ip 10.0.0.1 netmask 255.0.255.0").is_empty());
        assert!(stated_prefixes("ip 10.0.0.1 netmask 0.0.0.0").is_empty());
    }

    #[test]
    fn a_mask_is_not_paired_with_an_address_elsewhere_on_the_page() {
        // Two dotted quads far apart are unrelated. Pairing them would produce a network
        // nobody described.
        let far = format!("192.168.51.1{}netmask 255.255.255.0", " ".repeat(400));
        let found = stated_prefixes(&far);
        assert!(
            found
                .iter()
                .all(|p| !p.prefix.to_string().starts_with("192.168.51")),
            "{found:?}"
        );
    }

    #[test]
    fn the_same_network_stated_twice_is_recorded_once() {
        let found = stated_prefixes("lan 10.9.0.0/16 ... backup 10.9.0.0/16");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn extraction_does_not_panic_on_arbitrary_bytes() {
        // The body is whatever the device sent.
        for text in [
            "",
            "/",
            "//",
            "1.2.3.4/",
            "/24",
            "\\x",
            "\\xZZ",
            "999.999.999.999/24",
        ] {
            let _ = stated_prefixes(text);
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
