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
            _ => {}
        }
    }

    identity.title = extract_title(response);
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
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: idnx\r\nAccept: */*\r\nConnection: close\r\n\r\n"
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
