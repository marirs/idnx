//! AI runtime, agent and MCP discovery, targeted at one device.
//!
//! Two rules distinguish this from port-guessing.
//!
//! An open port is never evidence. Ports 3000, 8000 and 8080 host far more non-AI software
//! than AI software, so nothing here is claimed from a port number: every result comes from
//! a protocol response that only the named software produces.
//!
//! MCP requires negotiation. A `GET /sse` returning 200, 400 or 405 says only that
//! *something* is listening — plenty of unrelated servers answer that way. An MCP server is
//! confirmed only by a JSON-RPC `initialize` that returns a protocol version and server
//! identity, after which its tools, resources and prompts are enumerated.

use crate::net::endpoint::Endpoint;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::topology::TopologyEvidence;
use crate::topology::evidence::{Capability, Confidence, DeviceKey, EvidenceSource, Fact};

/// Ports worth asking. Membership here schedules a protocol probe and asserts nothing.
const AI_CANDIDATE_PORTS: &[u16] = &[11434, 1234, 8000, 8080, 5000, 3000, 8081, 9000];

/// A confirmed MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServer {
    pub endpoint: String,
    pub protocol_version: String,
    pub server_name: Option<String>,
    pub server_version: Option<String>,
    pub tools: Vec<String>,
    pub resources: Vec<String>,
    pub prompts: Vec<String>,
}

/// Builds the JSON-RPC `initialize` request that opens an MCP session.
pub fn mcp_initialize_request() -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"idnx","version":"{}"}}}}}}"#,
        env!("CARGO_PKG_VERSION")
    )
}

/// A JSON-RPC list request for one MCP collection.
pub fn mcp_list_request(id: u32, method: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}"}}"#)
}

/// A parsed HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    /// Header values are matched case-insensitively, as HTTP requires.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Parses a raw HTTP response, decoding chunked transfer and SSE framing.
///
/// Both matter for MCP: Streamable HTTP servers commonly reply chunked, and the legacy
/// transport replies as `text/event-stream` where the JSON sits behind `data:` prefixes.
/// Reading the raw bytes as if they were JSON fails against either.
pub fn parse_http_response(raw: &str) -> Option<HttpResponse> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))?;
    let mut lines = head.lines();
    let status_line = lines.next()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let content_type = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase());

    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });

    let mut body = if chunked {
        decode_chunked(body)
    } else {
        body.to_string()
    };

    if content_type
        .as_deref()
        .is_some_and(|c| c.contains("text/event-stream"))
    {
        body = decode_sse(&body);
    }

    Some(HttpResponse {
        status,
        content_type,
        headers,
        body,
    })
}

/// Reassembles a chunked transfer-encoded body.
pub fn decode_chunked(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;

    while let Some((size_line, remainder)) = rest.split_once("\r\n") {
        // A chunk size may carry extensions after a semicolon.
        let size_text = size_line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            break;
        };
        if size == 0 || remainder.len() < size {
            break;
        }
        out.push_str(&remainder[..size]);
        rest = remainder[size..].trim_start_matches("\r\n");
    }

    if out.is_empty() {
        body.to_string()
    } else {
        out
    }
}

/// Extracts the concatenated `data:` payload from an SSE stream.
pub fn decode_sse(body: &str) -> String {
    let mut out = String::new();
    for line in body.lines() {
        if let Some(data) = line.strip_prefix("data:") {
            out.push_str(data.trim());
        }
    }
    if out.is_empty() {
        body.to_string()
    } else {
        out
    }
}

/// A validated JSON-RPC result.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonRpcResult {
    pub id: u64,
    pub result: serde_json::Value,
}

/// Validates a JSON-RPC 2.0 response against the request that produced it.
///
/// Checks the envelope structurally rather than by substring: version, absence of an
/// error, a matching request id, and a result object. A body that merely contains the
/// characters `jsonrpc` is not a response.
pub fn parse_json_rpc(body: &str, expected_id: u64) -> Option<JsonRpcResult> {
    let value: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let object = value.as_object()?;

    if object.get("jsonrpc")?.as_str()? != "2.0" {
        return None;
    }
    if object.contains_key("error") {
        return None;
    }
    if object.get("id")?.as_u64()? != expected_id {
        return None;
    }

    Some(JsonRpcResult {
        id: expected_id,
        result: object.get("result")?.clone(),
    })
}

/// What an `initialize` handshake established.
#[derive(Debug, Clone, PartialEq)]
pub struct McpSession {
    pub protocol_version: String,
    pub server_name: Option<String>,
    pub server_version: Option<String>,
    /// Server-assigned session id, which stateful servers require on later requests.
    pub session_id: Option<String>,
    /// Capabilities the server advertised. Only these are enumerated afterwards.
    pub capabilities: Vec<String>,
}

/// Validates an `initialize` result.
///
/// Requires `protocolVersion` and `serverInfo`, which together are what distinguishes an
/// MCP server from anything else that happens to speak JSON-RPC.
pub fn parse_initialize_result(result: &serde_json::Value) -> Option<McpSession> {
    let object = result.as_object()?;
    let protocol_version = object.get("protocolVersion")?.as_str()?.to_string();
    let server_info = object.get("serverInfo")?.as_object()?;

    let capabilities = object
        .get("capabilities")
        .and_then(|c| c.as_object())
        .map(|c| c.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();

    Some(McpSession {
        protocol_version,
        server_name: server_info
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        server_version: server_info
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        session_id: None,
        capabilities,
    })
}

/// Extracts the `name` of each entry in a named result collection.
///
/// Reads `result.<collection>[].name` structurally, so a tool description mentioning the
/// word "name" cannot be mistaken for an entry.
pub fn parse_listing(result: &serde_json::Value, collection: &str) -> Vec<String> {
    let mut out: Vec<String> = result
        .as_object()
        .and_then(|o| o.get(collection))
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_object()?.get("name")?.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

/// One HTTP request/response exchange.
async fn http_exchange(
    ip: &Endpoint,
    port: u16,
    path: &str,
    method: &str,
    payload: Option<&str>,
    extra_headers: &[(String, String)],
    timeout_duration: Duration,
) -> Option<HttpResponse> {
    let mut stream = timeout(timeout_duration, TcpStream::connect(ip.socket_addr(port)))
        .await
        .ok()?
        .ok()?;

    let mut request = format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         User-Agent: idnx/{}\r\n\
         Accept: application/json, text/event-stream\r\n",
        method,
        path,
        ip,
        port,
        env!("CARGO_PKG_VERSION")
    );
    for (name, value) in extra_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    match payload {
        Some(body) => {
            request.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            ));
        }
        None => request.push_str("Connection: close\r\n\r\n"),
    }

    timeout(timeout_duration, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    while let Ok(Ok(n)) = timeout(timeout_duration, stream.read(&mut chunk)).await {
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        // Bounded so a streaming endpoint cannot hold the probe open indefinitely.
        if buf.len() > 262_144 {
            break;
        }
    }

    parse_http_response(&String::from_utf8_lossy(&buf))
}

/// Performs the full MCP lifecycle against one endpoint.
///
/// initialize -> notifications/initialized -> enumerate advertised collections. The
/// notification is required by the specification before normal requests, and the session
/// id and negotiated protocol version are echoed on every subsequent request, without
/// which a stateful server rejects them.
pub async fn confirm_mcp(
    ip: &Endpoint,
    port: u16,
    path: &str,
    timeout_duration: Duration,
) -> Option<McpServer> {
    let response = http_exchange(
        ip,
        port,
        path,
        "POST",
        Some(&mcp_initialize_request()),
        &[],
        timeout_duration,
    )
    .await?;

    // An authentication challenge means something MCP-shaped may be present but was not
    // confirmed; it is not evidence of a server.
    if response.status == 401 || response.status == 403 {
        return None;
    }

    let rpc = parse_json_rpc(&response.body, 1)?;
    let mut session = parse_initialize_result(&rpc.result)?;
    session.session_id = response.header("Mcp-Session-Id").map(|s| s.to_string());

    // Headers every subsequent request must carry.
    let mut headers = vec![(
        "MCP-Protocol-Version".to_string(),
        session.protocol_version.clone(),
    )];
    if let Some(id) = &session.session_id {
        headers.push(("Mcp-Session-Id".to_string(), id.clone()));
    }

    // The specification requires this notification before normal operation. It takes no
    // response, so its outcome is deliberately ignored.
    let _ = http_exchange(
        ip,
        port,
        path,
        "POST",
        Some(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
        &headers,
        timeout_duration,
    )
    .await;

    // Enumerate only what the server said it supports.
    let mut tools = Vec::new();
    let mut resources = Vec::new();
    let mut prompts = Vec::new();

    for (id, method, collection, sink) in [
        (2u64, "tools/list", "tools", &mut tools),
        (3, "resources/list", "resources", &mut resources),
        (4, "prompts/list", "prompts", &mut prompts),
    ] {
        if !session.capabilities.iter().any(|c| c == collection) {
            continue;
        }
        let Some(listing) = http_exchange(
            ip,
            port,
            path,
            "POST",
            Some(&mcp_list_request(id as u32, method)),
            &headers,
            timeout_duration,
        )
        .await
        else {
            continue;
        };
        if let Some(rpc) = parse_json_rpc(&listing.body, id) {
            *sink = parse_listing(&rpc.result, collection);
        }
    }

    Some(McpServer {
        endpoint: format!("http://{ip}:{port}{path}"),
        protocol_version: session.protocol_version,
        server_name: session.server_name,
        server_version: session.server_version,
        tools,
        resources,
        prompts,
    })
}

/// Runs AI and MCP discovery against one device.
pub async fn probe_ai_services(
    target: &Endpoint,
    device: &DeviceKey,
    open_ports: &[u16],
    timeout_duration: Duration,
    vantage: &str,
) -> Vec<TopologyEvidence> {
    let mut out = Vec::new();

    // Only ports already known to answer. Handshaking against closed ports costs a full
    // connect timeout each and can never produce evidence, which turned interrogation of a
    // silent device into the slowest part of a run.
    let reachable: Vec<u16> = AI_CANDIDATE_PORTS
        .iter()
        .copied()
        .filter(|p| open_ports.contains(p))
        .collect();
    if reachable.is_empty() {
        return out;
    }

    // Runtime detection, which already confirms via protocol endpoints rather than ports.
    if let Some(ai) =
        crate::probes::ai::probe_ai_runtime(target, &reachable, timeout_duration).await
    {
        out.push(
            TopologyEvidence::new(
                Fact::DeviceCapability {
                    device: device.clone(),
                    capability: Capability::AiRuntime,
                    detail: Some(ai.runtime_type.display_name().to_string()),
                },
                EvidenceSource::AiProtocol,
                // The runtime answered its own protocol endpoint.
                Confidence::Observed,
                vantage,
            )
            .with_detail(ai.summary_label()),
        );

        // A model catalogue is what the runtime says it holds.
        for model in &ai.models {
            out.push(TopologyEvidence::new(
                Fact::DeviceDescription {
                    device: device.clone(),
                    text: format!("model: {model}"),
                },
                EvidenceSource::AiProtocol,
                Confidence::Advertised,
                vantage,
            ));
        }

        if let Some(agent) = ai.agent_name.clone() {
            out.push(TopologyEvidence::new(
                Fact::DeviceCapability {
                    device: device.clone(),
                    capability: Capability::AiAgent,
                    detail: Some(agent),
                },
                EvidenceSource::AiProtocol,
                Confidence::Advertised,
                vantage,
            ));
        }
    }

    // MCP, confirmed only by negotiation.
    for &port in &reachable {
        for path in ["/mcp", "/sse", "/"] {
            let Some(server) = confirm_mcp(target, port, path, timeout_duration).await else {
                continue;
            };

            let detail = format!(
                "JSON-RPC initialize succeeded, protocol {}{}; {} tools, {} resources, {} prompts",
                server.protocol_version,
                server
                    .server_name
                    .as_deref()
                    .map(|n| format!(" ({n})"))
                    .unwrap_or_default(),
                server.tools.len(),
                server.resources.len(),
                server.prompts.len()
            );

            out.push(
                TopologyEvidence::new(
                    Fact::DeviceCapability {
                        device: device.clone(),
                        capability: Capability::McpServer,
                        detail: Some(server.endpoint.clone()),
                    },
                    EvidenceSource::Mcp,
                    Confidence::Observed,
                    vantage,
                )
                .with_detail(detail),
            );

            out.push(TopologyEvidence::new(
                Fact::Service {
                    address: target.address,
                    port,
                    protocol: "tcp",
                    detail: Some(format!("MCP {}", server.protocol_version)),
                },
                EvidenceSource::Mcp,
                Confidence::Observed,
                vantage,
            ));

            for tool in &server.tools {
                out.push(TopologyEvidence::new(
                    Fact::DeviceDescription {
                        device: device.clone(),
                        text: format!("MCP tool: {tool}"),
                    },
                    EvidenceSource::Mcp,
                    Confidence::Advertised,
                    vantage,
                ));
            }

            // One confirmed endpoint per port is enough.
            break;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic responses standing in for the three server shapes MCP defines.
    mod fixtures {
        pub const STATELESS_JSON: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 210\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{},\"resources\":{}},\"serverInfo\":{\"name\":\"demo-server\",\"version\":\"1.2.3\"}}}";

        pub const STATEFUL_WITH_SESSION: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: 7f3c9a\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"stateful\",\"version\":\"2.0\"}}}";

        pub const LEGACY_SSE: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"prompts\":{}},\"serverInfo\":{\"name\":\"sse-server\",\"version\":\"0.9\"}}}\n\n";

        /// Builds a chunked response, splitting the body so the sizes are correct by
        /// construction rather than hand-counted.
        pub fn chunked(body: &str) -> String {
            let mid = body.len() / 2;
            let (first, second) = body.split_at(mid);
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{}\r\n{:X}\r\n{}\r\n0\r\n\r\n",
                first.len(),
                first,
                second.len(),
                second
            )
        }

        /// What an unrelated server answering /sse produces. Must never confirm MCP.
        pub const NOT_MCP_405: &str =
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nMethod Not Allowed";
        pub const NOT_MCP_200: &str =
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello</body></html>";
        pub const AUTH_REQUIRED: &str =
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\n\r\n";
    }

    #[test]
    fn http_response_headers_and_status_are_parsed() {
        let r = parse_http_response(fixtures::STATELESS_JSON).expect("parses");
        assert_eq!(r.status, 200);
        assert!(
            r.content_type
                .as_deref()
                .unwrap()
                .contains("application/json")
        );
    }

    #[test]
    fn a_session_id_header_is_preserved() {
        // Stateful servers reject later requests without it.
        let r = parse_http_response(fixtures::STATEFUL_WITH_SESSION).expect("parses");
        assert_eq!(r.header("mcp-session-id"), Some("7f3c9a"));
        assert_eq!(r.header("Mcp-Session-Id"), Some("7f3c9a"));
    }

    #[test]
    fn an_sse_body_is_decoded_before_parsing() {
        // The JSON sits behind `data:` prefixes; reading raw bytes as JSON fails.
        let r = parse_http_response(fixtures::LEGACY_SSE).expect("parses");
        let rpc = parse_json_rpc(&r.body, 1).expect("JSON-RPC inside the SSE frame");
        let session = parse_initialize_result(&rpc.result).expect("initialize result");
        assert_eq!(session.protocol_version, "2024-11-05");
        assert_eq!(session.server_name.as_deref(), Some("sse-server"));
    }

    #[test]
    fn a_chunked_body_is_reassembled() {
        // Streamable HTTP servers commonly reply chunked; reading the frame as JSON fails.
        let payload = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"chunky","version":"1"}}}"#;
        let raw = fixtures::chunked(payload);

        let r = parse_http_response(&raw).expect("parses");
        assert_eq!(r.body, payload, "chunk sizes must not remain in the body");

        let rpc = parse_json_rpc(&r.body, 1).expect("valid envelope after reassembly");
        assert_eq!(
            parse_initialize_result(&rpc.result)
                .expect("initialize result")
                .server_name
                .as_deref(),
            Some("chunky")
        );
    }

    #[test]
    fn initialize_requires_protocol_version_and_server_info() {
        let r = parse_http_response(fixtures::STATELESS_JSON).expect("parses");
        let rpc = parse_json_rpc(&r.body, 1).expect("valid envelope");
        let session = parse_initialize_result(&rpc.result).expect("valid result");

        assert_eq!(session.protocol_version, "2024-11-05");
        assert_eq!(session.server_name.as_deref(), Some("demo-server"));
        assert!(session.capabilities.contains(&"tools".to_string()));
        assert!(session.capabilities.contains(&"resources".to_string()));
        assert!(
            !session.capabilities.contains(&"prompts".to_string()),
            "only advertised collections may be enumerated"
        );
    }

    #[test]
    fn a_bare_http_response_is_never_mcp() {
        for raw in [
            fixtures::NOT_MCP_405,
            fixtures::NOT_MCP_200,
            fixtures::AUTH_REQUIRED,
        ] {
            let parsed = parse_http_response(raw).expect("parses as HTTP");
            assert!(
                parse_json_rpc(&parsed.body, 1).is_none(),
                "an HTTP status must never confirm MCP: {raw}"
            );
        }
    }

    #[test]
    fn a_json_rpc_error_is_not_a_confirmation() {
        let body =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
        assert!(parse_json_rpc(body, 1).is_none());
    }

    #[test]
    fn a_mismatched_request_id_is_rejected() {
        // A response to some other request must not be accepted as ours.
        let body = r#"{"jsonrpc":"2.0","id":99,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"x"}}}"#;
        assert!(parse_json_rpc(body, 1).is_none());
    }

    #[test]
    fn a_wrong_jsonrpc_version_is_rejected() {
        let body = r#"{"jsonrpc":"1.0","id":1,"result":{"protocolVersion":"2024-11-05"}}"#;
        assert!(parse_json_rpc(body, 1).is_none());
    }

    #[test]
    fn json_rpc_without_mcp_fields_is_not_mcp() {
        // Speaking JSON-RPC is not the same as speaking MCP.
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
        let rpc = parse_json_rpc(body, 1).expect("valid JSON-RPC");
        assert!(parse_initialize_result(&rpc.result).is_none());
    }

    #[test]
    fn listings_are_read_from_their_own_collection() {
        // Structural, so a description mentioning "name" is not mistaken for an entry.
        let body = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[
            {"name":"search","description":"look up by name"},
            {"name":"fetch_url","inputSchema":{"properties":{"name":{}}}}
        ],"resources":[{"name":"README"}]}}"#;
        let rpc = parse_json_rpc(body, 2).expect("valid envelope");

        assert_eq!(
            parse_listing(&rpc.result, "tools"),
            vec!["fetch_url", "search"]
        );
        assert_eq!(parse_listing(&rpc.result, "resources"), vec!["README"]);
        assert!(parse_listing(&rpc.result, "prompts").is_empty());
    }

    #[test]
    fn the_initialize_request_is_well_formed_json_rpc() {
        let request = mcp_initialize_request();
        let value: serde_json::Value = serde_json::from_str(&request).expect("valid JSON");
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["method"], "initialize");
        assert!(value["params"]["protocolVersion"].is_string());
        assert!(value["params"]["clientInfo"]["name"].is_string());
    }

    #[test]
    fn list_requests_use_the_documented_methods() {
        for (id, method) in [
            (2, "tools/list"),
            (3, "resources/list"),
            (4, "prompts/list"),
        ] {
            let value: serde_json::Value =
                serde_json::from_str(&mcp_list_request(id, method)).expect("valid JSON");
            assert_eq!(value["method"], method);
            assert_eq!(value["id"], id);
        }
    }

    #[test]
    fn candidate_ports_schedule_work_without_asserting_anything() {
        // Where AI software is commonly found. Membership never becomes evidence: every
        // result in this module comes from a protocol response.
        assert!(AI_CANDIDATE_PORTS.contains(&11434));
        assert!(AI_CANDIDATE_PORTS.contains(&3000));
    }
}
