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

use std::net::Ipv4Addr;
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

/// Extracts a string field from a flat JSON object body.
///
/// Deliberately minimal: only the few identity fields below are read, and anything the
/// server sends that does not parse simply yields nothing rather than a guess.
fn json_string_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = body.find(&needle)? + needle.len();
    let rest = &body[start..];
    let colon = rest.find(':')? + 1;
    let rest = &rest[colon..];
    let open = rest.find('"')? + 1;
    let rest = &rest[open..];
    let close = rest.find('"')?;
    Some(rest[..close].to_string())
}

/// Extracts the `name` of each entry in a JSON-RPC list result.
pub fn json_names(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(index) = rest.find("\"name\"") {
        rest = &rest[index + 6..];
        let Some(colon) = rest.find(':') else { break };
        let after = &rest[colon + 1..];
        let Some(open) = after.find('"') else { break };
        let after = &after[open + 1..];
        let Some(close) = after.find('"') else { break };
        out.push(after[..close].to_string());
        rest = &after[close..];
    }
    out.sort();
    out.dedup();
    out
}

/// Confirms whether a JSON-RPC response is a valid MCP `initialize` result.
///
/// A server that merely returns 200 is not enough: the body must be a JSON-RPC result
/// carrying a protocol version, which is what an MCP server and nothing else produces.
pub fn parse_initialize_result(body: &str) -> Option<(String, Option<String>, Option<String>)> {
    if !body.contains("\"jsonrpc\"") || body.contains("\"error\"") {
        return None;
    }
    let version = json_string_field(body, "protocolVersion")?;
    let name = json_string_field(body, "name");
    let server_version = json_string_field(body, "version");
    Some((version, name, server_version))
}

/// Sends a JSON-RPC request over HTTP and returns the response body.
async fn json_rpc_post(
    ip: Ipv4Addr,
    port: u16,
    path: &str,
    payload: &str,
    timeout_duration: Duration,
) -> Option<String> {
    let mut stream = timeout(timeout_duration, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;

    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         User-Agent: idnx/{}\r\n\
         Content-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        path,
        ip,
        port,
        env!("CARGO_PKG_VERSION"),
        payload.len(),
        payload
    );

    timeout(timeout_duration, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 2048];
    while let Ok(Ok(n)) = timeout(timeout_duration, stream.read(&mut chunk)).await {
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 262_144 {
            break;
        }
    }

    let text = String::from_utf8_lossy(&buf).to_string();
    // Return the body only; headers are not evidence.
    text.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .or(Some(text))
}

/// Attempts a full MCP handshake against one endpoint.
pub async fn confirm_mcp(
    ip: Ipv4Addr,
    port: u16,
    path: &str,
    timeout_duration: Duration,
) -> Option<McpServer> {
    let body = json_rpc_post(ip, port, path, &mcp_initialize_request(), timeout_duration).await?;
    let (protocol_version, server_name, server_version) = parse_initialize_result(&body)?;

    // Only after a successful negotiation is it worth enumerating anything.
    let mut tools = Vec::new();
    let mut resources = Vec::new();
    let mut prompts = Vec::new();

    for (id, method, sink) in [
        (2u32, "tools/list", &mut tools),
        (3, "resources/list", &mut resources),
        (4, "prompts/list", &mut prompts),
    ] {
        if let Some(listing) = json_rpc_post(
            ip,
            port,
            path,
            &mcp_list_request(id, method),
            timeout_duration,
        )
        .await
        {
            *sink = json_names(&listing);
        }
    }

    Some(McpServer {
        endpoint: format!("http://{ip}:{port}{path}"),
        protocol_version,
        server_name,
        server_version,
        tools,
        resources,
        prompts,
    })
}

/// Runs AI and MCP discovery against one device.
pub async fn probe_ai_services(
    target: Ipv4Addr,
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
                    address: std::net::IpAddr::V4(target),
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

    #[test]
    fn initialize_result_requires_a_protocol_version() {
        let good = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"demo-server","version":"1.2.3"}}}"#;
        let parsed = parse_initialize_result(good).expect("valid initialize result");
        assert_eq!(parsed.0, "2024-11-05");
        assert_eq!(parsed.1.as_deref(), Some("demo-server"));
    }

    #[test]
    fn a_bare_http_response_is_not_mcp() {
        // These are exactly what an unrelated server answering /sse produces. None of them
        // may be accepted as MCP.
        assert!(parse_initialize_result("").is_none());
        assert!(parse_initialize_result("OK").is_none());
        assert!(parse_initialize_result("<html><body>404</body></html>").is_none());
        assert!(parse_initialize_result(r#"{"status":"ok"}"#).is_none());
        assert!(
            parse_initialize_result(r#"{"message":"Method Not Allowed"}"#).is_none(),
            "a 405 body must never confirm MCP"
        );
    }

    #[test]
    fn a_json_rpc_error_is_not_a_confirmation() {
        let err =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
        assert!(
            parse_initialize_result(err).is_none(),
            "a server that rejects initialize is not an MCP server"
        );
    }

    #[test]
    fn json_rpc_without_a_protocol_version_is_rejected() {
        // Something speaking JSON-RPC is still not necessarily MCP.
        let other = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
        assert!(parse_initialize_result(other).is_none());
    }

    #[test]
    fn tool_names_are_enumerated_from_a_list_result() {
        let body = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[
            {"name":"search","description":"..."},
            {"name":"fetch_url","inputSchema":{}},
            {"name":"search"}
        ]}}"#;
        assert_eq!(json_names(body), vec!["fetch_url", "search"]);
    }

    #[test]
    fn the_initialize_request_is_well_formed_json_rpc() {
        let request = mcp_initialize_request();
        assert!(request.contains("\"jsonrpc\":\"2.0\""));
        assert!(request.contains("\"method\":\"initialize\""));
        assert!(request.contains("\"protocolVersion\""));
        assert!(request.contains("\"clientInfo\""));
    }

    #[test]
    fn list_requests_use_the_documented_methods() {
        assert!(mcp_list_request(2, "tools/list").contains("\"method\":\"tools/list\""));
        assert!(mcp_list_request(3, "resources/list").contains("\"resources/list\""));
        assert!(mcp_list_request(4, "prompts/list").contains("\"prompts/list\""));
    }

    #[test]
    fn candidate_ports_schedule_work_without_asserting_anything() {
        // These are where AI software is commonly found; membership must never be treated
        // as evidence, which is why nothing in this module reads the port alone.
        assert!(AI_CANDIDATE_PORTS.contains(&11434));
        assert!(AI_CANDIDATE_PORTS.contains(&3000));
    }
}
