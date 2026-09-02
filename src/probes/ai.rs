//! AI Agent and Local LLM Runtime Prober.
//!
//! Provides zero-dependency, pure-Rust socket HTTP/1.1 interrogation of local LLM runtimes
//! (Ollama, LM Studio, vLLM, LocalAI), Model Context Protocol (MCP) servers, and AgentPin identities.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Identifies the category of detected AI runtime or agent interface
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiRuntimeType {
    Ollama,
    LmStudio,
    Vllm,
    LocalAi,
    McpServer,
    AgentPin,
    GenericLlm,
}

impl AiRuntimeType {
    pub fn display_name(&self) -> &'static str {
        match self {
            AiRuntimeType::Ollama => "Ollama",
            AiRuntimeType::LmStudio => "LM Studio",
            AiRuntimeType::Vllm => "vLLM",
            AiRuntimeType::LocalAi => "LocalAI",
            AiRuntimeType::McpServer => "Model Context Protocol (MCP)",
            AiRuntimeType::AgentPin => "AgentPin Agent",
            AiRuntimeType::GenericLlm => "LLM Inference Server",
        }
    }
}

/// Metadata and model inventory extracted from an active AI runtime
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiRuntimeInfo {
    pub runtime_type: AiRuntimeType,
    pub version: Option<String>,
    pub models: Vec<String>,
    pub mcp_endpoints: Vec<String>,
    pub agent_name: Option<String>,
    pub agent_description: Option<String>,
}

impl AiRuntimeInfo {
    pub fn summary_label(&self) -> String {
        let name = self
            .agent_name
            .as_deref()
            .unwrap_or(self.runtime_type.display_name());
        if !self.models.is_empty() {
            format!("{} (models: {})", name, self.models.join(", "))
        } else if let Some(ref ver) = self.version {
            format!("{} v{}", name, ver)
        } else {
            name.to_string()
        }
    }
}

/// Low-overhead HTTP/1.1 socket client over pure TcpStream
async fn http_get(
    ip: Ipv4Addr,
    port: u16,
    path: &str,
    timeout_duration: Duration,
) -> Option<(u16, String)> {
    let mut stream = timeout(timeout_duration, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         User-Agent: idnx/{}\r\n\
         Accept: application/json, text/event-stream, */*\r\n\
         Connection: close\r\n\r\n",
        path,
        ip,
        port,
        env!("CARGO_PKG_VERSION")
    );

    timeout(timeout_duration, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut response_bytes = Vec::with_capacity(4096);
    let mut buf = [0u8; 1024];

    let start = tokio::time::Instant::now();
    while start.elapsed() < timeout_duration && response_bytes.len() < 65536 {
        let remaining = timeout_duration.saturating_sub(start.elapsed());
        match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                response_bytes.extend_from_slice(&buf[..n]);
                // Stop early if header indicates not found or bad request
                if response_bytes.len() >= 12 && !response_bytes.starts_with(b"HTTP/1.") {
                    return None;
                }
            }
        }
    }

    if response_bytes.is_empty() {
        return None;
    }

    let response_str = String::from_utf8_lossy(&response_bytes);
    let mut lines = response_str.lines();
    let status_line = lines.next()?;

    // Parse status code from "HTTP/1.1 200 OK"
    let status_code: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let body = match response_str.find("\r\n\r\n") {
        Some(idx) => response_str[idx + 4..].to_string(),
        None => match response_str.find("\n\n") {
            Some(idx) => response_str[idx + 2..].to_string(),
            None => String::new(),
        },
    };

    Some((status_code, body))
}

// ---------------------------------------------------------------------------
// RESPONSE PARSERS
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct OllamaVersion {
    version: Option<String>,
}

#[derive(Deserialize)]
struct OllamaTags {
    models: Option<Vec<OllamaModel>>,
}

#[derive(Deserialize)]
struct OllamaModel {
    name: Option<String>,
    model: Option<String>,
}

/// Parses Ollama `/api/tags` and `/api/version` JSON
pub fn parse_ollama_tags(json_str: &str) -> Vec<String> {
    if let Ok(parsed) = serde_json::from_str::<OllamaTags>(json_str)
        && let Some(models) = parsed.models
    {
        return models
            .into_iter()
            .filter_map(|m| m.name.or(m.model))
            .collect();
    }
    Vec::new()
}

#[derive(Deserialize)]
struct OpenAiModelsResponse {
    data: Option<Vec<OpenAiModel>>,
}

#[derive(Deserialize)]
struct OpenAiModel {
    id: Option<String>,
}

/// Parses standard OpenAI `/v1/models` JSON
pub fn parse_openai_models(json_str: &str) -> Vec<String> {
    if let Ok(parsed) = serde_json::from_str::<OpenAiModelsResponse>(json_str)
        && let Some(models) = parsed.data
    {
        return models.into_iter().filter_map(|m| m.id).collect();
    }
    Vec::new()
}

#[derive(Deserialize)]
struct AgentPinManifest {
    name: Option<String>,
    description: Option<String>,
    version: Option<String>,
}

/// Parses AgentPin `/.well-known/agent-identity.json`
pub fn parse_agentpin_manifest(json_str: &str) -> Option<(String, Option<String>, Option<String>)> {
    let parsed: AgentPinManifest = serde_json::from_str(json_str).ok()?;
    let name = parsed.name?;
    Some((name, parsed.description, parsed.version))
}

// ---------------------------------------------------------------------------
// ACTIVE PROBES
// ---------------------------------------------------------------------------

/// Actively interrogates an open host for AI LLM runtimes, models, and MCP servers
pub async fn probe_ai_runtime(
    ip: Ipv4Addr,
    open_ports: &[u16],
    timeout_duration: Duration,
) -> Option<AiRuntimeInfo> {
    let probe_timeout = Duration::from_millis(timeout_duration.as_millis().min(500) as u64);

    // 1. Probe Ollama on port 11434
    if open_ports.contains(&11434)
        && let Some((status, body)) = http_get(ip, 11434, "/api/tags", probe_timeout).await
        && status == 200
    {
        let models = parse_ollama_tags(&body);
        let version =
            if let Some((_, ver_body)) = http_get(ip, 11434, "/api/version", probe_timeout).await {
                serde_json::from_str::<OllamaVersion>(&ver_body)
                    .ok()
                    .and_then(|v| v.version)
            } else {
                None
            };

        return Some(AiRuntimeInfo {
            runtime_type: AiRuntimeType::Ollama,
            version,
            models,
            mcp_endpoints: Vec::new(),
            agent_name: None,
            agent_description: None,
        });
    }

    // 2. Probe OpenAI-Compatible Runtimes (LM Studio on 1234, vLLM on 8000, LocalAI on 8080)
    for &port in &[1234, 8000, 8080, 5000] {
        if open_ports.contains(&port)
            && let Some((status, body)) = http_get(ip, port, "/v1/models", probe_timeout).await
            && status == 200
        {
            let models = parse_openai_models(&body);
            let runtime_type = match port {
                1234 => AiRuntimeType::LmStudio,
                8000 => AiRuntimeType::Vllm,
                8080 => AiRuntimeType::LocalAi,
                _ => AiRuntimeType::GenericLlm,
            };

            return Some(AiRuntimeInfo {
                runtime_type,
                version: None,
                models,
                mcp_endpoints: Vec::new(),
                agent_name: None,
                agent_description: None,
            });
        }
    }

    // 3. Probe MCP (Model Context Protocol) Streaming SSE Endpoints
    for &port in &[3000, 8000, 8080] {
        if open_ports.contains(&port)
            && let Some((status, _)) = http_get(ip, port, "/sse", probe_timeout).await
            && (status == 200 || status == 400 || status == 405)
        {
            return Some(AiRuntimeInfo {
                runtime_type: AiRuntimeType::McpServer,
                version: None,
                models: Vec::new(),
                mcp_endpoints: vec![format!("http://{}:{}/sse", ip, port)],
                agent_name: Some("MCP Server (SSE)".to_string()),
                agent_description: Some("Model Context Protocol streaming endpoint".to_string()),
            });
        }
    }

    // 4. Probe AgentPin Standard Identity on standard HTTP ports
    for &port in &[80, 443, 3000, 8080] {
        if open_ports.contains(&port)
            && let Some((status, body)) =
                http_get(ip, port, "/.well-known/agent-identity.json", probe_timeout).await
            && status == 200
            && let Some((name, desc, ver)) = parse_agentpin_manifest(&body)
        {
            return Some(AiRuntimeInfo {
                runtime_type: AiRuntimeType::AgentPin,
                version: ver,
                models: Vec::new(),
                mcp_endpoints: Vec::new(),
                agent_name: Some(name),
                agent_description: desc,
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// UNIT TESTS
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ollama_tags_synthetic() {
        let sample = r#"{
            "models": [
                {
                    "name": "deepseek-r1:7b",
                    "model": "deepseek-r1:7b",
                    "size": 4683075276
                },
                {
                    "name": "llama3.2:latest",
                    "model": "llama3.2:latest",
                    "size": 2019393189
                }
            ]
        }"#;

        let models = parse_ollama_tags(sample);
        assert_eq!(models.len(), 2);
        assert_eq!(models[0], "deepseek-r1:7b");
        assert_eq!(models[1], "llama3.2:latest");
    }

    #[test]
    fn test_parse_openai_models_synthetic() {
        let sample = r#"{
            "object": "list",
            "data": [
                {
                    "id": "qwen2.5-coder-32b-instruct",
                    "object": "model",
                    "created": 1700000000,
                    "owned_by": "lmstudio"
                }
            ]
        }"#;

        let models = parse_openai_models(sample);
        assert_eq!(models.len(), 1);
        assert_eq!(models[0], "qwen2.5-coder-32b-instruct");
    }

    #[test]
    fn test_parse_agentpin_manifest_synthetic() {
        let sample = r#"{
            "name": "SecurityResearchAgent",
            "description": "Autonomous threat hunter",
            "version": "1.2.0"
        }"#;

        let res = parse_agentpin_manifest(sample).unwrap();
        assert_eq!(res.0, "SecurityResearchAgent");
        assert_eq!(res.1.as_deref(), Some("Autonomous threat hunter"));
        assert_eq!(res.2.as_deref(), Some("1.2.0"));
    }
}
