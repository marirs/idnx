//! Standalone, zero-dependency interactive HTML topology graph generator.
//!
//! Generates a self-contained HTML/SVG visualization of the network topology
//! with force-directed physics, interactive zooming/panning, and detailed
//! device metadata inspection panels without requiring internet access or CDN assets.

use crate::engine::deep::ChildNetworkResult;
use crate::engine::scanner::{HostResult, ScanSummary};
use crate::fingerprint::classifier::{DeviceRole, classify_host};
use ipnet::Ipv4Net;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize)]
struct GraphNode {
    id: String,
    label: String,
    role: String,
    category: String,
    ip: Option<String>,
    ipv6: Vec<String>,
    mac: Option<String>,
    vendor: Option<String>,
    hostname: Option<String>,
    ports: Vec<String>,
    details: Option<String>,
    color: String,
    radius: f32,
}

#[derive(Debug, Serialize)]
struct GraphLink {
    source: String,
    target: String,
    label: Option<String>,
}

#[derive(Debug, Serialize)]
struct GraphData {
    nodes: Vec<GraphNode>,
    links: Vec<GraphLink>,
}

/// Generates a standalone interactive HTML graph file
pub fn export_interactive_topology_html(
    target_cidr: &Ipv4Net,
    summary: &ScanSummary,
    child_networks: &[ChildNetworkResult],
    physical_switches: &[&str],
    output_path: &Path,
) -> Result<(), String> {
    let mut nodes = Vec::new();
    let mut links = Vec::new();

    // 1. Root Local Subnet Node
    let root_id = format!("net_{}", target_cidr);
    nodes.push(GraphNode {
        id: root_id.clone(),
        label: format!("Local Subnet\n{}", target_cidr),
        role: "Subnet".to_string(),
        category: "Network".to_string(),
        ip: None,
        ipv6: Vec::new(),
        mac: None,
        vendor: None,
        hostname: None,
        ports: Vec::new(),
        details: Some(format!("Primary active network: {}", target_cidr)),
        color: "#00f0ff".to_string(),
        radius: 28.0,
    });

    // 2. Add Physical Unmanaged Switches if documented
    let mut switch_parent_id = root_id.clone();
    for (idx, sw_name) in physical_switches.iter().enumerate() {
        let sw_id = format!("sw_{}", idx);
        nodes.push(GraphNode {
            id: sw_id.clone(),
            label: sw_name.to_string(),
            role: "Switch".to_string(),
            category: "Switch".to_string(),
            ip: None,
            ipv6: Vec::new(),
            mac: None,
            vendor: None,
            hostname: None,
            ports: Vec::new(),
            details: Some("Physical Layer 2 Switch".to_string()),
            color: "#f59e0b".to_string(),
            radius: 22.0,
        });

        links.push(GraphLink {
            source: switch_parent_id.clone(),
            target: sw_id.clone(),
            label: Some("Ethernet Trunk".to_string()),
        });
        switch_parent_id = sw_id;
    }

    let default_gw = crate::net::interface::detect_local_network().ok().and_then(|i| i.default_gateway);

    // 3. Add Local Network Hosts
    for host in &summary.active_hosts {
        let is_gw = default_gw.map(|gw| gw == host.ip).unwrap_or(false);
        let host_node = build_host_node(host, is_gw);
        let host_id = host_node.id.clone();
        nodes.push(host_node);

        links.push(GraphLink {
            source: switch_parent_id.clone(),
            target: host_id,
            label: None,
        });
    }

    // 4. Add Child & Downstream Networks
    for (c_idx, child) in child_networks.iter().enumerate() {
        let child_net_id = format!("child_net_{}_{}", c_idx, child.cidr);
        let child_label = if let Some(ref name) = child.snmp_system_name {
            format!("{}\n{}", name, child.cidr)
        } else {
            format!("Subnet\n{}", child.cidr)
        };

        nodes.push(GraphNode {
            id: child_net_id.clone(),
            label: child_label,
            role: "Cascaded Subnet".to_string(),
            category: "Network".to_string(),
            ip: child.parent_router_ip.map(|ip| ip.to_string()),
            ipv6: Vec::new(),
            mac: None,
            vendor: None,
            hostname: child.snmp_system_name.clone(),
            ports: Vec::new(),
            details: child.snmp_system_descr.clone(),
            color: "#ec4899".to_string(),
            radius: 26.0,
        });

        // Link child network to local subnet
        links.push(GraphLink {
            source: root_id.clone(),
            target: child_net_id.clone(),
            label: Some("Routed Gateway".to_string()),
        });

        // Add child network hosts
        for host in &child.summary.active_hosts {
            let is_gw = host.ip == child.gateway;
            let host_node = build_host_node(host, is_gw);
            let host_id = host_node.id.clone();
            nodes.push(host_node);

            links.push(GraphLink {
                source: child_net_id.clone(),
                target: host_id,
                label: None,
            });
        }
    }

    // Embed JSON data and assemble HTML page
    let graph_data = GraphData { nodes, links };
    let json_data = serde_json::to_string(&graph_data)
        .map_err(|e| format!("Failed to serialize graph data: {}", e))?;

    let html_content = generate_html_document(target_cidr, &json_data);

    let mut file = File::create(output_path)
        .map_err(|e| format!("Failed to create graph file {:?}: {}", output_path, e))?;
    file.write_all(html_content.as_bytes())
        .map_err(|e| format!("Failed to write graph file: {}", e))?;

    Ok(())
}

fn build_host_node(host: &HostResult, is_gateway: bool) -> GraphNode {
    let role = classify_host(host, is_gateway);

    let (color, category, radius) = match role {
        DeviceRole::GatewayRouter => ("#3b82f6", "Gateway Router", 24.0),
        DeviceRole::Switch => ("#f59e0b", "Switch", 22.0),
        DeviceRole::AiAgentRuntime => ("#8b5cf6", "AI Agent / LLM Runtime", 22.0),
        DeviceRole::Workstation => ("#10b981", "Workstation / PC", 18.0),
        DeviceRole::SmartDevice => ("#06b6d4", "Smart IoT Device", 16.0),
        DeviceRole::GenericHost => {
            if host.open_ports.is_empty() {
                ("#64748b", "Stealth / Firewalled", 15.0)
            } else {
                ("#94a3b8", "Endpoint", 16.0)
            }
        }
    };

    let label = if let Some(ref h) = host.hostname {
        format!("{}\n{}", h, host.ip)
    } else if let Some(ref v) = host.vendor {
        format!("{}\n{}", v, host.ip)
    } else {
        host.ip.to_string()
    };

    let ports_list: Vec<String> = host
        .open_ports
        .iter()
        .map(|p| format!("{}/{} ({:?})", p.port, p.service, p.status))
        .collect();

    let details = host
        .ai_runtime
        .as_ref()
        .map(|ai| format!("AI Runtime: {}", ai.summary_label()));

    GraphNode {
        id: format!("host_{}", host.ip),
        label,
        role: format!("{:?}", role),
        category: category.to_string(),
        ip: Some(host.ip.to_string()),
        ipv6: host.ipv6_addrs.iter().map(|ip| ip.to_string()).collect(),
        mac: host.mac_address.clone(),
        vendor: host.vendor.clone(),
        hostname: host.hostname.clone(),
        ports: ports_list,
        details,
        color: color.to_string(),
        radius,
    }
}

fn generate_html_document(target_cidr: &Ipv4Net, json_data: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>idNX Topology Graph - {target_cidr}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #0b0f19;
    color: #f1f5f9;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    overflow: hidden;
    height: 100vh;
    display: flex;
  }}
  #graph-container {{
    flex: 1;
    height: 100vh;
    position: relative;
  }}
  canvas {{
    width: 100%;
    height: 100%;
    display: block;
  }}
  #sidebar {{
    width: 380px;
    height: 100vh;
    background: rgba(15, 23, 42, 0.95);
    backdrop-filter: blur(12px);
    border-left: 1px solid rgba(255, 255, 255, 0.1);
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 16px;
    overflow-y: auto;
    box-shadow: -8px 0 24px rgba(0,0,0,0.5);
  }}
  .badge {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
  }}
  .card {{
    background: rgba(30, 41, 59, 0.7);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 8px;
    padding: 16px;
  }}
  .meta-row {{
    display: flex;
    justify-content: space-between;
    margin-bottom: 8px;
    font-size: 13px;
  }}
  .meta-label {{ color: #94a3b8; }}
  .meta-val {{ font-weight: 500; color: #f8fafc; word-break: break-all; }}
  .port-tag {{
    display: inline-block;
    background: rgba(14, 165, 233, 0.2);
    border: 1px solid rgba(14, 165, 233, 0.4);
    color: #38bdf8;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
    margin: 2px;
  }}
  .header-brand {{
    font-size: 20px;
    font-weight: 800;
    color: #00f0ff;
    letter-spacing: -0.5px;
  }}
  .legend {{
    position: absolute;
    bottom: 24px;
    left: 24px;
    background: rgba(15, 23, 42, 0.85);
    border: 1px solid rgba(255,255,255,0.1);
    padding: 12px 16px;
    border-radius: 8px;
    display: flex;
    gap: 16px;
    font-size: 12px;
    pointer-events: none;
  }}
  .legend-item {{ display: flex; align-items: center; gap: 6px; }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
</style>
</head>
<body>

<div id="graph-container">
  <canvas id="canvas"></canvas>
  <div class="legend">
    <div class="legend-item"><span class="legend-dot" style="background:#00f0ff"></span> Subnet</div>
    <div class="legend-item"><span class="legend-dot" style="background:#3b82f6"></span> Gateway</div>
    <div class="legend-item"><span class="legend-dot" style="background:#f59e0b"></span> Switch</div>
    <div class="legend-item"><span class="legend-dot" style="background:#8b5cf6"></span> Server</div>
    <div class="legend-item"><span class="legend-dot" style="background:#10b981"></span> Workstation</div>
    <div class="legend-item"><span class="legend-dot" style="background:#06b6d4"></span> IoT</div>
  </div>
</div>

<div id="sidebar">
  <div class="header-brand">⚡ idNX Network Map</div>
  <p style="font-size:12px; color:#94a3b8">Target Subnet: <strong style="color:#f8fafc">{target_cidr}</strong></p>

  <div id="details-view">
    <div class="card" style="text-align:center; color:#94a3b8; padding:32px 16px">
      Click on any node in the topology graph to inspect full hardware and port details.
    </div>
  </div>
</div>

<script>
const data = {json_data};
const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d');

let width, height;
function resize() {{
  width = canvas.width = canvas.parentElement.clientWidth;
  height = canvas.height = canvas.parentElement.clientHeight;
}}
window.addEventListener('resize', resize);
resize();

// Graph nodes setup
const nodes = data.nodes.map(n => ({{
  ...n,
  x: width / 2 + (Math.random() - 0.5) * 300,
  y: height / 2 + (Math.random() - 0.5) * 300,
  vx: 0,
  vy: 0
}}));

const nodeMap = new Map();
nodes.forEach(n => nodeMap.set(n.id, n));

const links = data.links.map(l => ({{
  ...l,
  source: nodeMap.get(l.source),
  target: nodeMap.get(l.target)
}})).filter(l => l.source && l.target);

// Force-directed simulation
function stepSimulation() {{
  // Center gravity
  nodes.forEach(n => {{
    n.vx += (width / 2 - n.x) * 0.0005;
    n.vy += (height / 2 - n.y) * 0.0005;
  }});

  // Node repulsion
  for (let i = 0; i < nodes.length; i++) {{
    for (let j = i + 1; j < nodes.length; j++) {{
      const a = nodes[i];
      const b = nodes[j];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const minDist = a.radius + b.radius + 60;
      if (dist < minDist) {{
        const force = (minDist - dist) / dist * 0.05;
        a.vx -= dx * force;
        a.vy -= dy * force;
        b.vx += dx * force;
        b.vy += dy * force;
      }}
    }}
  }}

  // Link attraction
  links.forEach(l => {{
    const dx = l.target.x - l.source.x;
    const dy = l.target.y - l.source.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const targetDist = 90;
    const force = (dist - targetDist) * 0.003;
    l.source.vx += dx * force;
    l.source.vy += dy * force;
    l.target.vx -= dx * force;
    l.target.vy -= dy * force;
  }});

  // Position update & friction
  nodes.forEach(n => {{
    n.vx *= 0.85;
    n.vy *= 0.85;
    n.x += n.vx;
    n.y += n.vy;
  }});
}}

// Rendering loop
let selectedNode = null;
function render() {{
  stepSimulation();
  ctx.clearRect(0, 0, width, height);

  // Draw links
  links.forEach(l => {{
    ctx.beginPath();
    ctx.moveTo(l.source.x, l.source.y);
    ctx.lineTo(l.target.x, l.target.y);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.15)';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    if (l.label) {{
      const midX = (l.source.x + l.target.x) / 2;
      const midY = (l.source.y + l.target.y) / 2;
      ctx.fillStyle = '#64748b';
      ctx.font = '10px sans-serif';
      ctx.fillText(l.label, midX + 4, midY - 4);
    }}
  }});

  // Draw nodes
  nodes.forEach(n => {{
    ctx.save();
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
    ctx.fillStyle = n.color;
    ctx.shadowColor = n.color;
    ctx.shadowBlur = selectedNode === n ? 20 : 8;
    ctx.fill();

    if (selectedNode === n) {{
      ctx.lineWidth = 3;
      ctx.strokeStyle = '#ffffff';
      ctx.stroke();
    }}
    ctx.restore();

    // Node label
    ctx.fillStyle = '#f8fafc';
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'center';
    const lines = n.label.split('\n');
    lines.forEach((line, idx) => {{
      ctx.fillText(line, n.x, n.y + n.radius + 14 + (idx * 12));
    }});
  }});

  requestAnimationFrame(render);
}}
render();

// Interaction: click selection
canvas.addEventListener('click', e => {{
  const rect = canvas.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;
  const mouseY = e.clientY - rect.top;

  let clicked = null;
  for (let n of nodes) {{
    const dx = mouseX - n.x;
    const dy = mouseY - n.y;
    if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 5) {{
      clicked = n;
      break;
    }}
  }}

  selectedNode = clicked;
  updateSidebar(clicked);
}});

function updateSidebar(node) {{
  const container = document.getElementById('details-view');
  if (!node) {{
    container.innerHTML = `<div class="card" style="text-align:center; color:#94a3b8; padding:32px 16px">Click on any node in the topology graph to inspect full hardware and port details.</div>`;
    return;
  }}

  let portsHtml = node.ports.length > 0 
    ? node.ports.map(p => `<span class="port-tag">${{p}}</span>`).join('') 
    : '<span style="color:#64748b; font-size:12px">None detected / Stealth mode</span>';

  container.innerHTML = `
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px">
        <h3 style="font-size:16px; font-weight:700">${{node.hostname || node.ip || node.label.replace('\n', ' ')}}</h3>
        <span class="badge" style="background:${{node.color}}22; color:${{node.color}}; border:1px solid ${{node.color}}">${{node.category}}</span>
      </div>

      ${{node.ip ? `<div class="meta-row"><span class="meta-label">IP Address:</span><span class="meta-val">${{node.ip}}</span></div>` : ''}}
      ${{node.ipv6 && node.ipv6.length > 0 ? `<div class="meta-row"><span class="meta-label">IPv6 Address:</span><span class="meta-val">${{node.ipv6.join('<br>')}}</span></div>` : ''}}
      ${{node.mac ? `<div class="meta-row"><span class="meta-label">MAC Address:</span><span class="meta-val">${{node.mac}}</span></div>` : ''}}
      ${{node.vendor ? `<div class="meta-row"><span class="meta-label">OUI Vendor:</span><span class="meta-val">${{node.vendor}}</span></div>` : ''}}
      ${{node.hostname ? `<div class="meta-row"><span class="meta-label">Hostname:</span><span class="meta-val">${{node.hostname}}</span></div>` : ''}}
      ${{node.details ? `<div class="meta-row"><span class="meta-label">System Info:</span><span class="meta-val">${{node.details}}</span></div>` : ''}}

      <div style="margin-top:12px; border-top:1px solid rgba(255,255,255,0.08); padding-top:12px">
        <span class="meta-label" style="display:block; margin-bottom:6px">Open Ports & Services:</span>
        <div style="display:flex; flex-wrap:wrap">${{portsHtml}}</div>
      </div>
    </div>
  `;
}}
</script>
</body>
</html>"#
    )
}
