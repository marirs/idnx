//! Standalone interactive HTML rendering of the topology graph.
//!
//! Self-contained: no CDN, no build step, no network access when opened. The page shows
//! the same graded topology as the terminal view — every node carries its kind, confidence
//! and the evidence behind it, and every edge names the relationship that created it.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::engine::orchestrator::{DiscoveryReport, is_virtual_network};
use crate::topology::graph::{NodeId, NodeKind};
use crate::topology::{Confidence, TopologyGraph};

#[derive(Serialize)]
struct GraphNode {
    id: String,
    label: String,
    kind: String,
    confidence: String,
    detail: Vec<String>,
    evidence: Vec<String>,
    color: String,
    radius: f32,
}

#[derive(Serialize)]
struct GraphLink {
    source: String,
    target: String,
    label: String,
    confidence: String,
}

#[derive(Serialize)]
struct GraphData {
    nodes: Vec<GraphNode>,
    links: Vec<GraphLink>,
    vantage: String,
    blind_to: Vec<String>,
    unavailable: Vec<String>,
}

/// Colour by node kind. Opaque boundaries are deliberately the most prominent: a router
/// that terminates visibility is the most operationally important thing on the map.
fn colour_for(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Router => "#38bdf8",
        NodeKind::Switch => "#a78bfa",
        NodeKind::Network => "#22c55e",
        NodeKind::Vlan => "#eab308",
        NodeKind::OpaqueBoundary => "#f97316",
        NodeKind::Interface => "#64748b",
        NodeKind::Service => "#94a3b8",
        NodeKind::Host => "#e2e8f0",
    }
}

fn radius_for(kind: NodeKind) -> f32 {
    match kind {
        NodeKind::Router | NodeKind::OpaqueBoundary => 24.0,
        NodeKind::Switch | NodeKind::Network => 20.0,
        NodeKind::Vlan => 16.0,
        _ => 12.0,
    }
}

fn node_key(id: &NodeId) -> String {
    match id {
        NodeId::Interface(n, realm) => format!("iface:{n}{}", realm.suffix()),
        NodeId::Network(n, realm) => format!("net:{n}{}", realm.suffix()),
        NodeId::Vlan(v, realm) => format!("vlan:{v}{}", realm.suffix()),
        NodeId::Device(d) => format!("dev:{d}"),
        NodeId::Service(a, p, realm) => format!("svc:{a}:{p}{}", realm.suffix()),
    }
}

fn build_data(report: &DiscoveryReport) -> GraphData {
    let graph: &TopologyGraph = &report.graph;
    let mut nodes = Vec::new();

    for node in graph.nodes() {
        // Services are attributes of a host rather than topology; they would triple the
        // node count without adding a relationship anyone navigates.
        if node.kind == NodeKind::Service {
            continue;
        }

        // Every value here is chosen by the device it describes, or by a peer. It is
        // neutralised on the way into the page, not trusted because it reached the graph.
        use crate::output::safe::text as safe;

        let mut detail: Vec<String> = Vec::new();
        if let Some(vendor) = &node.vendor {
            detail.push(format!("vendor: {}", safe(vendor)));
        }
        for addr in &node.addresses {
            detail.push(addr.to_string());
        }
        for capability in &node.capabilities {
            detail.push(format!("capability: {}", safe(capability)));
        }
        for signal in &node.role_signals {
            detail.push(format!("role: {}", safe(signal)));
        }
        for description in &node.descriptions {
            detail.push(safe(description));
        }
        if let Some(reason) = &node.opaque_reason {
            detail.push(format!("boundary: {}", safe(reason)));
        }
        if let NodeId::Network(net, realm) = &node.id {
            let ifaces = graph.interfaces_for_network(net);
            if is_virtual_network(&ifaces) {
                detail.push("virtual / VPN network".to_string());
            }
            if report.oversized_scopes.contains(net) {
                detail.push("too large to enumerate address by address".to_string());
            }
            // The observation domain is part of this network's identity: two peers can
            // each hold a 10.0.0.0/24, and the page must show them as two.
            if !realm.is_local() {
                detail.push(format!("observed in {}", realm.label()));
            }
        }

        // Same for every other node whose identity is domain-scoped, so a viewer can tell
        // two identical-looking nodes apart.
        for realm in [match &node.id {
            NodeId::Interface(_, realm) | NodeId::Vlan(_, realm) => Some(realm),
            NodeId::Service(_, _, realm) => Some(realm),
            _ => None,
        }]
        .into_iter()
        .flatten()
        {
            if !realm.is_local() {
                detail.push(format!("observed in {}", realm.label()));
            }
        }

        let mut evidence: Vec<String> = node
            .provenance
            .iter()
            .map(|p| format!("{} ({})", p.source.label(), p.confidence.label()))
            .collect();
        evidence.sort();
        evidence.dedup();

        nodes.push(GraphNode {
            id: node_key(&node.id),
            label: node.display_name(),
            kind: node.kind.label().to_string(),
            confidence: node.confidence.label().to_string(),
            detail,
            evidence,
            color: colour_for(node.kind).to_string(),
            radius: radius_for(node.kind),
        });
    }

    let known: std::collections::HashSet<String> = nodes.iter().map(|n| n.id.clone()).collect();
    let links: Vec<GraphLink> = graph
        .edges()
        .filter_map(|edge| {
            let source = node_key(&edge.from);
            let target = node_key(&edge.to);
            // Skip edges to nodes that were not rendered, which would otherwise leave the
            // force layout referencing ids that do not exist.
            if !known.contains(&source) || !known.contains(&target) {
                return None;
            }
            Some(GraphLink {
                source,
                target,
                label: edge.relationship.label().to_string(),
                confidence: edge.confidence.label().to_string(),
            })
        })
        .collect();

    GraphData {
        nodes,
        links,
        vantage: format!(
            "{} ({})",
            report.visibility.vantage.interface,
            report.visibility.vantage.kind.label()
        ),
        blind_to: report.visibility.blind_to.clone(),
        unavailable: report.visibility.unavailable.clone(),
    }
}

/// Writes a standalone interactive topology page.
pub fn export_interactive_topology_html(
    report: &DiscoveryReport,
    output_path: &Path,
) -> Result<(), String> {
    let data = build_data(report);
    let json =
        serde_json::to_string(&data).map_err(|e| format!("Graph serialisation failed: {e}"))?;

    let summary = {
        let g = &report.graph;
        let mut observed = 0;
        let mut advertised = 0;
        let mut inferred = 0;
        for node in g.nodes() {
            match node.confidence {
                Confidence::Observed => observed += 1,
                Confidence::Advertised => advertised += 1,
                Confidence::Inferred => inferred += 1,
                Confidence::UserSupplied => {}
            }
        }
        format!("{observed} observed &middot; {advertised} advertised &middot; {inferred} inferred")
    };

    // Embedded in a <script> block, so JSON quoting is not sufficient on its own: a device
    // named "</script>..." would close the block and have the rest parsed as markup.
    let html = PAGE_TEMPLATE
        .replace("{{DATA}}", &crate::output::safe::embeddable_json(&json))
        .replace("{{SUMMARY}}", &summary)
        .replace("{{VERSION}}", env!("CARGO_PKG_VERSION"));

    let mut file =
        File::create(output_path).map_err(|e| format!("Cannot create {output_path:?}: {e}"))?;
    file.write_all(html.as_bytes())
        .map_err(|e| format!("Cannot write {output_path:?}: {e}"))?;

    Ok(())
}

/// The page. A small hand-written force simulation keeps this dependency-free, which
/// matters because the output must open from a file with no network access.
const PAGE_TEMPLATE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>idNX topology</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background:#0f172a; color:#e2e8f0; }
  header { padding:14px 20px; border-bottom:1px solid #1e293b; display:flex; gap:18px;
           align-items:baseline; flex-wrap:wrap; }
  h1 { font-size:16px; margin:0; font-weight:600; }
  .meta { color:#94a3b8; font-size:12px; }
  main { display:flex; height:calc(100vh - 58px); }
  canvas { flex:1; display:block; cursor:grab; }
  aside { width:330px; border-left:1px solid #1e293b; padding:16px; overflow-y:auto; }
  aside h2 { font-size:13px; margin:0 0 8px; text-transform:uppercase; letter-spacing:.06em;
             color:#94a3b8; }
  .legend span { display:inline-flex; align-items:center; gap:6px; margin:0 10px 6px 0;
                 font-size:12px; }
  .dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
  .row { margin:2px 0; font-size:12px; color:#cbd5e1; word-break:break-word; }
  .warn { color:#fbbf24; font-size:12px; margin:3px 0; }
  .empty { color:#64748b; font-style:italic; }
  code { background:#1e293b; padding:1px 5px; border-radius:4px; font-size:11px; }
</style>
</head>
<body>
<header>
  <h1>idNX topology</h1>
  <span class="meta">v{{VERSION}}</span>
  <span class="meta">{{SUMMARY}}</span>
</header>
<main>
  <canvas id="c"></canvas>
  <aside>
    <h2>Vantage</h2>
    <div class="row" id="vantage"></div>
    <div id="limits"></div>
    <h2 style="margin-top:18px">Legend</h2>
    <div class="legend" id="legend"></div>
    <h2 style="margin-top:18px">Selection</h2>
    <div id="sel"><div class="empty">Click a node.</div></div>
  </aside>
</main>
<script>
const DATA = {{DATA}};
const canvas = document.getElementById('c');
const ctx = canvas.getContext('2d');

document.getElementById('vantage').textContent = DATA.vantage;
const limits = document.getElementById('limits');
for (const b of DATA.blind_to) {
  const d = document.createElement('div');
  d.className = 'warn'; d.textContent = 'Not visible: ' + b; limits.appendChild(d);
}
for (const u of DATA.unavailable) {
  const d = document.createElement('div');
  d.className = 'warn'; d.textContent = u; limits.appendChild(d);
}

const kinds = {};
for (const n of DATA.nodes) kinds[n.kind] = n.color;
const legend = document.getElementById('legend');
for (const [kind, color] of Object.entries(kinds)) {
  // The colour is ours, but the kind is a graph value; built rather than concatenated.
  const s = document.createElement('span');
  const dot = document.createElement('i');
  dot.className = 'dot';
  dot.style.background = color;
  s.appendChild(dot);
  s.appendChild(document.createTextNode(kind));
  legend.appendChild(s);
}

let W = 0, H = 0;
function resize() {
  const dpr = window.devicePixelRatio || 1;
  W = canvas.clientWidth; H = canvas.clientHeight;
  canvas.width = W * dpr; canvas.height = H * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
window.addEventListener('resize', () => { resize(); });

// Seed positions deterministically so the same topology lays out the same way twice.
let seed = 42;
function rnd() { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; }

const nodes = DATA.nodes.map(n => ({...n, x: 0, y: 0, vx: 0, vy: 0}));
const index = new Map(nodes.map((n, i) => [n.id, i]));
const links = DATA.links
  .map(l => ({...l, s: index.get(l.source), t: index.get(l.target)}))
  .filter(l => l.s !== undefined && l.t !== undefined);

resize();
for (const n of nodes) { n.x = W / 2 + (rnd() - 0.5) * W * 0.7; n.y = H / 2 + (rnd() - 0.5) * H * 0.7; }

let view = {x: 0, y: 0, k: 1};
let selected = null, dragging = null, panning = false, last = null;

function step() {
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      let dx = b.x - a.x, dy = b.y - a.y;
      let d2 = dx*dx + dy*dy || 0.01;
      if (d2 > 90000) continue;
      const f = 2400 / d2;
      const d = Math.sqrt(d2);
      const ux = dx/d, uy = dy/d;
      a.vx -= ux*f; a.vy -= uy*f; b.vx += ux*f; b.vy += uy*f;
    }
  }
  for (const l of links) {
    const a = nodes[l.s], b = nodes[l.t];
    const dx = b.x-a.x, dy = b.y-a.y;
    const d = Math.sqrt(dx*dx+dy*dy) || 0.01;
    const f = (d - 130) * 0.012;
    const ux = dx/d, uy = dy/d;
    a.vx += ux*f; a.vy += uy*f; b.vx -= ux*f; b.vy -= uy*f;
  }
  for (const n of nodes) {
    n.vx += (W/2 - n.x) * 0.0012;
    n.vy += (H/2 - n.y) * 0.0012;
    n.vx *= 0.86; n.vy *= 0.86;
    if (n !== dragging) { n.x += n.vx; n.y += n.vy; }
  }
}

function draw() {
  ctx.save();
  ctx.clearRect(0, 0, W, H);
  ctx.translate(view.x, view.y); ctx.scale(view.k, view.k);

  ctx.lineWidth = 1;
  for (const l of links) {
    const a = nodes[l.s], b = nodes[l.t];
    ctx.strokeStyle = l.confidence === 'observed' ? '#334155' : '#1e293b';
    ctx.setLineDash(l.confidence === 'advertised' || l.confidence === 'inferred' ? [4, 4] : []);
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
  }
  ctx.setLineDash([]);

  for (const n of nodes) {
    ctx.beginPath(); ctx.arc(n.x, n.y, n.radius, 0, Math.PI*2);
    ctx.fillStyle = n.color; ctx.fill();
    if (n === selected) { ctx.strokeStyle = '#fff'; ctx.lineWidth = 2.5; ctx.stroke(); }
    ctx.fillStyle = '#e2e8f0';
    ctx.font = '11px -apple-system, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(n.label, n.x, n.y + n.radius + 13);
  }
  ctx.restore();
}

function loop() { step(); draw(); requestAnimationFrame(loop); }
loop();

function at(ev) {
  const r = canvas.getBoundingClientRect();
  const x = (ev.clientX - r.left - view.x) / view.k;
  const y = (ev.clientY - r.top - view.y) / view.k;
  return nodes.find(n => (n.x-x)**2 + (n.y-y)**2 <= (n.radius+5)**2) || null;
}

canvas.addEventListener('mousedown', ev => {
  const n = at(ev);
  if (n) { dragging = n; selected = n; show(n); }
  else { panning = true; }
  last = {x: ev.clientX, y: ev.clientY};
});
window.addEventListener('mousemove', ev => {
  if (dragging) {
    const r = canvas.getBoundingClientRect();
    dragging.x = (ev.clientX - r.left - view.x) / view.k;
    dragging.y = (ev.clientY - r.top - view.y) / view.k;
  } else if (panning && last) {
    view.x += ev.clientX - last.x; view.y += ev.clientY - last.y;
    last = {x: ev.clientX, y: ev.clientY};
  }
});
window.addEventListener('mouseup', () => { dragging = null; panning = false; last = null; });
canvas.addEventListener('wheel', ev => {
  ev.preventDefault();
  const f = ev.deltaY < 0 ? 1.1 : 0.9;
  view.k = Math.max(0.15, Math.min(4, view.k * f));
}, {passive: false});

// Every value below is chosen by the device it describes, or by a federated peer.
// Built as elements with textContent rather than concatenated into innerHTML: a device
// named '<img src=x onerror=...>' would otherwise execute the moment its node is clicked.
// Escaping the JSON stops it terminating the script block; it does nothing about this.
function row(text, className) {
  const d = document.createElement('div');
  d.className = className || 'row';
  d.textContent = text;
  return d;
}

function labelled(label, value) {
  const d = document.createElement('div');
  d.className = 'row';
  d.appendChild(document.createTextNode(label));
  const code = document.createElement('code');
  code.textContent = value;
  d.appendChild(code);
  return d;
}

function show(n) {
  const el = document.getElementById('sel');
  el.replaceChildren();

  const title = document.createElement('div');
  title.className = 'row';
  const strong = document.createElement('strong');
  strong.textContent = n.label;
  title.appendChild(strong);
  el.appendChild(title);

  el.appendChild(labelled('kind: ', n.kind));
  el.appendChild(labelled('confidence: ', n.confidence));
  for (const d of n.detail) el.appendChild(row(d));

  if (n.evidence.length) {
    const heading = document.createElement('h2');
    heading.style.marginTop = '14px';
    heading.textContent = 'Evidence';
    el.appendChild(heading);
    for (const e of n.evidence) el.appendChild(row(e));
  }
}
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::orchestrator::{ScopeRun, VisibilityReport};
    use crate::providers::{Vantage, VantageKind};
    use crate::topology::TopologyEvidence;
    use crate::topology::evidence::{DeviceKey, EvidenceSource, Fact, RoleSignal};

    fn report() -> DiscoveryReport {
        let mut graph = TopologyGraph::new();
        let mac = DeviceKey::mac("aa:bb:cc:dd:ee:ff");
        for ev in [
            TopologyEvidence::new(
                Fact::Network {
                    prefix: "10.0.0.0/24".parse().unwrap(),
                },
                EvidenceSource::KernelRoute,
                Confidence::Observed,
                "eth0",
            ),
            TopologyEvidence::new(
                Fact::DeviceAddress {
                    device: mac.clone(),
                    address: "10.0.0.1".parse().unwrap(),
                },
                EvidenceSource::ArpCache,
                Confidence::Observed,
                "eth0",
            ),
            TopologyEvidence::new(
                Fact::GatewayFor {
                    device: mac.clone(),
                    network: "10.0.0.0/24".parse().unwrap(),
                },
                EvidenceSource::KernelRoute,
                Confidence::Observed,
                "eth0",
            ),
            TopologyEvidence::new(
                Fact::DeviceRoleSignal {
                    device: mac,
                    signal: RoleSignal::DefaultGateway,
                },
                EvidenceSource::DefaultGateway,
                Confidence::Observed,
                "eth0",
            ),
        ] {
            graph.absorb(ev);
        }
        graph.finalize_roles();

        DiscoveryReport {
            graph,
            scope_runs: vec![ScopeRun {
                scope: None,
                runs: Vec::new(),
            }],
            pivot_runs: Vec::new(),
            coverage: Vec::new(),
            enrichment_elapsed: std::time::Duration::ZERO,
            enrichment_sequential_equivalent: std::time::Duration::ZERO,
            probes_attempted: 0,
            visibility: VisibilityReport {
                vantage: Vantage {
                    interface: "eth0".to_string(),
                    kind: VantageKind::Wired,
                    index: 0,
                    capture_available: true,
                },
                blind_to: vec!["switched unicast".to_string()],
                unavailable: Vec::new(),
                binding_mode: crate::net::socket::BindingMode::SourceAddress,
                observed_frames: Some(7),
                accepted_facts: Some(3),
            },
            oversized_scopes: Vec::new(),
            converged: true,
        }
    }

    #[test]
    fn the_page_never_builds_markup_from_graph_values() {
        // Escaping the embedded JSON stops a hostile name terminating the script block. It
        // does nothing about the name being concatenated into markup afterwards, which is
        // what made a device called "<img src=x onerror=...>" execute on click.
        assert!(
            !PAGE_TEMPLATE.contains("innerHTML ="),
            "graph values must be set as text, not parsed as markup"
        );
        assert!(PAGE_TEMPLATE.contains("textContent"));
    }

    #[test]
    fn graph_data_keeps_kinds_relationships_and_confidence() {
        let data = build_data(&report());

        assert!(data.nodes.iter().any(|n| n.kind == "router"));
        assert!(data.nodes.iter().any(|n| n.kind == "network"));
        assert!(data.links.iter().any(|l| l.label == "gateway for"));
        assert!(data.links.iter().all(|l| !l.confidence.is_empty()));
    }

    #[test]
    fn every_link_references_a_rendered_node() {
        // A dangling id would break the force layout silently.
        let data = build_data(&report());
        let ids: std::collections::HashSet<&str> =
            data.nodes.iter().map(|n| n.id.as_str()).collect();
        for link in &data.links {
            assert!(ids.contains(link.source.as_str()));
            assert!(ids.contains(link.target.as_str()));
        }
    }

    #[test]
    fn page_is_self_contained_and_writes() {
        let path = std::env::temp_dir().join("idnx_graph_test.html");
        export_interactive_topology_html(&report(), &path).expect("writes");
        let html = std::fs::read_to_string(&path).unwrap();

        assert!(html.contains("idNX topology"));
        assert!(html.contains("\"kind\":\"router\""));
        // No external resource may be referenced: the page must open offline.
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        assert!(!html.contains("{{DATA}}"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn vantage_limits_reach_the_page() {
        let data = build_data(&report());
        assert_eq!(data.vantage, "eth0 (wired)");
        assert!(!data.blind_to.is_empty());
    }
}
