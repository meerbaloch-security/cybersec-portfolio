"""Self-contained interactive HTML report for attack-paths.

No external libraries or network requests: layout is computed in Python and
drawn as inline SVG, with a small script for highlighting paths and
simulating fixes. The file can be opened offline or attached to a ticket.
"""

from __future__ import annotations

import html
import json

COL_X = [110, 355, 605, 850, 1090]
COL_TITLES = ["Entry point", "Foothold", "Identity", "Privilege", "Crown jewels & data"]
COL_OF = {"entry": 0, "compute": 1, "identity": 2, "privilege": 3, "data": 4}
ROW_GAP = 66
TOP = 90
NODE_W, NODE_H = 186, 46


def layout(data: dict) -> dict[str, tuple[float, float]]:
    """Columns by asset type; rows ordered by a few barycenter passes to reduce crossings."""
    cols: dict[int, list[str]] = {i: [] for i in range(5)}
    for n in data["nodes"]:
        cols[COL_OF[n["kind"]]].append(n["id"])
    # sort data by sensitivity first so crown jewels sit together at the top
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}
    sens = {n["id"]: n.get("sensitivity") for n in data["nodes"]}
    cols[4].sort(key=lambda i: rank[sens[i]])
    neighbours: dict[str, list[str]] = {}
    for e in data["edges"]:
        neighbours.setdefault(e["dst"], []).append(e["src"])
        neighbours.setdefault(e["src"], []).append(e["dst"])
    pos = {nid: i for c in cols.values() for i, nid in enumerate(c)}
    for _ in range(6):
        for c in (1, 2, 3):
            cols[c].sort(key=lambda nid: sum(pos[x] for x in neighbours.get(nid, [nid])) /
                         max(1, len(neighbours.get(nid, []))))
            for i, nid in enumerate(cols[c]):
                pos[nid] = i
        cols[0].sort(key=lambda nid: sum(pos[x] for x in neighbours.get(nid, [nid])) / max(1, len(neighbours.get(nid, []))))
        for i, nid in enumerate(cols[0]):
            pos[nid] = i
    tallest = max(len(c) for c in cols.values())
    coords = {}
    for c, ids in cols.items():
        offset = (tallest - len(ids)) * ROW_GAP / 2
        for i, nid in enumerate(ids):
            coords[nid] = (COL_X[c], TOP + offset + i * ROW_GAP)
    return coords


def edge_path(s: tuple[float, float], d: tuple[float, float], same_or_back: bool) -> str:
    (x1, y1), (x2, y2) = s, d
    if not same_or_back:
        sx, ex = x1 + NODE_W / 2, x2 - NODE_W / 2
        mx = (sx + ex) / 2
        return f"M{sx:.0f},{y1:.0f} C{mx:.0f},{y1:.0f} {mx:.0f},{y2:.0f} {ex:.0f},{y2:.0f}"
    if abs(x1 - x2) < 1:  # same column: loop out to the right
        sx = x1 + NODE_W / 2
        bulge = sx + 60 + abs(y2 - y1) * 0.15
        return f"M{sx:.0f},{y1:.0f} C{bulge:.0f},{y1:.0f} {bulge:.0f},{y2:.0f} {sx:.0f},{y2:.0f}"
    # backward (lateral movement): leave from the bottom, arc under, enter from the bottom
    sy, ey = y1 + NODE_H / 2, y2 + NODE_H / 2
    dip = max(sy, ey) + 46
    return f"M{x1 - 30:.0f},{sy:.0f} C{x1 - 30:.0f},{dip:.0f} {x2 + 30:.0f},{dip:.0f} {x2 + 30:.0f},{ey:.0f}"


def clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n - 1].rstrip() + "…"


def on_paths_only(data: dict) -> dict:
    """Keep only assets and moves that are part of at least one attack path."""
    used_edges = {eid for p in data["paths"] for eid in p["edges"]}
    used_nodes = {p["entry"] for p in data["paths"]} | {e["dst"] for e in data["edges"] if e["id"] in used_edges}
    return {**data, "edges": [e for e in data["edges"] if e["id"] in used_edges],
            "nodes": [n for n in data["nodes"] if n["id"] in used_nodes]}


def render(data: dict) -> str:
    e = html.escape
    data = on_paths_only(data)
    coords = layout(data)
    s = data["summary"]
    height = max(y for _, y in coords.values()) + 120

    edges_svg = []
    for ed in data["edges"]:
        a, b = coords[ed["src"]], coords[ed["dst"]]
        back = COL_OF[next(n["kind"] for n in data["nodes"] if n["id"] == ed["src"])] >= \
            COL_OF[next(n["kind"] for n in data["nodes"] if n["id"] == ed["dst"])]
        tip = f"{ed['label']} [{ed['technique']}]\n{ed['evidence']}" + (f"\nFix: {ed['fix']}" if ed["fix"] else "")
        edges_svg.append(f'<path class="edge" data-id="{e(ed["id"])}" d="{edge_path(a, b, back)}" '
                         f'marker-end="url(#arrow)"><title>{e(tip)}</title></path>')

    nodes_svg = []
    for n in data["nodes"]:
        x, y = coords[n["id"]]
        cls = f"node k-{n['kind']}" + (f" s-{n['sensitivity']}" if n["kind"] == "data" else "") + \
              (" jewel" if n["crown_jewel"] else "")
        sub = n["detail"] if n["kind"] != "data" else f"{(n.get('sensitivity') or '').upper()} · {n['detail']}"
        nodes_svg.append(
            f'<g class="{cls}" data-id="{e(n["id"])}" transform="translate({x - NODE_W / 2:.0f},{y - NODE_H / 2:.0f})">'
            f'<rect width="{NODE_W}" height="{NODE_H}" rx="10"/>'
            f'<text x="12" y="19" class="nl">{e(clip(n["label"], 22))}</text>'
            f'<text x="12" y="35" class="ns">{e(clip(sub, 31))}</text><title>{e(n["label"])}: {e(n["detail"])}</title></g>')

    heads = "".join(f'<text x="{x}" y="38" class="colh" text-anchor="middle">{t.upper()}</text>'
                    for x, t in zip(COL_X, COL_TITLES))

    payload = json.dumps({"paths": data["paths"], "plan": data["fix_plan"],
                          "edges": {ed["id"]: ed for ed in data["edges"]},
                          "nodes": {n["id"]: n for n in data["nodes"]}}).replace("</", "<\\/")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack Path Report</title>
<style>
:root{{--bg:#0b1020;--panel:#111827;--panel2:#1a2234;--line:#263045;--text:#e5e7eb;--muted:#94a3b8;--red:#f43f5e;--amber:#f59e0b;--green:#22c55e;--blue:#38bdf8;--violet:#a78bfa}}
:root[data-theme="light"]{{--bg:#f6f7fb;--panel:#ffffff;--panel2:#f1f4f9;--line:#dde3ee;--text:#111827;--muted:#5b6478}}
@media (prefers-color-scheme: light){{:root:not([data-theme="dark"]){{--bg:#f6f7fb;--panel:#ffffff;--panel2:#f1f4f9;--line:#dde3ee;--text:#111827;--muted:#5b6478}}}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
.wrap{{max-width:1320px;margin:0 auto;padding:28px 16px 60px}}
h1{{margin:0;font-size:28px;letter-spacing:-.02em}} .muted{{color:var(--muted)}}
.hero{{margin:18px 0 20px;font-size:19px;max-width:900px}} .hero b{{color:var(--red)}} .hero em{{color:var(--green);font-style:normal;font-weight:700}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:18px}}
.kpi{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}}
.kpi .v{{font-size:30px;font-weight:800;letter-spacing:-.02em}} .kpi .l{{color:var(--muted);font-size:13px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px}}
.graph{{overflow-x:auto}} svg{{display:block;min-width:1000px;width:100%;height:auto}}
.colh{{fill:var(--muted);font-size:11px;letter-spacing:.12em;font-weight:700}}
.edge{{fill:none;stroke:#475569;stroke-width:1.6;opacity:.55;transition:all .2s}}
.edge.hot{{stroke:var(--red);stroke-width:3.2;opacity:1}} .edge.cut{{stroke:var(--green);stroke-dasharray:6 5;opacity:.9;stroke-width:2.4}}
.edge.dim{{opacity:.12}}
.node rect{{fill:var(--panel2);stroke:var(--line);stroke-width:1.4;transition:all .2s}}
.node .nl{{fill:var(--text);font-size:13px;font-weight:650}} .node .ns{{fill:var(--muted);font-size:10.5px}}
.k-entry rect{{stroke:var(--violet)}} .k-compute rect{{stroke:var(--blue)}} .k-identity rect{{stroke:#64748b}}
.k-privilege rect{{stroke:var(--amber);stroke-width:2}} .s-critical rect{{stroke:var(--red);stroke-width:2.2}} .s-high rect{{stroke:var(--amber);stroke-width:2}}
.jewel rect{{filter:drop-shadow(0 0 6px rgba(244,63,94,.45))}}
.node.hot rect{{stroke:var(--red);stroke-width:3}} .node.dim{{opacity:.3}} .node.safe rect{{stroke:var(--green);stroke-width:2.4;filter:none}}
.cols{{display:grid;grid-template-columns:1.25fr 1fr;gap:16px;margin-top:16px}}
@media (max-width:900px){{.cols{{grid-template-columns:1fr}}}}
h2{{font-size:16px;margin:2px 4px 10px}}
.path{{border:1px solid var(--line);border-radius:10px;padding:9px 11px;margin-bottom:8px;cursor:pointer;background:var(--panel2);transition:border-color .15s}}
.path:hover,.path.sel{{border-color:var(--red)}} .path.broken{{opacity:.45}} .path.broken .chain{{text-decoration:line-through}}
.path .top{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}} .chain{{font-size:13px;margin-top:3px}}
.badge{{font-size:11px;font-weight:700;border-radius:999px;padding:1px 8px;border:1px solid}}
.r-hi{{color:var(--red);border-color:var(--red)}} .r-md{{color:var(--amber);border-color:var(--amber)}} .r-lo{{color:var(--muted);border-color:var(--line)}}
.steps{{display:none;margin:8px 0 2px;padding-left:18px;color:var(--muted);font-size:12.5px}} .path.sel .steps{{display:block}}
.steps code{{color:var(--blue)}}
.fix{{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);border-radius:10px;padding:10px 11px;margin-bottom:8px;background:var(--panel2);cursor:pointer}}
.fix input{{margin-top:3px;accent-color:var(--green);width:16px;height:16px}} .fix.on{{border-color:var(--green)}}
.fix .n{{font-weight:800;color:var(--green);min-width:18px}}
.meter{{height:10px;background:var(--panel2);border:1px solid var(--line);border-radius:99px;overflow:hidden;margin:8px 0 4px}}
.meter div{{height:100%;width:0;background:linear-gradient(90deg,var(--green),#86efac);transition:width .3s}}
.btns{{display:flex;gap:8px;margin:6px 0 12px;flex-wrap:wrap}} button{{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:6px 12px;cursor:pointer;font:inherit}}
button:hover{{border-color:var(--green)}}
.legend{{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted);font-size:12px;margin:2px 4px 8px}} .legend span::before{{content:"";display:inline-block;width:18px;height:3px;margin-right:6px;vertical-align:middle;background:currentColor}}
.legend .l1{{color:var(--red)}} .legend .l2{{color:var(--green)}} .legend .l3{{color:#64748b}}
footer{{margin-top:22px;color:var(--muted);font-size:12px}}
</style></head><body><div class="wrap">
<div class="muted">attack-paths · {e(s['account'])}</div>
<h1>Attack Path Report</h1>
<p class="hero"><b>{s['attack_paths']} ways</b> for an attacker to reach <b>{len(s['crown_jewels_reachable'])} crown jewels</b>, the shortest in just
<b>{s['easiest_path_steps']} steps</b>. <em>{s['fixes_to_break_all']} fixes break every one of them</em>, and the first 3 remove
<em>{s['risk_removed_by_top3']}% of the risk</em>.</p>
<div class="kpis">
 <div class="kpi"><div class="v" style="color:var(--red)" id="k-paths">{s['attack_paths']}</div><div class="l">attack paths remaining</div></div>
 <div class="kpi"><div class="v">{len(s['crown_jewels_reachable'])}</div><div class="l">crown jewels reachable</div></div>
 <div class="kpi"><div class="v">{len(s['entry_points'])}</div><div class="l">entry points ({e(', '.join(s['entry_points']))})</div></div>
 <div class="kpi"><div class="v">{s['easiest_path_steps']}</div><div class="l">steps in the shortest path</div></div>
 <div class="kpi"><div class="v" style="color:var(--green)">{s['fixes_to_break_all']}</div><div class="l">fixes to break every path</div></div>
</div>
<div class="card graph">
 <div class="legend"><span class="l1">selected attack path</span><span class="l2">blocked by a fix</span><span class="l3">possible attacker move</span>
 <span style="color:var(--muted)">Hover any arrow or box for evidence.</span></div>
 <svg viewBox="0 0 1200 {height:.0f}" role="img" aria-label="Attack path graph">
  <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
  <path d="M0,0 L10,5 L0,10 z" fill="#64748b"/></marker></defs>
  {heads}{''.join(edges_svg)}{''.join(nodes_svg)}
 </svg>
</div>
<div class="cols">
 <div class="card"><h2>Attack paths <span class="muted" style="font-weight:400">· click one to trace it</span></h2><div id="paths"></div></div>
 <div class="card"><h2>Fix plan <span class="muted" style="font-weight:400">· tick fixes to simulate them</span></h2>
  <div class="btns"><button id="all">Apply all fixes</button><button id="none">Reset</button></div>
  <div class="meter"><div id="meter"></div></div><div class="muted" id="mtext"></div><div id="fixes" style="margin-top:10px"></div></div>
</div>
<footer>Generated offline by attack-paths. Effort scores are estimates: 1 = trivial, 6 = hard. ATT&amp;CK techniques link each step to MITRE ATT&amp;CK.
Fictional environment; vulnerability data (CVSS, EPSS, CISA KEV) from a live scan by vuln-prioritizer.</footer>
</div>
<script>
const D = {payload};
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const cut = new Set(); let selected = null;
const nodeLabel = id => D.nodes[id].label;
function riskClass(r) {{ return r >= 50 ? 'r-hi' : r >= 25 ? 'r-md' : 'r-lo'; }}
function renderPaths() {{
  $('#paths').innerHTML = D.paths.map((p, i) => {{
    const chain = [nodeLabel(p.entry), ...p.edges.map(id => nodeLabel(D.edges[id].dst))].join(' → ');
    const steps = p.edges.map(id => `<li>${{D.edges[id].label}} <code>${{D.edges[id].technique}}</code></li>`).join('');
    return `<div class="path" data-i="${{i}}"><div class="top"><span class="badge ${{riskClass(p.risk)}}">risk ${{p.risk}}</span>
      <span class="muted">${{p.likelihood}} · ${{p.edges.length}} steps · ${{nodeLabel(p.target)}}</span></div>
      <div class="chain">${{chain}}</div><ol class="steps">${{steps}}</ol></div>`;
  }}).join('');
  $$('.path').forEach(el => el.onclick = () => {{ const i = +el.dataset.i; selected = selected === i ? null : i; update(); }});
}}
function renderFixes() {{
  $('#fixes').innerHTML = D.plan.map((f, i) => `<label class="fix" data-e="${{f.edge}}"><input type="checkbox">
    <span class="n">${{i + 1}}</span><span>${{f.fix}}<br><span class="muted">breaks ${{f.paths_broken}} path(s) · ${{f.risk_removed_pct}}% of risk removed by fixes 1–${{i + 1}}</span></span></label>`).join('');
  $$('.fix').forEach(el => el.querySelector('input').onchange = ev => {{
    ev.target.checked ? cut.add(el.dataset.e) : cut.delete(el.dataset.e); update(); }});
}}
function update() {{
  const broken = D.paths.map(p => p.edges.some(e => cut.has(e)));
  const left = broken.filter(b => !b).length;
  const total = D.paths.reduce((a, p) => a + p.risk, 0);
  const riskLeft = D.paths.reduce((a, p, i) => a + (broken[i] ? 0 : p.risk), 0);
  $('#k-paths').textContent = left;
  $('#k-paths').style.color = left ? 'var(--red)' : 'var(--green)';
  $('#meter').style.width = (100 - Math.round(100 * riskLeft / total)) + '%';
  $('#mtext').textContent = left ? `${{100 - Math.round(100 * riskLeft / total)}}% of risk removed · ${{left}} of ${{D.paths.length}} paths still open`
                                 : 'All attack paths to crown jewels are broken.';
  $$('.path').forEach((el, i) => {{ el.classList.toggle('broken', broken[i]); el.classList.toggle('sel', selected === i); }});
  $$('.fix').forEach(el => el.classList.toggle('on', cut.has(el.dataset.e)));
  const hot = new Set(selected !== null ? D.paths[selected].edges : []);
  const hotNodes = new Set(selected !== null ? [D.paths[selected].entry, ...D.paths[selected].edges.map(e => D.edges[e].dst)] : []);
  const live = new Set(D.paths.filter((p, i) => !broken[i]).flatMap(p => p.edges));
  $$('.edge').forEach(el => {{ const id = el.dataset.id;
    el.classList.toggle('hot', hot.has(id)); el.classList.toggle('cut', cut.has(id));
    el.classList.toggle('dim', (selected !== null && !hot.has(id) && !cut.has(id)) || (cut.size && !live.has(id) && !cut.has(id) && !hot.has(id))); }});
  const jewelsLeft = new Set(D.paths.filter((p, i) => !broken[i]).map(p => p.target));
  $$('.node').forEach(el => {{ const id = el.dataset.id;
    el.classList.toggle('hot', hotNodes.has(id)); el.classList.toggle('dim', selected !== null && !hotNodes.has(id));
    el.classList.toggle('safe', cut.size > 0 && D.nodes[id].crown_jewel && !jewelsLeft.has(id)); }});
}}
$('#all').onclick = () => {{ D.plan.forEach(f => cut.add(f.edge)); $$('.fix input').forEach(c => c.checked = true); selected = null; update(); }};
$('#none').onclick = () => {{ cut.clear(); $$('.fix input').forEach(c => c.checked = false); selected = null; update(); }};
renderPaths(); renderFixes(); selected = 0; update();
</script></body></html>"""
