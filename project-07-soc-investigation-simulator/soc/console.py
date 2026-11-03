"""Self-contained interactive SOC analyst console (single HTML file, no external requests)."""

from __future__ import annotations

import json

from .incidents import TACTIC_ORDER


def render(data: dict, validation: dict) -> str:
    win_rules = [r for r in validation["rules"]
                 if any(c["rule"] == r and c["alerts"] for c in validation["cells"]) or
                 r in {"powershell_encoded_command", "privileged_group_member_added"}]
    payload = json.dumps({"d": data, "v": validation, "tactics": TACTIC_ORDER, "winRules": win_rules},
                         default=str).replace("</", "<\\/")
    ev = data["evaluation"]
    va = validation["active"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Investigation Console</title>
<style>
:root{{--bg:#0a0f1c;--panel:#111827;--panel2:#172033;--line:#243047;--text:#e5e7eb;--muted:#94a3b8;--red:#f43f5e;--orange:#fb923c;--amber:#f59e0b;--green:#22c55e;--blue:#38bdf8;--violet:#a78bfa}}
:root[data-theme="light"]{{--bg:#f5f7fb;--panel:#fff;--panel2:#f1f4f9;--line:#dde3ee;--text:#0f172a;--muted:#5b6478}}
@media (prefers-color-scheme: light){{:root:not([data-theme="dark"]){{--bg:#f5f7fb;--panel:#fff;--panel2:#f1f4f9;--line:#dde3ee;--text:#0f172a;--muted:#5b6478}}}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
.wrap{{max-width:1400px;margin:0 auto;padding:22px 16px 60px}}
header{{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap}}
h1{{margin:0;font-size:24px;letter-spacing:-.02em}} .muted{{color:var(--muted)}} .small{{font-size:12px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0}}
.kpi{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px}}
.kpi .v{{font-size:26px;font-weight:800;letter-spacing:-.02em}} .kpi .l{{color:var(--muted);font-size:12px}}
.tabs{{display:flex;gap:6px;border-bottom:1px solid var(--line);margin-bottom:14px;flex-wrap:wrap}}
.tab{{background:none;border:0;color:var(--muted);padding:10px 14px;font:inherit;font-weight:600;cursor:pointer;border-bottom:2px solid transparent}}
.tab.on{{color:var(--text);border-color:var(--blue)}}
.view{{display:none}} .view.on{{display:block}}
.grid{{display:grid;grid-template-columns:360px 1fr;gap:14px}} @media (max-width:980px){{.grid{{grid-template-columns:1fr}}}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px}}
.inc{{border:1px solid var(--line);background:var(--panel2);border-radius:10px;padding:10px 12px;margin-bottom:8px;cursor:pointer}}
.inc.on{{border-color:var(--blue);box-shadow:0 0 0 1px var(--blue) inset}}
.inc .t{{font-weight:650;margin:3px 0 2px}}
.chip{{display:inline-block;font-size:11px;font-weight:700;border-radius:999px;padding:1px 8px;border:1px solid currentColor;margin-right:4px}}
.v-tp{{color:var(--red)}} .v-benign{{color:var(--green)}} .v-inc{{color:var(--amber)}}
.s-Critical{{color:var(--red)}} .s-High{{color:var(--orange)}} .s-Medium{{color:var(--amber)}} .s-Low,.s-Informational{{color:var(--muted)}}
h2{{font-size:20px;margin:4px 0 6px;letter-spacing:-.01em}} h3{{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:18px 0 8px}}
.chain{{display:flex;gap:3px;flex-wrap:wrap;margin:8px 0}} .chain span{{font-size:10.5px;padding:4px 6px;border-radius:6px;background:var(--panel2);color:var(--muted);border:1px solid var(--line)}}
.chain span.hit{{background:rgba(244,63,94,.15);color:var(--red);border-color:var(--red);font-weight:700}}
.chain span.last{{outline:2px solid var(--red)}}
.chain span.ok{{background:rgba(34,197,94,.12);color:var(--green);border-color:var(--green);font-weight:700}}
.tl{{position:relative;margin-left:8px;border-left:2px solid var(--line);padding-left:16px}}
.tl .e{{position:relative;margin-bottom:10px}} .tl .e::before{{content:"";position:absolute;left:-23px;top:5px;width:10px;height:10px;border-radius:50%;background:var(--muted)}}
.tl .e.alert::before{{background:var(--red)}} .tl .e.alert.ok::before{{background:var(--green)}}
.tl .time{{font:12px ui-monospace,monospace;color:var(--muted)}} .tl .ttl{{font-weight:650}} .tl .d{{color:var(--muted);font-size:12.5px;word-break:break-word}}
.tl .x{{color:var(--green);font-size:12px}}
.two{{display:grid;grid-template-columns:1fr 1fr;gap:12px}} @media (max-width:700px){{.two{{grid-template-columns:1fr}}}}
ul.ev{{margin:0;padding-left:18px}} ul.ev li{{margin:4px 0}}
.for li::marker{{color:var(--red)}} .against li::marker{{color:var(--green)}}
.box{{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:10px 12px}}
table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}} th{{color:var(--muted);font-size:12px;font-weight:600}}
code{{font:12px ui-monospace,monospace;background:var(--panel2);padding:1px 5px;border-radius:5px;word-break:break-all}}
.btn{{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:7px 12px;cursor:pointer;font:inherit}}
.btn:hover{{border-color:var(--blue)}}
.ents span{{display:inline-block;margin:2px 4px 2px 0;font:12px ui-monospace,monospace;background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:2px 7px}}
.matrix td,.matrix th{{text-align:center}} .matrix td:first-child,.matrix th:first-child{{text-align:left}}
.cell-TP{{background:rgba(34,197,94,.18);color:var(--green);font-weight:700}} .cell-FP{{background:rgba(244,63,94,.18);color:var(--red);font-weight:700}} .cell-FN{{background:rgba(245,158,11,.2);color:var(--amber)}}
dialog{{width:min(900px,94vw);max-height:88vh;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:14px;padding:0}}
dialog::backdrop{{background:rgba(0,0,0,.55)}} dialog pre{{margin:0;padding:16px;white-space:pre-wrap;font:12.5px/1.55 ui-monospace,monospace;max-height:70vh;overflow:auto}}
.dlgbar{{display:flex;gap:8px;justify-content:flex-end;padding:10px 12px;border-bottom:1px solid var(--line)}}
.callout{{border-left:3px solid var(--blue);padding:8px 12px;background:var(--panel2);border-radius:6px;margin:10px 0}}
</style></head><body><div class="wrap">
<header><div><div class="muted small">soc-sim · {data.get('company', '')} · 27 Oct 2026 · fictional environment</div>
<h1>SOC Investigation Console</h1></div>
<div class="muted small">Pipeline: telemetry → Sigma rules → correlation → incidents → verdict → report</div></header>
<div class="kpis">
 <div class="kpi"><div class="v">{data['events']}</div><div class="l">events ingested</div></div>
 <div class="kpi"><div class="v">{data['alerts']}</div><div class="l">alerts raised</div></div>
 <div class="kpi"><div class="v">{ev['total']}</div><div class="l">incidents after correlation</div></div>
 <div class="kpi"><div class="v" style="color:var(--red)">{sum(1 for i in data['incidents'] if i['verdict'] == 'True positive')}</div><div class="l">true positives (escalated)</div></div>
 <div class="kpi"><div class="v" style="color:var(--green)">{sum(1 for i in data['incidents'] if i['verdict'] == 'Benign')}</div><div class="l">benign, closed with justification</div></div>
 <div class="kpi"><div class="v" style="color:var(--amber)">{sum(1 for i in data['incidents'] if i['verdict'] == 'Inconclusive')}</div><div class="l">inconclusive (needs info)</div></div>
 <div class="kpi"><div class="v">{ev['correct']}/{ev['total']}</div><div class="l">verdicts match ground truth</div></div>
 <div class="kpi"><div class="v">{va['detected']}/{va['expected']}</div><div class="l">detections on real attack data, {va['false_positive_alerts']} FP</div></div>
</div>
<div class="tabs"><button class="tab on" data-v="incidents">Incidents</button><button class="tab" data-v="alerts">Alert queue</button>
<button class="tab" data-v="validation">Detection validation (real data)</button></div>

<section class="view on" id="v-incidents"><div class="grid"><div id="list"></div><div class="card" id="detail"></div></div></section>
<section class="view" id="v-alerts"><div class="card"><table id="alerts"></table></div></section>
<section class="view" id="v-validation"><div class="card" id="val"></div></section>
<footer class="muted small" style="margin-top:20px">All company names, users, IPs and domains are fictional (documentation IP ranges). Real-data validation uses
<a href="https://github.com/OTRF/Security-Datasets" style="color:var(--blue)">OTRF Security-Datasets</a> (MIT). Recommendations only: nothing is changed on any system.</footer>
</div>
<dialog id="dlg"><div class="dlgbar"><button class="btn" id="copy">Copy</button><button class="btn" id="dl">Download .md</button><button class="btn" id="close">Close</button></div><pre id="md"></pre></dialog>
<script>
const P = {payload};
const D = P.d, V = P.v;
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c]));
const md = s => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\\*\\*([^*]+)\\*\\*/g, '<b>$1</b>');
const vcls = v => v === 'True positive' ? 'v-tp' : v === 'Benign' ? 'v-benign' : 'v-inc';
const ORDER = {{'True positive':0,'Inconclusive':1,'Benign':2}};
let cur = D.incidents.map((x,i)=>i).sort((a,b)=> ORDER[D.incidents[a].verdict]-ORDER[D.incidents[b].verdict] || D.incidents[b].risk-D.incidents[a].risk || D.incidents[b].score-D.incidents[a].score)[0];
document.querySelectorAll('.tab').forEach(b => b.onclick = () => {{
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('on', x === b));
  document.querySelectorAll('.view').forEach(x => x.classList.toggle('on', x.id === 'v-' + b.dataset.v)); }});
function list() {{
  const idx = D.incidents.map((x,i)=>i).sort((a,b)=> ORDER[D.incidents[a].verdict]-ORDER[D.incidents[b].verdict] || D.incidents[b].risk-D.incidents[a].risk || D.incidents[b].score-D.incidents[a].score);
  $('#list').innerHTML = idx.map(i => {{ const x = D.incidents[i]; return `<div class="inc ${{i===cur?'on':''}}" data-i="${{i}}">
    <span class="chip ${{vcls(x.verdict)}}">${{x.verdict}}</span><span class="chip s-${{x.severity}}">${{x.severity}}</span>
    <div class="t">${{esc(x.title)}}</div><div class="muted small">${{x.id}} · ${{x.alerts.length}} alert(s) · ${{x.start.slice(11,16)}} UTC · confidence ${{x.confidence}}</div></div>`; }}).join('');
  document.querySelectorAll('.inc').forEach(el => el.onclick = () => {{ cur = +el.dataset.i; list(); detail(); }});
}}
function detail() {{
  const x = D.incidents[cur];
  const hitCls = x.verdict === 'Benign' ? 'ok' : 'hit';
  const chain = P.tactics.map(t => `<span class="${{x.tactics.includes(t)?hitCls:''}} ${{x.stage===t && x.verdict!=='Benign'?'last':''}}">${{t.replace('-', ' ')}}</span>`).join('');
  const ents = Object.entries(x.entities).flatMap(([k,vs]) => vs.map(v => `<span title="${{k}}">${{k}}: ${{esc(v)}}</span>`)).join('');
  const tl = x.timeline.map(t => `<div class="e ${{t.kind}} ${{t.explained?'ok':''}}"><div class="time">${{t.time}} · ${{t.kind==='alert'?'ALERT':'context'}}${{t.technique?' · '+esc(t.technique):''}}</div>
     <div class="ttl">${{esc(t.title)}}</div><div class="d">${{esc(t.detail.length>220?t.detail.slice(0,217)+'…':t.detail)}}</div>${{t.explained?`<div class="x">✓ ${{esc(t.explained)}}</div>`:''}}</div>`).join('');
  const li = a => a.length ? a.map(s => `<li>${{md(s)}}</li>`).join('') : '<li class="muted">None</li>';
  const tech = x.techniques.map(t => `<tr><td><a style="color:var(--blue)" href="https://attack.mitre.org/techniques/${{t.id.replace('.','/')}}/">${{t.id}}</a></td><td>${{esc(t.name)}}</td><td class="muted">${{esc(t.evidence)}} · ${{t.time}}</td></tr>`).join('');
  const recs = Object.entries(x.recommendations).map(([p,items]) => `<div class="box" style="margin-bottom:8px"><b>${{p}}</b><ol style="margin:6px 0 0;padding-left:20px">${{items.map(i=>`<li>${{md(i)}}</li>`).join('')}}</ol></div>`).join('');
  const iocs = x.iocs.length ? `<h3>Indicators of compromise</h3><div class="ents">${{x.iocs.map(i=>`<span>${{i.type}}: ${{esc(i.value)}}</span>`).join('')}}</div>` : '';
  $('#detail').innerHTML = `<div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;align-items:flex-start">
    <div><div class="muted small">${{x.id}} · ${{esc(x.status)}}</div><h2>${{esc(x.title)}}</h2>
    <span class="chip ${{vcls(x.verdict)}}">${{x.verdict}} · ${{x.confidence}} confidence</span><span class="chip s-${{x.severity}}">${{x.severity}} · risk ${{x.risk}}</span></div>
    <button class="btn" id="rep">📄 Incident report</button></div>
    <p>${{md(x.summary)}}</p><div class="ents">${{ents}}</div>
    <h3>ATT&amp;CK progression</h3><div class="chain">${{chain}}</div>
    <div class="two"><div><h3>Evidence for malicious activity</h3><ul class="ev for">${{li(x.evidence_for)}}</ul></div>
    <div><h3>Evidence against / benign explanations</h3><ul class="ev against">${{li(x.evidence_against)}}</ul></div></div>
    <h3>Enrichment</h3><ul class="ev">${{li(x.observations)}}</ul>
    <h3>Timeline</h3><div class="tl">${{tl}}</div>
    ${{tech?`<h3>MITRE ATT&amp;CK techniques</h3><table>${{tech}}</table>`:''}}
    <h3>Open questions and uncertainties</h3><ul class="ev">${{li(x.uncertainties)}}</ul>${{iocs}}
    <h3>Recommended actions</h3>${{recs}}`;
  $('#rep').onclick = () => {{ $('#md').textContent = x.report_markdown; $('#dlg').showModal(); }};
}}
function alerts() {{
  const rows = D.incidents.flatMap(x => x.alerts.map(a => ({{...a, inc: x}}))).sort((a,b) => a.time.localeCompare(b.time));
  const lv = l => ({{critical:'s-Critical',high:'s-High',medium:'s-Medium',low:'s-Low'}})[l]||'s-Low';
  $('#alerts').innerHTML = `<tr><th>Time</th><th>Severity</th><th>Alert</th><th>ATT&amp;CK</th><th>Incident</th><th>Triage</th></tr>` +
    rows.map(a => `<tr><td><code>${{a.time.slice(11,19)}}</code></td><td><span class="chip ${{lv(a.level)}}">${{a.level}}</span></td><td>${{esc(a.title)}}<div class="muted small">${{esc(a.rule)}}${{a.events>1?' · '+a.events+' events':''}}</div></td>
      <td class="small">${{a.techniques.join(', ')}}</td><td><a href="#" data-inc="${{D.incidents.indexOf(a.inc)}}" style="color:var(--blue)">${{a.inc.id}}</a></td>
      <td class="small">${{a.explained?'<span style="color:var(--green)">✓ '+esc(a.explained)+'</span>':'<span class="chip '+vcls(a.inc.verdict)+'">'+a.inc.verdict+'</span>'}}</td></tr>`).join('');
  document.querySelectorAll('[data-inc]').forEach(el => el.onclick = ev => {{ ev.preventDefault(); cur = +el.dataset.inc; list(); detail(); document.querySelector('[data-v=incidents]').click(); }});
}}
function validation() {{
  const ds = V.datasets;
  const head = '<tr><th>Rule</th>' + ds.map(d => `<th title="${{esc(d.name)}}">${{esc(d.technique.split(' ')[0])}}<div class="muted small" style="font-weight:400">${{esc(d.technique.split(' ').slice(1).join(' '))}}<br>${{d.events}} events</div></th>`).join('') + '</tr>';
  const rows = P.winRules.map(r => '<tr><td>' + esc(r) + (V.status[r]==='deprecated'?' <span class="chip s-Low">deprecated v1</span>':'') + '</td>' + ds.map(d => {{
    const c = V.cells.find(c => c.rule===r && c.dataset===d.name);
    const txt = {{TP:'✓ '+c.alerts, FP:'✗ '+c.alerts+' FP', FN:'missed', TN:'·'}}[c.kind];
    return `<td class="cell-${{c.kind}}" title="${{esc(c.samples.join('\\n'))}}">${{txt}}</td>`; }}).join('') + '</tr>').join('');
  $('#val').innerHTML = `<h2>Rules tested against real attack telemetry</h2>
   <p class="muted">${{ds.length}} OTRF Security-Datasets (${{V.total_events.toLocaleString()}} real Windows Security, Sysmon and PowerShell events), each recording one attack technique plus the lab's normal background activity.
   A rule firing on a dataset for a <i>different</i> technique is a false positive on real-world noise. Hover a cell to see what matched.</p>
   <div class="kpis"><div class="kpi"><div class="v" style="color:var(--green)">${{V.active.detected}}/${{V.active.expected}}</div><div class="l">expected detections</div></div>
   <div class="kpi"><div class="v">${{V.active.false_positive_alerts}}</div><div class="l">false-positive alerts (active rules)</div></div>
   <div class="kpi"><div class="v">${{V.active.missed}}</div><div class="l">missed</div></div></div>
   <div style="overflow-x:auto"><table class="matrix">${{head}}${{rows}}</table></div>
   <div class="callout"><b>Tuning story.</b> The first Run-key rule matched any registry path containing <code>\\\\Run</code>. On real data it raised
   ${{V.naive_run_key.false_positive_alerts}} false positives: <code>lsass.exe</code> writing <code>W32Time\\\\SecureTimeLimits\\\\RunTime</code>. The tuned rule matches
   <code>\\\\CurrentVersion\\\\Run\\\\</code> only: same detection, ${{V.tuned_run_key.false_positive_alerts}} false positives.</div>
   <div class="callout"><b>Data-quality finding.</b> In the LSASS dataset, Sysmon's <code>UtcTime</code> field is 16 hours away from the event's record time, so the same
   process start appeared twice. The pipeline uses record time and de-duplicates Sysmon 1 / Security 4688 by process ID.</div>`;
}}
$('#close').onclick = () => $('#dlg').close();
$('#copy').onclick = () => navigator.clipboard && navigator.clipboard.writeText($('#md').textContent);
$('#dl').onclick = () => {{ const x = D.incidents[cur]; const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([x.report_markdown], {{type:'text/markdown'}})); a.download = x.id + '.md'; a.click(); }};
list(); detail(); alerts(); validation();
</script></body></html>"""
