from __future__ import annotations

import json
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any

from .dashboard import DashboardServer
from .lifecycle_repository import IncidentLifecycleRepository
from .retention_health import assess_retention_health
from .storage import SentinelStore


class QuietWardDashboardServer(DashboardServer):
    """QuietWard v0.5 local read-only operations and incident dashboard."""

    @staticmethod
    def _coverage(store: SentinelStore) -> dict[str, Any] | None:
        raw = store.get_metadata("last_coverage_report")
        if not raw:
            return None
        try:
            value = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict):
            return None
        value["actions_executed"] = 0
        return value

    @staticmethod
    def _overview(store: SentinelStore, limit: int) -> dict[str, Any]:
        value = DashboardServer._overview(store, limit)
        lifecycle = IncidentLifecycleRepository(store.connection)
        value["lifecycle"] = lifecycle.summary()
        value["incidents"] = lifecycle.recent_incidents(limit=limit)
        value["lifecycle_transitions"] = lifecycle.recent_transitions(min(limit, 100))
        value["coverage"] = QuietWardDashboardServer._coverage(store)
        value["retention"] = assess_retention_health(store.settings, value["summary"]).to_dict()
        value["product"] = "QuietWard"
        value["dashboard_mode"] = "read_only"
        value["actions_executed"] = 0
        return value

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urllib.parse.urlparse(handler.path)
        if parsed.path not in {
            "/api/incidents",
            "/api/lifecycle",
            "/api/coverage",
            "/api/retention",
        }:
            super()._handle(handler)
            return

        if not self._authorized(handler):
            self._json(handler, HTTPStatus.UNAUTHORIZED, {"error": "unauthorized", "actions_executed": 0})
            return

        query = urllib.parse.parse_qs(parsed.query)
        try:
            limit = min(500, max(1, int(query.get("limit", ["100"])[0])))
        except (TypeError, ValueError):
            self._json(handler, HTTPStatus.BAD_REQUEST, {"error": "limit must be an integer", "actions_executed": 0})
            return
        active_only = str(query.get("active", ["0"])[0]).casefold() in {"1", "true", "yes"}

        with SentinelStore(self.storage) as store:
            lifecycle = IncidentLifecycleRepository(store.connection)
            if parsed.path == "/api/incidents":
                result = {
                    "summary": lifecycle.summary(),
                    "incidents": lifecycle.recent_incidents(limit=limit, active_only=active_only),
                    "actions_executed": 0,
                }
            elif parsed.path == "/api/lifecycle":
                result = {
                    "summary": lifecycle.summary(),
                    "transitions": lifecycle.recent_transitions(limit),
                    "actions_executed": 0,
                }
            elif parsed.path == "/api/coverage":
                result = {"coverage": self._coverage(store), "actions_executed": 0}
            else:
                storage_summary = store.summary()
                result = assess_retention_health(store.settings, storage_summary).to_dict()
        self._json(handler, HTTPStatus.OK, result)

    @staticmethod
    def _html() -> str:
        return r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QuietWard</title>
<style>
:root{color-scheme:dark;--bg:#0a0f18;--panel:#111927;--panel2:#172235;--line:#28374d;--text:#eff5ff;--muted:#9eacc1;--good:#56d68c;--warn:#f2c45d;--bad:#ff7182;--accent:#78a9ff;--quiet:#6d7f99}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#15213a 0,#0a0f18 42%);font-family:Inter,Segoe UI,Arial,sans-serif;color:var(--text)}
header{position:sticky;top:0;z-index:5;background:rgba(10,15,24,.94);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.wrap{max-width:1280px;margin:auto;padding:18px}.brand{display:flex;align-items:center;justify-content:space-between;gap:16px}.brand h1{margin:0;font-size:24px}.brand p{margin:4px 0 0;color:var(--muted);font-size:13px}
.pill{padding:8px 12px;border:1px solid var(--line);border-radius:999px;background:var(--panel);font-size:13px}.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}.muted{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:16px 0}.card,.panel{background:rgba(17,25,39,.96);border:1px solid var(--line);border-radius:15px;box-shadow:0 14px 36px rgba(0,0,0,.18)}.card{padding:14px;min-height:100px}.label{font-size:12px;color:var(--muted)}.value{font-size:25px;font-weight:750;margin-top:8px}.sub{font-size:12px;color:var(--muted);margin-top:6px;line-height:1.4}
.panel{padding:17px;margin:13px 0}.panel h2{font-size:17px;margin:0 0 12px}.panel-head{display:flex;justify-content:space-between;gap:10px;align-items:center}.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 12px}button,select{border:1px solid var(--line);border-radius:8px;background:var(--panel2);color:var(--text);padding:8px 10px}button{cursor:pointer}button:hover{border-color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:9px 7px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}.sev{font-weight:700;text-transform:uppercase;font-size:11px}.sev-critical{color:#ff4963}.sev-high{color:var(--bad)}.sev-medium{color:var(--warn)}.sev-low,.sev-info{color:var(--good)}
.state{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 7px;font-size:11px}.state-new{color:var(--accent)}.state-changed{color:var(--warn)}.state-recurring{color:#c2a3ff}.state-resolved{color:var(--good)}
.coverage-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:9px}.domain{padding:10px;border:1px solid var(--line);border-radius:10px;background:var(--panel2)}.domain strong{display:block;font-size:13px}.domain span{font-size:11px;color:var(--muted)}.domain-complete{border-color:#285b43}.domain-degraded,.domain-not_due{border-color:#6d5930}.domain-disabled{opacity:.7}
.retention{display:grid;grid-template-columns:repeat(5,1fr);gap:9px}.meter{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:10px}.bar{height:6px;background:#26344a;border-radius:999px;overflow:hidden;margin-top:7px}.fill{height:100%;background:var(--accent)}.fill.warnfill{background:var(--warn)}
.error{padding:9px 10px;border:1px solid #61303d;background:#321824;color:#ffdce1;border-radius:9px;margin:7px 0}.empty{padding:14px 0;color:var(--muted)}.safety{display:flex;gap:10px;align-items:flex-start}.safety strong{color:var(--good)}
.drawer{position:fixed;inset:0;display:none;background:rgba(0,0,0,.65);z-index:20;padding:20px}.drawer.open{display:flex;justify-content:flex-end}.drawer-card{width:min(720px,100%);height:100%;overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:15px;padding:18px}.drawer-head{display:flex;justify-content:space-between;gap:10px}.drawer pre{white-space:pre-wrap;background:#080e17;padding:12px;border-radius:9px;overflow:auto;font-size:12px}
@media(max-width:1080px){.grid{grid-template-columns:repeat(3,1fr)}.coverage-grid{grid-template-columns:repeat(2,1fr)}.retention{grid-template-columns:repeat(3,1fr)}}@media(max-width:700px){.grid{grid-template-columns:repeat(2,1fr)}.coverage-grid,.retention{grid-template-columns:1fr}.brand{align-items:flex-start;flex-direction:column}table{display:block;overflow:auto}}@media(max-width:460px){.grid{grid-template-columns:1fr}.wrap{padding:13px}}
</style>
</head>
<body>
<header><div class="wrap brand"><div><h1>QuietWard</h1><p>Local, observation-only security monitoring · v0.5 development dashboard</p></div><div id="overall" class="pill">Loading…</div></div></header>
<main class="wrap">
<section class="grid">
<div class="card"><div class="label">Last observation</div><div id="last" class="value" style="font-size:15px">—</div><div class="sub">Most recent persisted cycle</div></div>
<div class="card"><div class="label">Active incidents</div><div id="active" class="value">—</div><div id="life-sub" class="sub">—</div></div>
<div class="card"><div class="label">Monitoring coverage</div><div id="coverage" class="value" style="font-size:18px">—</div><div id="coverage-sub" class="sub">—</div></div>
<div class="card"><div class="label">Evidence integrity</div><div id="evidence" class="value" style="font-size:18px">—</div><div class="sub">Signed local observation chain</div></div>
<div class="card"><div class="label">Retention pressure</div><div id="retention-state" class="value" style="font-size:18px">—</div><div id="retention-sub" class="sub">—</div></div>
<div class="card"><div class="label">Actions executed</div><div id="actions" class="value good">0</div><div class="sub">Dashboard and monitor remain read-only</div></div>
</section>
<section class="panel"><div class="panel-head"><h2>Incident lifecycle</h2><button id="refresh">Refresh</button></div><div id="incidents"></div></section>
<section class="panel"><h2>Monitoring coverage</h2><div id="coverage-domains" class="coverage-grid"></div></section>
<section class="panel"><h2>Findings</h2><div class="toolbar"><select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select><select id="review"><option value="">All review states</option><option>open</option><option>acknowledged</option><option>expected</option><option>resolved</option><option>suppressed</option></select></div><div id="findings"></div></section>
<section class="panel"><h2>Collector and Defender context</h2><div id="collector"></div><div id="collector-errors"></div><div id="defender"></div></section>
<section class="panel"><h2>Bounded local retention</h2><div id="retention" class="retention"></div></section>
<section class="panel safety"><strong>Observation only.</strong><span class="muted">QuietWard does not quarantine files, stop processes, change firewall rules, isolate the host, or execute remediation from this dashboard.</span></section>
</main>
<div id="drawer" class="drawer"><div class="drawer-card"><div class="drawer-head"><h2 id="drawer-title">Finding</h2><button id="close">Close</button></div><div id="drawer-body"></div></div></div>
<script>
const app={data:null};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=v=>v?new Date(v).toLocaleString():'—';
const sevClass=s=>'sev sev-'+esc((s||'info').toLowerCase());
function activeReview(f){const state=(f.review||{}).state||'open';return !['resolved','expected','suppressed'].includes(state)}
function renderTop(d){const s=d.summary||{},life=d.lifecycle||{},chain=s.evidence_chain||{},cov=d.coverage,ret=d.retention||{};
 document.getElementById('last').textContent=fmt((s.last_cycle||{}).completed_at);
 document.getElementById('active').textContent=life.active??0;document.getElementById('life-sub').textContent=`${life.incidents??0} tracked · ${life.transitions??0} retained transitions`;
 const c=document.getElementById('coverage');const safe=cov&&cov.resolution_safe===true;c.textContent=!cov?'No report':safe?'Complete':'Review needed';c.className='value '+(!cov?'muted':safe?'good':'warn');document.getElementById('coverage-sub').textContent=!cov?'Waiting for a completed service cycle':`${cov.degraded_count||0} degraded/not-due domain(s)`;
 const e=document.getElementById('evidence');e.textContent=chain.valid===false?'Invalid':'Valid';e.className='value '+(chain.valid===false?'bad':'good');
 const reached=ret.caps_reached||[];const rs=document.getElementById('retention-state');rs.textContent=reached.length?'Pruning active':'Within bounds';rs.className='value '+(reached.length?'warn':'good');document.getElementById('retention-sub').textContent=reached.length?reached.join(', '):`${ret.retention_days??'—'} day age window`;
 document.getElementById('actions').textContent=d.actions_executed??0;
 const urgent=(d.findings||[]).some(f=>activeReview(f)&&['critical','high'].includes(f.severity));const badChain=chain.valid===false;const overall=document.getElementById('overall');overall.textContent=badChain?'Evidence problem':urgent?'Review findings':(!cov||!safe)?'Coverage review':'Monitoring normally';overall.className='pill '+(badChain?'bad':urgent||!safe?'warn':'good');}
function renderIncidents(d){const rows=(d.incidents||[]).slice(0,100);const el=document.getElementById('incidents');if(!rows.length){el.innerHTML='<div class="empty">No lifecycle incidents recorded yet.</div>';return;}el.innerHTML='<table><thead><tr><th>State</th><th>Severity</th><th>Incident</th><th>First seen</th><th>Last seen</th><th>Cycles</th><th>Occurrences</th></tr></thead><tbody>'+rows.map(r=>`<tr><td><span class="state state-${esc(r.state)}">${esc(r.state)}</span></td><td class="${sevClass((r.incident||{}).severity)}">${esc((r.incident||{}).severity)}</td><td><code>${esc((r.incident||{}).incident_key)}</code></td><td>${esc(fmt(r.first_seen))}</td><td>${esc(fmt(r.last_seen))}</td><td>${esc(r.cycles_seen)}</td><td>${esc(r.occurrences)}</td></tr>`).join('')+'</tbody></table>';}
function renderCoverage(d){const cov=d.coverage;const el=document.getElementById('coverage-domains');if(!cov){el.innerHTML='<div class="empty">Coverage details will appear after the service completes a cycle.</div>';return;}el.innerHTML=(cov.domains||[]).map(x=>`<div class="domain domain-${esc(x.state)}"><strong>${esc(x.name)}</strong><span>${esc(x.state)}${x.reason_code?' · '+esc(x.reason_code):''}${x.issue_count?' · '+esc(x.issue_count)+' issue(s)':''}</span></div>`).join('');}
function renderFindings(d){let rows=d.findings||[];const sev=document.getElementById('severity').value,review=document.getElementById('review').value;if(sev)rows=rows.filter(x=>x.severity===sev);if(review)rows=rows.filter(x=>((x.review||{}).state||'open')===review);const el=document.getElementById('findings');if(!rows.length){el.innerHTML='<div class="empty">No findings match the current filters.</div>';return;}el.innerHTML='<table><thead><tr><th>Severity</th><th>Finding</th><th>Score</th><th>Review</th><th>Observed</th></tr></thead><tbody>'+rows.map(f=>`<tr data-id="${esc(f.finding_id)}"><td class="${sevClass(f.severity)}">${esc(f.severity)}</td><td><button class="finding" data-id="${esc(f.finding_id)}">${esc(f.title||f.finding_id)}</button><div class="sub">${esc(f.summary||'')}</div></td><td>${esc(f.score)}</td><td>${esc((f.review||{}).state||'open')}</td><td>${esc(fmt(f.created_at))}</td></tr>`).join('')+'</tbody></table>';document.querySelectorAll('button.finding').forEach(b=>b.onclick=()=>openFinding(b.dataset.id));}
function renderCollector(d){const c=d.collector||{};document.getElementById('collector').innerHTML=`<div class="sub">Collector: ${esc(c.version||'not yet available')} · observed ${esc(fmt(c.observed_at))}</div>`;const errs=d.collector_errors||[];document.getElementById('collector-errors').innerHTML=errs.length?errs.map(e=>`<div class="error">${esc(e)}</div>`).join(''):'<div class="sub good">No collector warnings in the latest snapshot.</div>';const defender=c.microsoft_defender;document.getElementById('defender').innerHTML=defender?`<div class="sub">Microsoft Defender · antivirus ${defender.antivirus_enabled===false?'disabled':'enabled'} · real-time ${defender.real_time_protection_enabled===false?'disabled':'enabled'} · active threats ${esc(defender.active_threat_count||0)}</div>`:'<div class="sub">Microsoft Defender context unavailable or not applicable.</div>';}
function renderRetention(d){const ret=d.retention||{},el=document.getElementById('retention');const rows=ret.capacities||[];if(!rows.length){el.innerHTML='<div class="empty">Retention metrics unavailable.</div>';return;}el.innerHTML=rows.map(x=>{const pct=Math.round((x.utilization||0)*100);return `<div class="meter"><div class="label">${esc(x.name)}</div><strong>${esc(x.current)} / ${esc(x.limit)}</strong><div class="bar"><div class="fill ${pct>=90?'warnfill':''}" style="width:${Math.min(100,pct)}%"></div></div><div class="sub">${pct}% utilized</div></div>`}).join('');}
async function openFinding(id){if(!id)return;try{const r=await fetch('/api/finding?id='+encodeURIComponent(id),{cache:'no-store'});const d=await r.json();if(!r.ok)throw new Error(d.error||'request failed');document.getElementById('drawer-title').textContent=d.finding?.title||id;document.getElementById('drawer-body').innerHTML=`<p>${esc(d.finding?.summary||'')}</p><pre>${esc(JSON.stringify(d,null,2))}</pre>`;document.getElementById('drawer').classList.add('open')}catch(e){alert('Unable to open finding: '+e.message)}}
function render(){const d=app.data;if(!d)return;renderTop(d);renderIncidents(d);renderCoverage(d);renderFindings(d);renderCollector(d);renderRetention(d)}
async function refresh(){const button=document.getElementById('refresh');button.disabled=true;try{const r=await fetch('/api/overview?limit=200',{cache:'no-store'});const d=await r.json();if(!r.ok)throw new Error(d.error||'request failed');app.data=d;render()}catch(e){document.getElementById('overall').textContent='Dashboard unavailable';document.getElementById('overall').className='pill bad'}finally{button.disabled=false}}
document.getElementById('refresh').onclick=refresh;document.getElementById('severity').onchange=render;document.getElementById('review').onchange=render;document.getElementById('close').onclick=()=>document.getElementById('drawer').classList.remove('open');document.getElementById('drawer').onclick=e=>{if(e.target.id==='drawer')e.currentTarget.classList.remove('open')};refresh();setInterval(refresh,15000);
</script>
</body>
</html>"""
