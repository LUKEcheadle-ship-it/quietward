from __future__ import annotations

import hmac
import ipaddress
import json
import os
import threading
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .config import DashboardSettings, StorageSettings
from .storage import SentinelStore


def _is_loopback(bind: str) -> bool:
    if bind == "localhost":
        return True
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        return False


def _is_private(bind: str) -> bool:
    try:
        address = ipaddress.ip_address(bind)
    except ValueError:
        return False
    return address.is_private or address in ipaddress.ip_network("100.64.0.0/10")


class DashboardServer:
    def __init__(self, settings: DashboardSettings, storage: StorageSettings) -> None:
        if not _is_loopback(settings.bind):
            if not settings.allow_private_network_bind or not _is_private(settings.bind):
                raise ValueError(
                    "dashboard may bind only to loopback unless an explicit "
                    "private-network bind is enabled"
                )
            if settings.token_file is None:
                raise ValueError(
                    "private-network dashboard binding requires token_file"
                )
        self.settings = settings
        self.storage = storage
        self.token = self._load_token(settings.token_file) if settings.token_file else None
        server_self = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "QuietWardDashboard/2"

            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                server_self._handle(self)

            def do_POST(self) -> None:
                try:
                    length = min(65536, max(0, int(self.headers.get("Content-Length", "0"))))
                except ValueError:
                    length = 0
                if length:
                    self.rfile.read(length)
                server_self._json(
                    self,
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {"error": "read-only dashboard", "actions_executed": 0},
                )

            do_PUT = do_POST
            do_PATCH = do_POST
            do_DELETE = do_POST

        self.httpd = ThreadingHTTPServer((settings.bind, settings.port), Handler)
        self.thread: threading.Thread | None = None

    @staticmethod
    def _load_token(path: Path) -> str:
        token = path.read_text(encoding="utf-8").strip()
        if len(token) < 24:
            raise ValueError("dashboard token must be at least 24 characters")
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise ValueError(
                "dashboard token file must not be group/world accessible"
            )
        return token

    @property
    def address(self) -> tuple[str, int]:
        host, port = self.httpd.server_address[:2]
        return str(host), int(port)

    def start(self) -> None:
        if self.thread is not None:
            raise RuntimeError("dashboard already started")
        self.thread = threading.Thread(
            target=self.httpd.serve_forever,
            name="quietward-dashboard",
            daemon=True,
        )
        self.thread.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=5)
            self.thread = None

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def _authorized(self, handler: BaseHTTPRequestHandler) -> bool:
        if self.token is None:
            return True
        supplied = handler.headers.get("Authorization", "")
        return supplied.startswith("Bearer ") and hmac.compare_digest(
            supplied[7:], self.token
        )

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        if not self._authorized(handler):
            self._json(
                handler,
                HTTPStatus.UNAUTHORIZED,
                {"error": "unauthorized", "actions_executed": 0},
            )
            return
        parsed = urllib.parse.urlparse(handler.path)
        query = urllib.parse.parse_qs(parsed.query)
        try:
            limit = min(500, max(1, int(query.get("limit", ["100"])[0])))
        except (TypeError, ValueError):
            self._json(
                handler,
                HTTPStatus.BAD_REQUEST,
                {"error": "limit must be an integer", "actions_executed": 0},
            )
            return

        with SentinelStore(self.storage) as store:
            if parsed.path == "/health" or parsed.path == "/api/summary":
                self._json(handler, HTTPStatus.OK, store.summary())
            elif parsed.path == "/api/overview":
                self._json(handler, HTTPStatus.OK, self._overview(store, limit))
            elif parsed.path == "/api/events":
                self._json(
                    handler,
                    HTTPStatus.OK,
                    {
                        "events": store.recent_events(limit),
                        "actions_executed": 0,
                    },
                )
            elif parsed.path == "/api/findings":
                self._json(
                    handler,
                    HTTPStatus.OK,
                    {
                        "findings": store.recent_findings(limit),
                        "actions_executed": 0,
                    },
                )
            elif parsed.path == "/api/finding":
                finding_id = str(query.get("id", [""])[0]).strip()
                if not finding_id:
                    self._json(
                        handler,
                        HTTPStatus.BAD_REQUEST,
                        {
                            "error": "finding id is required",
                            "actions_executed": 0,
                        },
                    )
                    return
                try:
                    bundle = store.incident_bundle(finding_id)
                except KeyError:
                    self._json(
                        handler,
                        HTTPStatus.NOT_FOUND,
                        {
                            "error": "finding not found",
                            "actions_executed": 0,
                        },
                    )
                    return
                self._json(handler, HTTPStatus.OK, bundle)
            elif parsed.path == "/":
                body = self._html().encode("utf-8")
                self._headers(
                    handler,
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    len(body),
                )
                handler.wfile.write(body)
            else:
                self._json(
                    handler,
                    HTTPStatus.NOT_FOUND,
                    {"error": "not found", "actions_executed": 0},
                )

    @staticmethod
    def _overview(store: SentinelStore, limit: int) -> dict[str, Any]:
        snapshot = store.latest_snapshot()
        collector = None
        collector_errors: list[str] = []
        if snapshot is not None:
            collector = {
                "version": snapshot.collector_version,
                "observed_at": snapshot.to_dict()["observed_at"],
                "microsoft_defender": snapshot.defender.to_dict() if snapshot.defender else None,
            }
            collector_errors = list(snapshot.errors)
        return {
            "summary": store.summary(),
            "findings": store.recent_findings(limit),
            "events": store.recent_events(min(limit, 100)),
            "collector": collector,
            "collector_errors": collector_errors,
            "actions_executed": 0,
            "mode": "observe_only",
        }

    @staticmethod
    def _html() -> str:
        return r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QuietWard</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2d;--panel2:#18233a;--line:#263654;--text:#eef4ff;--muted:#9eabc2;--good:#45d483;--warn:#f4c95d;--bad:#ff6b77;--critical:#ff3d5a;--accent:#75a7ff}
*{box-sizing:border-box}
body{margin:0;background:linear-gradient(145deg,#080d19,#0e1730);font-family:Inter,Segoe UI,Arial,sans-serif;color:var(--text)}
header{position:sticky;top:0;z-index:5;background:rgba(8,13,25,.94);backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
.wrap{max-width:1240px;margin:auto;padding:20px}
.brand{display:flex;gap:14px;align-items:center;justify-content:space-between}
.brand h1{font-size:24px;margin:0}.brand p{margin:4px 0 0;color:var(--muted)}
.pill{border:1px solid var(--line);border-radius:999px;padding:8px 12px;font-size:13px;background:var(--panel)}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:18px 0}
.card,.panel{background:rgba(18,26,45,.96);border:1px solid var(--line);border-radius:16px;box-shadow:0 14px 40px rgba(0,0,0,.18)}
.card{padding:16px}.card .value{font-size:28px;font-weight:750;margin-top:8px}.label{color:var(--muted);font-size:13px}
.panel{padding:18px;margin:14px 0}.panel h2{font-size:17px;margin:0 0 12px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
select,button{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:9px;padding:9px 11px}
button{cursor:pointer}button:hover{border-color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:11px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
.sev{font-weight:700;text-transform:uppercase;font-size:12px}.sev-critical{color:var(--critical)}.sev-high{color:var(--bad)}.sev-medium{color:var(--warn)}.sev-low,.sev-info{color:var(--good)}
.state{font-size:12px;color:var(--muted)}
.empty{color:var(--muted);padding:20px 0}
.error{background:#321924;border:1px solid #623040;color:#ffd9dd;border-radius:10px;padding:10px;margin:8px 0}
.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.help{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.help div{background:var(--panel2);border-radius:12px;padding:14px}.help strong{display:block;margin-bottom:7px}
.drawer{position:fixed;inset:0;display:none;background:rgba(0,0,0,.64);z-index:20;padding:24px}.drawer.open{display:flex;justify-content:flex-end}
.drawer-card{width:min(720px,100%);height:100%;overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px}
.drawer-head{display:flex;justify-content:space-between;gap:10px}.drawer pre{white-space:pre-wrap;background:#09101e;padding:12px;border-radius:10px;overflow:auto}
.small{font-size:12px;color:var(--muted)}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}.help{grid-template-columns:1fr}table{display:block;overflow:auto}}
@media(max-width:560px){.grid{grid-template-columns:1fr}.brand{align-items:flex-start;flex-direction:column}.wrap{padding:14px}}
</style>
</head>
<body>
<header><div class="wrap brand"><div><h1>QuietWard</h1><p>Local, read-only security monitoring</p></div><div id="status" class="pill">Loading status…</div></div></header>
<main class="wrap">
<section class="grid">
<div class="card"><div class="label">Last scan</div><div id="last-scan" class="value" style="font-size:16px">—</div></div>
<div class="card"><div class="label">Open high/critical</div><div id="attention" class="value">—</div></div>
<div class="card"><div class="label">High / medium / low</div><div id="severity-counts" class="value" style="font-size:20px">—</div></div>
<div class="card"><div class="label">Evidence chain</div><div id="evidence" class="value" style="font-size:18px">—</div></div>
<div class="card"><div class="label">Actions executed</div><div id="actions" class="value good">0</div></div>
</section>

<section class="panel">
<h2>What needs your attention</h2>
<div class="toolbar">
<select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
<select id="review"><option value="">All review states</option><option>open</option><option>acknowledged</option><option>expected</option><option>resolved</option><option>suppressed</option></select>
<button id="refresh">Refresh</button>
</div>
<div id="findings"></div>
</section>

<section class="panel">
<h2>Collector health and errors</h2>
<div id="collector"></div>
<div id="collector-errors"></div>
<div id="defender"></div>
</section>
<section class="panel"><strong class="good">QuietWard did not alter this computer.</strong> <span class="small">Monitoring is observation-only; suggestions cannot execute from this dashboard.</span></section>
<section class="panel">
<h2>How to use QuietWard</h2>
<div class="help">
<div><strong>1. Look at high and critical findings</strong><span class="small">Open a finding to see why it was raised, its evidence, and any non-executable remediation proposal.</span></div>
<div><strong>2. Confirm expected activity</strong><span class="small">Use the command line incident review tools to mark known services or changes as expected. The dashboard stays read-only.</span></div>
<div><strong>3. Run diagnostics when something looks wrong</strong><span class="small">Run <code>quietward diagnose --pretty</code> to check the collector, database, evidence chain, and service state.</span></div>
</div>
</section>
</main>

<div id="drawer" class="drawer"><div class="drawer-card"><div class="drawer-head"><h2 id="drawer-title">Finding</h2><button id="close">Close</button></div><div id="drawer-body"></div></div></div>

<script>
const state={data:null};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sevClass=s=>'sev sev-'+esc((s||'info').toLowerCase());
function activeAttention(findings){return findings.filter(f=>['critical','high'].includes(f.severity)&&['open','acknowledged'].includes((f.review||{}).state||'open')).length}
function render(){
 const d=state.data;if(!d)return;
 const s=d.summary||{}, findings=d.findings||[], chain=s.evidence_chain||{};
 document.getElementById('last-scan').textContent=((s.last_cycle||{}).completed_at||'Not completed yet');
 document.getElementById('attention').textContent=activeAttention(findings);
 const by=s.findings_by_severity||{}; document.getElementById('severity-counts').textContent=(by.high||0)+' / '+(by.medium||0)+' / '+((by.low||0)+(by.info||0));
 const evidence=document.getElementById('evidence'); evidence.textContent=chain.valid===false?'Invalid':'Valid'; evidence.className='value '+(chain.valid===false?'bad':'good');
 document.getElementById('actions').textContent=d.actions_executed??0;
 const errors=d.collector_errors||[]; const critical=activeAttention(findings);
 const ok=chain.valid!==false && errors.length===0;
 const status=document.getElementById('status');
 status.textContent=chain.valid===false?'Evidence check failed':critical?critical+' urgent finding'+(critical===1?'':'s'):errors.length?'Collector warning':'Monitoring normally';
 status.className='pill '+(chain.valid===false?'bad':critical?'warn':ok?'good':'warn');
 const sev=document.getElementById('severity').value, review=document.getElementById('review').value;
 const filtered=findings.filter(f=>(!sev||f.severity===sev)&&(!review||((f.review||{}).state||'open')===review));
 const box=document.getElementById('findings');
 if(!filtered.length){box.innerHTML='<div class="empty">No findings match this filter.</div>'}
 else{
  box.innerHTML='<table><thead><tr><th>Severity</th><th>Finding</th><th>Why it matters</th><th>State</th><th></th></tr></thead><tbody>'+ 
  filtered.map(f=>'<tr><td><span class="'+sevClass(f.severity)+'">'+esc(f.severity)+'</span><br><span class="small">Score '+esc(f.score)+'</span></td><td><strong>'+esc(f.title||f.finding_id)+'</strong><br><span class="small">'+esc(f.created_at)+'</span></td><td>'+esc(f.summary||'No summary')+'</td><td><span class="state">'+esc((f.review||{}).state||'open')+'</span></td><td><button data-id="'+esc(f.finding_id)+'">Details</button></td></tr>').join('')+
  '</tbody></table>';
  box.querySelectorAll('button[data-id]').forEach(b=>b.onclick=()=>openFinding(b.dataset.id));
 }
 const c=d.collector||{};
 document.getElementById('collector').innerHTML=c.version?'<div><strong>'+esc(c.version)+'</strong><br><span class="small">Last observation: '+esc(c.observed_at)+'</span></div>':'<div class="empty">No collector snapshot yet.</div>';
 document.getElementById('collector-errors').innerHTML=errors.length?errors.map(e=>'<div class="error">'+esc(e)+'</div>').join(''):'<div class="good">No collector errors reported in the latest snapshot.</div>';
 const md=c.microsoft_defender; document.getElementById('defender').innerHTML=md?'<div class="panel"><strong>Microsoft Defender evidence</strong><p>Antivirus: '+(md.antivirus_enabled?'enabled':'disabled')+' · Real-time protection: '+(md.real_time_protection_enabled?'enabled':'disabled')+' · Active threats reported: '+esc(md.active_threat_count)+'</p><span class="small">This is status reported by Microsoft Defender, not QuietWard’s own malware verdict.</span></div>':'';
}
async function load(){
 try{const r=await fetch('/api/overview?limit=250',{cache:'no-store'});if(!r.ok)throw new Error('HTTP '+r.status);state.data=await r.json();render()}
 catch(e){const s=document.getElementById('status');s.textContent='Dashboard cannot read QuietWard data';s.className='pill bad';document.getElementById('collector-errors').innerHTML='<div class="error">'+esc(e.message)+'</div>'}
}
async function openFinding(id){
 const drawer=document.getElementById('drawer'),body=document.getElementById('drawer-body');drawer.classList.add('open');body.innerHTML='<div class="empty">Loading…</div>';
 try{
  const r=await fetch('/api/finding?id='+encodeURIComponent(id),{cache:'no-store'});if(!r.ok)throw new Error('HTTP '+r.status);
  const b=await r.json(),f=b.finding||{},review=b.review||{},proposals=b.proposals||[],events=b.events||[];
  document.getElementById('drawer-title').textContent=f.title||'Finding';
  body.innerHTML='<p><span class="'+sevClass(f.severity)+'">'+esc(f.severity)+'</span> · score '+esc(f.score)+' · '+esc(review.state||'open')+'</p>'+ 
   '<p>'+esc(f.summary||'')+'</p>'+ 
   '<h3>Reasons</h3><ul>'+((f.reasons||[]).map(x=>'<li>'+esc(x)+'</li>').join('')||'<li>No reasons recorded.</li>')+'</ul>'+ 
   '<h3>Recommended response</h3>'+ (proposals.length?proposals.map(p=>'<div class="panel"><strong>'+esc(p.action_type)+'</strong><p>'+esc(p.reason)+'</p><span class="small">Approval required: '+esc(p.requires_approval)+' · Executable now: '+esc(p.executable_in_current_mode)+'</span></div>').join(''):'<p class="small">No remediation proposal was generated. Review the evidence before changing the system.</p>')+
   '<h3>Supporting events</h3><p class="small">'+events.length+' event(s). Raw sensitive identities are not displayed.</p>'+ (events.length?'<ul>'+events.map(e=>'<li><strong>'+esc(e.kind||'security event')+'</strong> observed by '+esc(e.source||'QuietWard')+' at '+esc(e.observed_at||'unknown time')+'</li>').join('')+'</ul>':'<p class="small">No supporting events are available.</p>');
 }catch(e){body.innerHTML='<div class="error">'+esc(e.message)+'</div>'}
}
document.getElementById('refresh').onclick=load;
document.getElementById('severity').onchange=render;
document.getElementById('review').onchange=render;
document.getElementById('close').onclick=()=>document.getElementById('drawer').classList.remove('open');
document.getElementById('drawer').onclick=e=>{if(e.target.id==='drawer')e.currentTarget.classList.remove('open')};
load();setInterval(load,15000);
</script>
</body>
</html>"""

    @staticmethod
    def _headers(
        handler: BaseHTTPRequestHandler,
        status: HTTPStatus,
        content_type: str,
        length: int,
    ) -> None:
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(length))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.send_header("X-Frame-Options", "DENY")
        handler.send_header("Referrer-Policy", "no-referrer")
        handler.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; connect-src 'self'; "
            "img-src 'none'; object-src 'none'; frame-ancestors 'none'",
        )
        handler.end_headers()

    def _json(
        self,
        handler: BaseHTTPRequestHandler,
        status: HTTPStatus,
        value: dict[str, Any],
    ) -> None:
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self._headers(
            handler,
            status,
            "application/json; charset=utf-8",
            len(body),
        )
        handler.wfile.write(body)
