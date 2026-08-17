from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import threading
import urllib.parse
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .config import DashboardSettings, StorageSettings
from .storage import SentinelStore


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_NON_URGENT_STATES = {"expected", "resolved", "suppressed"}


def normalize_severity(value: object) -> str:
    """Normalize display-only severity without changing stored evidence."""
    severity = str(value or "").strip().lower()
    return "medium" if severity == "mid" else severity


def translate_reason(value: object) -> str:
    """Translate only documented reason shapes; unknown input remains verbatim."""
    raw = str(value or "")
    probability = re.fullmatch(r"tiny_model_probability=([+-]?(?:\d+(?:\.\d*)?|\.\d+))", raw)
    if probability:
        number = float(probability.group(1))
        if 0 <= number <= 1:
            return f"The local model assigned this event a {number * 100:.1f}% risk score."
    persistence = re.fullmatch(r"base:persistence_change=([+-]?(?:\d+(?:\.\d*)?|\.\d+))", raw)
    if persistence:
        return "QuietWard detected a persistence-related system change."
    return raw


def _subject_category(value: object) -> str:
    subject = str(value or "").strip().lower()
    if ":" in subject and re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", subject.split(":", 1)[0]):
        return subject.split(":", 1)[0]
    if re.match(r"^[a-z]:[\\/]", subject) or subject.startswith(("/", "\\\\")):
        return "path"
    if re.fullmatch(r"[0-9a-f]{16,}", subject):
        return "hash"
    return "generic"


def _normalized_title(value: object) -> str:
    title = re.sub(r"\b(?:sha(?:1|256)?[-: ]*)?[0-9a-f]{16,}\b", " ", str(value or "").lower())
    title = re.sub(r"\b\d+\b", " ", title)
    return " ".join(re.findall(r"[a-z0-9]+", title)) or "untitled finding"


def _reason_family(finding: dict[str, Any]) -> str:
    families: set[str] = set()
    for raw in finding.get("reasons") or []:
        reason = str(raw).lower()
        if reason.startswith("tiny_model_probability="):
            families.add("tiny-model")
        elif reason.startswith("base:") and "=" in reason:
            families.add(reason[5:].split("=", 1)[0])
        elif reason.startswith("rule:"):
            families.add(reason.split("=", 1)[0])
    return "+".join(sorted(families)) or "unclassified"


def finding_group_key(finding: dict[str, Any]) -> str:
    """Stable semantic family: title + subject category + allowlisted detector family."""
    return "|".join((
        _normalized_title(finding.get("title")),
        _subject_category(finding.get("subject")),
        _reason_family(finding),
    ))


def _timestamp_value(value: object) -> float:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError, OverflowError):
        return float("-inf")


def finding_sort_key(finding: dict[str, Any]) -> tuple[object, ...]:
    severity = normalize_severity(finding.get("severity"))
    state = str((finding.get("review") or {}).get("state") or "open").lower()
    return (
        _SEVERITY_ORDER.get(severity, 99),
        state in _NON_URGENT_STATES,
        -_timestamp_value(finding.get("created_at")),
        str(finding.get("finding_id") or ""),
    )


def group_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        grouped.setdefault(finding_group_key(finding), []).append(finding)
    result = []
    for key, children in grouped.items():
        children.sort(key=finding_sort_key)
        states = sorted({str((child.get("review") or {}).get("state") or "open") for child in children})
        newest = max(children, key=lambda child: _timestamp_value(child.get("created_at")))
        result.append({
            "group_key": key,
            "title": str(children[0].get("title") or "Untitled finding"),
            "count": len(children),
            "severity": normalize_severity(children[0].get("severity")),
            "newest_at": newest.get("created_at"),
            "review_summary": states[0] if len(states) == 1 else "Mixed: " + ", ".join(states),
            "explanation": str(children[0].get("summary") or "Review the contained observations and supporting evidence."),
            "findings": children,
        })
    result.sort(key=lambda group: finding_sort_key(group["findings"][0]))
    return result


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
                finding = bundle.get("finding") or {}
                finding["reason_explanations"] = [translate_reason(item) for item in finding.get("reasons") or []]
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
        summary = store.summary()
        findings = store.recent_findings(limit)
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
            "summary": summary,
            "findings": sorted(findings, key=finding_sort_key),
            "finding_groups": group_findings(findings),
            "raw_finding_count": int(summary.get("findings", len(findings))),
            "displayed_finding_count": len(findings),
            "display_limit": limit,
            "findings_truncated": int(summary.get("findings", 0)) > len(findings),
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
button:disabled{cursor:wait;opacity:.65}.header-actions{display:flex;gap:9px;align-items:center}.welcome-head,.group-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
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
.refresh-status{min-height:18px}.group{border:1px solid var(--line);border-radius:12px;margin:10px 0;background:var(--panel2)}.group>summary{cursor:pointer;padding:14px;list-style-position:inside}.group>summary:focus-visible,button:focus-visible,select:focus-visible{outline:3px solid var(--accent);outline-offset:2px}.group-body{padding:0 14px 14px}.count-note{margin:8px 0;color:var(--muted)}details.technical{margin-top:12px}details.technical pre{white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}.help{grid-template-columns:1fr}table{display:block;overflow:auto}}
@media(max-width:560px){.grid{grid-template-columns:1fr}.brand{align-items:flex-start;flex-direction:column}.wrap{padding:14px}}
</style>
</head>
<body>
<header><div class="wrap brand"><div><h1>QuietWard</h1><p>Local, read-only security monitoring</p></div><div class="header-actions"><button id="help" aria-controls="welcome">Help</button><div id="status" class="pill" aria-live="polite">Loading status…</div></div></div></header>
<main class="wrap">
<section id="welcome" class="panel" aria-labelledby="welcome-title">
<div class="welcome-head"><div><h2 id="welcome-title">How to use QuietWard</h2><p class="small">QuietWard observes and explains security signals. It does not automatically remediate, quarantine, or alter this computer.</p></div><button id="dismiss-help" aria-label="Dismiss welcome panel">Dismiss</button></div>
<div class="help">
<div><strong>1. Start with critical and high findings</strong><span class="small">They appear first. Expand a group to review each original finding and open its evidence.</span></div>
<div><strong>2. Review; don’t expect automatic fixes</strong><span class="small">Use the command-line review workflow for expected activity. The dashboard remains observation-only.</span></div>
<div><strong>3. Run diagnostics</strong><span class="small">Run <code>quietward diagnose --pretty</code> to check collection, storage, evidence integrity, and service state.</span></div>
</div></section>
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
<div id="refresh-status" class="small refresh-status" role="status" aria-live="polite"></div>
<div id="count-note" class="count-note"></div>
<div id="findings"></div>
</section>

<section class="panel">
<h2>Collector health and errors</h2>
<div id="collector"></div>
<div id="collector-errors"></div>
<div id="defender"></div>
</section>
<section class="panel"><strong class="good">QuietWard did not alter this computer.</strong> <span class="small">Monitoring is observation-only; suggestions cannot execute from this dashboard.</span></section>
</main>

<div id="drawer" class="drawer"><div class="drawer-card"><div class="drawer-head"><h2 id="drawer-title">Finding</h2><button id="close">Close</button></div><div id="drawer-body"></div></div></div>

<script>
const state={data:null,loading:false,request:0,expanded:new Set(),timer:null};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const normalizeSeverity=s=>String(s||'').toLowerCase()==='mid'?'medium':String(s||'unknown').toLowerCase();
const sevClass=s=>'sev sev-'+esc(normalizeSeverity(s));
function activeAttention(findings){return findings.filter(f=>['critical','high'].includes(normalizeSeverity(f.severity))&&['open','acknowledged'].includes((f.review||{}).state||'open')).length}
function timestamp(value,now=new Date()){
 if(!value)return {text:'Not available',exact:'No timestamp recorded'};
 const date=new Date(value);if(Number.isNaN(date.getTime()))return {text:'Invalid timestamp',exact:String(value)};
 const exact=date.toISOString();const delta=now.getTime()-date.getTime(),future=delta<0,seconds=Math.abs(delta)/1000;
 let text;if(seconds<45)text=future?'in a few seconds':'just now';else if(seconds<3600){const n=Math.round(seconds/60);text=future?'in '+n+' minute'+(n===1?'':'s'):n+' minute'+(n===1?'':'s')+' ago'}
 else if(seconds<86400){const n=Math.round(seconds/3600);text=future?'in '+n+' hour'+(n===1?'':'s'):n+' hour'+(n===1?'':'s')+' ago'}
 else text=new Intl.DateTimeFormat(undefined,{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}).format(date);
 return {text,exact};
}
function timeHtml(value){const t=timestamp(value);return '<time datetime="'+esc(t.exact)+'" title="Exact UTC: '+esc(t.exact)+'" aria-label="'+esc(t.text+'; exact UTC '+t.exact)+'">'+esc(t.text)+'</time>'}
function reviewMatches(f,review){return !review||((f.review||{}).state||'open')===review}
function render(){
 const d=state.data;if(!d)return;
 const s=d.summary||{}, findings=d.findings||[], chain=s.evidence_chain||{};
 document.getElementById('last-scan').innerHTML=(s.last_cycle||{}).completed_at?timeHtml(s.last_cycle.completed_at):'Not completed yet';
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
 const groups=(d.finding_groups||[]).map(g=>({...g,findings:(g.findings||[]).filter(f=>(!sev||normalizeSeverity(f.severity)===sev)&&reviewMatches(f,review))})).filter(g=>g.findings.length);
 const box=document.getElementById('findings');
 const visible=groups.reduce((n,g)=>n+g.findings.length,0),total=d.raw_finding_count??findings.length;
 document.getElementById('count-note').textContent=groups.length+' group'+(groups.length===1?'':'s')+' · '+visible+' matching raw finding'+(visible===1?'':'s')+' · '+total+' raw total'+(d.findings_truncated?' (showing newest '+d.displayed_finding_count+'; display limit '+d.display_limit+')':'');
 if(!groups.length){box.innerHTML='<div class="empty">No findings match these filters.</div>'}
 else{
  box.innerHTML=groups.map(g=>{const highest=g.findings[0],states=[...new Set(g.findings.map(f=>(f.review||{}).state||'open'))],newest=g.findings.reduce((a,f)=>new Date(f.created_at)>new Date(a.created_at)?f:a,g.findings[0]);return '<details class="group" data-group="'+esc(g.group_key)+'" '+(state.expanded.has(g.group_key)?'open':'')+'><summary><strong>'+esc(g.title)+' — '+g.findings.length+' finding'+(g.findings.length===1?'':'s')+'</strong><br><span class="'+sevClass(highest.severity)+'">Highest: '+esc(normalizeSeverity(highest.severity))+'</span> · '+timeHtml(newest.created_at)+' · <span class="state">'+esc(states.length===1?states[0]:'Mixed: '+states.sort().join(', '))+'</span><br><span class="small">'+esc(g.explanation||'Review the contained evidence.')+'</span></summary><div class="group-body"><table><thead><tr><th>Severity</th><th>Finding</th><th>Why it matters</th><th>State</th><th></th></tr></thead><tbody>'+g.findings.map(f=>'<tr><td><span class="'+sevClass(f.severity)+'">'+esc(normalizeSeverity(f.severity))+'</span><br><span class="small">Score '+esc(f.score)+'</span></td><td><strong>'+esc(f.title||f.finding_id)+'</strong><br><span class="small">'+timeHtml(f.created_at)+'</span></td><td>'+esc(f.summary||'No summary')+'</td><td><span class="state">'+esc((f.review||{}).state||'open')+'</span></td><td><button data-id="'+esc(f.finding_id)+'">Details</button></td></tr>').join('')+'</tbody></table></div></details>'}).join('');
  box.querySelectorAll('details[data-group]').forEach(d=>d.ontoggle=()=>d.open?state.expanded.add(d.dataset.group):state.expanded.delete(d.dataset.group));
  box.querySelectorAll('button[data-id]').forEach(b=>b.onclick=()=>openFinding(b.dataset.id));
 }
 const c=d.collector||{};
 document.getElementById('collector').innerHTML=c.version?'<div><strong>'+esc(c.version)+'</strong><br><span class="small">Last observation: '+timeHtml(c.observed_at)+'</span></div>':'<div class="empty">No collector snapshot yet.</div>';
 document.getElementById('collector-errors').innerHTML=errors.length?errors.map(e=>'<div class="error">'+esc(e)+'</div>').join(''):'<div class="good">No collector errors reported in the latest snapshot.</div>';
 const md=c.microsoft_defender; document.getElementById('defender').innerHTML=md?'<div class="panel"><strong>Microsoft Defender evidence</strong><p>Antivirus: '+(md.antivirus_enabled?'enabled':'disabled')+' · Real-time protection: '+(md.real_time_protection_enabled?'enabled':'disabled')+' · Active threats reported: '+esc(md.active_threat_count)+'</p><span class="small">This is status reported by Microsoft Defender, not QuietWard’s own malware verdict.</span></div>':'';
}
async function load(source='automatic'){
 if(state.loading)return false;state.loading=true;const request=++state.request,button=document.getElementById('refresh'),message=document.getElementById('refresh-status');
 button.disabled=true;button.textContent='Refreshing…';message.textContent=source==='manual'?'Refreshing…':'';
 try{const r=await fetch('/api/overview?limit=500',{cache:'no-store'});if(!r.ok)throw new Error('HTTP '+r.status);const next=await r.json();if(!next||typeof next!=='object'||!Array.isArray(next.findings)||!Array.isArray(next.finding_groups))throw new Error('Malformed dashboard response');if(request!==state.request)return false;state.data=next;render();const t=timestamp(new Date().toISOString());message.innerHTML='Last refreshed '+timeHtml(new Date().toISOString());return true}
 catch(e){const s=document.getElementById('status');s.textContent='Refresh failed — showing previous data';s.className='pill bad';message.innerHTML='<span class="bad">Could not refresh: '+esc(e.message)+'. Previously displayed data was preserved.</span>';return false}
 finally{if(request===state.request){state.loading=false;button.disabled=false;button.textContent='Refresh'}}
}
async function openFinding(id){
 const drawer=document.getElementById('drawer'),body=document.getElementById('drawer-body');drawer.classList.add('open');body.innerHTML='<div class="empty">Loading…</div>';
 try{
  const r=await fetch('/api/finding?id='+encodeURIComponent(id),{cache:'no-store'});if(!r.ok)throw new Error('HTTP '+r.status);
  const b=await r.json(),f=b.finding||{},review=b.review||{},proposals=b.proposals||[],events=b.events||[];
  document.getElementById('drawer-title').textContent=f.title||'Finding';
  body.innerHTML='<p><span class="'+sevClass(f.severity)+'">'+esc(f.severity)+'</span> · score '+esc(f.score)+' · '+esc(review.state||'open')+'</p>'+ 
   '<p>'+esc(f.summary||'')+'</p>'+ 
   '<h3>Why QuietWard raised this</h3><ul>'+(((f.reason_explanations||f.reasons||[]).map(x=>'<li>'+esc(x)+'</li>').join(''))||'<li>No reasons recorded.</li>')+'</ul><details class="technical"><summary>Raw Event Log</summary><pre>'+esc((f.reasons||[]).join('\n')||'No raw reasons recorded.')+'</pre></details>'+
   '<h3>Recommended response</h3>'+ (proposals.length?proposals.map(p=>'<div class="panel"><strong>'+esc(p.action_type)+'</strong><p>'+esc(p.reason)+'</p><span class="small">Approval required: '+esc(p.requires_approval)+' · Executable now: '+esc(p.executable_in_current_mode)+'</span></div>').join(''):'<p class="small">No remediation proposal was generated. Review the evidence before changing the system.</p>')+
   '<h3>Supporting events</h3><p class="small">'+events.length+' event(s). Raw sensitive identities are not displayed.</p>'+ (events.length?'<ul>'+events.map(e=>'<li><strong>'+esc(e.kind||'security event')+'</strong> observed by '+esc(e.source||'QuietWard')+' at '+timeHtml(e.observed_at)+'</li>').join('')+'</ul>':'<p class="small">No supporting events are available.</p>');
 }catch(e){body.innerHTML='<div class="error">'+esc(e.message)+'</div>'}
}
document.getElementById('refresh').onclick=()=>load('manual');
document.getElementById('severity').onchange=render;
document.getElementById('review').onchange=render;
document.getElementById('close').onclick=()=>document.getElementById('drawer').classList.remove('open');
document.getElementById('drawer').onclick=e=>{if(e.target.id==='drawer')e.currentTarget.classList.remove('open')};
const welcome=document.getElementById('welcome');if(localStorage.getItem('quietward-welcome-dismissed')==='1')welcome.hidden=true;
document.getElementById('dismiss-help').onclick=()=>{welcome.hidden=true;localStorage.setItem('quietward-welcome-dismissed','1');document.getElementById('help').focus()};
document.getElementById('help').onclick=()=>{welcome.hidden=false;localStorage.removeItem('quietward-welcome-dismissed');document.getElementById('welcome-title').focus?.()};
load('initial');if(!state.timer)state.timer=setInterval(()=>load('automatic'),15000);
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
