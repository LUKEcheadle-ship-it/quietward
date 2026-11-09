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
    """Local read-only operations panels extending the shared findings dashboard."""

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
    def _operations_panels() -> str:
        return """<section class="panel"><h2>Incident lifecycle</h2>
<div id="life-sub" class="small"></div><div id="incidents"></div></section>
<section class="panel"><h2>Monitoring coverage</h2><div id="coverage-status" class="small"></div>
<div id="coverage-domains" class="operations-grid"></div></section>
<section class="panel"><h2>Bounded local retention</h2><div id="retention-status" class="small"></div>
<div id="retention" class="operations-grid"></div></section>"""

    @staticmethod
    def _operations_script() -> str:
        return r"""
function renderIncidents(d){const rows=(d.incidents||[]).slice(0,100);const el=document.getElementById('incidents');if(!rows.length){el.innerHTML='<div class="empty">No lifecycle incidents recorded yet.</div>';return;}el.innerHTML='<table><thead><tr><th>State</th><th>Severity</th><th>Incident</th><th>First seen</th><th>Last seen</th><th>Cycles</th><th>Occurrences</th></tr></thead><tbody>'+rows.map(r=>`<tr><td><span class="state state-${esc(r.state)}">${esc(r.state)}</span></td><td class="${sevClass((r.incident||{}).severity)}">${esc((r.incident||{}).severity)}</td><td><code>${esc((r.incident||{}).incident_key)}</code></td><td>${timeHtml(r.first_seen)}</td><td>${timeHtml(r.last_seen)}</td><td>${esc(r.cycles_seen)}</td><td>${esc(r.occurrences)}</td></tr>`).join('')+'</tbody></table>';}
function renderCoverage(d){const cov=d.coverage;const el=document.getElementById('coverage-domains');if(!cov){el.innerHTML='<div class="empty">Coverage details will appear after the service completes a cycle.</div>';return;}el.innerHTML=(cov.domains||[]).map(x=>`<div class="domain domain-${esc(x.state)}"><strong>${esc(x.name)}</strong><span>${esc(x.state)}${x.reason_code?' · '+esc(x.reason_code):''}${x.issue_count?' · '+esc(x.issue_count)+' issue(s)':''}</span></div>`).join('');}
function renderRetention(d){const ret=d.retention||{},el=document.getElementById('retention');const rows=ret.capacities||[];if(!rows.length){el.innerHTML='<div class="empty">Retention metrics unavailable.</div>';return;}el.innerHTML=rows.map(x=>{const pct=Number.isFinite(Number(x.utilization))?Math.max(0,Math.round(Number(x.utilization)*100)):0;return `<div class="meter"><div class="label">${esc(x.name)}</div><strong>${esc(x.current)} / ${esc(x.limit)}</strong><div class="bar"><div class="fill ${pct>=90?'warnfill':''}" style="width:${Math.min(100,pct)}%"></div></div><div class="sub">${pct}% utilized</div></div>`}).join('');}
function renderOperations(d){
 const life=d.lifecycle||{},cov=d.coverage,ret=d.retention||{};
 const coverageHealthy=cov&&(cov.operationally_healthy??cov.resolution_safe)===true;
 document.getElementById('life-sub').textContent=(life.active??0)+' active · '+(life.incidents??0)+' tracked · '+(life.transitions??0)+' retained transitions';
 document.getElementById('coverage-status').textContent=!cov?'No coverage report':coverageHealthy?'Coverage operationally healthy':(cov.degraded_count||0)+' degraded/not-due domain(s) — review coverage';
 document.getElementById('retention-status').textContent=(ret.caps_reached||[]).length?'Pruning active: '+ret.caps_reached.join(', '):(ret.retention_days??'Unknown')+' day age window';
 renderIncidents(d);renderCoverage(d);renderRetention(d);
 if(!coverageHealthy){const status=document.getElementById('status');if(status.className==='pill good'){status.textContent='Coverage review';status.className='pill warn'}}
}
"""
