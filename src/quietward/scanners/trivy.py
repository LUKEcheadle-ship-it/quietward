from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from ..contracts import EventKind, SecurityEvent
from .common import bounded, event_id, observed_time, require_host_id, sort_events

_SEVERITY_CVSS_FLOOR = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "UNKNOWN": 0.0,
}


def _cvss(vulnerability: dict[str, Any], severity: str) -> float:
    scores: list[float] = []
    cvss = vulnerability.get("CVSS")
    if isinstance(cvss, dict):
        for vendor in cvss.values():
            if not isinstance(vendor, dict):
                continue
            for key in ("V3Score", "V2Score"):
                raw = vendor.get(key)
                if isinstance(raw, (int, float)):
                    scores.append(float(raw))
    return max(scores, default=_SEVERITY_CVSS_FLOOR.get(severity, 0.0))


def parse_trivy_json(
    text: str,
    host_id: str,
    *,
    observed_at: datetime | None = None,
) -> list[SecurityEvent]:
    host = require_host_id(host_id)
    timestamp = observed_time(observed_at)
    try:
        report = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid Trivy JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise ValueError("Trivy report must be a JSON object")

    artifact = bounded(report.get("ArtifactName"), 300) or "unknown-artifact"
    results = report.get("Results")
    if results is None:
        results = []
    if not isinstance(results, list):
        raise ValueError("Trivy Results must be a list")

    events: list[SecurityEvent] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        target = bounded(result.get("Target"), 300) or artifact
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            continue
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            vulnerability_id = bounded(item.get("VulnerabilityID"), 100)
            package = bounded(item.get("PkgName"), 200)
            installed = bounded(item.get("InstalledVersion"), 200)
            if not vulnerability_id or not package or not installed:
                continue
            fixed = bounded(item.get("FixedVersion"), 200)
            severity = bounded(item.get("Severity"), 20).upper() or "UNKNOWN"
            title = bounded(item.get("Title"), 300)
            severity_source = bounded(item.get("SeveritySource"), 80)
            subject = f"package:{package}"
            events.append(
                SecurityEvent(
                    event_id=event_id("trivy", host, subject, f"{vulnerability_id}|{installed}|{target}"),
                    observed_at=timestamp,
                    host_id=host,
                    source="trivy_json_adapter",
                    kind=EventKind.PACKAGE_VULNERABILITY,
                    subject=subject,
                    attributes={
                        "vulnerability_id": vulnerability_id,
                        "package": package,
                        "installed_version": installed,
                        "fixed_version": fixed or None,
                        "fix_available": bool(fixed),
                        "severity": severity,
                        "severity_source": severity_source or None,
                        "cvss": _cvss(item, severity),
                        "target": target,
                        "artifact": artifact,
                        "title": title or None,
                        "raw_description_persisted": False,
                        "raw_references_persisted": False,
                    },
                    confidence=0.95,
                )
            )
    return sort_events(events)
