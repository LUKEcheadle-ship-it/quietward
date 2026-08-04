from __future__ import annotations
from math import log2
from .contracts import EventAssessment,EventKind,SecurityEvent,Severity
BASE_WEIGHTS={
EventKind.MALWARE_SIGNATURE:95.0,EventKind.YARA_MATCH:82.0,EventKind.CONTAINER_ESCAPE_INDICATOR:92.0,
EventKind.SENSITIVE_FILE_CHANGE:48.0,EventKind.EXECUTABLE_CREATED:30.0,EventKind.PRIVILEGE_ESCALATION:42.0,
EventKind.AUTH_FAILURE:8.0,EventKind.NEW_LISTENING_PORT:28.0,EventKind.OUTBOUND_CONNECTION:14.0,
EventKind.PACKAGE_VULNERABILITY:25.0,EventKind.PROCESS_START:3.0,EventKind.FILE_CHANGE:2.0,
EventKind.CONFIGURATION_WEAKNESS:22.0,EventKind.CONTAINER_CHANGE:5.0,EventKind.CONTAINER_CONFIGURATION_CHANGE:42.0,
EventKind.ACCOUNT_CHANGE:32.0,EventKind.PERSISTENCE_CHANGE:44.0,EventKind.SELF_INTEGRITY_CHANGE:58.0,
EventKind.EVIDENCE_INTEGRITY_FAILURE:90.0,EventKind.COLLECTOR_HEALTH:0.0}
def severity_for_score(score:float)->Severity:
    if score>=85:return Severity.CRITICAL
    if score>=65:return Severity.HIGH
    if score>=40:return Severity.MEDIUM
    if score>=15:return Severity.LOW
    return Severity.INFO
class DeterministicRiskScorer:
    def score(self,event:SecurityEvent)->EventAssessment:
        reasons=[];base=BASE_WEIGHTS[event.kind];score=base*event.confidence;reasons.append(f"base:{event.kind.value}={base:.1f}")
        if event.confidence<1:reasons.append(f"confidence_multiplier={event.confidence:.2f}")
        attrs=event.attributes
        for key,bonus,label in (("known_bad_hash",30,"known_bad_hash"),("unsigned_executable",15,"unsigned_executable"),("external_destination",10,"external_destination"),("privileged_context",12,"privileged_context"),("persistence_indicator",18,"persistence_indicator"),("external_bind",8,"external_bind")):
            if bool(attrs.get(key)):score+=bonus;reasons.append(f"{label}=+{bonus}")
        markers=attrs.get("suspicious_markers") or attrs.get("risk_markers") or attrs.get("security_markers")
        if markers:
            bonus=min(30.0,10.0*len(set(markers)));score+=bonus;reasons.append(f"suspicious_markers=+{bonus:.1f}")
        failed=int(attrs.get("failed_count") or 0)
        if failed>1:
            bonus=min(25.0,5.0*log2(failed));score+=bonus;reasons.append(f"failed_count={failed}:+{bonus:.1f}")
        cvss=float(attrs.get("cvss") or 0)
        if cvss>0:
            bonus=min(30.0,cvss*3);score+=bonus;reasons.append(f"cvss={cvss:.1f}:+{bonus:.1f}")
        deviation=float(attrs.get("baseline_deviation") or 0)
        if deviation>0:
            bonus=min(20.0,max(0.0,deviation)*20.0);score+=bonus;reasons.append(f"baseline_deviation={deviation:.2f}:+{bonus:.1f}")
        score=max(0,min(100,score));return EventAssessment(event.event_id,score,severity_for_score(score),tuple(reasons))
