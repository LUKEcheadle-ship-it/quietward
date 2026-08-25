from __future__ import annotations

from typing import Iterable, Mapping, Any


SCANNER_SOURCES = {"clamav", "yara", "trivy", "debsecan"}


def _collector_domain(source: str) -> str | None:
    value = source.casefold().strip()
    if value.endswith("_process_snapshot"):
        return "processes"
    if value.endswith("_socket_snapshot"):
        return "listening_sockets"
    if value.endswith("_connection_snapshot"):
        return "outbound_connections"
    if value.endswith("_container_snapshot"):
        return "docker"
    if value in {"docker_read_only_snapshot", "docker_inspect_read_only"}:
        return "docker"
    if value.endswith("_file_integrity_snapshot"):
        return "sensitive_files"
    if value.endswith("_persistence_snapshot"):
        return "persistence"
    if value in {
        "windows_security_log",
        "debian_auth_journal",
        "windows_security_log_read_only",
        "journald_ssh_read_only",
    }:
        return "authentication"
    if value in {"sentinel_self_integrity", "quietward_self_integrity"}:
        return "self_integrity"
    if value in {"sentinel_evidence_chain", "quietward_evidence_chain"}:
        return "evidence_chain"
    if value in {"microsoft_defender", "windows_defender"}:
        return "microsoft_defender"
    return None


def _state(value: Mapping[str, Any]) -> str:
    return str(value.get("state") or "").casefold()


def incident_resolution_safe(
    event_sources: Iterable[str],
    coverage_domains: Iterable[Mapping[str, Any]],
    *,
    global_resolution_safe: bool,
) -> bool:
    sources = tuple(sorted({str(item).casefold().strip() for item in event_sources if str(item).strip()}))
    if not sources:
        return bool(global_resolution_safe)

    domains = [dict(item) for item in coverage_domains]
    by_name = {str(item.get("name") or ""): item for item in domains}

    for source in sources:
        if source in SCANNER_SOURCES:
            prefix = f"scanner:{source}:"
            matches = [item for name, item in by_name.items() if name.startswith(prefix)]
            if not matches or any(_state(item) != "complete" for item in matches):
                return False
            continue

        domain_name = _collector_domain(source)
        if domain_name is None:
            if not global_resolution_safe:
                return False
            continue
        relevant = by_name.get(domain_name)
        if relevant is None or _state(relevant) != "complete":
            return False

    return True
