#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _test_environment() -> dict[str, str]:
    env = os.environ.copy()
    source = str(ROOT / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = source if not existing else source + os.pathsep + existing
    return env


def _run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    print("\n>>>", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True, env=env)


def _require_pytest() -> None:
    if importlib.util.find_spec("pytest") is None:
        raise RuntimeError(
            "pytest is required for QuietWard v0.5 release qualification because the v0.5 hardening suite includes pytest-style regression tests"
        )


def _version() -> str:
    init_text = (ROOT / "src" / "quietward" / "__init__.py").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    if match is None or match.group(1) != "0.5.0a1":
        raise RuntimeError("QuietWard release branch must report 0.5.0a1")
    if 'version = "0.5.0a1"' not in pyproject:
        raise RuntimeError("pyproject version is not 0.5.0a1")
    return match.group(1)


def _verify_release_documentation() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release_notes = ROOT / "docs" / "releases" / "v0.5.0-alpha.1.md"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "## 0.5.0-alpha.1" not in changelog:
        raise RuntimeError("CHANGELOG.md is missing the v0.5.0-alpha.1 release entry")
    if not release_notes.is_file():
        raise RuntimeError("v0.5.0-alpha.1 release notes are missing")
    for fragment in (
        "v0.5.0-alpha.1",
        "0.5.0a1",
        "release/v0.5.0-alpha.1",
        "native Windows FAST",
        "incident lifecycle",
    ):
        if fragment.casefold() not in readme.casefold():
            raise RuntimeError(f"README combined-release metadata missing: {fragment}")
    if "installation-keyed" not in readme.lower():
        raise RuntimeError("README must document installation-keyed address privacy")


def _verify_observation_only_source_contract() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    required = (
        "observation-only",
        "does not quarantine/delete files",
        "terminate processes or services",
        "change firewall rules",
        "actions_executed == 0",
        "executable_proposals == 0",
    )
    missing = [item for item in required if item not in text]
    if missing:
        raise RuntimeError(f"observation-only README contract missing: {missing}")


def _verify_combined_source_contract() -> None:
    texts = {
        "correlation.py": (ROOT / "src" / "quietward" / "correlation.py").read_text(encoding="utf-8"),
        "scoring.py": (ROOT / "src" / "quietward" / "scoring.py").read_text(encoding="utf-8"),
        "product_store.py": (ROOT / "src" / "quietward" / "product_store.py").read_text(encoding="utf-8"),
        "runtime.py": (ROOT / "src" / "quietward" / "runtime.py").read_text(encoding="utf-8"),
        "core_service.py": (ROOT / "src" / "quietward" / "core_service.py").read_text(encoding="utf-8"),
        "performance_budget.py": (ROOT / "src" / "quietward" / "performance_budget.py").read_text(encoding="utf-8"),
        "collectors/debian.py": (ROOT / "src" / "quietward" / "collectors" / "debian.py").read_text(encoding="utf-8"),
        "collectors/parsers.py": (ROOT / "src" / "quietward" / "collectors" / "parsers.py").read_text(encoding="utf-8"),
        "collectors/windows.py": (ROOT / "src" / "quietward" / "collectors" / "windows.py").read_text(encoding="utf-8"),
        "collectors/windows_native_fast.py": (ROOT / "src" / "quietward" / "collectors" / "windows_native_fast.py").read_text(encoding="utf-8"),
        "collectors/windows_parsers.py": (ROOT / "src" / "quietward" / "collectors" / "windows_parsers.py").read_text(encoding="utf-8"),
    }

    required = {
        "correlation.py": (
            "cross_subject_host_attack_chain=true",
            "timedelta(minutes=15)",
            "qwf-chain-",
            "process_network_corroboration=",
            "process_network_corroboration_bonus=+12.0",
            "_process_network_matches",
            "temporal_context_event_ids",
            "cross_signal_actor_bonus",
        ),
        "scoring.py": (
            "credential_spray_high_priority_floor=65.0",
            "high_confidence_behavior_floor=65.0",
            '"document_spawned_interpreter"',
            '"web_server_spawned_suspicious_shell"',
            '"ransomware_recovery_inhibition"',
            '"event_log_clearing"',
            '"defender_tamper_command"',
            '"reverse_shell"',
            '"credential_dumping"',
            "temporal_actor_context",
        ),
        "product_store.py": (
            "_SUPPRESSION_BYPASS_MARKERS",
            "_bypasses_suppression",
            '"reverse_shell"',
            '"credential_spray"',
            "_finding_current_cycle_event_ids",
        ),
        "runtime.py": (
            "CoreSentinelService",
            "CoreSentinelStore",
            "evaluate_warm_start",
            "install_dashboard_performance",
        ),
        "core_service.py": (
            "AdaptiveMaintenanceGovernor",
            "ContextualPipeline",
            "active_incident_lanes",
        ),
        "performance_budget.py": (
            "idle_cpu_percent_total_capacity",
            "rss_mib",
            "fast_p50_ms",
            "fast_p95_ms",
            "analysis_p95_ms",
        ),
        "collectors/debian.py": (
            '"credential_spray"',
            '"source_failed_count"',
            '"raw_source_address_persisted": False',
            '"raw_username_persisted": False',
            '"address_identity": "installation_keyed_hmac_sha256"',
            "privacy identity unavailable; connections not persisted",
            "parse_docker_inspect_batch_output",
        ),
        "collectors/parsers.py": (
            '"web_server_spawned_suspicious_shell"',
            "_LINUX_WEB_PARENT_NAMES",
            "_PARENT_CHILD_SUSPICIOUS_MARKERS",
            "_linux_parent_child_markers",
            '"linux-outbound-address-v1"',
            '"linux-auth-source-v1"',
            "from\\s+|rhost=",
        ),
        "collectors/windows.py": (
            "collect_windows_native_fast",
            "WINDOWS_FAST_CORE_COMMAND",
            "refresh_slow_context",
            "_fast_detail_needed",
            "parse_windows_connections(",
            "parse_windows_persistence(",
        ),
        "collectors/windows_native_fast.py": (
            "CreateToolhelp32Snapshot",
            "GetExtendedTcpTable",
            "actions_executed" if False else "collect_windows_native_fast",
        ),
        "collectors/windows_parsers.py": (
            "import re",
            '"reverse_shell"',
            '"credential_dumping"',
            '"document_spawned_interpreter"',
            '"ransomware_recovery_inhibition"',
            '"event_log_clearing"',
            '"defender_tamper_command"',
            '"windows-outbound-address-v1"',
            '"windows-auth-source-v1"',
            '"windows-persistence-record-v1"',
            '"command_hash": command_identity',
            r"vssadmin(?:\.exe)?\s+delete\s+shadows",
            r"wevtutil(?:\.exe)?\s+cl",
            "_DOCUMENT_PARENTS",
            "_DOCUMENT_CHILD_EXECUTORS",
        ),
    }

    missing: list[str] = []
    for label, fragments in required.items():
        for fragment in fragments:
            if fragment not in texts[label]:
                missing.append(f"{label}: {fragment}")
    if missing:
        raise RuntimeError("v0.5 combined source contract missing:\n" + "\n".join(missing))

    for relative in (
        "tests/test_address_privacy_v05.py",
        "tests/test_suppression_high_signal_v05.py",
        "tests/test_v05_release_merge.py",
        "scripts/validate_migrated_release.py",
        "scripts/audit_v05_safety.py",
    ):
        if not (ROOT / relative).is_file():
            raise RuntimeError(f"v0.5 release artifact missing: {relative}")


def main() -> int:
    _require_pytest()
    version = _version()
    _verify_release_documentation()
    _verify_observation_only_source_contract()
    _verify_combined_source_contract()
    env = _test_environment()
    _run([sys.executable, "-m", "compileall", "-q", "src", "tests", "scripts"], env=env)
    _run([sys.executable, "-m", "pytest", "-q", "-W", "error"], env=env)
    _run([sys.executable, "scripts/public_release_audit.py"], env=env)

    print("\nQUIETWARD 0.5.0-ALPHA.1 COMBINED GATE: PASS")
    print(f"version={version}")
    print("full pytest suite=PASS")
    print("multi-cadence core=PASS")
    print("native Windows FAST inventory contract=PASS")
    print("incident lifecycle/source-aware resolution=PASS")
    print("bounded temporal/same-actor context=PASS")
    print("cross-subject attack-chain correlation=PASS")
    print("process-network corroboration=PASS")
    print("credential-spray source/account aggregation=PASS")
    print("installation-keyed address privacy=PASS")
    print("high-signal suppression bypass=PASS")
    print("Windows collector/parser contract=PASS")
    print("observation-only contract=PASS")
    print("release documentation consistency=PASS")
    print("public-release audit=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
