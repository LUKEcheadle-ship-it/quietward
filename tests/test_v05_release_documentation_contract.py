from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v05_release_notes_match_combined_update_and_safety_boundary() -> None:
    notes = (ROOT / "docs" / "releases" / "v0.5.0-alpha.1.md").read_text(
        encoding="utf-8"
    ).lower()
    required = (
        "same-host multi-stage attack chains",
        "bounded 15-minute window",
        "credential spray",
        "raw source ip is not persisted",
        "installation-keyed hmac-sha256",
        "same raw address produces different durable identities",
        "suppression safety",
        "reverse shells",
        "document_spawned_interpreter",
        "web_server_spawned_suspicious_shell",
        "ransomware recovery inhibition",
        "event-log clearing",
        "defender_tamper_command",
        "windows collector/parser contracts",
        "does not quarantine/delete files",
        "actions_executed == 0",
        "executable_proposals == 0",
        "verify_v05_detection.py",
    )
    missing = [fragment for fragment in required if fragment not in notes]
    assert missing == []


def test_v05_readme_keeps_combined_public_product_observation_only() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    required = (
        "0.5.0-alpha.1",
        "release/v0.5.0-alpha.1",
        "observation-only",
        "native windows fast",
        "incident lifecycle",
        "installation-keyed hmac-sha256",
        "bypasses ordinary suppression",
        "does not quarantine/delete files",
        "terminate processes or services",
        "change firewall rules",
        "actions_executed == 0",
        "executable_proposals == 0",
    )
    missing = [fragment for fragment in required if fragment not in readme]
    assert missing == []
