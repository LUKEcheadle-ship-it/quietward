from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v05_release_notes_match_combined_update_and_safety_boundary() -> None:
    notes = (ROOT / "docs" / "releases" / "v0.5.0-alpha.1.md").read_text(
        encoding="utf-8"
    ).lower()
    required = (
        "lower-cost always-on monitoring",
        "fast",
        "standard",
        "deep",
        "maintenance",
        "read-only native windows apis",
        "new",
        "recurring",
        "changed",
        "resolved",
        "bounded five-minute in-memory context window",
        "same-host multi-stage attack chains",
        "process/network corroboration",
        "credential spray",
        "installation-keyed hmac-sha256",
        "fail closed",
        "suppression safety",
        "reverse-shell behavior",
        "credential dumping/theft",
        "ransomware recovery inhibition",
        "event-log clearing",
        "actions_executed == 0",
        "executable_proposals == 0",
        "checksum sidecar",
        "current-head commit",
        "native windows 11 and debian 12 qualification",
        "experimental alpha",
    )
    missing = [fragment for fragment in required if fragment not in notes]
    assert missing == []


def test_v05_readme_keeps_combined_public_product_observation_only() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    required = (
        "0.5.0-alpha.1",
        "0.5.0a1",
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
