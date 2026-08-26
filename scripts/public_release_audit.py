#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import tomllib
from pathlib import Path

FORBIDDEN_SUFFIXES = {
    ".sqlite",
    ".sqlite3",
    ".db",
    ".gguf",
    ".onnx",
    ".safetensors",
    ".pt",
    ".pth",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
}
FORBIDDEN_PARTS = {
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "scanner-cache",
    "malware-samples",
    "quarantine",
    "qualification",
    "quietward.egg-info",
}
PRIVATE_ONLY_PATHS = {
    Path("NOTICE"),
    Path("scripts/migrate_private_repo_to_quietward.py"),
    Path("tests/test_migrate_private_repo_to_quietward.py"),
    Path("docs/CORE_ENGINEERING_CHECKPOINT.md"),
    Path("docs/CORE_PERFORMANCE_ARCHITECTURE.md"),
    Path("docs/P520_V05_EXECUTION.md"),
    Path("docs/V0.5_DEVELOPMENT_PLAN.md"),
    Path("docs/V05_APPROVAL_PACKET.md"),
}
SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
}
LEGACY_IDENTIFIERS = (
    "Forge" + " Sentinel",
    "forge-" + "sentinel",
    "forge_" + "sentinel",
    "Quiet" + "ward",
)
COMPATIBILITY_ROOT = Path("src") / ("forge_" + "sentinel")
COMPATIBILITY_FILES = {
    COMPATIBILITY_ROOT / "__init__.py",
    COMPATIBILITY_ROOT / "__main__.py",
    Path("scripts/migrate_pre_rename_user_install.py"),
    Path("scripts/install_user_service.sh"),
    Path("tests/test_pre_rename_migration.py"),
    Path("docs/DEPLOYMENT.md"),
    Path("docs/PRIVACY.md"),
    Path("src/quietward/config.py"),
    Path("src/quietward/collectors/privacy.py"),
    Path("src/quietward/evidence.py"),
    Path("src/quietward/privacy_identity.py"),
    Path("tests/test_config.py"),
    Path("tests/test_evidence_signing.py"),
    Path("tests/test_privacy_identity.py"),
}
REQUIRED = {
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SUPPORT.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "docs/PRIVACY.md",
    "docs/FIRST_RUN.md",
    "docs/WINDOWS.md",
    "docs/RELEASE_CHECKLIST.md",
    "docs/V05_REVIEW_GUIDE.md",
    "docs/V05_MARKETING_KIT.md",
    "docs/V05_DETECTION_REGRESSION_MATRIX.md",
    "docs/releases/v0.5.0-alpha.1.md",
    "scripts/build_release_bundle.py",
    "scripts/build_release_candidate.ps1",
    "scripts/verify_release_bundle.py",
    "scripts/public_release_audit.py",
    "scripts/audit_v05_safety.py",
    "scripts/validate_migrated_release.py",
    "scripts/verify_v05_detection.py",
    "scripts/build_sbom.py",
    "scripts/migrate_pre_rename_user_install.py",
    "scripts/validate_release.sh",
    "scripts/install_windows.ps1",
    "scripts/uninstall_windows.ps1",
    "scripts/qualify_windows.ps1",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/pull_request_template.md",
}


def _display_version(pep440: str) -> str:
    return re.sub(r"a([0-9]+)$", r"-alpha.\1", pep440)


def _release_metadata_checks(root: Path, blockers: list[str]) -> None:
    try:
        value = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        pep440 = str(value["project"]["version"])
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        blockers.append(f"cannot determine project version: {exc}")
        return
    project = value.get("project") or {}
    if project.get("name") != "quietward":
        blockers.append("project distribution name must be quietward")
    scripts = project.get("scripts") or {}
    if scripts.get("quietward") != "quietward.console:main":
        blockers.append("QuietWard CLI entry point is missing or incorrect")
    version = _display_version(pep440)
    notes = root / "docs" / "releases" / f"v{version}.md"
    if not notes.is_file():
        blockers.append(
            f"missing release notes for {version}: {notes.relative_to(root)}"
        )
    try:
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    except OSError as exc:
        blockers.append(f"cannot read changelog: {exc}")
    else:
        if f"## {version}" not in changelog:
            blockers.append(f"changelog does not contain version {version}")


def _legacy_brand_checks(
    relative: Path,
    text: str,
    blockers: list[str],
) -> None:
    path_text = relative.as_posix()
    compatibility_file = relative in COMPATIBILITY_FILES
    compatibility_path = (
        len(relative.parts) >= len(COMPATIBILITY_ROOT.parts)
        and relative.parts[: len(COMPATIBILITY_ROOT.parts)]
        == COMPATIBILITY_ROOT.parts
    )
    for identifier in LEGACY_IDENTIFIERS:
        if identifier in path_text and not compatibility_path:
            blockers.append(
                f"retired QuietWard identifier in path: {relative}"
            )
        if identifier in text and not compatibility_file:
            blockers.append(
                f"retired QuietWard identifier in content: {relative}"
            )


def audit(root: Path) -> dict[str, object]:
    blockers: list[str] = []
    warnings: list[str] = []
    files_checked = 0
    blockers.extend(
        f"missing required file: {path}"
        for path in sorted(REQUIRED)
        if not (root / path).is_file()
    )
    blockers.extend(
        f"private-only path remained in public tree: {path.as_posix()}"
        for path in sorted(PRIVATE_ONLY_PATHS, key=lambda item: item.as_posix())
        if (root / path).exists()
    )
    workflows = root / ".github" / "workflows"
    if workflows.exists() and any(path.is_file() for path in workflows.rglob("*")):
        blockers.append("GitHub Actions workflows are not permitted for this release line")
    _release_metadata_checks(root, blockers)

    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts or path.suffix.lower() == ".pyc":
            continue
        if any(part in FORBIDDEN_PARTS for part in relative.parts):
            continue
        files_checked += 1
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            blockers.append(f"forbidden artifact: {relative}")
            continue
        if path.stat().st_size > 2_000_000:
            warnings.append(f"large file requires review: {relative}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            warnings.append(f"binary file requires review: {relative}")
            continue
        _legacy_brand_checks(relative, text, blockers)
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                blockers.append(f"possible {label}: {relative}")
        if "/home/" in text or "/Users/" in text or "C:\\Users\\" in text:
            warnings.append(f"possible machine-specific path: {relative}")

    return {
        "decision": "PASS" if not blockers else "FAIL",
        "files_checked": files_checked,
        "blockers": sorted(set(blockers)),
        "warnings": warnings,
        "actions_executed": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args()
    report = audit(args.root.resolve())
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["decision"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
