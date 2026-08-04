#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST = "RELEASE-MANIFEST.json"
MANIFEST_FORMAT = "quietward-release-manifest-v1"
REQUIRED = {
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "docs/FIRST_RUN.md",
    "docs/RELEASE_CHECKLIST.md",
    "scripts/install_windows.ps1",
    "scripts/uninstall_windows.ps1",
    "scripts/qualify_windows.ps1",
    "scripts/public_release_audit.py",
}
FORBIDDEN_PARTS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "qualification",
    "scanner-cache",
    "quarantine",
    "malware-samples",
}
FORBIDDEN_SUFFIXES = {
    ".pyc",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".log",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
}


def display_version(pep440: str) -> str:
    return re.sub(r"a([0-9]+)$", r"-alpha.\1", pep440)


def _safe_name(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name


def verify(archive_path: Path) -> dict[str, Any]:
    archive_path = archive_path.resolve()
    blockers: list[str] = []
    warnings: list[str] = []

    if not archive_path.is_file():
        return {"decision": "FAIL", "blockers": ["archive does not exist"], "archive": str(archive_path)}

    archive_sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    try:
        archive = zipfile.ZipFile(archive_path)
    except (OSError, zipfile.BadZipFile) as exc:
        return {"decision": "FAIL", "blockers": [f"invalid ZIP archive: {exc}"], "archive": str(archive_path)}

    version = "unknown"
    manifest_version = "unknown"
    with archive:
        names = [item.filename for item in archive.infolist()]
        if len(names) != len(set(names)):
            blockers.append("archive contains duplicate paths")
        for name in names:
            if not _safe_name(name):
                blockers.append(f"unsafe archive path: {name}")

        manifest: dict[str, Any]
        if MANIFEST not in names:
            blockers.append(f"missing {MANIFEST}")
            manifest = {"files": []}
        else:
            try:
                loaded = json.loads(archive.read(MANIFEST))
            except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                blockers.append(f"invalid release manifest: {exc}")
                manifest = {"files": []}
            else:
                if not isinstance(loaded, dict):
                    blockers.append("release manifest root must be an object")
                    manifest = {"files": []}
                else:
                    manifest = loaded

        if manifest.get("format") != MANIFEST_FORMAT:
            blockers.append("release manifest format is missing or unsupported")
        if manifest.get("project") != "quietward":
            blockers.append("release manifest project is not quietward")
        manifest_version = str(manifest.get("version") or "unknown")

        raw_entries = manifest.get("files")
        if not isinstance(raw_entries, list):
            blockers.append("release manifest files must be a list")
            raw_entries = []

        manifest_paths: list[str] = []
        for index, raw in enumerate(raw_entries):
            if not isinstance(raw, dict):
                blockers.append(f"manifest entry {index} is not an object")
                continue
            name = str(raw.get("path") or "")
            manifest_paths.append(name)
            if not _safe_name(name):
                blockers.append(f"unsafe manifest path: {name}")
                continue
            try:
                payload = archive.read(name)
            except KeyError:
                blockers.append(f"manifest file missing from archive: {name}")
                continue
            expected_hash = str(raw.get("sha256") or "")
            expected_bytes = raw.get("bytes")
            actual_hash = hashlib.sha256(payload).hexdigest()
            if actual_hash != expected_hash:
                blockers.append(f"hash mismatch: {name}")
            if not isinstance(expected_bytes, int) or expected_bytes != len(payload):
                blockers.append(f"size mismatch: {name}")

        if manifest_paths != sorted(manifest_paths):
            blockers.append("manifest paths are not deterministically sorted")
        if len(manifest_paths) != len(set(manifest_paths)):
            blockers.append("manifest contains duplicate paths")

        payload_names = sorted(name for name in names if name != MANIFEST)
        if sorted(manifest_paths) != payload_names:
            blockers.append("archive contents do not exactly match the manifest")

        missing = sorted(REQUIRED - set(payload_names))
        blockers.extend(f"missing required release file: {name}" for name in missing)

        for name in payload_names:
            path = PurePosixPath(name)
            if any(part in FORBIDDEN_PARTS for part in path.parts):
                blockers.append(f"forbidden release path: {name}")
            if path.suffix.lower() in FORBIDDEN_SUFFIXES:
                blockers.append(f"forbidden release artifact: {name}")

        if "pyproject.toml" in payload_names:
            try:
                project = tomllib.loads(archive.read("pyproject.toml").decode("utf-8"))
                version = str(project["project"]["version"])
            except (KeyError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                blockers.append(f"cannot read project version: {exc}")
        if version != "unknown" and manifest_version != version:
            blockers.append("manifest version does not match pyproject.toml")

        release_version = display_version(version)
        release_note = f"docs/releases/v{release_version}.md"
        if version != "unknown" and release_note not in payload_names:
            blockers.append(f"missing versioned release notes: {release_note}")
        if "CHANGELOG.md" in payload_names and version != "unknown":
            changelog = archive.read("CHANGELOG.md").decode("utf-8", errors="replace")
            if f"## {release_version}" not in changelog:
                blockers.append(f"changelog does not contain version {release_version}")

        failed_crc = archive.testzip()
        if failed_crc is not None:
            blockers.append(f"ZIP CRC verification failed: {failed_crc}")

    return {
        "decision": "PASS" if not blockers else "FAIL",
        "archive": str(archive_path),
        "archive_sha256": archive_sha256,
        "archive_bytes": archive_path.stat().st_size,
        "version": display_version(version),
        "manifest_version": manifest_version,
        "files": len(names) - (1 if MANIFEST in names else 0),
        "blockers": blockers,
        "warnings": warnings,
        "actions_executed": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a QuietWard deterministic release archive")
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    result = verify(args.archive)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["decision"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
