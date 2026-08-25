#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import tomllib
import zipfile
from pathlib import Path

EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "qualification",
    "scanner-cache",
    "malware-samples",
    "quarantine",
}
EXCLUDED_SUFFIXES = {
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
FIXED_TIMESTAMP = (2026, 1, 1, 0, 0, 0)
MANIFEST_FORMAT = "quietward-release-manifest-v1"


def included_files(root: Path) -> list[Path]:
    values: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        values.append(relative)
    return sorted(values, key=lambda item: item.as_posix())


def project_version(root: Path) -> str:
    value = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(value["project"]["version"])


def build(root: Path, output: Path) -> dict[str, object]:
    files = included_files(root)
    manifest_files = []
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative in files:
            data = (root / relative).read_bytes()
            info = zipfile.ZipInfo(relative.as_posix(), FIXED_TIMESTAMP)
            info.external_attr = (0o755 if data.startswith(b"#!") else 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
            manifest_files.append(
                {
                    "path": relative.as_posix(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                }
            )
        manifest = {
            "format": MANIFEST_FORMAT,
            "project": "quietward",
            "version": project_version(root),
            "files": manifest_files,
        }
        manifest_data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        info = zipfile.ZipInfo("RELEASE-MANIFEST.json", FIXED_TIMESTAMP)
        info.external_attr = 0o644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, manifest_data)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return {
        "archive": str(output),
        "version": project_version(root),
        "files": len(files),
        "sha256": digest,
        "bytes": output.stat().st_size,
        "manifest_format": MANIFEST_FORMAT,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(json.dumps(build(args.root.resolve(), args.output.resolve()), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
