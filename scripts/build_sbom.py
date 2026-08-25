#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tomllib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
TOOL_NAME = "quietward-sbom/1"
DEFAULT_EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
    "qualification",
    "private-beta-reports",
}
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _spdx_id(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-.")
    return normalized or "item"


def _iso_timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _link_like(details: os.stat_result) -> bool:
    attributes = int(getattr(details, "st_file_attributes", 0))
    return stat.S_ISLNK(details.st_mode) or bool(
        attributes & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    if left.st_ino and right.st_ino:
        return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
    return (
        left.st_dev,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _safe_regular_file(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(details.st_mode)
        and not _link_like(details)
        and int(getattr(details, "st_nlink", 1)) == 1
    )


def _safe_relative(path: Path) -> str:
    pure = PurePosixPath(path.as_posix())
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ValueError(f"unsafe SBOM path: {path}")
    return pure.as_posix()


def _read_bytes(path: Path, *, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect SBOM input {path}: {exc}") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or _link_like(before)
        or int(getattr(before, "st_nlink", 1)) != 1
    ):
        raise ValueError(f"SBOM input must be a single-link regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open SBOM input safely {path}: {exc}") from exc
    chunks: list[bytes] = []
    total = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _link_like(opened)
            or int(getattr(opened, "st_nlink", 1)) != 1
            or not _same_file(before, opened)
        ):
            raise ValueError(f"SBOM input changed during validation: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"SBOM input exceeds {max_bytes} bytes: {path}")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError(f"SBOM input disappeared during read: {path}: {exc}") from exc
    if _link_like(after) or not _same_file(before, after):
        raise ValueError(f"SBOM input changed during read: {path}")
    return b"".join(chunks)


def discover_files(
    root: Path,
    *,
    excluded_parts: set[str] = DEFAULT_EXCLUDED_PARTS,
) -> tuple[Path, ...]:
    resolved = root.resolve(strict=True)
    files: list[Path] = []
    for path in resolved.rglob("*"):
        relative = path.relative_to(resolved)
        if any(part in excluded_parts for part in relative.parts):
            continue
        try:
            details = path.lstat()
        except OSError as exc:
            raise ValueError(f"cannot inspect SBOM path {relative}: {exc}") from exc
        if _link_like(details):
            raise ValueError(f"link-like SBOM path is forbidden: {relative}")
        if stat.S_ISDIR(details.st_mode):
            continue
        if (
            not stat.S_ISREG(details.st_mode)
            or int(getattr(details, "st_nlink", 1)) != 1
        ):
            raise ValueError(f"hard-linked or non-regular SBOM path: {relative}")
        files.append(relative)
    return tuple(sorted(files, key=lambda item: item.as_posix()))


def project_metadata(root: Path) -> tuple[str, str, str]:
    value = tomllib.loads(_read_bytes(root / "pyproject.toml").decode("utf-8"))
    project = value.get("project")
    if not isinstance(project, Mapping):
        raise ValueError("pyproject.toml is missing [project]")
    name = str(project.get("name") or "").strip()
    version = str(project.get("version") or "").strip()
    license_value = project.get("license")
    license_text = "NOASSERTION"
    if isinstance(license_value, Mapping):
        license_text = str(license_value.get("text") or "NOASSERTION").strip()
    elif isinstance(license_value, str):
        license_text = license_value.strip()
    if not name or not version:
        raise ValueError("project name and version are required")
    return name, version, license_text or "NOASSERTION"


def generate_sbom(
    root: Path,
    relative_files: Iterable[Path],
    *,
    created: str,
    source_commit: str,
) -> dict[str, object]:
    resolved = root.resolve(strict=True)
    name, version, declared_license = project_metadata(resolved)
    normalized_commit = source_commit.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", normalized_commit):
        raise ValueError("source_commit must be a full 40-character Git SHA")
    created_at = _iso_timestamp(created)

    file_records: list[dict[str, object]] = []
    relationships: list[dict[str, str]] = []
    aggregate = hashlib.sha256()
    package_id = "SPDXRef-Package-" + _spdx_id(name)

    for index, relative in enumerate(
        sorted(relative_files, key=lambda item: item.as_posix()), start=1
    ):
        relative_text = _safe_relative(relative)
        payload = _read_bytes(resolved / relative)
        digest = hashlib.sha256(payload).hexdigest()
        aggregate.update(relative_text.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\n")
        file_id = f"SPDXRef-File-{index:05d}-{_spdx_id(relative.name)}"
        file_records.append(
            {
                "fileName": "./" + relative_text,
                "SPDXID": file_id,
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": package_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )

    verification = aggregate.hexdigest()
    namespace = (
        "https://spdx.org/spdxdocs/"
        + _spdx_id(name)
        + "-"
        + _spdx_id(version)
        + "-"
        + normalized_commit[:12]
        + "-"
        + verification[:16]
    )
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-{version}",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": created_at,
            "creators": [f"Tool: {TOOL_NAME}"],
        },
        "documentDescribes": [package_id],
        "packages": [
            {
                "name": name,
                "SPDXID": package_id,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": declared_license,
                "licenseDeclared": declared_license,
                "copyrightText": "NOASSERTION",
                "packageVerificationCode": {
                    "packageVerificationCodeValue": verification
                },
                "externalRefs": [
                    {
                        "referenceCategory": "OTHER",
                        "referenceType": "quietward:git-commit",
                        "referenceLocator": normalized_commit,
                    }
                ],
            }
        ],
        "files": file_records,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": package_id,
            },
            *relationships,
        ],
        "annotations": [
            {
                "annotationDate": created_at,
                "annotationType": "OTHER",
                "annotator": f"Tool: {TOOL_NAME}",
                "comment": "Generated offline from a bounded regular-file source tree.",
            }
        ],
    }


def write_sbom(output: Path, document: Mapping[str, object]) -> None:
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to replace existing SBOM: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(output, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="build an offline deterministic SPDX SBOM")
    parser.add_argument("output", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--created", required=True, help="ISO-8601 release creation time")
    parser.add_argument("--source-commit", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve(strict=True)
    files = discover_files(root)
    document = generate_sbom(
        root,
        files,
        created=args.created,
        source_commit=args.source_commit,
    )
    write_sbom(args.output, document)
    print(
        json.dumps(
            {
                "decision": "PASS",
                "output": str(args.output.resolve()),
                "files": len(document["files"]),
                "source_commit": args.source_commit.lower(),
                "actions_executed": 0,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
