#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sqlite3
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from quietward import __version__
from quietward.config import load_config
from quietward.contracts import (
    ActionProposal,
    ActionType,
    AnalysisReport,
    EventAssessment,
    Finding,
    SecurityEvent,
    Severity,
)
from quietward.integrations.response import build_response_handoff_events
from quietward.privacy_identity import PrivacyIdentity


MAX_HANDOFF_BYTES = 2_000_000
DEFAULT_MAX_PENDING_FILES = 2048
_CHAIN_HASH = re.compile(r"^[0-9a-f]{64}$")


class OutboxError(RuntimeError):
    pass


def _utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise OutboxError("stored QuietWard timestamp is invalid")
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise OutboxError("stored QuietWard timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OutboxError("stored QuietWard timestamp is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _report_from_dict(value: Any) -> AnalysisReport:
    if not isinstance(value, dict):
        raise OutboxError("stored QuietWard report is invalid")
    try:
        assessments = tuple(
            EventAssessment(
                event_id=str(item["event_id"]),
                score=float(item["score"]),
                severity=Severity(str(item["severity"])),
                reasons=tuple(str(reason) for reason in item.get("reasons", [])),
            )
            for item in value.get("assessments", [])
        )
        findings = tuple(
            Finding(
                finding_id=str(item["finding_id"]),
                created_at=_utc(item["created_at"]),
                host_id=str(item["host_id"]),
                subject=str(item["subject"]),
                title=str(item["title"]),
                summary=str(item["summary"]),
                score=float(item["score"]),
                severity=Severity(str(item["severity"])),
                evidence_event_ids=tuple(str(event_id) for event_id in item.get("evidence_event_ids", [])),
                reasons=tuple(str(reason) for reason in item.get("reasons", [])),
                requires_human_approval=bool(item.get("requires_human_approval", True)),
            )
            for item in value.get("findings", [])
        )
        proposals = tuple(
            ActionProposal(
                proposal_id=str(item["proposal_id"]),
                finding_id=str(item["finding_id"]),
                action_type=ActionType(str(item["action_type"])),
                target=str(item["target"]),
                reason=str(item["reason"]),
                destructive=bool(item["destructive"]),
                requires_approval=bool(item.get("requires_approval", True)),
                executable_in_current_mode=bool(item.get("executable_in_current_mode", False)),
            )
            for item in value.get("action_proposals", [])
        )
        return AnalysisReport(
            generated_at=_utc(value["generated_at"]),
            mode=str(value["mode"]),
            events_analyzed=int(value["events_analyzed"]),
            assessments=assessments,
            findings=findings,
            action_proposals=proposals,
            actions_executed=int(value.get("actions_executed", 0)),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise OutboxError("stored QuietWard report cannot be reconstructed safely") from exc


def _events_from_dict(value: Any) -> list[SecurityEvent]:
    if not isinstance(value, list):
        raise OutboxError("stored QuietWard events are invalid")
    try:
        return [SecurityEvent.from_dict(item) for item in value]
    except (TypeError, ValueError) as exc:
        raise OutboxError("stored QuietWard event cannot be reconstructed safely") from exc


def _private_directory(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    if resolved.is_symlink() or not resolved.is_dir():
        raise OutboxError("Response handoff outbox must be a normal directory")
    if os.name != "nt":
        mode = stat.S_IMODE(resolved.stat().st_mode)
        if mode & 0o077:
            try:
                resolved.chmod(0o700)
            except OSError as exc:
                raise OutboxError("Response handoff outbox permissions are unsafe") from exc
    return resolved


def _read_existing_regular_file(path: Path) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise OutboxError(f"existing handoff is unavailable: {path.name}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OutboxError(f"existing handoff is not a normal file: {path.name}")
    if info.st_size > MAX_HANDOFF_BYTES:
        raise OutboxError(f"existing handoff exceeds the bounded file-size limit: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OutboxError(f"existing handoff could not be opened safely: {path.name}") from exc
    try:
        data = os.read(descriptor, MAX_HANDOFF_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_HANDOFF_BYTES:
        raise OutboxError(f"existing handoff exceeds the bounded file-size limit: {path.name}")
    return data


def _atomic_json(path: Path, value: dict[str, Any], *, exclusive: bool) -> None:
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(data) > MAX_HANDOFF_BYTES:
        raise OutboxError("Response handoff exceeds the bounded file-size limit")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{time.time_ns()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short Response handoff outbox write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        if exclusive and path.exists():
            existing = _read_existing_regular_file(path)
            if existing != data:
                raise OutboxError(f"existing handoff changed unexpectedly: {path.name}")
            temporary.unlink()
            return
        os.replace(temporary, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _state_path(outbox: Path) -> Path:
    return outbox / ".quietward-response-outbox-state.json"


def _load_state(outbox: Path) -> tuple[int, str | None, bool]:
    path = _state_path(outbox)
    if not path.exists():
        return 0, None, False
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OutboxError("Response handoff outbox state is unreadable") from exc
    if not isinstance(value, dict) or value.get("format") != "quietward-response-outbox-state-v1":
        raise OutboxError("Response handoff outbox state is invalid")
    if value.get("network_requests_performed") != 0 or value.get("actions_executed") != 0:
        raise OutboxError("Response handoff outbox state violates the observation-only contract")
    cycle_id = value.get("last_cycle_id", 0)
    if not isinstance(cycle_id, int) or isinstance(cycle_id, bool) or cycle_id < 0:
        raise OutboxError("Response handoff outbox state cycle is invalid")
    chain_hash = value.get("last_chain_hash")
    if cycle_id == 0:
        if chain_hash not in {None, ""}:
            raise OutboxError("Response handoff outbox state has a hash without a cycle")
        return 0, None, True
    if not isinstance(chain_hash, str) or not _CHAIN_HASH.fullmatch(chain_hash):
        raise OutboxError("Response handoff outbox state chain hash is invalid")
    return cycle_id, chain_hash, True


def _save_state(outbox: Path, cycle_id: int, chain_hash: str) -> None:
    _atomic_json(
        _state_path(outbox),
        {
            "format": "quietward-response-outbox-state-v1",
            "last_cycle_id": cycle_id,
            "last_chain_hash": chain_hash,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "network_requests_performed": 0,
            "actions_executed": 0,
        },
        exclusive=False,
    )


def _open_read_only(database: Path) -> sqlite3.Connection:
    resolved = database.expanduser().resolve()
    if not resolved.is_file():
        raise OutboxError(f"QuietWard database does not exist: {resolved}")
    connection = sqlite3.connect(f"file:{resolved.as_posix()}?mode=ro", uri=True, timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _metadata(connection: sqlite3.Connection, key: str) -> str | None:
    try:
        row = connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
    except sqlite3.OperationalError as exc:
        raise OutboxError("QuietWard metadata table is unavailable") from exc
    return str(row[0]) if row is not None else None


def _verify_evidence_chain(connection: sqlite3.Connection) -> tuple[int, str, int, str | None]:
    anchor_cycle_raw = _metadata(connection, "evidence_chain_anchor_cycle")
    anchor_hash_raw = _metadata(connection, "evidence_chain_anchor_hash")
    if (anchor_cycle_raw is None) != (anchor_hash_raw is None):
        raise OutboxError("QuietWard evidence-chain anchor metadata is incomplete")
    if anchor_cycle_raw is None:
        anchor_cycle = 0
        anchor_hash = "0" * 64
    else:
        try:
            anchor_cycle = int(anchor_cycle_raw)
        except ValueError as exc:
            raise OutboxError("QuietWard evidence-chain anchor cycle is invalid") from exc
        if anchor_cycle < 0 or not isinstance(anchor_hash_raw, str) or not _CHAIN_HASH.fullmatch(anchor_hash_raw):
            raise OutboxError("QuietWard evidence-chain anchor is invalid")
        anchor_hash = anchor_hash_raw

    previous = anchor_hash
    maximum_cycle = anchor_cycle
    last_hash: str | None = None
    try:
        rows = connection.execute(
            "SELECT cycle_id,previous_hash,payload_hash,chain_hash,payload_json FROM evidence_chain ORDER BY cycle_id"
        )
    except sqlite3.OperationalError as exc:
        raise OutboxError("QuietWard evidence-chain schema is unavailable") from exc
    for row in rows:
        cycle_id = int(row["cycle_id"])
        payload = str(row["payload_json"])
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()
        expected_chain_hash = hashlib.sha256(
            f"{previous}|{payload_hash}|{cycle_id}".encode()
        ).hexdigest()
        if str(row["previous_hash"]) != previous:
            raise OutboxError(f"QuietWard evidence chain failed at cycle {cycle_id}: previous hash mismatch")
        if str(row["payload_hash"]) != payload_hash:
            raise OutboxError(f"QuietWard evidence chain failed at cycle {cycle_id}: payload hash mismatch")
        if str(row["chain_hash"]) != expected_chain_hash:
            raise OutboxError(f"QuietWard evidence chain failed at cycle {cycle_id}: chain hash mismatch")
        previous = expected_chain_hash
        last_hash = expected_chain_hash
        maximum_cycle = max(maximum_cycle, cycle_id)
    return anchor_cycle, anchor_hash, maximum_cycle, last_hash


def _resolve_start_cycle(
    connection: sqlite3.Connection,
    *,
    anchor_cycle: int,
    anchor_hash: str,
    maximum_cycle: int,
    state_cycle: int,
    state_hash: str | None,
    state_exists: bool,
) -> tuple[int, str | None]:
    if not state_exists:
        return anchor_cycle, anchor_hash if anchor_cycle else None
    if state_cycle > maximum_cycle:
        raise OutboxError("outbox state is ahead of the QuietWard evidence chain")
    if state_cycle < anchor_cycle:
        raise OutboxError("outbox state fell behind the retained QuietWard evidence-chain anchor")
    if state_cycle == 0:
        return 0, None
    if state_cycle == anchor_cycle:
        expected = anchor_hash
    else:
        row = connection.execute(
            "SELECT chain_hash FROM evidence_chain WHERE cycle_id=?",
            (state_cycle,),
        ).fetchone()
        if row is None:
            raise OutboxError("outbox state cycle is missing from the retained QuietWard evidence chain")
        expected = str(row[0])
    if state_hash != expected:
        raise OutboxError("outbox state chain hash does not match QuietWard evidence")
    return state_cycle, state_hash


def _bundle(
    *,
    cycle_id: int,
    chain_hash: str,
    payload: dict[str, Any],
    identity: PrivacyIdentity,
) -> dict[str, Any] | None:
    events = _events_from_dict(payload.get("events"))
    report = _report_from_dict(payload.get("report"))
    handoff_events = build_response_handoff_events(
        report,
        events,
        privacy_identity=identity,
        source_version=__version__,
        operating_system=platform.system(),
        source_cycle_id=cycle_id,
        source_chain_hash=chain_hash,
    )
    if not handoff_events:
        return None
    host_ids = sorted({str(item["host_id"]) for item in handoff_events})
    if len(host_ids) != 1:
        raise OutboxError("one QuietWard cycle produced a cross-host Response handoff")
    return {
        "format": "quietward-response-handoff-v1",
        "generated_at": str(payload.get("completed_at") or datetime.now(timezone.utc).isoformat()),
        "source_version": __version__,
        "source_cycle_id": cycle_id,
        "source_chain_hash": chain_hash,
        "host_ids": host_ids,
        "events": handoff_events,
        "safety": {
            "observation_only_source": True,
            "actions_executed": 0,
            "executable_authority": False,
            "raw_finding_subjects_included": False,
            "network_request_performed": False,
        },
    }


def export_once(
    database: Path,
    outbox: Path,
    identity: PrivacyIdentity,
    *,
    max_pending_files: int = DEFAULT_MAX_PENDING_FILES,
) -> dict[str, int]:
    if not 1 <= max_pending_files <= 10000:
        raise OutboxError("max pending files must be between 1 and 10000")
    resolved_outbox = _private_directory(outbox)
    state_cycle, state_hash, state_exists = _load_state(resolved_outbox)
    pending = len(list(resolved_outbox.glob("cycle-*.json")))
    exported = skipped = advanced = 0

    with _open_read_only(database) as connection:
        anchor_cycle, anchor_hash, maximum_cycle, _ = _verify_evidence_chain(connection)
        last_cycle, _ = _resolve_start_cycle(
            connection,
            anchor_cycle=anchor_cycle,
            anchor_hash=anchor_hash,
            maximum_cycle=maximum_cycle,
            state_cycle=state_cycle,
            state_hash=state_hash,
            state_exists=state_exists,
        )
        rows = connection.execute(
            "SELECT cycle_id,chain_hash,payload_json FROM evidence_chain WHERE cycle_id>? ORDER BY cycle_id",
            (last_cycle,),
        )
        for row in rows:
            cycle_id = int(row["cycle_id"])
            chain_hash = str(row["chain_hash"])
            try:
                payload = json.loads(str(row["payload_json"]))
            except json.JSONDecodeError as exc:
                raise OutboxError(f"cycle {cycle_id} evidence payload is invalid") from exc
            if not isinstance(payload, dict):
                raise OutboxError(f"cycle {cycle_id} evidence payload is not an object")
            bundle = _bundle(
                cycle_id=cycle_id,
                chain_hash=chain_hash,
                payload=payload,
                identity=identity,
            )
            if bundle is None:
                skipped += 1
            else:
                filename = f"cycle-{cycle_id:010d}-{chain_hash[:16]}.json"
                path = resolved_outbox / filename
                if not path.exists() and pending >= max_pending_files:
                    raise OutboxError("Response handoff outbox is full; ingestion must catch up")
                existed = path.exists()
                _atomic_json(path, bundle, exclusive=True)
                if not existed:
                    pending += 1
                    exported += 1
            _save_state(resolved_outbox, cycle_id, chain_hash)
            last_cycle = cycle_id
            advanced += 1

    return {
        "cycles_advanced": advanced,
        "handoffs_exported": exported,
        "cycles_without_findings": skipped,
        "last_cycle_id": last_cycle,
        "pending_files": pending,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Continuously export sanitized QuietWard evidence-chain findings to a private local Response handoff outbox"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("~/.config/quietward/config.json").expanduser(),
    )
    parser.add_argument("--outbox", type=Path)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--max-pending-files", type=int, default=DEFAULT_MAX_PENDING_FILES)
    args = parser.parse_args()

    if not 1 <= args.interval <= 300:
        raise OutboxError("poll interval must be between 1 and 300 seconds")
    config = load_config(args.config)
    key_path = config.collector.privacy_identity_key_path
    if key_path is None:
        raise OutboxError("collector.privacy_identity_key_path is required for Response handoff")
    identity = PrivacyIdentity.load(
        key_path,
        namespace=config.collector.privacy_identity_namespace,
    )
    outbox = (args.outbox or (config.state_dir / "response-handoff-outbox")).expanduser()
    if not outbox.is_absolute():
        raise OutboxError("Response handoff outbox path must be absolute")

    while True:
        result = export_once(
            config.storage.database_path,
            outbox,
            identity,
            max_pending_files=args.max_pending_files,
        )
        if args.once:
            print(json.dumps(result, sort_keys=True))
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OutboxError as exc:
        print(f"QuietWard Response handoff outbox failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
