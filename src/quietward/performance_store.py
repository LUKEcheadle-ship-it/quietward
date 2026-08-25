from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable

from .config import StorageSettings
from .storage import SentinelStore


class PerformanceSentinelStore(SentinelStore):
    """SentinelStore with bounded-cost hot paths for the persistent service."""

    def __init__(
        self,
        settings: StorageSettings,
        *,
        full_audit_interval_seconds: float = 300.0,
        runtime_summary_cache_seconds: float = 300.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if full_audit_interval_seconds <= 0:
            raise ValueError("full_audit_interval_seconds must be positive")
        if runtime_summary_cache_seconds <= 0:
            raise ValueError("runtime_summary_cache_seconds must be positive")
        self.full_audit_interval_seconds = float(full_audit_interval_seconds)
        self.runtime_summary_cache_seconds = float(runtime_summary_cache_seconds)
        self._monotonic = monotonic
        self._verified_cycle_id = 0
        self._verified_chain_hash: str | None = None
        self._last_full_audit_at: float | None = None
        self._latest_snapshot_loaded = False
        self._latest_snapshot_cache = None
        self._runtime_summary_cache: dict[str, Any] | None = None
        self._runtime_summary_cache_at: float | None = None
        self._verification_metadata_at: float | None = None
        self._verification_metadata_key: tuple[object, ...] | None = None
        self._evidence_dirty = True
        self._last_verification_result: dict[str, Any] | None = None
        self._last_verification_data_version: int | None = None
        super().__init__(settings)

    def latest_snapshot(self):
        if self._latest_snapshot_loaded:
            return self._latest_snapshot_cache
        value = super().latest_snapshot()
        self._latest_snapshot_cache = value
        self._latest_snapshot_loaded = True
        return value

    def _database_data_version(self) -> int:
        row = self.connection.execute("PRAGMA data_version").fetchone()
        return int(row[0]) if row is not None else -1

    def _mark_evidence_dirty(self) -> None:
        self._evidence_dirty = True

    def persist_cycle(self, batch, report, **kwargs):
        result = super().persist_cycle(batch, report, **kwargs)
        self._latest_snapshot_cache = batch.snapshot
        self._latest_snapshot_loaded = True
        self._mark_evidence_dirty()
        return result

    def runtime_summary(self) -> dict[str, Any]:
        now = self._monotonic()
        cache_age = (
            None
            if self._runtime_summary_cache_at is None
            else max(0.0, now - self._runtime_summary_cache_at)
        )
        if (
            self._runtime_summary_cache is None
            or cache_age is None
            or cache_age >= self.runtime_summary_cache_seconds
        ):
            value = dict(super().summary())
            value["runtime_summary_cached"] = False
            value["runtime_summary_cache_age_seconds"] = 0.0
            self._runtime_summary_cache = dict(value)
            self._runtime_summary_cache_at = now
            return value

        value = dict(self._runtime_summary_cache)
        last = self.connection.execute(
            """
            SELECT completed_at,status,events_count,findings_count,
                   actions_executed,error
            FROM cycles ORDER BY id DESC LIMIT 1
            """
        ).fetchone()
        value["last_cycle"] = dict(last) if last else None
        value["evidence_chain"] = self.verify_evidence_chain()
        value["runtime_summary_cached"] = True
        value["runtime_summary_cache_age_seconds"] = round(cache_age, 3)
        value["actions_executed"] = 0
        return value

    def _checkpoint_from_full(self, result: dict[str, Any]) -> None:
        row = self.connection.execute(
            "SELECT cycle_id,chain_hash FROM evidence_chain ORDER BY cycle_id DESC LIMIT 1"
        ).fetchone()
        if row is not None:
            self._verified_cycle_id = int(row[0])
            self._verified_chain_hash = str(row[1])
            return
        anchor_cycle, anchor_hash = self._chain_anchor()
        self._verified_cycle_id = anchor_cycle
        self._verified_chain_hash = anchor_hash

    def _full_verify(self, now: float) -> dict[str, Any]:
        result = dict(super().verify_evidence_chain())
        result["verification_mode"] = "full"
        result["cycles_checked_this_pass"] = int(result.get("cycles_checked", 0) or 0)
        result["full_audit_interval_seconds"] = self.full_audit_interval_seconds
        if result.get("valid"):
            self._checkpoint_from_full(result)
            self._last_full_audit_at = now
        return result

    def _incremental_verify(self) -> dict[str, Any]:
        configured_key_id = self.get_metadata("evidence_signing_key_id")
        configured_algorithm = self.get_metadata("evidence_signing_algorithm")
        required_from = self._signing_required_from_cycle()
        errors: list[str] = []

        if configured_key_id is not None:
            if self.signer is None:
                errors.append("evidence signing key is required to verify signatures")
            elif self.signer.key_id != configured_key_id:
                errors.append("evidence signing key does not match the database")
            elif self.signer.algorithm != configured_algorithm:
                errors.append("evidence signing algorithm does not match the database")

        previous = self._verified_chain_hash
        if previous is None:
            _, previous = self._chain_anchor()
        rows = self.connection.execute(
            """
            SELECT cycle_id,previous_hash,payload_hash,chain_hash,payload_json
            FROM evidence_chain WHERE cycle_id>? ORDER BY cycle_id
            """,
            (self._verified_cycle_id,),
        ).fetchall()
        signatures_checked = 0
        checked_this_pass = 0
        last_cycle = self._verified_cycle_id
        last_hash = previous

        for row in rows:
            cycle_id = int(row[0])
            payload = str(row[4])
            payload_hash = hashlib.sha256(payload.encode()).hexdigest()
            expected = hashlib.sha256(
                f"{last_hash}|{payload_hash}|{cycle_id}".encode()
            ).hexdigest()
            if str(row[1]) != last_hash:
                errors.append(f"cycle {cycle_id}: previous hash mismatch")
            if str(row[2]) != payload_hash:
                errors.append(f"cycle {cycle_id}: payload hash mismatch")
            if str(row[3]) != expected:
                errors.append(f"cycle {cycle_id}: chain hash mismatch")

            if required_from is not None and cycle_id >= required_from:
                signature_row = self.connection.execute(
                    """
                    SELECT algorithm,key_id,signature
                    FROM evidence_signatures WHERE cycle_id=?
                    """,
                    (cycle_id,),
                ).fetchone()
                if signature_row is None:
                    errors.append(f"cycle {cycle_id}: evidence signature missing")
                else:
                    signatures_checked += 1
                    algorithm, key_id, signature = map(str, signature_row)
                    if algorithm != configured_algorithm:
                        errors.append(f"cycle {cycle_id}: signature algorithm mismatch")
                    if key_id != configured_key_id:
                        errors.append(f"cycle {cycle_id}: signature key mismatch")
                    if (
                        self.signer is not None
                        and self.signer.key_id == configured_key_id
                        and not self.signer.verify(cycle_id, str(row[3]), signature)
                    ):
                        errors.append(f"cycle {cycle_id}: signature mismatch")
            last_cycle = cycle_id
            last_hash = str(row[3])
            checked_this_pass += 1

        retained = int(self.connection.execute("SELECT COUNT(*) FROM evidence_chain").fetchone()[0])
        anchor_cycle, anchor_hash = self._chain_anchor()
        result = {
            "valid": not errors,
            "cycles_checked": retained,
            "cycles_checked_this_pass": checked_this_pass,
            "last_chain_hash": last_hash if retained else None,
            "anchor_cycle": anchor_cycle or None,
            "anchor_hash": anchor_hash if anchor_cycle else None,
            "errors": errors[:100],
            "cryptographically_signed": configured_key_id is not None,
            "signature_algorithm": configured_algorithm,
            "signature_key_id": configured_key_id,
            "signature_required_from_cycle": required_from,
            "signatures_checked": signatures_checked,
            "verification_mode": "incremental",
            "full_audit_interval_seconds": self.full_audit_interval_seconds,
        }
        if not errors:
            self._verified_cycle_id = last_cycle
            self._verified_chain_hash = last_hash
        return result

    def _remember_verification(self, result: dict[str, Any]) -> None:
        self._last_verification_result = dict(result)
        self._last_verification_data_version = self._database_data_version()
        self._evidence_dirty = not bool(result.get("valid", False))

    def _cached_unchanged_verification(self) -> dict[str, Any] | None:
        if self._evidence_dirty or self._last_verification_result is None:
            return None
        if self._last_verification_data_version != self._database_data_version():
            return None
        value = dict(self._last_verification_result)
        value["cycles_checked_this_pass"] = 0
        value["verification_mode"] = "cached_unchanged"
        value["verification_reused"] = True
        value["full_audit_interval_seconds"] = self.full_audit_interval_seconds
        return value

    def _cache_verification_status(self, result: dict[str, Any]) -> None:
        now = self._monotonic()
        key = (
            bool(result.get("valid", False)),
            int(result.get("cycles_checked", 0) or 0),
            str(result.get("last_chain_hash") or ""),
            bool(result.get("cryptographically_signed", False)),
            str(result.get("signature_algorithm") or ""),
        )
        if (
            self._verification_metadata_key == key
            and self._verification_metadata_at is not None
            and now - self._verification_metadata_at < 300.0
        ):
            return
        safe = {
            "valid": bool(result.get("valid", False)),
            "cycles_checked": int(result.get("cycles_checked", 0) or 0),
            "cycles_checked_this_pass": int(result.get("cycles_checked_this_pass", 0) or 0),
            "last_chain_hash": result.get("last_chain_hash"),
            "anchor_cycle": result.get("anchor_cycle"),
            "cryptographically_signed": bool(result.get("cryptographically_signed", False)),
            "signature_algorithm": result.get("signature_algorithm"),
            "signatures_checked": int(result.get("signatures_checked", 0) or 0),
            "verification_mode": str(result.get("verification_mode") or "unknown"),
            "full_audit_interval_seconds": self.full_audit_interval_seconds,
            "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "actions_executed": 0,
        }
        try:
            with self.connection:
                self.set_metadata(
                    "last_evidence_verification_report",
                    json.dumps(safe, sort_keys=True, separators=(",", ":")),
                )
            self._verification_metadata_key = key
            self._verification_metadata_at = now
        except Exception:
            pass

    def verify_evidence_chain(self) -> dict[str, Any]:
        now = self._monotonic()
        due = (
            self._last_full_audit_at is None
            or now - self._last_full_audit_at >= self.full_audit_interval_seconds
        )
        if due:
            result = self._full_verify(now)
            self._remember_verification(result)
            self._cache_verification_status(result)
            return result

        cached = self._cached_unchanged_verification()
        if cached is not None:
            return cached

        incremental = self._incremental_verify()
        if incremental["valid"]:
            self._remember_verification(incremental)
            self._cache_verification_status(incremental)
            return incremental

        full = self._full_verify(now)
        full["incremental_fallback_triggered"] = True
        self._remember_verification(full)
        self._cache_verification_status(full)
        return full
