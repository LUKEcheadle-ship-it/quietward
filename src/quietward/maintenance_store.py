from __future__ import annotations

import hashlib
import time
from typing import Callable

from .config import StorageSettings
from .product_store import ProductSentinelStore
from .storage import PersistResult, _json, _utc, _utc_now


class MaintenanceSentinelStore(ProductSentinelStore):
    """Product store with bounded maintenance and quiet-path compaction."""

    def __init__(
        self,
        settings: StorageSettings,
        *,
        prune_interval_seconds: float = 300.0,
        full_snapshot_interval_seconds: float = 300.0,
        quiet_durable_interval_seconds: float = 300.0,
        monotonic: Callable[[], float] = time.monotonic,
        **kwargs,
    ) -> None:
        if prune_interval_seconds <= 0:
            raise ValueError("prune_interval_seconds must be positive")
        if full_snapshot_interval_seconds <= 0:
            raise ValueError("full_snapshot_interval_seconds must be positive")
        if quiet_durable_interval_seconds <= 0:
            raise ValueError("quiet_durable_interval_seconds must be positive")
        self.prune_interval_seconds = float(prune_interval_seconds)
        self.full_snapshot_interval_seconds = float(full_snapshot_interval_seconds)
        self.quiet_durable_interval_seconds = float(quiet_durable_interval_seconds)
        self._maintenance_monotonic = monotonic
        self._last_prune_at: float | None = None
        self._last_full_snapshot_at: float | None = None
        self._last_durable_cycle_at: float | None = None
        self._last_full_defender = None
        self._last_full_collector_version: str | None = None
        self._quiet_cycles_compacted = 0
        self._quiet_cycles_volatile = 0
        self._last_persistence_mode = "uninitialized"
        super().__init__(settings, monotonic=monotonic, **kwargs)

    @property
    def persistence_mode(self) -> str:
        return self._last_persistence_mode

    def _prune_locked(self) -> None:
        now = self._maintenance_monotonic()
        if (
            self._last_prune_at is not None
            and now - self._last_prune_at < self.prune_interval_seconds
        ):
            return
        super()._prune_locked()
        self._last_prune_at = now

    def _active_incident_count(self) -> int:
        table = self.connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type='table' AND name='incident_lifecycle'
            """
        ).fetchone()
        if table is None:
            return 0
        return int(
            self.connection.execute(
                "SELECT COUNT(*) FROM incident_lifecycle WHERE active=1"
            ).fetchone()[0]
        )

    def _quiet_cycle_eligible(self, batch, report, kwargs: dict[str, object]) -> bool:
        if self._last_full_snapshot_at is None:
            return False
        now = self._maintenance_monotonic()
        if now - self._last_full_snapshot_at >= self.full_snapshot_interval_seconds:
            return False
        if kwargs.get("status", "ok") != "ok" or kwargs.get("error") is not None:
            return False
        if batch.events or report.findings or report.action_proposals:
            return False
        if batch.snapshot.errors:
            return False
        if batch.snapshot.collector_version != self._last_full_collector_version:
            return False
        if batch.snapshot.defender != self._last_full_defender:
            return False
        return True

    def _volatile_quiet_reference(self, batch) -> PersistResult | None:
        if self._last_durable_cycle_at is None:
            return None
        now = self._maintenance_monotonic()
        if now - self._last_durable_cycle_at >= self.quiet_durable_interval_seconds:
            return None
        if self._active_incident_count() != 0:
            return None
        cycle_row = self.connection.execute(
            """
            SELECT c.id,e.chain_hash
            FROM cycles c
            LEFT JOIN evidence_chain e ON e.cycle_id=c.id
            ORDER BY c.id DESC LIMIT 1
            """
        ).fetchone()
        snapshot_row = self.connection.execute(
            "SELECT id FROM snapshots ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if cycle_row is None or snapshot_row is None:
            return None
        self._latest_snapshot_cache = batch.snapshot
        self._latest_snapshot_loaded = True
        self._quiet_cycles_volatile += 1
        self._last_persistence_mode = "volatile"
        return PersistResult(
            0,
            0,
            0,
            int(snapshot_row[0]),
            int(cycle_row[0]),
            str(cycle_row[1]) if cycle_row[1] is not None else None,
            None,
        )

    def persist_cycle(self, batch, report, **kwargs):
        if self._quiet_cycle_eligible(batch, report, kwargs):
            volatile = self._volatile_quiet_reference(batch)
            if volatile is not None:
                return volatile
            result = self.persist_quiet_cycle(batch, report, **kwargs)
            self._quiet_cycles_compacted += 1
            self._last_durable_cycle_at = self._maintenance_monotonic()
            self._last_persistence_mode = "reference"
            return result
        result = super().persist_cycle(batch, report, **kwargs)
        now = self._maintenance_monotonic()
        self._last_full_snapshot_at = now
        self._last_durable_cycle_at = now
        self._last_full_defender = batch.snapshot.defender
        self._last_full_collector_version = batch.snapshot.collector_version
        self._last_persistence_mode = "full"
        return result

    def persist_quiet_cycle(
        self,
        batch,
        report,
        *,
        started_at,
        completed_at,
        status: str = "ok",
        error: str | None = None,
    ) -> PersistResult:
        if report.actions_executed != 0:
            raise ValueError("observation-only reports must execute zero actions")
        if batch.events or report.findings or report.action_proposals:
            raise ValueError("quiet-cycle persistence requires zero security observations")
        if batch.snapshot.errors:
            raise ValueError("quiet-cycle persistence requires an error-free snapshot")

        required_from = self._signing_required_from_cycle()
        if required_from is not None and self.signer is None:
            raise ValueError("evidence signing key is required for new cycles")

        created = _utc_now()
        signature: str | None = None
        with self.connection:
            snapshot_row = self.connection.execute(
                """
                SELECT id,observed_at,host_id,collector_version
                FROM snapshots ORDER BY id DESC LIMIT 1
                """
            ).fetchone()
            if snapshot_row is None:
                raise ValueError("quiet-cycle persistence requires a full snapshot baseline")
            if str(snapshot_row[2]) != batch.snapshot.host_id:
                raise ValueError("quiet-cycle snapshot host does not match baseline")
            snapshot_id = int(snapshot_row[0])

            cursor = self.connection.execute(
                """
                INSERT INTO cycles(
                    started_at,completed_at,status,events_count,
                    findings_count,actions_executed,error
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    _utc(started_at),
                    _utc(completed_at),
                    status,
                    0,
                    0,
                    0,
                    error,
                ),
            )
            cycle_id = int(cursor.lastrowid)

            payload = _json(
                {
                    "started_at": _utc(started_at),
                    "completed_at": _utc(completed_at),
                    "status": status,
                    "error": error,
                    "snapshot_mode": "reference",
                    "snapshot_reference": {
                        "snapshot_id": snapshot_id,
                        "observed_at": str(snapshot_row[1]),
                        "host_id": str(snapshot_row[2]),
                        "collector_version": str(snapshot_row[3]),
                    },
                    "events": [],
                    "report": report.to_dict(),
                    "quiet_cycle": True,
                }
            )
            payload_hash = hashlib.sha256(payload.encode()).hexdigest()
            row = self.connection.execute(
                "SELECT chain_hash FROM evidence_chain ORDER BY cycle_id DESC LIMIT 1"
            ).fetchone()
            if row:
                previous_hash = str(row[0])
            else:
                _, previous_hash = self._chain_anchor()
            chain_hash = hashlib.sha256(
                f"{previous_hash}|{payload_hash}|{cycle_id}".encode()
            ).hexdigest()
            self.connection.execute(
                """
                INSERT INTO evidence_chain(
                    cycle_id,previous_hash,payload_hash,chain_hash,payload_json,created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    cycle_id,
                    previous_hash,
                    payload_hash,
                    chain_hash,
                    payload,
                    created,
                ),
            )
            if self.signer is not None:
                signature = self.signer.sign(cycle_id, chain_hash)
                self.connection.execute(
                    """
                    INSERT INTO evidence_signatures(
                        cycle_id,algorithm,key_id,signature,created_at
                    ) VALUES(?,?,?,?,?)
                    """,
                    (
                        cycle_id,
                        self.signer.algorithm,
                        self.signer.key_id,
                        signature,
                        created,
                    ),
                )

            self.set_metadata("last_cycle_at", created)
            self.set_metadata("last_cycle_status", status)
            self._prune_locked()

        self._latest_snapshot_cache = batch.snapshot
        self._latest_snapshot_loaded = True
        self._last_persistence_mode = "reference"
        self._mark_evidence_dirty()
        return PersistResult(
            0,
            0,
            0,
            snapshot_id,
            cycle_id,
            chain_hash,
            signature,
        )

    def force_maintenance_prune(self) -> None:
        with self.connection:
            super()._prune_locked()
        self._last_prune_at = self._maintenance_monotonic()
        self._mark_evidence_dirty()

    def maintenance_state(self) -> dict[str, object]:
        now = self._maintenance_monotonic()
        return {
            "prune_interval_seconds": self.prune_interval_seconds,
            "full_snapshot_interval_seconds": self.full_snapshot_interval_seconds,
            "quiet_durable_interval_seconds": self.quiet_durable_interval_seconds,
            "last_persistence_mode": self._last_persistence_mode,
            "seconds_since_prune": round(max(0.0, now - self._last_prune_at), 3) if self._last_prune_at is not None else None,
            "seconds_since_full_snapshot": round(max(0.0, now - self._last_full_snapshot_at), 3) if self._last_full_snapshot_at is not None else None,
            "seconds_since_durable_cycle": round(max(0.0, now - self._last_durable_cycle_at), 3) if self._last_durable_cycle_at is not None else None,
            "quiet_cycles_compacted": self._quiet_cycles_compacted,
            "quiet_cycles_volatile": self._quiet_cycles_volatile,
            "actions_executed": 0,
        }
