from __future__ import annotations

from typing import Any, Iterable, Mapping

from .finding_lifecycle import (
    LifecycleRecord,
    LifecycleState,
    build_incident_identity,
    observe_incident,
    resolve_absent_incidents,
)
from .incident_coverage import incident_resolution_safe
from .lifecycle_repository import (
    IncidentLifecycleRepository,
    LifecycleCycleSummary,
    _utc,
)


class SourceAwareIncidentLifecycleRepository(IncidentLifecycleRepository):
    """Lifecycle repository that resolves absence against relevant source coverage."""

    _RECORD_COLUMNS = """
        incident_key,signature,finding_id,host_id,subject,severity,
        score_band,event_kinds_json,event_sources_json,state,
        first_seen,last_seen,resolved_at,cycles_seen,occurrences,
        active,last_cycle_id
    """

    def catch_up_from_evidence_chain(self, *, up_to_cycle_id: int | None = None) -> int:
        last_processed = self.last_processed_cycle_id()
        if up_to_cycle_id is not None and up_to_cycle_id <= last_processed:
            return 0
        return super().catch_up_from_evidence_chain(up_to_cycle_id=up_to_cycle_id)

    def _load_relevant_records(
        self,
        incident_keys: Iterable[str],
    ) -> dict[str, LifecycleRecord]:
        keys = tuple(sorted({str(item) for item in incident_keys if str(item)}))
        if keys:
            placeholders = ",".join("?" for _ in keys)
            rows = self.connection.execute(
                f"""
                SELECT {self._RECORD_COLUMNS}
                FROM incident_lifecycle
                WHERE active=1 OR incident_key IN ({placeholders})
                """,
                keys,
            ).fetchall()
        else:
            rows = self.connection.execute(
                f"""
                SELECT {self._RECORD_COLUMNS}
                FROM incident_lifecycle WHERE active=1
                """
            ).fetchall()
        records: dict[str, LifecycleRecord] = {}
        for row in rows:
            record = self._record_from_row(row)
            records[record.identity.incident_key] = record
        return records

    def reconcile_cycle(
        self,
        cycle_id: int,
        findings: Iterable[Mapping[str, Any]],
        events: Iterable[Mapping[str, Any]],
        *,
        observed_at,
        coverage_complete: bool,
        coverage_domains: Iterable[Mapping[str, Any]] | None = None,
    ) -> LifecycleCycleSummary:
        if coverage_domains is None:
            return super().reconcile_cycle(
                cycle_id,
                findings,
                events,
                observed_at=observed_at,
                coverage_complete=coverage_complete,
            )

        if cycle_id <= 0:
            raise ValueError("cycle_id must be positive")
        _utc(observed_at)
        last_processed = self.last_processed_cycle_id()
        if cycle_id <= last_processed:
            return LifecycleCycleSummary(
                cycle_id=cycle_id,
                new=0,
                recurring=0,
                changed=0,
                resolved=0,
                active_total=self.active_count(),
                coverage_complete=coverage_complete,
                already_processed=True,
            )
        if last_processed and cycle_id != last_processed + 1:
            raise ValueError(
                f"lifecycle cycle gap: expected {last_processed + 1}, got {cycle_id}"
            )

        event_values = [dict(item) for item in events]
        finding_values = [dict(item) for item in findings]
        identities = [build_incident_identity(finding, event_values) for finding in finding_values]
        records = self._load_relevant_records(identity.incident_key for identity in identities)
        domain_values = [dict(item) for item in coverage_domains]
        seen: set[str] = set()
        updated: dict[str, LifecycleRecord] = {}
        transition_keys: set[str] = set()
        state_counts = {state: 0 for state in LifecycleState}

        for identity in identities:
            previous = records.get(identity.incident_key)
            record = observe_incident(previous, identity, observed_at=observed_at)
            records[identity.incident_key] = record
            updated[identity.incident_key] = record
            seen.add(identity.incident_key)
            state_counts[record.state] += 1
            if (
                previous is None
                or not previous.active
                or previous.state == LifecycleState.RESOLVED
                or previous.identity.signature != identity.signature
            ):
                transition_keys.add(identity.incident_key)

        for incident_key, previous in tuple(records.items()):
            if incident_key in seen or not previous.active:
                continue
            source_safe = incident_resolution_safe(
                previous.identity.event_sources,
                domain_values,
                global_resolution_safe=coverage_complete,
            )
            resolved = resolve_absent_incidents(
                {incident_key: previous},
                set(),
                completed_at=observed_at,
                coverage_complete=source_safe,
            )[incident_key]
            records[incident_key] = resolved
            if previous.active and not resolved.active:
                updated[incident_key] = resolved
                transition_keys.add(incident_key)
                state_counts[LifecycleState.RESOLVED] += 1

        with self.connection:
            for incident_key, record in updated.items():
                self._upsert_record(record, cycle_id)
                if incident_key in transition_keys:
                    self._transition(record, cycle_id, observed_at)
            self._set_meta("last_processed_cycle_id", str(cycle_id))
            self._prune_locked()

        return LifecycleCycleSummary(
            cycle_id=cycle_id,
            new=state_counts[LifecycleState.NEW],
            recurring=state_counts[LifecycleState.RECURRING],
            changed=state_counts[LifecycleState.CHANGED],
            resolved=state_counts[LifecycleState.RESOLVED],
            active_total=self.active_count(),
            coverage_complete=coverage_complete,
        )
