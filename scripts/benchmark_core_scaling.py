#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quietward.cadence import CadenceLane
from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import StorageSettings
from quietward.core_store import CoreSentinelStore
from quietward.pipeline import SentinelPipeline
from quietward.source_aware_lifecycle import SourceAwareIncidentLifecycleRepository


def _percentile(values: list[float], fraction: float) -> float:
    if not values: return 0.0
    ordered = sorted(values); index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction)))); return ordered[index]

def _stats(values: list[float]) -> dict[str, float]:
    return {"mean": round(statistics.fmean(values), 3) if values else 0.0, "p50": round(_percentile(values, .50), 3), "p95": round(_percentile(values, .95), 3), "max": round(max(values), 3) if values else 0.0}

def _seed_resolved(repository, count: int, observed_at: datetime) -> None:
    stamp = observed_at.isoformat().replace("+00:00", "Z")
    rows = [(f"resolved-{index:08d}", f"signature-{index:08d}", f"finding-{index:08d}", "synthetic-host", f"synthetic-subject-{index:08d}", "low", 20, '["new_listening_port"]', '["windows_socket_snapshot"]', "resolved", stamp, stamp, stamp, 2, 1, 0, 1) for index in range(count)]
    with repository.connection:
        repository.connection.executemany("INSERT INTO incident_lifecycle(incident_key,signature,finding_id,host_id,subject,severity,score_band,event_kinds_json,event_sources_json,state,first_seen,last_seen,resolved_at,cycles_seen,occurrences,active,last_cycle_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

def benchmark_history(history_rows: int, repetitions: int) -> dict[str, object]:
    connection = sqlite3.connect(":memory:")
    try:
        repository = SourceAwareIncidentLifecycleRepository(connection); observed = datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc); _seed_resolved(repository, history_rows, observed); values=[]; sizes=[]
        for _ in range(repetitions):
            started=time.perf_counter(); relevant=repository._load_relevant_records(()); values.append((time.perf_counter()-started)*1000.0); sizes.append(len(relevant))
        return {"resolved_history_rows": history_rows, "rows_materialized_per_query": max(sizes, default=0), "active_projection_ms": _stats(values)}
    finally: connection.close()

def benchmark_quiet_writes(cycles: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary); settings=StorageSettings(database_path=root/"synthetic.sqlite3", alert_log_path=root/"alerts.jsonl", max_cycles=max(100,cycles+10), max_snapshots=max(100,cycles+10)); monotonic=[0.0]; observed=datetime(2026,8,8,10,0,tzinfo=timezone.utc); report=SentinelPipeline().analyze([])
        with CoreSentinelStore(settings, monotonic=lambda:monotonic[0]) as store:
            store.set_cycle_observation_scope({"processes","listening_sockets"},{CadenceLane.FAST}); modes={}
            for index in range(cycles):
                monotonic[0]=float(index*60); now=observed+timedelta(minutes=index); store.persist_cycle(CollectionBatch(CollectorSnapshot(now,"synthetic-host",collector_version="synthetic-read-only-v1"),()), report, started_at=now, completed_at=now); modes[store.persistence_mode]=modes.get(store.persistence_mode,0)+1
            summary=store.summary(); return {"observations":cycles,"durable_cycles":int(summary["cycles"]),"durable_snapshots":int(summary["snapshots"]),"evidence_rows":int(summary["cycles"]),"persistence_modes":modes,"write_reduction_ratio":round(1.0-(int(summary["cycles"])/max(1,cycles)),4),"evidence_chain_valid":bool(summary["evidence_chain"]["valid"])}
def main()->int:
    parser=argparse.ArgumentParser(description="benchmark QuietWard history projection and quiet-write scaling"); parser.add_argument("--history-rows",type=int,default=25000); parser.add_argument("--repetitions",type=int,default=20); parser.add_argument("--quiet-cycles",type=int,default=60); parser.add_argument("--pretty",action="store_true"); args=parser.parse_args()
    if not 0<=args.history_rows<=250000: raise ValueError("history-rows must be between 0 and 250000")
    if not 1<=args.repetitions<=100: raise ValueError("repetitions must be between 1 and 100")
    if not 2<=args.quiet_cycles<=1000: raise ValueError("quiet-cycles must be between 2 and 1000")
    result={"format":"quietward-core-scaling-benchmark-v1","history":benchmark_history(args.history_rows,args.repetitions),"quiet_writes":benchmark_quiet_writes(args.quiet_cycles),"safety":{"temporary_database_only":True,"production_database_touched":False,"scanner_jobs_executed":0,"actions_executed":0}}; print(json.dumps(result,indent=2 if args.pretty else None,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
