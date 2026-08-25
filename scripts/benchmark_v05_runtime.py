#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,statistics,time
from pathlib import Path
from quietward.collectors import build_collector
from quietward.config import load_config
from quietward.pipeline import SentinelPipeline

def percentile(values:list[float],fraction:float)->float:
    if not values:return 0.0
    ordered=sorted(values); index=min(len(ordered)-1,max(0,int(round((len(ordered)-1)*fraction)))); return ordered[index]
def _reset_command_metrics(collector:object)->None:
    runner=getattr(collector,"runner",None)
    if runner is None:return
    if hasattr(runner,"commands_executed"):runner.commands_executed=0
    if hasattr(runner,"command_duration_ms"):runner.command_duration_ms=0.0
def _command_metrics(collector:object,cycles:int)->dict[str,object]|None:
    runner=getattr(collector,"runner",None); snapshot=getattr(runner,"performance_snapshot",None)
    if not callable(snapshot):return None
    value=dict(snapshot()); commands=int(value.get("commands_executed",0) or 0); value["mean_commands_per_cycle"]=round(commands/cycles,3) if cycles else 0.0; return value
def benchmark(config_path:Path,*,cycles:int)->dict[str,object]:
    if cycles<2 or cycles>50:raise ValueError("cycles must be between 2 and 50")
    config=load_config(config_path); collector=build_collector(config.collector); pipeline=SentinelPipeline(); collector_ms=[]; analysis_ms=[]; event_counts=[]; snapshot_sizes=[]; baseline=collector.collect(None); previous=baseline.snapshot; _reset_command_metrics(collector)
    for _ in range(cycles):
        started=time.perf_counter(); batch=collector.collect(previous); collector_elapsed=(time.perf_counter()-started)*1000.0; analysis_started=time.perf_counter(); report=pipeline.analyze(list(batch.events)); analysis_elapsed=(time.perf_counter()-analysis_started)*1000.0; collector_ms.append(collector_elapsed); analysis_ms.append(analysis_elapsed); event_counts.append(len(batch.events)); snapshot_sizes.append(len(json.dumps(batch.snapshot.to_dict(),sort_keys=True))); 
        if report.actions_executed!=0:raise RuntimeError("benchmark observed a non-zero action count")
        previous=batch.snapshot
    combined=[l+r for l,r in zip(collector_ms,analysis_ms)]; command_metrics=_command_metrics(collector,cycles)
    return {"format":"quietward-v05-runtime-benchmark-v2","cycles_measured":cycles,"collector_ms":{"mean":round(statistics.fmean(collector_ms),3),"p50":round(percentile(collector_ms,.5),3),"p95":round(percentile(collector_ms,.95),3),"max":round(max(collector_ms),3)},"analysis_ms":{"mean":round(statistics.fmean(analysis_ms),3),"p50":round(percentile(analysis_ms,.5),3),"p95":round(percentile(analysis_ms,.95),3),"max":round(max(analysis_ms),3)},"observation_ms":{"mean":round(statistics.fmean(combined),3),"p50":round(percentile(combined,.5),3),"p95":round(percentile(combined,.95),3),"max":round(max(combined),3)},"external_commands":command_metrics,"events":{"max_per_cycle":max(event_counts,default=0),"mean_per_cycle":round(statistics.fmean(event_counts),3)},"snapshot_json_bytes":{"max":max(snapshot_sizes,default=0),"mean":round(statistics.fmean(snapshot_sizes),1)},"safety":{"persisted_cycles":0,"scanner_jobs_executed":0,"actions_executed":0,"remediation_executed":False}}
def main()->int:
    parser=argparse.ArgumentParser(description="measure bounded QuietWard read-only runtime latency"); parser.add_argument("--config",type=Path,required=True); parser.add_argument("--cycles",type=int,default=5); parser.add_argument("--pretty",action="store_true"); args=parser.parse_args(); result=benchmark(args.config,cycles=args.cycles); print(json.dumps(result,indent=2 if args.pretty else None,sort_keys=True)); return 0
if __name__=="__main__":raise SystemExit(main())
