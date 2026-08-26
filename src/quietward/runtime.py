from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from .alerts import DeterministicExplainer, LocalAlertSink
from .cadence import CadenceController, CadenceLane
from .config import SentinelConfig
from .core_service import CoreSentinelService
from .core_store import CoreSentinelStore
from .dashboard_performance import install_dashboard_performance
from .integrations.ollama import OllamaIncidentExplainer
from .integrity import SelfIntegrityMonitor
from .models import HybridRiskScorer, LinearPriorityModel
from .pipeline import SentinelPipeline
from .warm_start import evaluate_warm_start

# CLI imports the QuietWard dashboard class before importing this runtime module.
# Installing here modifies that same class object for product run/serve paths.
install_dashboard_performance()


def bundled_model_path() -> Path:
    return Path(
        str(
            files("quietward.model_artifacts").joinpath(
                "quietward_priority_tiny_v1.json"
            )
        )
    )


def build_pipeline(config: SentinelConfig) -> SentinelPipeline:
    if not config.tiny_model.enabled:
        return SentinelPipeline()
    return SentinelPipeline(
        scorer=HybridRiskScorer(
            LinearPriorityModel.load(
                config.tiny_model.model_path or bundled_model_path()
            )
        )
    )


def build_explainer(config: SentinelConfig):
    return (
        OllamaIncidentExplainer(config.micro_llm)
        if config.micro_llm.enabled
        else DeterministicExplainer()
    )


def build_integrity_monitor(
    config: SentinelConfig,
    host_id: str,
) -> SelfIntegrityMonitor | None:
    if not config.self_integrity.enabled:
        return None
    model_path = config.tiny_model.model_path or bundled_model_path()
    return SelfIntegrityMonitor.default(
        host_id,
        package_root=Path(__file__).resolve().parent,
        config_path=config.config_path,
        model_path=model_path,
        extra_paths=config.self_integrity.extra_paths,
    )


def build_service(config: SentinelConfig) -> CoreSentinelService:
    store = CoreSentinelStore(config.storage)
    fast = config.collector.interval_seconds
    phase_unit = min(60.0, fast)
    cadence = CadenceController(
        fast_seconds=fast,
        standard_seconds=max(300.0, fast),
        deep_seconds=max(300.0, fast),
        maintenance_seconds=max(300.0, fast),
        phase_offsets_seconds={
            CadenceLane.STANDARD: phase_unit,
            CadenceLane.DEEP: phase_unit * 2.0,
            CadenceLane.MAINTENANCE: phase_unit * 3.0,
        },
    )
    warm_start = evaluate_warm_start(store, fast_seconds=fast)
    if warm_start.eligible:
        cadence.restore_due_schedule(warm_start.due_in_seconds)
    try:
        service = CoreSentinelService(
            config,
            store=store,
            cadence_controller=cadence,
            pipeline=build_pipeline(config),
            alert_sink=LocalAlertSink(
                config.storage.alert_log_path,
                explainer=build_explainer(config),
            ),
        )
    except Exception:
        store.close()
        raise
    service.owns_store = True
    service.warm_start_plan = warm_start
    service.integrity_monitor = build_integrity_monitor(
        config,
        service.collector.host_id,
    )
    return service
