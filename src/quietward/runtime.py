from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from .alerts import DeterministicExplainer, LocalAlertSink
from .config import SentinelConfig
from .integrations.ollama import OllamaIncidentExplainer
from .integrity import SelfIntegrityMonitor
from .models import HybridRiskScorer, LinearPriorityModel
from .pipeline import SentinelPipeline
from .service import SentinelService


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
    if config.micro_llm.enabled:
        return OllamaIncidentExplainer(config.micro_llm)
    return DeterministicExplainer()


def build_integrity_monitor(
    config: SentinelConfig, host_id: str
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


def build_service(config: SentinelConfig) -> SentinelService:
    service = SentinelService(
        config,
        pipeline=build_pipeline(config),
        alert_sink=LocalAlertSink(
            config.storage.alert_log_path,
            explainer=build_explainer(config),
        ),
    )
    service.integrity_monitor = build_integrity_monitor(
        config, service.collector.host_id
    )
    return service
