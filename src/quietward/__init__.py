"""QuietWard offline-first cybersecurity monitoring system."""

from .collectors import (
    CollectionBatch,
    CollectorSnapshot,
    ConnectionRecord,
    DebianCollectorConfig,
    DebianReadOnlyCollector,
    PersistenceRecord,
)
from .config import SentinelConfig, load_config
from .contracts import ActionProposal, ActionType, AnalysisReport, EventAssessment, EventKind, Finding, SecurityEvent, Severity
from .integrity import SelfIntegrityMonitor
from .models import HybridRiskScorer, LinearPriorityModel
from .pipeline import SentinelPipeline
from .qualification import QualificationConfig, QualificationReport, TargetHostQualifier
from .scanners import ScannerExecutionResult, ScannerExecutor, parse_clamav_output, parse_debsecan_simple, parse_trivy_json, parse_yara_output
from .service import SentinelService
from .storage import SentinelStore

# Public QuietWard names. The Sentinel-prefixed classes remain as compatibility
# aliases for pre-rename alpha consumers.
QuietWardConfig = SentinelConfig
QuietWardPipeline = SentinelPipeline
QuietWardService = SentinelService
QuietWardStore = SentinelStore

__all__ = [
    "ActionProposal", "ActionType", "AnalysisReport", "CollectionBatch", "CollectorSnapshot",
    "ConnectionRecord", "DebianCollectorConfig", "DebianReadOnlyCollector", "EventAssessment",
    "EventKind", "Finding", "HybridRiskScorer", "LinearPriorityModel", "PersistenceRecord",
    "QualificationConfig", "QualificationReport", "QuietWardConfig", "QuietWardPipeline",
    "QuietWardService", "QuietWardStore", "ScannerExecutionResult", "ScannerExecutor",
    "SecurityEvent", "SelfIntegrityMonitor", "SentinelConfig", "SentinelPipeline",
    "SentinelService", "SentinelStore", "Severity", "TargetHostQualifier", "load_config",
    "parse_clamav_output", "parse_debsecan_simple", "parse_trivy_json", "parse_yara_output",
]

__version__ = "0.4.0a2"
