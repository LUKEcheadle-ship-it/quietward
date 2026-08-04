"""Scanner execution and pure report adapters."""

from .clamav import parse_clamav_output
from .debsecan import parse_debsecan_simple
from .execution import ScannerExecutionResult, ScannerExecutor
from .trivy import parse_trivy_json
from .yara import parse_yara_output

__all__ = [
    "ScannerExecutionResult",
    "ScannerExecutor",
    "parse_clamav_output",
    "parse_debsecan_simple",
    "parse_trivy_json",
    "parse_yara_output",
]
