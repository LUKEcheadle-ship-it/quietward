from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    KNOWN_LIMITATION = "KNOWN_LIMITATION"
    SKIP = "SKIP"


@dataclass(frozen=True, slots=True)
class AttackCase:
    case_id: str
    category: str
    title: str
    expectation: str
    destructive: bool = False
    documented_limitation: bool = False


@dataclass(frozen=True, slots=True)
class CaseResult:
    case: AttackCase
    verdict: Verdict
    evidence: dict[str, Any] = field(default_factory=dict)
    detail: str = ""
