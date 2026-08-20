from __future__ import annotations

from collections.abc import Iterable

from .matrix import CASES, validate_matrix
from .models import AttackCase, CaseResult, Verdict


def classify_unimplemented(case: AttackCase) -> CaseResult:
    verdict = Verdict.KNOWN_LIMITATION if case.documented_limitation else Verdict.SKIP
    detail = (
        "Documented v1 limitation; characterize without scoring as a release regression."
        if case.documented_limitation
        else "Probe not implemented in the foundation runner yet."
    )
    return CaseResult(case=case, verdict=verdict, detail=detail)


def plan_results(cases: Iterable[AttackCase] = CASES) -> list[CaseResult]:
    validate_matrix()
    return [classify_unimplemented(case) for case in cases]
