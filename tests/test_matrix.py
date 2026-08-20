from collections import Counter

from qw_adversary.matrix import CASES, validate_matrix
from qw_adversary.models import Verdict
from qw_adversary.runner import plan_results


def test_matrix_is_valid_and_non_destructive() -> None:
    validate_matrix()
    assert CASES
    assert not any(case.destructive for case in CASES)


def test_matrix_covers_core_v1_trust_boundaries() -> None:
    categories = {case.category for case in CASES}
    assert {
        "protocol-auth",
        "agent-lifecycle",
        "approval-policy",
        "action-result",
        "malicious-response",
        "endpoint-state",
        "audit",
        "concurrency",
        "data-hardening",
    } <= categories


def test_known_limitations_are_not_scored_as_failures_in_foundation_plan() -> None:
    results = plan_results()
    for result in results:
        if result.case.documented_limitation:
            assert result.verdict == Verdict.KNOWN_LIMITATION


def test_case_ids_have_expected_namespace_distribution() -> None:
    prefixes = Counter(case.case_id.split("-", 1)[0] for case in CASES)
    assert prefixes["AUTH"] >= 8
    assert prefixes["SERVER"] >= 5
    assert prefixes["AUDIT"] >= 4
