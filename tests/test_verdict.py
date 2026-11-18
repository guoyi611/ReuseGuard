"""Tests for the verdict rules."""

from __future__ import annotations

from reuseguard.models import (
    Confidence,
    Decision,
    FilterResult,
    FilterStatus,
    Finding,
    RiskLevel,
    ScanReport,
    ScanStatus,
)
from reuseguard.stages.verdict import decide
from tests.fakes import make_repo


def _filter(status: FilterStatus = FilterStatus.PASSED, score: float | None = 8.0) -> FilterResult:
    return FilterResult(status=status, score=score)


def _scan(
    *,
    status: ScanStatus = ScanStatus.SCANNED,
    risk: RiskLevel = RiskLevel.NONE,
    files: int = 10,
    findings: list[Finding] | None = None,
    truncated: bool = False,
) -> ScanReport:
    return ScanReport(
        status=status,
        risk=risk,
        files_scanned=files,
        findings=findings or [],
        truncated=truncated,
    )


def _finding(severity: RiskLevel = RiskLevel.HIGH) -> Finding:
    return Finding(
        rule_id="test-rule",
        title="Test finding",
        severity=severity,
        category="test",
        path="app.py",
        message="test",
        line=3,
    )


def test_filter_rejection_always_avoids() -> None:
    verdict = decide(make_repo(), _filter(FilterStatus.SKIPPED, 2.0), _scan())

    assert verdict.decision is Decision.AVOID
    assert verdict.confidence is Confidence.HIGH


def test_disabled_scan_is_inspect() -> None:
    verdict = decide(make_repo(), _filter(), _scan(status=ScanStatus.DISABLED))

    assert verdict.decision is Decision.INSPECT
    assert verdict.confidence is Confidence.LOW


def test_failed_scan_is_inspect() -> None:
    verdict = decide(make_repo(), _filter(), _scan(status=ScanStatus.ERROR))

    assert verdict.decision is Decision.INSPECT
    assert verdict.confidence is Confidence.LOW


def test_critical_risk_avoids() -> None:
    verdict = decide(
        make_repo(),
        _filter(),
        _scan(risk=RiskLevel.CRITICAL, findings=[_finding(RiskLevel.CRITICAL)]),
    )

    assert verdict.decision is Decision.AVOID
    assert verdict.confidence is Confidence.HIGH


def test_high_risk_avoids() -> None:
    verdict = decide(make_repo(), _filter(), _scan(risk=RiskLevel.HIGH, findings=[_finding()]))

    assert verdict.decision is Decision.AVOID
    assert verdict.confidence is Confidence.MEDIUM


def test_medium_risk_is_inspect() -> None:
    verdict = decide(
        make_repo(),
        _filter(),
        _scan(risk=RiskLevel.MEDIUM, findings=[_finding(RiskLevel.MEDIUM)]),
    )

    assert verdict.decision is Decision.INSPECT


def test_clean_repository_with_good_score_is_use() -> None:
    verdict = decide(make_repo(), _filter(), _scan())

    assert verdict.decision is Decision.USE
    assert verdict.confidence is Confidence.HIGH


def test_low_risk_findings_do_not_block_use() -> None:
    verdict = decide(
        make_repo(),
        _filter(),
        _scan(risk=RiskLevel.LOW, findings=[_finding(RiskLevel.LOW)]),
    )

    assert verdict.decision is Decision.USE


def test_unknown_scorecard_is_inspect() -> None:
    verdict = decide(make_repo(), _filter(FilterStatus.UNKNOWN, None), _scan())

    assert verdict.decision is Decision.INSPECT


def test_low_score_is_inspect_even_when_clean() -> None:
    verdict = decide(make_repo(), _filter(score=4.5), _scan())

    assert verdict.decision is Decision.INSPECT


def test_archived_repository_is_inspect() -> None:
    verdict = decide(make_repo(archived=True), _filter(), _scan())

    assert verdict.decision is Decision.INSPECT
    assert any("archived" in reason.lower() for reason in verdict.reasons)


def test_truncated_scan_is_inspect() -> None:
    verdict = decide(make_repo(), _filter(), _scan(truncated=True))

    assert verdict.decision is Decision.INSPECT


def test_empty_scan_is_inspect() -> None:
    verdict = decide(make_repo(), _filter(), _scan(files=0))

    assert verdict.decision is Decision.INSPECT


def test_disabled_scorecard_is_inspect() -> None:
    verdict = decide(make_repo(), _filter(FilterStatus.DISABLED, None), _scan())

    assert verdict.decision is Decision.INSPECT


def test_decide_does_not_mark_verdicts_withheld() -> None:
    verdict = decide(make_repo(), _filter(), _scan(status=ScanStatus.DISABLED))

    # Hiding a verdict is a report-level presentation choice, not a decision rule.
    assert verdict.decision is Decision.INSPECT
    assert verdict.withheld is False


def test_decide_adds_license_unknown_limitation() -> None:
    repo = make_repo(license_spdx=None)

    verdict = decide(repo, _filter(), _scan())

    assert any("license" in item.lower() for item in verdict.limitations)


def test_decide_omits_license_limitation_when_declared() -> None:
    repo = make_repo(license_spdx="MIT")

    verdict = decide(repo, _filter(), _scan())

    assert not any("license" in item.lower() and "unconfirmed" in item.lower()
                   for item in verdict.limitations)
