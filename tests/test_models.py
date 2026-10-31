"""Tests for the shared data model."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from reuseguard.models import (
    Assessment,
    Candidate,
    Confidence,
    Decision,
    FilterResult,
    FilterStatus,
    Finding,
    RepoMeta,
    RepoRef,
    Report,
    RiskLevel,
    ScanReport,
    ScanStatus,
    Similarity,
    Verdict,
    merge_scan_reports,
    to_jsonable,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("psf/requests", ("psf", "requests")),
        ("https://github.com/psf/requests", ("psf", "requests")),
        ("https://github.com/psf/requests.git", ("psf", "requests")),
        ("https://github.com/psf/requests/tree/main", ("psf", "requests")),
        ("git@github.com:psf/requests.git", ("psf", "requests")),
        ("github.com/psf/requests", ("psf", "requests")),
    ],
)
def test_repo_ref_parse(value: str, expected: tuple[str, str]) -> None:
    ref = RepoRef.parse(value)
    assert (ref.owner, ref.name) == expected
    assert ref.full_name == "psf/requests"
    assert ref.url == "https://github.com/psf/requests"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://gitlab.com/psf/requests",
        "https://github.com@evil.example/psf/requests",
        "https://evil.example/psf/requests",
        "psf",
        "psf/requests/extra",
        "https://github.com/psf",
        "https://github.com/../requests",
    ],
)
def test_repo_ref_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError):
        RepoRef.parse(value)


def test_jsonable_handles_dataclasses_enums_and_datetimes() -> None:
    stamp = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    report = Report(
        tool_version="0.1.0",
        generated_at=stamp,
        seed=RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed"),
        assessments=[],
    )

    payload = to_jsonable(report)

    assert payload["generated_at"] == "2026-10-30T12:00:00+00:00"
    assert payload["seed"]["full_name"] == "acme/seed"


def test_report_counts_all_decisions() -> None:
    repo = RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed")
    assessments = [
        _assessment(repo, Decision.USE),
        _assessment(repo, Decision.INSPECT),
        _assessment(repo, Decision.AVOID),
    ]
    report = Report(
        tool_version="0.1.0",
        generated_at=datetime.now(timezone.utc),
        seed=repo,
        assessments=assessments,
    )

    assert report.counts() == {"use": 1, "inspect": 1, "avoid": 1}
    assert report.to_dict()["counts"]["avoid"] == 1


def test_scan_report_ignores_suppressed_findings_for_risk_counts() -> None:
    from reuseguard.models import Finding

    finding = Finding(
        rule_id="test",
        title="Test",
        severity=RiskLevel.HIGH,
        category="test",
        path="README.md",
        message="example",
        suppressed=True,
    )
    report = ScanReport(status=ScanStatus.SCANNED, findings=[finding])
    assert report.counts()["high"] == 0
    assert len(report.suppressed_findings) == 1


def _assessment(repo: RepoMeta, decision: Decision) -> Assessment:
    return Assessment(
        candidate=Candidate(repo=repo, similarity=Similarity(total=50.0)),
        filter=FilterResult(status=FilterStatus.PASSED, score=8.0),
        scan=ScanReport(status=ScanStatus.SCANNED),
        verdict=Verdict(decision=decision, confidence=Confidence.HIGH),
    )


def _finding(
    rule_id: str,
    severity: RiskLevel,
    *,
    path: str = "app.py",
    line: int = 1,
    suppressed: bool = False,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        category="test",
        path=path,
        line=line,
        message="test",
        suppressed=suppressed,
    )


def _scanned(scanner: str, *findings: Finding, files: int = 10) -> ScanReport:
    return ScanReport(
        status=ScanStatus.SCANNED,
        risk=RiskLevel.NONE,
        findings=list(findings),
        files_scanned=files,
        bytes_scanned=1000,
        scanner=scanner,
    )


def test_merge_scan_reports_combines_findings_and_keeps_the_highest_risk() -> None:
    builtin = _scanned("builtin-patterns", _finding("py-eval-exec", RiskLevel.MEDIUM))
    secrets = _scanned("gitleaks", _finding("gitleaks:aws-access-token", RiskLevel.HIGH, line=7))

    merged = merge_scan_reports([builtin, secrets])

    assert merged.status is ScanStatus.SCANNED
    assert merged.scanner == "builtin-patterns+gitleaks"
    assert merged.risk is RiskLevel.HIGH
    assert {finding.rule_id for finding in merged.findings} == {
        "py-eval-exec",
        "gitleaks:aws-access-token",
    }
    # Coverage comes from the widest single scanner; summing would double count.
    assert merged.files_scanned == 10
    assert merged.bytes_scanned == 1000


def test_merge_scan_reports_deduplicates_findings() -> None:
    finding = _finding("py-eval-exec", RiskLevel.MEDIUM)
    merged = merge_scan_reports([_scanned("a", finding), _scanned("b", finding)])

    assert len(merged.findings) == 1


def test_merge_scan_reports_marks_truncated_when_any_scanner_truncated() -> None:
    clean = _scanned("builtin-patterns")
    truncated = _scanned("gitleaks")
    truncated.truncated = True

    assert merge_scan_reports([clean, truncated]).truncated is True


def test_merge_scan_reports_propagates_a_scanner_error() -> None:
    builtin = _scanned("builtin-patterns", _finding("py-eval-exec", RiskLevel.MEDIUM))
    failure = ScanReport(status=ScanStatus.ERROR, scanner="gitleaks", error="boom")

    merged = merge_scan_reports([builtin, failure])

    assert merged.status is ScanStatus.ERROR
    assert "gitleaks: boom" in (merged.error or "")
    # Surviving evidence is kept; it is the verdict that refuses to call it clean.
    assert [finding.rule_id for finding in merged.findings] == ["py-eval-exec"]


def test_merge_scan_reports_ignores_suppressed_findings_for_risk() -> None:
    suppressed = _finding("gitleaks:private-key", RiskLevel.HIGH, suppressed=True)
    merged = merge_scan_reports([_scanned("a"), _scanned("b", suppressed)])

    assert merged.risk is RiskLevel.NONE


def test_merge_scan_reports_returns_a_single_report_unchanged() -> None:
    report = _scanned("builtin-patterns")

    assert merge_scan_reports([report]) is report


def test_merge_scan_reports_returns_first_report_when_nothing_scanned() -> None:
    disabled = ScanReport(status=ScanStatus.DISABLED, error="off")
    skipped = ScanReport(status=ScanStatus.SKIPPED, error="skip")

    assert merge_scan_reports([disabled, skipped]) is disabled


def test_merge_scan_reports_requires_at_least_one_report() -> None:
    with pytest.raises(ValueError):
        merge_scan_reports([])
