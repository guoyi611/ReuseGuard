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
    RepoMeta,
    RepoRef,
    Report,
    RiskLevel,
    ScanReport,
    ScanStatus,
    Similarity,
    Verdict,
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
