"""Tests for the reputation gate."""

from __future__ import annotations

from reuseguard.adapters.scorecard import ScorecardError
from reuseguard.models import FilterStatus
from reuseguard.stages.reputation import evaluate_reputation
from tests.fakes import FakeScorecard, make_repo, scorecard_payload


def test_passing_score_is_accepted() -> None:
    repo = make_repo()
    client = FakeScorecard({repo.full_name: scorecard_payload(8.4)})

    result = evaluate_reputation(repo, client)

    assert result.status is FilterStatus.PASSED
    assert result.score == 8.4
    assert result.checks["Maintained"] == 10
    assert result.checked_at == "2026-10-20"


def test_low_score_is_skipped() -> None:
    repo = make_repo()
    client = FakeScorecard({repo.full_name: scorecard_payload(1.2)})

    result = evaluate_reputation(repo, client, min_score=2.0)

    assert result.status is FilterStatus.SKIPPED
    assert any("below" in reason for reason in result.reasons)


def test_maintained_and_vulnerabilities_zero_is_skipped() -> None:
    repo = make_repo()
    payload = scorecard_payload(6.0, {"Maintained": 0, "Vulnerabilities": 0})
    client = FakeScorecard({repo.full_name: payload})

    result = evaluate_reputation(repo, client)

    assert result.status is FilterStatus.SKIPPED
    assert any("Maintained and Vulnerabilities" in reason for reason in result.reasons)


def test_archived_repository_gets_a_warning_but_can_pass() -> None:
    repo = make_repo(archived=True)
    client = FakeScorecard({repo.full_name: scorecard_payload(8.0)})

    result = evaluate_reputation(repo, client)

    assert result.status is FilterStatus.PASSED
    assert any("archived" in warning for warning in result.warnings)


def test_missing_scorecard_record_is_unknown() -> None:
    repo = make_repo()
    client = FakeScorecard({})

    result = evaluate_reputation(repo, client)

    assert result.status is FilterStatus.UNKNOWN
    assert result.score is None
    assert result.error


def test_scorecard_error_is_unknown() -> None:
    repo = make_repo()
    client = FakeScorecard({repo.full_name: ScorecardError("service unavailable")})

    result = evaluate_reputation(repo, client)

    assert result.status is FilterStatus.UNKNOWN
    assert "unavailable" in (result.error or "")


def test_negative_score_is_unknown() -> None:
    repo = make_repo()
    client = FakeScorecard({repo.full_name: scorecard_payload(-1.0)})

    result = evaluate_reputation(repo, client)

    assert result.status is FilterStatus.UNKNOWN
    assert result.score is None


def test_disabled_filter_does_not_call_scorecard() -> None:
    repo = make_repo()
    client = FakeScorecard({})

    result = evaluate_reputation(repo, client, enabled=False)

    assert result.status is FilterStatus.DISABLED
    assert client.calls == []
