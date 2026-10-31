"""End-to-end pipeline tests with fake adapters (no network)."""

from __future__ import annotations

from pathlib import Path

from reuseguard.adapters.snapshot import SnapshotError
from reuseguard.config import Settings
from reuseguard.models import Decision, FilterStatus, RepoRef, ScanStatus
from reuseguard.pipeline import Pipeline, remove_tree
from reuseguard.stages.recall import score_similarity
from tests.fakes import FakeGitHub, FakeScorecard, make_repo, make_snapshot, scorecard_payload


def _snapshot_factory(calls: list[str], fail: bool = False):
    def snapshot_fn(repo, destination, **_kwargs):
        calls.append(repo.full_name)
        if fail:
            raise SnapshotError("simulated download failure")
        return make_snapshot(
            Path(destination),
            {
                "README.md": f"# {repo.full_name}\n",
                "app.py": "def get(url):\n    return url\n",
            },
        )

    return snapshot_fn


def test_pipeline_assesses_seed_and_alternatives() -> None:
    seed = make_repo("acme/seed")
    alternative = make_repo("acme/alternative", stars=500, topics=["http", "client"])
    github = FakeGitHub(seed, [alternative])
    scorecard = FakeScorecard(
        {
            seed.full_name: scorecard_payload(8.0),
            alternative.full_name: scorecard_payload(7.5),
        }
    )
    calls: list[str] = []

    report = Pipeline(
        Settings(max_candidates=5),
        github,
        scorecard,
        snapshot_fn=_snapshot_factory(calls),
    ).run(RepoRef.parse("acme/seed"))

    assert len(report.assessments) == 2
    assert [assessment.candidate.role for assessment in report.assessments] == [
        "seed",
        "alternative",
    ]
    assert all(assessment.verdict.decision is Decision.USE for assessment in report.assessments)
    assert calls == ["acme/seed", "acme/alternative"]
    assert report.recall_queries
    assert report.elapsed_seconds >= 0


def test_reputation_skip_prevents_snapshot_download() -> None:
    seed = make_repo("acme/seed")
    alternative = make_repo("acme/alternative")
    github = FakeGitHub(seed, [alternative])
    scorecard = FakeScorecard(
        {
            seed.full_name: scorecard_payload(8.0),
            alternative.full_name: scorecard_payload(1.0),
        }
    )
    calls: list[str] = []

    report = Pipeline(
        Settings(max_candidates=5),
        github,
        scorecard,
        snapshot_fn=_snapshot_factory(calls),
    ).run(RepoRef.parse("acme/seed"))

    rejected = report.assessments[1]
    assert rejected.filter.status is FilterStatus.SKIPPED
    assert rejected.scan.status is ScanStatus.SKIPPED
    assert rejected.verdict.decision is Decision.AVOID
    assert calls == ["acme/seed"]


def test_snapshot_failure_becomes_inspect() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    calls: list[str] = []

    report = Pipeline(
        Settings(max_candidates=0),
        github,
        scorecard,
        snapshot_fn=_snapshot_factory(calls, fail=True),
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.status is ScanStatus.ERROR
    assert assessment.verdict.decision is Decision.INSPECT


def test_unexpected_snapshot_exception_becomes_scan_error() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})

    def broken_snapshot(_repo, _destination, **_kwargs):
        raise ValueError("unexpected adapter bug")

    report = Pipeline(
        Settings(max_candidates=0),
        github,
        scorecard,
        snapshot_fn=broken_snapshot,
    ).run(RepoRef.parse("acme/seed"))

    assert report.assessments[0].scan.status is ScanStatus.ERROR
    assert report.assessments[0].verdict.decision is Decision.INSPECT


def test_disabled_scan_needs_no_snapshot() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    calls: list[str] = []

    report = Pipeline(
        Settings(max_candidates=0, enable_scan=False),
        github,
        scorecard,
        snapshot_fn=_snapshot_factory(calls),
    ).run(RepoRef.parse("acme/seed"))

    assert report.assessments[0].scan.status is ScanStatus.DISABLED
    assert report.assessments[0].verdict.decision is Decision.INSPECT
    assert calls == []


def test_no_recall_assesses_only_the_seed() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [make_repo("acme/other")])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})

    report = Pipeline(
        Settings(enable_recall=False),
        github,
        scorecard,
        snapshot_fn=_snapshot_factory([]),
    ).run(RepoRef.parse("acme/seed"))

    assert len(report.assessments) == 1
    assert report.recall_queries == []
    assert github.queries == []


def test_keep_workdir_preserves_snapshot_directory() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})

    report = Pipeline(
        Settings(max_candidates=0, keep_workdir=True),
        github,
        scorecard,
        snapshot_fn=_snapshot_factory([]),
    ).run(RepoRef.parse("acme/seed"))

    assert report.workdir is not None
    workdir = Path(report.workdir)
    assert workdir.exists()
    remove_tree(workdir)
    assert not workdir.exists()


def test_recall_ranking_prefers_more_similar_repository() -> None:
    seed = make_repo("acme/seed", topics=["http", "client"], language="Python")
    close = make_repo("acme/close", stars=1000, topics=["http", "client"], language="Python")
    far = make_repo("acme/far", stars=1000, topics=["database"], language="Go")
    github = FakeGitHub(seed, [far, close])
    assert score_similarity(seed, close).total > score_similarity(seed, far).total
    scorecard = FakeScorecard(
        {
            seed.full_name: scorecard_payload(8.0),
            close.full_name: scorecard_payload(8.0),
            far.full_name: scorecard_payload(8.0),
        }
    )

    report = Pipeline(
        Settings(max_candidates=2),
        github,
        scorecard,
        snapshot_fn=_snapshot_factory([]),
    ).run(RepoRef.parse("acme/seed"))

    assert [assessment.candidate.repo.full_name for assessment in report.assessments[1:]] == [
        "acme/close",
        "acme/far",
    ]


def test_idea_mode_assesses_candidates_without_a_seed() -> None:
    dummy_seed = make_repo("acme/dummy")
    candidate = make_repo(
        "acme/http-client",
        description="A fast HTTP client with retries",
        language="Python",
    )
    github = FakeGitHub(dummy_seed, [candidate])
    scorecard = FakeScorecard({candidate.full_name: scorecard_payload(8.0)})
    calls: list[str] = []

    report = Pipeline(
        Settings(max_candidates=3),
        github,
        scorecard,
        snapshot_fn=_snapshot_factory(calls),
    ).run_idea("fast HTTP client", language="Python")

    assert report.seed is None
    assert report.query == "fast HTTP client"
    assert len(report.assessments) == 1
    assert report.assessments[0].candidate.role == "candidate"
    assert report.assessments[0].verdict.decision is Decision.USE
    assert calls == ["acme/http-client"]
    assert any("language:Python" in query for query in report.recall_queries)


def test_idea_mode_with_no_results_returns_empty_report() -> None:
    dummy_seed = make_repo("acme/dummy")
    github = FakeGitHub(dummy_seed, [])
    scorecard = FakeScorecard({})

    report = Pipeline(
        Settings(max_candidates=3),
        github,
        scorecard,
        snapshot_fn=_snapshot_factory([]),
    ).run_idea("something with no results", language=None)

    assert report.assessments == []
    assert report.seed is None
    assert any("No candidate" in warning for warning in report.warnings)
