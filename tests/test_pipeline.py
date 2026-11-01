"""End-to-end pipeline tests with fake adapters (no network)."""

from __future__ import annotations

import json
from pathlib import Path

from reuseguard.adapters.process import CommandResult
from reuseguard.adapters.sandbox import DockerStatus
from reuseguard.adapters.snapshot import SnapshotError
from reuseguard.config import Settings
from reuseguard.models import Decision, FilterStatus, RepoRef, RiskLevel, SandboxStatus, ScanStatus
from reuseguard.pipeline import Pipeline, remove_tree
from reuseguard.stages.recall import score_similarity
from tests.fakes import (
    FakeCommandRunner,
    FakeGitHub,
    FakeScorecard,
    make_repo,
    make_snapshot,
    sandbox_probe_output,
    scorecard_payload,
)


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


def test_discover_only_withholds_verdict_without_changing_the_decision() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})

    report = Pipeline(
        Settings(max_candidates=0, enable_scan=False, discover_only=True),
        github,
        scorecard,
        snapshot_fn=_snapshot_factory([]),
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert report.discover_only is True
    assert assessment.scan.status is ScanStatus.DISABLED
    assert assessment.verdict.withheld is True
    # The decision itself is still computed the same way; only display changed.
    assert assessment.verdict.decision is Decision.INSPECT


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


def test_idea_mode_skips_invalid_names_before_scorecard() -> None:
    dummy_seed = make_repo("acme/dummy")
    valid = make_repo("acme/pixel", description="AI 2D pixel art generator")
    invalid = make_repo("gege-circle/.github")
    github = FakeGitHub(dummy_seed, [invalid, valid])
    scorecard = FakeScorecard({valid.full_name: scorecard_payload(8.0)})

    report = Pipeline(
        Settings(max_candidates=3, enable_scan=False),
        github,
        scorecard,
    ).run_idea("AI 2D pixel art generator")

    assert [assessment.candidate.repo.full_name for assessment in report.assessments] == [
        "acme/pixel"
    ]
    assert scorecard.calls == ["acme/pixel"]
    assert any("invalid repository name" in warning for warning in report.warnings)


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


# --- Sandbox stage ----------------------------------------------------------

_RISKY_FILES = {"evil.pth": "import os\nos.system('id')\n"}
_CLEAN_FILES = {"app.py": "def get(url):\n    return url\n"}


class _FakeDetector:
    def __init__(self, status: DockerStatus) -> None:
        self.status = status
        self.calls = 0

    def __call__(self, **_kwargs) -> DockerStatus:
        self.calls += 1
        return self.status


def _files_snapshot_factory(files: dict[str, str]):
    def snapshot_fn(repo, destination, **_kwargs):
        return make_snapshot(Path(destination), files)

    return snapshot_fn


def _run_with_sandbox(
    *,
    mode: str,
    files: dict[str, str],
    runner: FakeCommandRunner,
    detector: _FakeDetector,
    sandbox_image: str = "python:3.11-slim",
):
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    return Pipeline(
        Settings(max_candidates=0, sandbox_mode=mode, sandbox_image=sandbox_image),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(files),
        sandbox_runner=runner,
        sandbox_detect=detector,
    ).run(RepoRef.parse("acme/seed"))


def test_sandbox_off_by_default_never_contacts_docker() -> None:
    detector = _FakeDetector(DockerStatus(available=True, version="27"))
    runner = FakeCommandRunner()

    report = _run_with_sandbox(mode="off", files=_RISKY_FILES, runner=runner, detector=detector)

    assessment = report.assessments[0]
    assert assessment.scan.risk is RiskLevel.HIGH
    assert assessment.sandbox is None
    assert detector.calls == 0
    assert runner.calls == []


def test_sandbox_auto_runs_for_high_risk() -> None:
    detector = _FakeDetector(DockerStatus(available=True, version="27"))
    runner = FakeCommandRunner(
        [CommandResult(argv=(), returncode=0, stdout=sandbox_probe_output())]
    )

    report = _run_with_sandbox(mode="auto", files=_RISKY_FILES, runner=runner, detector=detector)

    assessment = report.assessments[0]
    assert assessment.sandbox is not None
    assert assessment.sandbox.status is SandboxStatus.COMPLETED
    assert assessment.sandbox.containment_ok is True
    assert detector.calls == 1
    assert runner.calls[0][0][:2] == ("docker", "run")
    assert any(
        "does not execute repository code" in item for item in assessment.verdict.limitations
    )


def test_sandbox_auto_skips_low_risk() -> None:
    detector = _FakeDetector(DockerStatus(available=True, version="27"))
    runner = FakeCommandRunner()

    report = _run_with_sandbox(mode="auto", files=_CLEAN_FILES, runner=runner, detector=detector)

    assert report.assessments[0].scan.risk is RiskLevel.NONE
    assert report.assessments[0].sandbox is None
    assert detector.calls == 0
    assert runner.calls == []


def test_sandbox_all_runs_even_for_low_risk() -> None:
    detector = _FakeDetector(DockerStatus(available=True, version="27"))
    runner = FakeCommandRunner(
        [CommandResult(argv=(), returncode=0, stdout=sandbox_probe_output())]
    )

    report = _run_with_sandbox(mode="all", files=_CLEAN_FILES, runner=runner, detector=detector)

    assert report.assessments[0].sandbox is not None
    assert report.assessments[0].sandbox.status is SandboxStatus.COMPLETED
    assert detector.calls == 1


def test_sandbox_unavailable_is_a_warning_not_a_verdict_change() -> None:
    detector = _FakeDetector(
        DockerStatus(available=False, reason="Cannot connect to the Docker daemon")
    )
    runner = FakeCommandRunner()

    report = _run_with_sandbox(mode="all", files=_CLEAN_FILES, runner=runner, detector=detector)

    assessment = report.assessments[0]
    assert assessment.sandbox is not None
    assert assessment.sandbox.status is SandboxStatus.UNAVAILABLE
    assert assessment.verdict.decision is Decision.USE
    assert runner.calls == []
    assert any("sandbox unavailable" in warning for warning in report.warnings)
    assert any("no Docker daemon" in item for item in assessment.verdict.limitations)


def test_sandbox_timeout_is_recorded_and_cleaned_up() -> None:
    detector = _FakeDetector(DockerStatus(available=True, version="27"))
    runner = FakeCommandRunner(
        [
            CommandResult(argv=(), timed_out=True),
            CommandResult(argv=(), returncode=0),
        ]
    )

    report = _run_with_sandbox(mode="all", files=_RISKY_FILES, runner=runner, detector=detector)

    assessment = report.assessments[0]
    assert assessment.sandbox is not None
    assert assessment.sandbox.status is SandboxStatus.TIMEOUT
    assert assessment.verdict.decision is Decision.AVOID
    assert runner.calls[1][0][:3] == ("docker", "rm", "-f")
    assert any("did not complete" in warning for warning in report.warnings)


def test_sandbox_containment_failure_is_flagged() -> None:
    detector = _FakeDetector(DockerStatus(available=True, version="27"))
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=sandbox_probe_output(src_writable=True),
            )
        ]
    )

    report = _run_with_sandbox(mode="all", files=_CLEAN_FILES, runner=runner, detector=detector)

    assessment = report.assessments[0]
    assert assessment.sandbox is not None
    assert assessment.sandbox.containment_ok is False
    assert any("containment checks did not pass" in warning for warning in report.warnings)


def test_sandbox_invalid_image_degrades_to_error() -> None:
    detector = _FakeDetector(DockerStatus(available=True, version="27"))
    runner = FakeCommandRunner()

    report = _run_with_sandbox(
        mode="all",
        files=_CLEAN_FILES,
        runner=runner,
        detector=detector,
        sandbox_image="-v",
    )

    assessment = report.assessments[0]
    assert assessment.sandbox is not None
    assert assessment.sandbox.status is SandboxStatus.ERROR
    assert detector.calls == 0
    assert runner.calls == []
    assert any("sandbox configuration is invalid" in warning for warning in report.warnings)


def test_sandbox_does_not_run_when_scan_was_rejected() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(1.0)})
    detector = _FakeDetector(DockerStatus(available=True, version="27"))
    runner = FakeCommandRunner()

    report = Pipeline(
        Settings(max_candidates=0, sandbox_mode="all"),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(_RISKY_FILES),
        sandbox_runner=runner,
        sandbox_detect=detector,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.filter.status is FilterStatus.SKIPPED
    assert assessment.sandbox is None
    assert detector.calls == 0
    assert runner.calls == []


# --- Semgrep integration ----------------------------------------------------


def _semgrep_output(path: str = "app.py", severity: str = "ERROR") -> str:
    return json.dumps(
        {
            "version": "1.90.0",
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval",
                    "path": path,
                    "start": {"line": 3, "col": 1},
                    "extra": {
                        "message": "Detected eval",
                        "severity": severity,
                        "lines": "eval(user_input)",
                        "metadata": {"category": "security"},
                    },
                }
            ],
            "errors": [],
            "paths": {"scanned": [path], "skipped": []},
        }
    )


def _semgrep_config(tmp_path: Path) -> Path:
    config = tmp_path / "semgrep.yaml"
    config.write_text("rules: []\n", encoding="utf-8")
    return config


def test_semgrep_scanner_replaces_the_builtin_scanner(tmp_path: Path) -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = FakeCommandRunner([CommandResult(argv=(), returncode=0, stdout=_semgrep_output())])

    def builtin_must_not_run(*_args, **_kwargs):
        raise AssertionError("built-in scanner should not run when Semgrep succeeds")

    report = Pipeline(
        Settings(max_candidates=0, semgrep_config=str(_semgrep_config(tmp_path))),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory({"app.py": "eval(user_input)\n"}),
        scan_fn=builtin_must_not_run,
        semgrep_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.status is ScanStatus.SCANNED
    assert assessment.scan.scanner == "semgrep"
    assert assessment.scan.risk is RiskLevel.HIGH
    assert assessment.verdict.decision is Decision.AVOID
    assert runner.calls[0][0][0] == "semgrep"


def test_semgrep_missing_binary_falls_back_to_builtin(tmp_path: Path) -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = FakeCommandRunner(
        [CommandResult(argv=(), returncode=None, stderr="executable not found")]
    )

    report = Pipeline(
        Settings(max_candidates=0, semgrep_config=str(_semgrep_config(tmp_path))),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(_RISKY_FILES),
        semgrep_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.scanner == "builtin-patterns"
    assert assessment.scan.risk is RiskLevel.HIGH
    assert any("used the built-in scanner" in warning for warning in report.warnings)


def test_semgrep_failure_does_not_silently_fall_back(tmp_path: Path) -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = FakeCommandRunner([CommandResult(argv=(), returncode=2, stderr="bad config")])

    def builtin_must_not_run(*_args, **_kwargs):
        raise AssertionError("a configured Semgrep failure must not fall back")

    report = Pipeline(
        Settings(max_candidates=0, semgrep_config=str(_semgrep_config(tmp_path))),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(_CLEAN_FILES),
        scan_fn=builtin_must_not_run,
        semgrep_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.status is ScanStatus.ERROR
    assert assessment.scan.scanner == "semgrep"
    assert assessment.verdict.decision is Decision.INSPECT
    assert "bad config" in (assessment.scan.error or "")


def test_semgrep_missing_config_is_a_scan_error(tmp_path: Path) -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})

    report = Pipeline(
        Settings(
            max_candidates=0,
            semgrep_config=str(tmp_path / "missing.yaml"),
        ),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(_CLEAN_FILES),
        semgrep_runner=FakeCommandRunner(),
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.status is ScanStatus.ERROR
    assert "config path does not exist" in (assessment.scan.error or "")


# --- gitleaks integration ---------------------------------------------------


def _gitleaks_payload(path: str = "config.py") -> str:
    return json.dumps(
        [
            {
                "RuleID": "aws-access-token",
                "Description": "AWS Access Token",
                "StartLine": 2,
                "Match": "key = AKIAIOSFODNN7EXAMPLE",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": path,
                "Tags": [],
            }
        ]
    )


class _GitleaksRunner:
    """Fake gitleaks runner: writes the JSON report the adapter expects."""

    def __init__(self, payload: str | None = None, result: CommandResult | None = None) -> None:
        self.payload = payload
        self.result = result
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def __call__(self, argv, *, timeout: float) -> CommandResult:
        recorded = tuple(argv)
        self.calls.append((recorded, timeout))
        if self.payload is not None:
            report_path = recorded[recorded.index("--report-path") + 1]
            Path(report_path).write_text(self.payload, encoding="utf-8")
        return self.result or CommandResult(argv=recorded, returncode=0)


def test_gitleaks_is_additive_to_the_builtin_scanner() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = _GitleaksRunner(_gitleaks_payload())

    report = Pipeline(
        Settings(max_candidates=0, enable_gitleaks=True),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(
            {"app.py": "def get(url):\n    return url\n", "config.py": "key = x\n"}
        ),
        gitleaks_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.status is ScanStatus.SCANNED
    assert assessment.scan.scanner == "builtin-patterns+gitleaks"
    assert assessment.scan.risk is RiskLevel.HIGH
    # The built-in scanner still provides the file count for the merged report.
    assert assessment.scan.files_scanned == 2
    assert assessment.verdict.decision is Decision.AVOID
    assert any("git history" in item for item in assessment.verdict.limitations)
    assert runner.calls[0][0][:2] == ("gitleaks", "dir")


def test_gitleaks_disabled_by_default_never_runs() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = _GitleaksRunner(_gitleaks_payload())

    report = Pipeline(
        Settings(max_candidates=0),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(_CLEAN_FILES),
        gitleaks_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assert runner.calls == []
    assert report.assessments[0].scan.scanner == "builtin-patterns"


def test_gitleaks_missing_binary_warns_and_keeps_builtin() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = _GitleaksRunner(
        result=CommandResult(argv=(), returncode=None, stderr="executable not found")
    )

    report = Pipeline(
        Settings(max_candidates=0, enable_gitleaks=True),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(_CLEAN_FILES),
        gitleaks_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.status is ScanStatus.SCANNED
    assert assessment.scan.scanner == "builtin-patterns"
    assert any("gitleaks is unavailable" in warning for warning in report.warnings)


def test_gitleaks_failure_is_a_scan_error_not_a_silent_fallback() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = _GitleaksRunner(result=CommandResult(argv=(), returncode=1, stderr="bad config"))

    report = Pipeline(
        Settings(max_candidates=0, enable_gitleaks=True),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(_CLEAN_FILES),
        gitleaks_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.status is ScanStatus.ERROR
    assert assessment.scan.scanner == "builtin-patterns+gitleaks"
    assert "bad config" in (assessment.scan.error or "")
    assert assessment.verdict.decision is Decision.INSPECT


def test_gitleaks_runs_alongside_semgrep(tmp_path: Path) -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    semgrep_runner = FakeCommandRunner(
        [CommandResult(argv=(), returncode=0, stdout=_semgrep_output(severity="WARNING"))]
    )
    gitleaks_runner = _GitleaksRunner(_gitleaks_payload())

    report = Pipeline(
        Settings(
            max_candidates=0,
            semgrep_config=str(_semgrep_config(tmp_path)),
            enable_gitleaks=True,
        ),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(
            {"app.py": "eval(user_input)\n", "config.py": "key = x\n"}
        ),
        semgrep_runner=semgrep_runner,
        gitleaks_runner=gitleaks_runner,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.scanner == "semgrep+gitleaks"
    assert {finding.rule_id for finding in assessment.scan.findings} == {
        "python.lang.security.audit.eval",
        "gitleaks:aws-access-token",
    }
    assert assessment.scan.risk is RiskLevel.HIGH


# --- OSV integration --------------------------------------------------------


def _osv_payload(path: str = "package-lock.json", package: str = "example") -> str:
    return json.dumps(
        {
            "results": [
                {
                    "source": {"path": path, "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": package,
                                "version": "1.3.1",
                                "ecosystem": "npm",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-c3h9-896r-86jm",
                                    "summary": "Improper input validation",
                                    "database_specific": {"severity": "HIGH"},
                                }
                            ],
                            "groups": [{"ids": ["GHSA-c3h9-896r-86jm"]}],
                        }
                    ],
                }
            ]
        }
    )


class _OsvRunner:
    """Fake osv-scanner runner: writes the JSON report the adapter expects."""

    def __init__(self, payload: str | None = None, result: CommandResult | None = None) -> None:
        self.payload = payload
        self.result = result
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def __call__(self, argv, *, timeout: float) -> CommandResult:
        recorded = tuple(argv)
        self.calls.append((recorded, timeout))
        if self.payload is not None:
            report_path = recorded[recorded.index("--output-file") + 1]
            Path(report_path).write_text(self.payload, encoding="utf-8")
        return self.result or CommandResult(argv=recorded, returncode=0)


def test_osv_is_additive_and_a_high_advisory_triggers_avoid() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = _OsvRunner(_osv_payload())

    report = Pipeline(
        Settings(max_candidates=0, enable_osv=True),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(
            {"app.py": "def get(url):\n    return url\n", "package-lock.json": "{}\n"}
        ),
        osv_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.status is ScanStatus.SCANNED
    assert assessment.scan.scanner == "builtin-patterns+osv"
    assert assessment.scan.risk is RiskLevel.HIGH
    # The built-in scanner skips lockfiles, so only app.py counts there; OSV
    # supplies the lockfile evidence without inflating the file count.
    assert assessment.scan.files_scanned == 1
    assert assessment.verdict.decision is Decision.AVOID
    assert any("lockfiles" in item for item in assessment.verdict.limitations)
    assert runner.calls[0][0][:3] == ("osv-scanner", "scan", "source")


def test_osv_disabled_by_default_never_runs() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = _OsvRunner(_osv_payload())

    report = Pipeline(
        Settings(max_candidates=0),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(_CLEAN_FILES),
        osv_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assert runner.calls == []
    assert report.assessments[0].scan.scanner == "builtin-patterns"


def test_osv_missing_binary_warns_and_keeps_builtin() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = _OsvRunner(
        result=CommandResult(argv=(), returncode=None, stderr="executable not found")
    )

    report = Pipeline(
        Settings(max_candidates=0, enable_osv=True),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(_CLEAN_FILES),
        osv_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.scanner == "builtin-patterns"
    assert assessment.verdict.decision is Decision.USE
    assert any("osv-scanner is unavailable" in warning for warning in report.warnings)


def test_osv_failure_is_a_scan_error_not_a_silent_fallback() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = _OsvRunner(result=CommandResult(argv=(), returncode=127, stderr="network down"))

    report = Pipeline(
        Settings(max_candidates=0, enable_osv=True),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(_CLEAN_FILES),
        osv_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.status is ScanStatus.ERROR
    assert assessment.scan.scanner == "builtin-patterns+osv"
    assert "network down" in (assessment.scan.error or "")
    assert assessment.verdict.decision is Decision.INSPECT


def test_osv_without_a_lockfile_marks_coverage_incomplete() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})
    runner = _OsvRunner(result=CommandResult(argv=(), returncode=128))

    report = Pipeline(
        Settings(max_candidates=0, enable_osv=True),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(_CLEAN_FILES),
        osv_runner=runner,
    ).run(RepoRef.parse("acme/seed"))

    assessment = report.assessments[0]
    assert assessment.scan.truncated is True
    assert assessment.verdict.decision is Decision.INSPECT
    assert any("found no lockfile" in warning for warning in report.warnings)


def test_all_additive_scanners_keep_their_order_in_the_name() -> None:
    seed = make_repo("acme/seed")
    github = FakeGitHub(seed, [])
    scorecard = FakeScorecard({seed.full_name: scorecard_payload(8.0)})

    report = Pipeline(
        Settings(max_candidates=0, enable_gitleaks=True, enable_osv=True),
        github,
        scorecard,
        snapshot_fn=_files_snapshot_factory(
            {"app.py": "def get(url):\n    return url\n", "package-lock.json": "{}\n"}
        ),
        gitleaks_runner=_GitleaksRunner(_gitleaks_payload("config.py")),
        osv_runner=_OsvRunner(_osv_payload()),
    ).run(RepoRef.parse("acme/seed"))

    assert report.assessments[0].scan.scanner == "builtin-patterns+gitleaks+osv"
