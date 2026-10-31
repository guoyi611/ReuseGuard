"""Tests for CLI exit codes and output handling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reuseguard import cli
from reuseguard.demo import build_demo_report


def test_demo_command_writes_markdown(tmp_path: Path) -> None:
    output = tmp_path / "report.md"

    code = cli.main(["demo", "-o", str(output)])

    assert code == 0
    assert "# ReuseGuard report" in output.read_text(encoding="utf-8")


def test_demo_command_writes_json(tmp_path: Path) -> None:
    output = tmp_path / "report.json"

    code = cli.main(["demo", "--format", "json", "-o", str(output)])

    assert code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["counts"]["avoid"] == 2


def test_invalid_url_returns_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["check", "https://evil.example/acme/seed", "--no-scan"])

    assert code == 2
    assert "only github.com" in capsys.readouterr().err


def test_fail_on_threshold() -> None:
    report = build_demo_report()

    assert cli._exit_code(report, "never") == 0
    assert cli._exit_code(report, "avoid") == 3
    assert cli._exit_code(report, "inspect") == 3


class _DummyClient:
    def __init__(self, **_kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        pass


class _FakePipeline:
    def __init__(self, report) -> None:
        self._report = report
        self.idea: tuple[str, str | None] | None = None

    def run(self, _ref):
        return self._report

    def run_idea(self, idea: str, *, language: str | None = None):
        self.idea = (idea, language)
        return self._report


def test_check_command_uses_pipeline_and_writes_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "check.md"
    report = build_demo_report()
    monkeypatch.setattr(cli, "GitHubClient", _DummyClient)
    monkeypatch.setattr(cli, "ScorecardClient", _DummyClient)
    monkeypatch.setattr(cli, "Pipeline", lambda *_args, **_kwargs: _FakePipeline(report))
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(["check", "acme/seed", "-o", str(output), "--quiet"])

    assert code == 0
    assert "acme/http-kit" in output.read_text(encoding="utf-8")


def test_check_command_fail_on_avoid_returns_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "check.md"
    report = build_demo_report()
    monkeypatch.setattr(cli, "GitHubClient", _DummyClient)
    monkeypatch.setattr(cli, "ScorecardClient", _DummyClient)
    monkeypatch.setattr(cli, "Pipeline", lambda *_args, **_kwargs: _FakePipeline(report))
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(["check", "acme/seed", "-o", str(output), "--fail-on", "avoid", "--quiet"])

    assert code == 3


def test_check_idea_calls_run_idea(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "idea.md"
    report = build_demo_report()
    fake = _FakePipeline(report)
    monkeypatch.setattr(cli, "GitHubClient", _DummyClient)
    monkeypatch.setattr(cli, "ScorecardClient", _DummyClient)
    monkeypatch.setattr(cli, "Pipeline", lambda *_args, **_kwargs: fake)
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(
        [
            "check",
            "--idea",
            "fast HTTP client",
            "--language",
            "Python",
            "-o",
            str(output),
            "--quiet",
        ]
    )

    assert code == 0
    assert fake.idea == ("fast HTTP client", "Python")
    assert output.exists()


def test_check_requires_exactly_one_input(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check"]) == 2
    assert cli.main(["check", "acme/seed", "--idea", "x"]) == 2
    assert cli.main(["check", "--idea", "x", "--no-recall"]) == 2
    captured = capsys.readouterr()
    assert "provide" in captured.err
    assert "--no-recall" in captured.err
