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


def test_sandbox_flag_parsing() -> None:
    parser = cli.build_parser()

    assert parser.parse_args(["check", "acme/seed"]).sandbox is None
    assert parser.parse_args(["check", "acme/seed", "--sandbox"]).sandbox == "all"
    assert parser.parse_args(["check", "acme/seed", "--sandbox", "auto"]).sandbox == "auto"
    assert parser.parse_args(["check", "acme/seed", "--sandbox", "off"]).sandbox == "off"


def test_sandbox_options_require_the_sandbox_flag(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check", "acme/seed", "--sandbox-image", "python:3.11-slim"]) == 2
    assert cli.main(["check", "acme/seed", "--sandbox-timeout", "30"]) == 2
    assert "require --sandbox" in capsys.readouterr().err


def test_sandbox_requires_static_scanning(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check", "acme/seed", "--sandbox", "--no-scan"]) == 2
    assert "requires static scanning" in capsys.readouterr().err


def test_sandbox_rejects_invalid_image(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["check", "acme/seed", "--sandbox", "--sandbox-image", "bad image"])

    assert code == 2
    assert "invalid sandbox image" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["0.5", "601"])
def test_sandbox_timeout_must_be_in_range(value: str) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["check", "acme/seed", "--sandbox", "--sandbox-timeout", value])

    assert excinfo.value.code == 2


def test_sandbox_settings_are_forwarded_to_the_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "sandbox.md"
    report = build_demo_report()
    captured: dict[str, object] = {}

    class _CapturingPipeline:
        def __init__(self, settings, *_args, **_kwargs) -> None:
            captured["settings"] = settings

        def run(self, _ref):
            return report

    monkeypatch.setattr(cli, "GitHubClient", _DummyClient)
    monkeypatch.setattr(cli, "ScorecardClient", _DummyClient)
    monkeypatch.setattr(cli, "Pipeline", _CapturingPipeline)
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(
        [
            "check",
            "acme/seed",
            "--sandbox",
            "auto",
            "--sandbox-image",
            "python:3.12-slim",
            "--sandbox-timeout",
            "30",
            "-o",
            str(output),
            "--quiet",
        ]
    )

    assert code == 0
    settings = captured["settings"]
    assert settings.sandbox_mode == "auto"
    assert settings.sandbox_image == "python:3.12-slim"
    assert settings.sandbox_timeout == 30.0


def test_semgrep_config_must_exist(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["check", "acme/seed", "--semgrep-config", str(tmp_path / "missing.yaml")])

    assert code == 2
    assert "semgrep config path does not exist" in capsys.readouterr().err


def test_semgrep_timeout_requires_config(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["check", "acme/seed", "--semgrep-timeout", "60"])

    assert code == 2
    assert "requires --semgrep-config" in capsys.readouterr().err


def test_semgrep_requires_static_scanning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "rules.yaml"
    config.write_text("rules: []\n", encoding="utf-8")

    code = cli.main(["check", "acme/seed", "--semgrep-config", str(config), "--no-scan"])

    assert code == 2
    assert "requires static scanning" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["5", "4000"])
def test_semgrep_timeout_must_be_in_range(tmp_path: Path, value: str) -> None:
    config = tmp_path / "rules.yaml"
    config.write_text("rules: []\n", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            [
                "check",
                "acme/seed",
                "--semgrep-config",
                str(config),
                "--semgrep-timeout",
                value,
            ]
        )

    assert excinfo.value.code == 2


def test_semgrep_settings_are_forwarded_to_the_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "semgrep.md"
    config = tmp_path / "rules.yaml"
    config.write_text("rules: []\n", encoding="utf-8")
    report = build_demo_report()
    captured: dict[str, object] = {}

    class _CapturingPipeline:
        def __init__(self, settings, *_args, **_kwargs) -> None:
            captured["settings"] = settings

        def run(self, _ref):
            return report

    monkeypatch.setattr(cli, "GitHubClient", _DummyClient)
    monkeypatch.setattr(cli, "ScorecardClient", _DummyClient)
    monkeypatch.setattr(cli, "Pipeline", _CapturingPipeline)
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(
        [
            "check",
            "acme/seed",
            "--semgrep-config",
            str(config),
            "--semgrep-timeout",
            "120",
            "-o",
            str(output),
            "--quiet",
        ]
    )

    assert code == 0
    settings = captured["settings"]
    assert settings.semgrep_config == str(config)
    assert settings.semgrep_timeout == 120.0


# --- gitleaks ---------------------------------------------------------------


def test_gitleaks_timeout_requires_gitleaks(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["check", "acme/seed", "--gitleaks-timeout", "60"])

    assert code == 2
    assert "requires --gitleaks" in capsys.readouterr().err


def test_gitleaks_requires_static_scanning(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["check", "acme/seed", "--gitleaks", "--no-scan"])

    assert code == 2
    assert "requires static scanning" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["5", "4000"])
def test_gitleaks_timeout_must_be_in_range(value: str) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["check", "acme/seed", "--gitleaks", "--gitleaks-timeout", value])

    assert excinfo.value.code == 2


def test_gitleaks_settings_are_forwarded_to_the_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "gitleaks.md"
    report = build_demo_report()
    captured: dict[str, object] = {}

    class _CapturingPipeline:
        def __init__(self, settings, *_args, **_kwargs) -> None:
            captured["settings"] = settings

        def run(self, _ref):
            return report

    monkeypatch.setattr(cli, "GitHubClient", _DummyClient)
    monkeypatch.setattr(cli, "ScorecardClient", _DummyClient)
    monkeypatch.setattr(cli, "Pipeline", _CapturingPipeline)
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(
        [
            "check",
            "acme/seed",
            "--gitleaks",
            "--gitleaks-timeout",
            "120",
            "-o",
            str(output),
            "--quiet",
        ]
    )

    assert code == 0
    settings = captured["settings"]
    assert settings.enable_gitleaks is True
    assert settings.gitleaks_timeout == 120.0
