"""Tests for YAML policy loading and policy-driven CLI settings."""

from __future__ import annotations

from pathlib import Path

import pytest

from reuseguard import cli
from reuseguard.config import ConfigError, Settings, load_policy
from reuseguard.demo import build_demo_report
from reuseguard.models import RiskLevel
from tests.test_cli import _DummyClient


def _write_policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "reuseguard.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_full_policy(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
version: 1
thresholds:
  scorecard_min: 3.0
  use_scorecard_min: 6.0
limits:
  max_candidates: 2
  min_stars: 10
  max_repo_mb: 20
  max_files: 50
  max_file_kb: 128
  max_scan_mb: 2
  timeout: 5.0
features:
  recall: false
  scorecard: true
  scan: true
rules:
  disable:
    - generic-secret
  severity:
    py-eval-exec: high
suppress:
  paths:
    - "src/generated/**"
""",
    )

    policy = load_policy(path)

    assert policy.scorecard_min == 3.0
    assert policy.use_scorecard_min == 6.0
    assert policy.max_candidates == 2
    assert policy.min_stars == 10
    assert policy.timeout == 5.0
    assert policy.recall is False
    assert policy.scorecard is True
    assert policy.disabled_rules == frozenset({"generic-secret"})
    assert policy.severity_overrides["py-eval-exec"] is RiskLevel.HIGH
    assert policy.suppress_paths == ("src/generated/**",)


def test_empty_policy_uses_defaults(tmp_path: Path) -> None:
    policy = load_policy(_write_policy(tmp_path, ""))

    assert policy.max_candidates is None
    assert policy.disabled_rules == frozenset()
    assert policy.severity_overrides == {}


@pytest.mark.parametrize(
    "text",
    [
        "thresholds: []\n",
        "unknown_section: {}\n",
        "rules:\n  disable: [not-a-rule]\n",
        "rules:\n  severity: {py-eval-exec: severe}\n",
        "limits:\n  max_files: -1\n",
        "features:\n  scan: 1\n",
        "version: 2\n",
    ],
)
def test_invalid_policy_is_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_policy(_write_policy(tmp_path, text))


def test_cli_applies_policy_and_keeps_flag_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(
        tmp_path,
        """
limits:
  max_candidates: 2
  min_stars: 10
thresholds:
  use_scorecard_min: 6.0
features:
  scan: true
rules:
  disable: [generic-secret]
suppress:
  paths: ["src/generated/**"]
""",
    )
    captured: dict[str, Settings] = {}

    class _CapturePipeline:
        def __init__(self, settings, _github, _scorecard) -> None:
            captured["settings"] = settings

        def run(self, _ref):
            return build_demo_report()

    monkeypatch.setattr(cli, "GitHubClient", _DummyClient)
    monkeypatch.setattr(cli, "ScorecardClient", _DummyClient)
    monkeypatch.setattr(cli, "Pipeline", _CapturePipeline)
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(
        [
            "check",
            "acme/seed",
            "--config",
            str(path),
            "--no-scan",
            "--min-stars",
            "99",
            "--quiet",
        ]
    )

    assert code == 0
    settings = captured["settings"]
    assert settings.max_candidates == 2
    assert settings.min_stars == 99
    assert settings.timeout == 20.0
    assert settings.use_scorecard_min == 6.0
    assert settings.enable_scan is False
    assert settings.disabled_rules == frozenset({"generic-secret"})
    assert settings.suppress_paths == ("src/generated/**",)
    assert settings.config_path == str(path)
    assert settings.severity_overrides == {}


def test_cli_rejects_invalid_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_policy(tmp_path, "rules:\n  disable: [not-a-rule]\n")
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(["check", "acme/seed", "--config", str(path)])

    assert code == 2
