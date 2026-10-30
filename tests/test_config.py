"""Tests for token resolution and settings serialization."""

from __future__ import annotations

import subprocess

import pytest

from reuseguard.config import Settings, resolve_github_token


@pytest.fixture(autouse=True)
def _clear_token_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)


def test_environment_token_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")

    assert resolve_github_token(allow_gh_cli=False) == "from-env"


def test_gh_token_is_a_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_TOKEN", "from-gh-env")

    assert resolve_github_token(allow_gh_cli=False) == "from-gh-env"


def test_gh_cli_is_used_only_when_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reuseguard.config.shutil.which", lambda _name: "/usr/bin/gh")
    monkeypatch.setattr(
        "reuseguard.config.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["gh", "auth", "token"], returncode=0, stdout="cli-token\n", stderr=""
        ),
    )

    assert resolve_github_token(allow_gh_cli=True) == "cli-token"
    assert resolve_github_token(allow_gh_cli=False) is None


def test_missing_gh_is_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reuseguard.config.shutil.which", lambda _name: None)

    assert resolve_github_token(allow_gh_cli=True) is None


def test_settings_public_dict_hides_token() -> None:
    settings = Settings(token="secret-token")

    public = settings.public_dict()

    assert "token" not in public
    assert public["token_configured"] is True
    assert public["max_candidates"] == 5
