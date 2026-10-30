"""Runtime settings and credential resolution."""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from . import __version__

DEFAULT_USER_AGENT = f"reuseguard/{__version__}"


def resolve_github_token(*, allow_gh_cli: bool = True) -> str | None:
    """Resolve a GitHub token from the environment, then optionally from ``gh``.

    Using an authenticated token raises the REST limit from 60 to 5,000 requests
    per hour and is strongly recommended. The token is never written to a report
    or printed.
    """
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name, "").strip()
        if value:
            return value

    if allow_gh_cli and shutil.which("gh"):
        try:
            completed = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        token = completed.stdout.strip()
        if completed.returncode == 0 and token:
            return token
    return None


@dataclass(frozen=True)
class Settings:
    """All knobs that influence a pipeline run."""

    token: str | None = None
    timeout: float = 20.0
    max_candidates: int = 5
    min_stars: int = 50
    max_repo_mb: int = 150
    max_files: int = 2000
    max_file_kb: int = 1024
    max_scan_mb: int = 20
    scorecard_min: float = 2.0
    enable_recall: bool = True
    enable_scorecard: bool = True
    enable_scan: bool = True
    keep_workdir: bool = False
    user_agent: str = DEFAULT_USER_AGENT

    def public_dict(self) -> dict[str, Any]:
        """Serialize settings without leaking the token."""
        data = {
            field.name: getattr(self, field.name)
            for field in dataclasses.fields(self)
            if field.name != "token"
        }
        data["token_configured"] = bool(self.token)
        return data
