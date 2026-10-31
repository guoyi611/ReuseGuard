"""Shared test doubles and model factories."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from reuseguard.adapters.sandbox import CommandResult
from reuseguard.adapters.scorecard import ScorecardNotFound
from reuseguard.adapters.snapshot import ExtractionStats, Snapshot
from reuseguard.models import RepoMeta


def make_repo(full_name: str = "acme/seed", **overrides) -> RepoMeta:
    values = {
        "full_name": full_name,
        "html_url": f"https://github.com/{full_name}",
        "description": "A small HTTP client toolkit for tests.",
        "stars": 100,
        "forks": 10,
        "language": "Python",
        "topics": ["http", "client"],
        "license_spdx": "MIT",
        "pushed_at": datetime.now(timezone.utc),
        "created_at": datetime(2022, 1, 1, tzinfo=timezone.utc),
        "default_branch": "main",
        "size_kb": 100,
    }
    values.update(overrides)
    return RepoMeta(**values)


def scorecard_payload(score: float = 8.0, checks: dict[str, float] | None = None) -> dict:
    checks = checks or {
        "Maintained": 10,
        "Code-Review": 8,
        "Dangerous-Workflow": 10,
        "Token-Permissions": 9,
        "Vulnerabilities": 10,
        "Binary-Artifacts": 10,
    }
    return {
        "date": "2026-10-20",
        "score": score,
        "checks": [{"name": name, "score": value} for name, value in checks.items()],
    }


class FakeGitHub:
    def __init__(
        self,
        seed: RepoMeta,
        results: list[RepoMeta] | None = None,
        *,
        search_error: Exception | None = None,
    ) -> None:
        self.seed = seed
        self.results = results or []
        self.search_error = search_error
        self.queries: list[str] = []

    def get_repo(self, _ref):
        return self.seed

    def search_repositories(self, query: str, *, per_page: int = 20):
        self.queries.append(query)
        if self.search_error is not None:
            raise self.search_error
        return self.results[:per_page]


class FakeScorecard:
    def __init__(self, by_name: dict[str, dict | Exception]) -> None:
        self.by_name = by_name
        self.calls: list[str] = []

    def fetch(self, ref):
        self.calls.append(ref.full_name)
        value = self.by_name.get(ref.full_name)
        if value is None:
            raise ScorecardNotFound("not indexed")
        if isinstance(value, Exception):
            raise value
        return value


def make_snapshot(destination: Path, files: dict[str, str]) -> Snapshot:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination / "tree"
    root.mkdir()
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return Snapshot(root=root, stats=ExtractionStats(files=len(files)), archive_bytes=100)


class FakeCommandRunner:
    """Records argv lists and replays canned :class:`CommandResult` values."""

    def __init__(self, results: list[CommandResult] | None = None) -> None:
        self.results = list(results or [])
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def __call__(self, argv, *, timeout: float) -> CommandResult:
        recorded = tuple(argv)
        self.calls.append((recorded, timeout))
        if self.results:
            return self.results.pop(0)
        return CommandResult(argv=recorded, returncode=1, stderr="no fake result queued")


def sandbox_probe_payload(**overrides) -> dict:
    payload = {
        "python": "3.11.9",
        "files": 3,
        "bytes": 120,
        "symlinks": 0,
        "executables": 0,
        "errors": [],
        "src_writable": False,
        "tmp_writable": True,
        "network_reachable": False,
        "network_target": "1.1.1.1:443",
        "src_entries": 2,
    }
    payload.update(overrides)
    return payload


def sandbox_probe_output(**overrides) -> str:
    payload = sandbox_probe_payload(**overrides)
    return f"REUSEGUARD_PROBE {json.dumps(payload, sort_keys=True)}\n"
