"""Tests for Markdown and JSON rendering."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from reuseguard.demo import build_demo_report
from reuseguard.models import (
    Assessment,
    Candidate,
    Confidence,
    Decision,
    FilterResult,
    FilterStatus,
    Finding,
    RepoMeta,
    Report,
    RiskLevel,
    SandboxReport,
    SandboxStatus,
    ScanReport,
    ScanStatus,
    Similarity,
    Verdict,
)
from reuseguard.report import render, render_json, render_markdown


def test_demo_markdown_contains_summary_and_limitations() -> None:
    report = build_demo_report()

    markdown = render_markdown(report)

    assert markdown.startswith("# ReuseGuard report")
    assert "Demo report" in markdown
    assert "**Verdicts:** 2 USE · 1 INSPECT · 2 AVOID" in markdown
    assert "## Limitations" in markdown
    assert "acme/suspicious-helper — AVOID" in markdown
    assert "npm-lifecycle" in markdown
    assert "<details>" in markdown


def test_demo_markdown_does_not_escape_query_operators() -> None:
    markdown = render_markdown(build_demo_report())

    assert "stars:>=50" in markdown
    assert "stars:&gt;=50" not in markdown


def test_demo_json_is_machine_readable() -> None:
    report = build_demo_report()

    payload = json.loads(render_json(report))

    assert payload["schema_version"] == 1
    assert payload["demo"] is True
    assert payload["counts"] == {"use": 2, "inspect": 1, "avoid": 2}
    assert payload["assessments"][3]["scan"]["risk"] == "high"


def test_render_rejects_unknown_format() -> None:
    with pytest.raises(ValueError):
        render(build_demo_report(), "xml")


def test_user_text_is_html_escaped() -> None:
    repo = RepoMeta(
        full_name="acme/seed",
        html_url="https://github.com/acme/seed",
        description="<script>alert(1)</script> | unsafe",
    )
    report = Report(
        tool_version="0.1.0",
        generated_at=datetime.now(timezone.utc),
        seed=repo,
        assessments=[
            Assessment(
                candidate=Candidate(repo=repo),
                filter=FilterResult(status=FilterStatus.PASSED, score=8.0),
                scan=ScanReport(status=ScanStatus.SCANNED),
                verdict=Verdict(decision=Decision.USE, confidence=Confidence.HIGH),
            )
        ],
    )

    markdown = render_markdown(report)

    assert "<script>" not in markdown
    assert "&lt;script&gt;" in markdown
    assert "\\| unsafe" in markdown


def test_idea_report_uses_query_header_and_keyword_breakdown() -> None:
    repo = RepoMeta(
        full_name="acme/http",
        html_url="https://github.com/acme/http",
        description="A fast HTTP client",
    )
    report = Report(
        tool_version="0.1.0",
        generated_at=datetime.now(timezone.utc),
        seed=None,
        query="fast HTTP client",
        assessments=[
            Assessment(
                candidate=Candidate(
                    repo=repo,
                    role="candidate",
                    similarity=Similarity(
                        total=88.0,
                        keywords=40.0,
                        language=20.0,
                        recency=18.0,
                        popularity=10.0,
                    ),
                ),
                filter=FilterResult(status=FilterStatus.PASSED, score=8.0),
                scan=ScanReport(status=ScanStatus.SCANNED),
                verdict=Verdict(decision=Decision.USE, confidence=Confidence.HIGH),
            )
        ],
    )

    markdown = render_markdown(report)

    assert "**Idea:** fast HTTP client" in markdown
    assert "**Seed:**" not in markdown
    assert "keywords 40.0" in markdown
    assert "| candidate |" in markdown
    assert "No candidate repositories" not in markdown


def test_empty_idea_report_is_rendered() -> None:
    report = Report(
        tool_version="0.1.0",
        generated_at=datetime.now(timezone.utc),
        seed=None,
        query="nothing matches",
        assessments=[],
    )

    markdown = render_markdown(report)

    assert "**Idea:** nothing matches" in markdown
    assert "No candidate repositories were found." in markdown


def _sandbox_report(sandbox: SandboxReport) -> Report:
    repo = RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed")
    return Report(
        tool_version="0.3.0",
        generated_at=datetime.now(timezone.utc),
        seed=repo,
        assessments=[
            Assessment(
                candidate=Candidate(repo=repo, role="seed"),
                filter=FilterResult(status=FilterStatus.PASSED, score=8.0),
                scan=ScanReport(status=ScanStatus.SCANNED, files_scanned=10),
                verdict=Verdict(decision=Decision.USE, confidence=Confidence.HIGH),
                sandbox=sandbox,
            )
        ],
        settings={
            "sandbox_mode": "all",
            "sandbox_image": "python:3.11-slim",
            "sandbox_timeout": 20,
        },
    )


def test_sandbox_section_reports_containment_evidence() -> None:
    sandbox = SandboxReport(
        status=SandboxStatus.COMPLETED,
        image="python:3.11-slim",
        duration_seconds=1.8,
        containment_ok=True,
        memory_mb=256,
        cpus=0.5,
        pids_limit=64,
        timeout_seconds=20,
        probe={
            "files": 12,
            "bytes": 2048,
            "symlinks": 0,
            "executables": 1,
            "src_entries": 3,
            "src_writable": False,
            "tmp_writable": True,
            "network_reachable": False,
        },
    )

    markdown = render_markdown(_sandbox_report(sandbox))

    assert "### Sandbox — containment verified" in markdown
    assert "one container run" in markdown
    assert "12 files" in markdown
    assert "`/src` writable: **no**" in markdown
    assert "network reachable: **no**" in markdown
    assert "does not execute repository code" in markdown
    assert "not evidence that the repository is safe" in markdown
    assert "| containment ok |" in markdown


def test_sandbox_section_flags_failed_containment() -> None:
    sandbox = SandboxReport(
        status=SandboxStatus.COMPLETED,
        image="python:3.11-slim",
        containment_ok=False,
        probe={
            "src_entries": 3,
            "src_writable": True,
            "network_reachable": True,
            "tmp_writable": True,
        },
    )

    markdown = render_markdown(_sandbox_report(sandbox))

    assert "### Sandbox — containment NOT verified" in markdown
    assert "**Containment check failed:**" in markdown
    assert "the repository mount was writable" in markdown
    assert "the container could reach the network" in markdown
    assert "**containment failed**" in markdown


def test_sandbox_unavailable_is_rendered_without_safety_claims() -> None:
    sandbox = SandboxReport(
        status=SandboxStatus.UNAVAILABLE,
        image="python:3.11-slim",
        error="Cannot connect to the Docker daemon",
    )

    markdown = render_markdown(_sandbox_report(sandbox))

    assert "### Sandbox — unavailable" in markdown
    assert "Cannot connect to the Docker daemon" in markdown
    assert "not evidence that the repository is safe" in markdown


def test_sandbox_error_text_is_escaped() -> None:
    sandbox = SandboxReport(
        status=SandboxStatus.ERROR,
        error="<script>alert(1)</script>",
    )

    markdown = render_markdown(_sandbox_report(sandbox))

    assert "<script>" not in markdown
    assert "&lt;script&gt;" in markdown


def test_demo_json_includes_sandbox_evidence() -> None:
    payload = json.loads(render_json(build_demo_report()))

    assert payload["assessments"][3]["sandbox"]["status"] == "completed"
    assert payload["assessments"][3]["sandbox"]["containment_ok"] is True
    assert payload["assessments"][0]["sandbox"] is None


def test_external_rule_id_is_escaped_in_tables() -> None:
    repo = RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed")
    report = Report(
        tool_version="0.4.0",
        generated_at=datetime.now(timezone.utc),
        seed=repo,
        assessments=[
            Assessment(
                candidate=Candidate(repo=repo),
                filter=FilterResult(status=FilterStatus.PASSED, score=8.0),
                scan=ScanReport(
                    status=ScanStatus.SCANNED,
                    risk=RiskLevel.HIGH,
                    files_scanned=1,
                    scanner="semgrep",
                    findings=[
                        Finding(
                            rule_id="evil|`<script>",
                            title="external",
                            severity=RiskLevel.HIGH,
                            category="security",
                            path="app.py",
                            line=1,
                            message="matched",
                        )
                    ],
                ),
                verdict=Verdict(decision=Decision.AVOID, confidence=Confidence.MEDIUM),
            )
        ],
    )

    markdown = render_markdown(report)

    assert "evil\\|" in markdown
