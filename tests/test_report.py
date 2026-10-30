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
    RepoMeta,
    Report,
    ScanReport,
    ScanStatus,
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
