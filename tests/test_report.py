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
from reuseguard.stages.recall import score_similarity


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


def _discover_only_report() -> Report:
    repo = RepoMeta(
        full_name="acme/pixel",
        html_url="https://github.com/acme/pixel",
        description="A 2D pixel art generator",
        stars=10_912,
    )
    return Report(
        tool_version="0.7.0",
        generated_at=datetime.now(timezone.utc),
        seed=None,
        query="AI 2D pixel art generator",
        discover_only=True,
        assessments=[
            Assessment(
                candidate=Candidate(
                    repo=repo,
                    role="candidate",
                    similarity=Similarity(
                        total=82.5,
                        keywords=40.0,
                        language=10.0,
                        recency=20.0,
                        popularity=12.5,
                    ),
                ),
                filter=FilterResult(status=FilterStatus.PASSED, score=7.2),
                scan=ScanReport(
                    status=ScanStatus.DISABLED,
                    error="Static scanning disabled with --no-scan.",
                ),
                verdict=Verdict(
                    decision=Decision.INSPECT,
                    confidence=Confidence.LOW,
                    reasons=["Static scanning was disabled, so there is no code-level evidence."],
                    limitations=["No static scan was performed."],
                    withheld=True,
                ),
            )
        ],
        settings={"enable_scan": False, "discover_only": True},
    )


def test_discover_only_markdown_hides_verdicts_and_scan_columns() -> None:
    markdown = render_markdown(_discover_only_report())

    assert "**Verdicts:** withheld (no static scan)" in markdown
    assert "No static scan was performed, so no verdict is given." in markdown
    assert "| # | Repository | Role | Stars | Match | Scorecard | Verdict |" in markdown
    assert "| Static risk |" not in markdown
    assert "| Sandbox |" not in markdown
    assert "| candidate | 10,912 | 82.5 | 7.2/10 | — |" in markdown
    assert "**INSPECT FIRST**" not in markdown
    assert "## 1. acme/pixel" in markdown
    assert "### Verdict — withheld" in markdown


def test_discover_only_json_keeps_decision_but_marks_it_withheld() -> None:
    payload = json.loads(render_json(_discover_only_report()))

    assert payload["discover_only"] is True
    assert payload["settings"]["discover_only"] is True
    assessment = payload["assessments"][0]
    assert assessment["scan"]["status"] == "disabled"
    assert assessment["verdict"]["decision"] == "inspect"
    assert assessment["verdict"]["confidence"] == "low"
    assert assessment["verdict"]["withheld"] is True


def test_default_markdown_still_shows_verdicts_and_scan_columns() -> None:
    markdown = render_markdown(build_demo_report())

    assert (
        "| # | Repository | Role | Stars | Match | Scorecard | Static risk | Sandbox | Verdict |"
        in markdown
    )
    assert "**AVOID**" in markdown
    assert "No static scan was performed, so no verdict is given." not in markdown


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


def test_run_details_show_dependency_scan() -> None:
    repo = RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed")
    report = Report(
        tool_version="0.6.0",
        generated_at=datetime.now(timezone.utc),
        seed=repo,
        assessments=[
            Assessment(
                candidate=Candidate(repo=repo),
                filter=FilterResult(status=FilterStatus.PASSED, score=8.0),
                scan=ScanReport(
                    status=ScanStatus.SCANNED,
                    files_scanned=3,
                    scanner="builtin-patterns+osv",
                ),
                verdict=Verdict(decision=Decision.USE, confidence=Confidence.HIGH),
            )
        ],
        settings={"enable_osv": True, "osv_timeout": 300.0},
    )

    markdown = render_markdown(report)

    assert "Dependency scan: `osv-scanner`" in markdown
    assert "api.osv.dev" in markdown
    assert "`builtin-patterns+osv` scanned 3 files" in markdown


def test_demo_similarity_uses_the_fixed_report_clock() -> None:
    """The demo must not drift with the wall clock: recency is scored at _NOW."""
    report = build_demo_report()
    seed = report.assessments[0].candidate.repo
    candidate = report.assessments[3].candidate.repo
    similarity = report.assessments[3].candidate.similarity

    assert similarity is not None
    expected = score_similarity(seed, candidate, now=report.generated_at)
    assert similarity.total == expected.total


def _assessment_with_findings(findings: list[Finding]) -> Assessment:
    repo = RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed")
    return Assessment(
        candidate=Candidate(repo=repo),
        filter=FilterResult(status=FilterStatus.PASSED, score=8.0),
        scan=ScanReport(
            status=ScanStatus.SCANNED,
            risk=RiskLevel.HIGH,
            files_scanned=5,
            scanner="builtin-patterns+osv",
            findings=findings,
        ),
        verdict=Verdict(decision=Decision.AVOID, confidence=Confidence.MEDIUM),
    )


def test_dev_only_findings_are_collapsed_separately() -> None:
    findings = [
        Finding(
            rule_id="osv:GHSA-prod",
            title="prod vuln",
            severity=RiskLevel.HIGH,
            category="dependency",
            path="package-lock.json",
            message="Production dependency. bad",
            scope="production",
        ),
        Finding(
            rule_id="osv:GHSA-dev",
            title="dev vuln",
            severity=RiskLevel.HIGH,
            category="dependency",
            path="package-lock.json",
            message="Development-only dependency. bad",
            scope="development",
        ),
    ]
    report = Report(
        tool_version="0.7.2",
        generated_at=datetime.now(timezone.utc),
        seed=RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed"),
        assessments=[_assessment_with_findings(findings)],
    )

    markdown = render_markdown(report)

    assert "**Production findings**" in markdown
    assert "osv:GHSA-prod" in markdown
    assert "<summary>1 development-only finding(s) (collapsed)</summary>" in markdown
    assert "osv:GHSA-dev" in markdown
    # summary line splits prod/dev counts
    assert "1 production + 1 development" in markdown


def test_pure_dev_findings_do_not_produce_a_production_table() -> None:
    findings = [
        Finding(
            rule_id="osv:GHSA-dev",
            title="dev only",
            severity=RiskLevel.MEDIUM,
            category="dependency",
            path="package-lock.json",
            message="Development-only dependency.",
            scope="development",
        ),
    ]
    report = Report(
        tool_version="0.7.2",
        generated_at=datetime.now(timezone.utc),
        seed=RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed"),
        assessments=[_assessment_with_findings(findings)],
    )

    markdown = render_markdown(report)

    assert "**Production findings**" not in markdown
    assert "<summary>1 development-only finding(s) (collapsed)</summary>" in markdown


def test_finding_scope_is_serialized_in_json() -> None:
    findings = [
        Finding(
            rule_id="osv:GHSA-x",
            title="x",
            severity=RiskLevel.MEDIUM,
            category="dependency",
            path="package-lock.json",
            message="m",
            scope="development",
        ),
    ]
    report = Report(
        tool_version="0.7.2",
        generated_at=datetime.now(timezone.utc),
        seed=RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed"),
        assessments=[_assessment_with_findings(findings)],
    )

    payload = report.to_dict()

    finding_payload = payload["assessments"][0]["scan"]["findings"][0]
    assert finding_payload["scope"] == "development"
