"""Tests for the gitleaks adapter (no gitleaks installation required).

Every test drives :class:`GitleaksScanner` through an injected runner, so none of
them start a process, touch the network, or need a gitleaks binary.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reuseguard.adapters import gitleaks as gitleaks_module
from reuseguard.adapters.gitleaks import (
    GitleaksError,
    GitleaksOptions,
    GitleaksScanner,
    GitleaksUnavailable,
)
from reuseguard.adapters.process import CommandResult
from reuseguard.adapters.scanner import ScanLimits
from reuseguard.models import RiskLevel, ScanStatus, to_jsonable

SECRET = "AKIAIOSFODNN7EXAMPLE"


def _leak(**overrides) -> dict:
    leak = {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "StartLine": 7,
        "EndLine": 7,
        "StartColumn": 1,
        "EndColumn": 22,
        "Match": f"aws_access_key_id = {SECRET}",
        "Secret": SECRET,
        "File": "config.py",
        "Tags": [],
        "Fingerprint": "config.py:aws-access-token:7",
    }
    leak.update(overrides)
    return leak


def _payload(leaks: list | None = None) -> str:
    return json.dumps(leaks or [])


class _Runner:
    """Fake runner that writes the JSON report the adapter asks it to write."""

    def __init__(self, payload: str | None = None, result: CommandResult | None = None) -> None:
        self.payload = payload
        self.result = result
        self.calls: list[tuple[tuple[str, ...], float]] = []
        self.config: str | None = None
        self.config_path: Path | None = None
        self.ignore_path: Path | None = None
        self.ignore_path_is_dir = False

    def __call__(self, argv, *, timeout: float) -> CommandResult:
        recorded = tuple(argv)
        self.calls.append((recorded, timeout))
        if "--config" in recorded:
            self.config_path = Path(recorded[recorded.index("--config") + 1])
            self.config = self.config_path.read_text(encoding="utf-8")
        if "--gitleaks-ignore-path" in recorded:
            self.ignore_path = Path(recorded[recorded.index("--gitleaks-ignore-path") + 1])
            self.ignore_path_is_dir = self.ignore_path.is_dir()
        if self.payload is not None and "--report-path" in recorded:
            report = Path(recorded[recorded.index("--report-path") + 1])
            report.write_text(self.payload, encoding="utf-8")
        return self.result or CommandResult(argv=recorded, returncode=0)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "config.py").write_text(f"aws_access_key_id = {SECRET}\n", encoding="utf-8")
    return root


def _scanner(runner) -> GitleaksScanner:
    return GitleaksScanner(GitleaksOptions(process_timeout=30.0), runner=runner)


def test_scan_maps_leaks_into_findings(tmp_path: Path) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(_payload([_leak()]))).scan(root)

    assert report.status is ScanStatus.SCANNED
    assert report.scanner == "gitleaks"
    assert report.risk is RiskLevel.HIGH
    assert report.files_scanned == 0
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.rule_id == "gitleaks:aws-access-token"
    assert finding.title == "AWS Access Token"
    assert finding.category == "secret"
    assert finding.path == "config.py"
    assert finding.line == 7
    assert finding.severity is RiskLevel.HIGH
    assert finding.suppressed is False


def test_secret_value_never_reaches_the_finding(tmp_path: Path) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(_payload([_leak()]))).scan(root)

    finding = report.findings[0]
    rendered = json.dumps(to_jsonable(report))
    assert SECRET not in rendered
    assert SECRET not in repr(finding)
    assert gitleaks_module._REDACTION_MARKER in (finding.evidence or "")


def test_multiline_match_is_redacted_and_flattened(tmp_path: Path) -> None:
    root = _root(tmp_path)
    leak = _leak(Match=f"key = {SECRET}\nnext line")

    report = _scanner(_Runner(_payload([leak]))).scan(root)

    evidence = report.findings[0].evidence or ""
    assert SECRET not in evidence
    assert "\n" not in evidence
    assert "next line" in evidence


def test_pre_redacted_output_is_accepted(tmp_path: Path) -> None:
    root = _root(tmp_path)
    leak = _leak(Secret="REDACTED", Match="aws_access_key_id = REDACTED")

    report = _scanner(_Runner(_payload([leak]))).scan(root)

    evidence = report.findings[0].evidence or ""
    assert "REDACTED" in evidence
    assert SECRET not in evidence


@pytest.mark.parametrize(
    ("secret", "match", "expected"),
    [
        ("abc", "key=abc", gitleaks_module._REDACTION_MARKER),
        ("", "key=supersecret", None),
    ],
)
def test_short_or_missing_secret_hides_the_context(
    tmp_path: Path, secret: str, match: str, expected: str | None
) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(_payload([_leak(Secret=secret, Match=match)]))).scan(root)

    assert report.findings[0].evidence == expected


def test_command_pins_rules_and_blocks_repository_controls(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = _Runner(_payload())

    _scanner(runner).scan(root, limits=ScanLimits(max_file_bytes=3 * 1024 * 1024))

    argv, timeout = runner.calls[0]
    assert argv[0] == "gitleaks"
    assert argv[1] == "dir"
    assert argv[2] == str(root.resolve())
    assert argv[argv.index("--report-format") + 1] == "json"
    assert argv[argv.index("--exit-code") + 1] == "0"
    assert argv[argv.index("--max-target-megabytes") + 1] == "3"
    assert "--redact" in argv
    assert "--no-banner" in argv
    assert "--no-color" in argv
    assert "--ignore-gitleaks-allow" in argv
    # The snapshot is a tarball without .git, and remote rules must stay off.
    assert "--no-git" not in argv
    assert "auto" not in argv
    assert timeout == 30.0


def test_repository_supplied_config_and_ignore_file_are_avoided(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / ".gitleaks.toml").write_text("[[allowlists]]\npaths = ['.*']\n", encoding="utf-8")
    (root / ".gitleaksignore").write_text("everything\n", encoding="utf-8")
    runner = _Runner(_payload())

    _scanner(runner).scan(root)

    argv, _ = runner.calls[0]
    config_path = Path(argv[argv.index("--config") + 1])
    ignore_path = Path(argv[argv.index("--gitleaks-ignore-path") + 1])
    report_path = Path(argv[argv.index("--report-path") + 1])
    # None of the paths the adapter controls may live inside the snapshot.
    assert not str(config_path).startswith(str(root))
    assert not str(ignore_path).startswith(str(root))
    assert not str(report_path).startswith(str(root))
    assert "useDefault = true" in (runner.config or "")
    # The ignore path exists (and is empty) while gitleaks runs.
    assert runner.ignore_path_is_dir is True


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        ("private-key", RiskLevel.HIGH),
        ("aws-access-token", RiskLevel.HIGH),
        ("github-pat", RiskLevel.HIGH),
        ("slack-bot-token", RiskLevel.HIGH),
        ("gcp-api-key", RiskLevel.HIGH),
        ("generic-api-key", RiskLevel.MEDIUM),
        ("netrc-credentials", RiskLevel.MEDIUM),
        ("unknown-vendor-rule", RiskLevel.MEDIUM),
    ],
)
def test_severity_mapping(tmp_path: Path, rule_id: str, expected: RiskLevel) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(_payload([_leak(RuleID=rule_id)]))).scan(root)

    assert report.findings[0].severity is expected


def test_missing_binary_raises_unavailable(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = _Runner(result=CommandResult(argv=(), returncode=None, stderr="executable not found"))

    with pytest.raises(GitleaksUnavailable, match="not found"):
        _scanner(runner).scan(root)


def test_timeout_returns_error(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = _Runner(result=CommandResult(argv=(), timed_out=True))

    report = _scanner(runner).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "timed out" in (report.error or "")


def test_nonzero_exit_returns_error(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = _Runner(result=CommandResult(argv=(), returncode=1, stderr="failed to load config"))

    report = _scanner(runner).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "status 1" in (report.error or "")
    assert "failed to load config" in (report.error or "")


def test_unknown_flag_exit_hints_at_the_required_release(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = _Runner(result=CommandResult(argv=(), returncode=126, stderr="unknown command"))

    report = _scanner(runner).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "dir" in (report.error or "")
    assert "126" in (report.error or "")


def test_missing_report_returns_error(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = _Runner(payload=None, result=CommandResult(argv=(), returncode=0))

    report = _scanner(runner).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "did not write a report" in (report.error or "")


def test_invalid_json_returns_error(tmp_path: Path) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner("{not json")).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "could not parse" in (report.error or "")


def test_report_larger_than_limit_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    monkeypatch.setattr(gitleaks_module, "MAX_REPORT_BYTES", 8)

    report = _scanner(_Runner(_payload([_leak()]))).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "too large" in (report.error or "")


def test_empty_report_is_a_clean_scan(tmp_path: Path) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner("[]")).scan(root)

    assert report.status is ScanStatus.SCANNED
    assert report.findings == []
    assert report.risk is RiskLevel.NONE
    assert report.truncated is False


def test_null_report_is_treated_as_empty(tmp_path: Path) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner("null")).scan(root)

    assert report.status is ScanStatus.SCANNED
    assert report.findings == []


def test_leaks_object_is_accepted_defensively(tmp_path: Path) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(json.dumps({"leaks": [_leak()]}))).scan(root)

    assert report.status is ScanStatus.SCANNED
    assert len(report.findings) == 1


def test_unexpected_report_shape_returns_error(tmp_path: Path) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(json.dumps({"results": []}))).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "shape" in (report.error or "")


def test_path_outside_root_is_ignored(tmp_path: Path) -> None:
    root = _root(tmp_path)
    leaks = [_leak(File="/etc/passwd"), _leak(File="../escape.py"), _leak(File="config.py")]

    report = _scanner(_Runner(_payload(leaks))).scan(root)

    assert [finding.path for finding in report.findings] == ["config.py"]


def test_docs_and_test_paths_are_suppressed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    for relative in ("tests/test_app.py", "docs/example.py", "README.md"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")
    leaks = [
        _leak(File="tests/test_app.py"),
        _leak(File="docs/example.py"),
        _leak(File="README.md"),
    ]

    report = _scanner(_Runner(_payload(leaks))).scan(root)

    assert report.risk is RiskLevel.NONE
    assert report.effective_findings == []
    assert len(report.suppressed_findings) == 3


def test_policy_suppress_globs_are_applied(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "src").mkdir()
    (root / "src" / "generated.py").write_text("x\n", encoding="utf-8")

    report = _scanner(_Runner(_payload([_leak(File="src/generated.py")]))).scan(
        root, suppress_globs=("src/generated.py",)
    )

    assert report.findings[0].suppressed is True
    assert "policy suppression" in (report.findings[0].suppression_reason or "")


@pytest.mark.parametrize("rule", ["aws-access-token", "gitleaks:aws-access-token"])
def test_disabled_rule_is_dropped(tmp_path: Path, rule: str) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(_payload([_leak()]))).scan(root, disabled_rules=frozenset({rule}))

    assert report.findings == []


@pytest.mark.parametrize("rule", ["aws-access-token", "gitleaks:aws-access-token"])
def test_severity_override_is_applied(tmp_path: Path, rule: str) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(_payload([_leak()]))).scan(
        root, severity_overrides={rule: RiskLevel.CRITICAL}
    )

    assert report.findings[0].severity is RiskLevel.CRITICAL


def test_max_findings_truncates(tmp_path: Path) -> None:
    root = _root(tmp_path)
    leaks = [_leak(StartLine=1), _leak(StartLine=2)]

    report = _scanner(_Runner(_payload(leaks))).scan(root, limits=ScanLimits(max_findings=1))

    assert len(report.findings) == 1
    assert report.truncated is True


def test_duplicate_leaks_are_collapsed(tmp_path: Path) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(_payload([_leak(), _leak()]))).scan(root)

    assert len(report.findings) == 1


def test_malformed_entries_are_ignored(tmp_path: Path) -> None:
    root = _root(tmp_path)
    entries = [None, {}, {"RuleID": 42}, {"RuleID": ""}, _leak()]

    report = _scanner(_Runner(_payload(entries))).scan(root)

    assert len(report.findings) == 1


def test_non_directory_root_returns_error_without_running(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    target.write_text("x", encoding="utf-8")
    runner = _Runner(_payload())

    report = _scanner(runner).scan(target)

    assert report.status is ScanStatus.ERROR
    assert "not exist" in (report.error or "")
    assert runner.calls == []


def test_missing_start_line_is_tolerated(tmp_path: Path) -> None:
    root = _root(tmp_path)
    leak = _leak()
    del leak["StartLine"]

    report = _scanner(_Runner(_payload([leak]))).scan(root)

    assert report.findings[0].line is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"binary": ""},
        {"binary": "   "},
        {"process_timeout": 5},
        {"process_timeout": 4000},
    ],
)
def test_options_reject_unsafe_values(kwargs: dict) -> None:
    with pytest.raises(GitleaksError):
        GitleaksOptions(**kwargs)
