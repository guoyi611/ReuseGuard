"""Tests for the Semgrep adapter (no Semgrep installation required)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reuseguard.adapters.process import CommandResult
from reuseguard.adapters.scanner import ScanLimits
from reuseguard.adapters.semgrep import (
    SemgrepError,
    SemgrepOptions,
    SemgrepScanner,
    SemgrepUnavailable,
)
from reuseguard.models import RiskLevel, ScanStatus
from tests.fakes import FakeCommandRunner


def _result(
    *,
    check_id: str = "python.lang.security.audit.eval",
    path: str = "app.py",
    line: int = 5,
    severity: str = "ERROR",
    message: str = "Detected eval",
    lines: str = "eval(user_input)",
    metadata: dict | None = None,
) -> dict:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 20},
        "extra": {
            "message": message,
            "severity": severity,
            "lines": lines,
            "metadata": metadata or {"category": "security"},
        },
    }


def _payload(
    results: list | None = None,
    *,
    errors: list | None = None,
    scanned: list | None = None,
    skipped: list | None = None,
) -> str:
    return json.dumps(
        {
            "version": "1.90.0",
            "results": results or [],
            "errors": errors or [],
            "paths": {"scanned": scanned or [], "skipped": skipped or []},
        }
    )


def _scanner(tmp_path: Path, runner: FakeCommandRunner) -> SemgrepScanner:
    config = tmp_path / "rules.yaml"
    config.write_text("rules:\n  - id: test\n", encoding="utf-8")
    options = SemgrepOptions(config=config, process_timeout=30.0)
    return SemgrepScanner(options, runner=runner)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    return root


def test_scan_maps_semgrep_results(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=_payload(
                    [_result(path=str(root / "app.py"))],
                    scanned=[str(root / "app.py")],
                ),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(root, limits=ScanLimits())

    assert report.status is ScanStatus.SCANNED
    assert report.scanner == "semgrep"
    assert report.risk is RiskLevel.HIGH
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.rule_id == "python.lang.security.audit.eval"
    assert finding.path == "app.py"
    assert finding.line == 5
    assert finding.severity is RiskLevel.HIGH
    assert finding.evidence == "eval(user_input)"
    assert report.files_scanned == 1
    assert report.bytes_scanned > 0
    assert report.truncated is False


@pytest.mark.parametrize(
    ("severity", "metadata", "expected"),
    [
        ("ERROR", {"category": "security"}, RiskLevel.HIGH),
        ("WARNING", {"category": "security"}, RiskLevel.MEDIUM),
        ("INFO", {"category": "security"}, RiskLevel.LOW),
        ("WARNING", {"category": "security", "severity": "critical"}, RiskLevel.CRITICAL),
        ("UNKNOWN", {"category": "security"}, RiskLevel.LOW),
    ],
)
def test_severity_mapping(
    tmp_path: Path, severity: str, metadata: dict, expected: RiskLevel
) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=_payload(
                    [_result(severity=severity, metadata=metadata)],
                    scanned=["app.py"],
                ),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(root)

    assert report.findings[0].severity is expected


def test_command_uses_only_local_rules_and_hardened_flags(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner([CommandResult(argv=(), returncode=0, stdout=_payload())])

    _scanner(tmp_path, runner).scan(root, limits=ScanLimits(max_file_bytes=1234))

    argv, timeout = runner.calls[0]
    assert argv[0] == "semgrep"
    assert argv[1] == "scan"
    assert "--json" in argv
    assert "--quiet" in argv
    assert "--metrics=off" in argv
    assert "--disable-version-check" in argv
    assert "--no-git-ignore" in argv
    assert "--config" in argv
    assert str(tmp_path / "rules.yaml") in argv
    assert "auto" not in argv
    assert "--jobs" in argv
    assert "1" in argv
    assert str(root) == argv[-1]
    assert timeout == 30.0


def test_missing_binary_raises_unavailable(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [CommandResult(argv=(), returncode=None, stderr="executable not found")]
    )

    with pytest.raises(SemgrepUnavailable, match="not found"):
        _scanner(tmp_path, runner).scan(root)


def test_timeout_returns_error(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner([CommandResult(argv=(), timed_out=True)])

    report = _scanner(tmp_path, runner).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "timed out" in (report.error or "")


def test_nonzero_exit_returns_error(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner([CommandResult(argv=(), returncode=2, stderr="invalid config")])

    report = _scanner(tmp_path, runner).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "status 2" in (report.error or "")
    assert "invalid config" in (report.error or "")


def test_invalid_json_returns_error(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner([CommandResult(argv=(), returncode=0, stdout="{not json")])

    report = _scanner(tmp_path, runner).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "could not parse" in (report.error or "")


def test_json_with_leading_logs_is_parsed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout="some warning\n" + _payload([_result()], scanned=["app.py"]),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(root)

    assert report.status is ScanStatus.SCANNED
    assert len(report.findings) == 1


def test_missing_results_list_returns_error(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [CommandResult(argv=(), returncode=0, stdout=json.dumps({"errors": []}))]
    )

    report = _scanner(tmp_path, runner).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "results" in (report.error or "")


def test_missing_config_returns_error_without_running(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner()
    options = SemgrepOptions(config=tmp_path / "missing.yaml")
    scanner = SemgrepScanner(options, runner=runner)

    report = scanner.scan(root)

    assert report.status is ScanStatus.ERROR
    assert "config path does not exist" in (report.error or "")
    assert runner.calls == []


def test_non_directory_root_returns_error(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    target.write_text("x", encoding="utf-8")

    report = _scanner(tmp_path, FakeCommandRunner()).scan(target)

    assert report.status is ScanStatus.ERROR
    assert "not exist" in (report.error or "")


def test_docs_and_test_paths_are_suppressed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    for relative in ("tests/test_app.py", "docs/example.py", "README.md"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("eval(x)\n", encoding="utf-8")
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=_payload(
                    [
                        _result(path="tests/test_app.py"),
                        _result(path="docs/example.py"),
                        _result(path="README.md"),
                    ],
                    scanned=["tests/test_app.py", "docs/example.py", "README.md"],
                ),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(root)

    assert report.risk is RiskLevel.NONE
    assert len(report.effective_findings) == 0
    assert len(report.suppressed_findings) == 3
    assert all(finding.suppression_reason for finding in report.suppressed_findings)


def test_policy_suppress_globs_are_applied(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "src").mkdir()
    (root / "src" / "generated.py").write_text("eval(x)\n", encoding="utf-8")
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=_payload([_result(path="src/generated.py")], scanned=["app.py"]),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(root, suppress_globs=("src/generated.py",))

    assert report.risk is RiskLevel.NONE
    assert report.findings[0].suppressed is True
    assert "policy suppression" in (report.findings[0].suppression_reason or "")


def test_path_outside_root_is_ignored(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=_payload(
                    [_result(path="/etc/passwd"), _result(path="../escape.py")],
                    scanned=["app.py"],
                ),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(root)

    assert report.findings == []


def test_errors_mark_coverage_incomplete(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=_payload(
                    [_result()],
                    errors=[{"type": "Timeout", "message": "file timed out"}],
                    scanned=["app.py"],
                ),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(root)

    assert report.truncated is True


def test_skipped_paths_mark_coverage_incomplete(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=_payload(
                    [_result()],
                    scanned=["app.py"],
                    skipped=["huge.py"],
                ),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(root)

    assert report.truncated is True
    assert report.files_skipped == 1


def test_max_findings_truncates(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=_payload(
                    [_result(line=1), _result(line=2)],
                    scanned=["app.py"],
                ),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(root, limits=ScanLimits(max_findings=1))

    assert len(report.findings) == 1
    assert report.truncated is True


def test_disabled_rule_is_dropped(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=_payload([_result()], scanned=["app.py"]),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(
        root, disabled_rules=frozenset({"python.lang.security.audit.eval"})
    )

    assert report.findings == []


def test_duplicate_findings_are_collapsed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=_payload([_result(), _result()], scanned=["app.py"]),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(root)

    assert len(report.findings) == 1


def test_malformed_result_entries_are_ignored(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=0,
                stdout=_payload(
                    [None, {}, {"check_id": 42}, _result(path="app.py")],
                    scanned=["app.py"],
                ),
            )
        ]
    )

    report = _scanner(tmp_path, runner).scan(root)

    assert len(report.findings) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"binary": ""},
        {"rule_timeout": 0.5},
        {"rule_timeout": 500},
        {"process_timeout": 5},
        {"process_timeout": 4000},
        {"max_memory_mb": 64},
        {"max_memory_mb": 9000},
    ],
)
def test_options_reject_unsafe_values(tmp_path: Path, kwargs: dict) -> None:
    with pytest.raises(SemgrepError):
        SemgrepOptions(config=tmp_path / "rules.yaml", **kwargs)
