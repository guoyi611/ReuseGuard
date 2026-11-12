"""Tests for the OSV adapter (no osv-scanner installation required).

The JSON shapes used here follow osv-scanner v2 documentation: a top-level
``results`` list, each entry carrying a ``source`` path and ``packages`` whose
vulnerabilities are grouped by alias under ``groups``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reuseguard.adapters import osv as osv_module
from reuseguard.adapters.osv import (
    OsvError,
    OsvOptions,
    OsvScanner,
    OsvUnavailable,
)
from reuseguard.adapters.process import CommandResult
from reuseguard.adapters.scanner import ScanLimits
from reuseguard.models import RiskLevel, ScanStatus

GHSA = "GHSA-c3h9-896r-86jm"


def _vuln(
    vuln_id: str = GHSA,
    *,
    summary: str = "Improper input validation in example package",
    severity: str | None = "HIGH",
    aliases: list[str] | None = None,
) -> dict:
    vulnerability: dict = {
        "id": vuln_id,
        "aliases": aliases or [],
        "summary": summary,
    }
    if severity is not None:
        vulnerability["database_specific"] = {"severity": severity}
    return vulnerability


def _package(
    name: str = "example",
    version: str = "1.3.1",
    ecosystem: str = "npm",
    *,
    vulnerabilities: list | None = None,
    groups: list | None = None,
) -> dict:
    vulnerabilities = vulnerabilities if vulnerabilities is not None else [_vuln()]
    entry: dict = {
        "package": {"name": name, "version": version, "ecosystem": ecosystem},
        "vulnerabilities": vulnerabilities,
    }
    if groups is None:
        groups = [{"ids": [item["id"] for item in vulnerabilities]}]
    entry["groups"] = groups
    return entry


def _result(
    path: str = "package-lock.json",
    packages: list | None = None,
    *,
    source_type: str = "lockfile",
) -> dict:
    return {
        "source": {"path": path, "type": source_type},
        "packages": packages if packages is not None else [_package()],
    }


def _payload(results: list | None = None) -> str:
    return json.dumps({"results": results or []})


class _Runner:
    """Fake runner that writes the JSON report the adapter asks for."""

    def __init__(self, payload: str | None = None, result: CommandResult | None = None) -> None:
        self.payload = payload
        self.result = result
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def __call__(self, argv, *, timeout: float) -> CommandResult:
        recorded = tuple(argv)
        self.calls.append((recorded, timeout))
        if self.payload is not None and "--output-file" in recorded:
            report = Path(recorded[recorded.index("--output-file") + 1])
            report.write_text(self.payload, encoding="utf-8")
        return self.result or CommandResult(argv=recorded, returncode=0)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "package-lock.json").write_text("{}\n", encoding="utf-8")
    return root


def _scanner(runner) -> OsvScanner:
    return OsvScanner(OsvOptions(process_timeout=30.0), runner=runner)


def test_scan_maps_a_vulnerable_package(tmp_path: Path) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(_payload([_result()]))).scan(root)

    assert report.status is ScanStatus.SCANNED
    assert report.scanner == "osv"
    assert report.risk is RiskLevel.HIGH
    assert report.files_scanned == 0
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.rule_id == f"osv:{GHSA}"
    assert finding.category == "dependency"
    assert finding.path == "package-lock.json"
    assert finding.line is None
    assert finding.severity is RiskLevel.HIGH
    assert finding.title == "Improper input validation in example package"
    assert "example@1.3.1" in (finding.evidence or "")
    assert f"https://osv.dev/vulnerability/{GHSA}" in (finding.evidence or "")
    assert finding.suppressed is False


def test_exit_code_one_is_findings_not_failure(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = _Runner(_payload([_result()]), result=CommandResult(argv=(), returncode=1))

    report = _scanner(runner).scan(root)

    assert report.status is ScanStatus.SCANNED
    assert len(report.findings) == 1


def test_clean_scan_with_packages_is_not_truncated(tmp_path: Path) -> None:
    root = _root(tmp_path)
    clean = _result(packages=[_package(vulnerabilities=[], groups=[])])

    report = _scanner(_Runner(_payload([clean]))).scan(root)

    assert report.status is ScanStatus.SCANNED
    assert report.findings == []
    assert report.truncated is False


def test_no_packages_found_marks_coverage_incomplete(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = _Runner(result=CommandResult(argv=(), returncode=128, stderr="no packages found"))

    report = _scanner(runner).scan(root)

    assert report.status is ScanStatus.SCANNED
    assert report.findings == []
    assert report.truncated is True


@pytest.mark.parametrize("returncode", [2, 126, 127, 129, 255])
def test_other_exit_codes_are_errors(tmp_path: Path, returncode: int) -> None:
    root = _root(tmp_path)
    runner = _Runner(result=CommandResult(argv=(), returncode=returncode, stderr="boom"))

    report = _scanner(runner).scan(root)

    assert report.status is ScanStatus.ERROR
    assert f"status {returncode}" in (report.error or "")
    assert "boom" in (report.error or "")


def test_aliases_are_grouped_into_one_finding(tmp_path: Path) -> None:
    root = _root(tmp_path)
    vulnerabilities = [
        _vuln(GHSA, aliases=["CVE-2021-3121"]),
        _vuln("GO-2021-0053", summary="", severity=None, aliases=[GHSA]),
    ]
    package = _package(vulnerabilities=vulnerabilities, groups=[{"ids": [GHSA, "GO-2021-0053"]}])

    report = _scanner(_Runner(_payload([_result(packages=[package])]))).scan(root)

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.rule_id == f"osv:{GHSA}"
    assert "Also tracked as GO-2021-0053" in finding.message


def test_multiple_packages_with_the_same_advisory_are_merged(tmp_path: Path) -> None:
    root = _root(tmp_path)
    packages = [_package("alpha"), _package("beta")]

    report = _scanner(_Runner(_payload([_result(packages=packages)]))).scan(root)

    assert len(report.findings) == 1
    message = report.findings[0].message
    assert "alpha@1.3.1" in message
    assert "beta@1.3.1" in message


def test_same_advisory_in_two_lockfiles_is_two_findings(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "sub").mkdir()
    (root / "sub" / "package-lock.json").write_text("{}\n", encoding="utf-8")

    report = _scanner(_Runner(_payload([_result(), _result("sub/package-lock.json")]))).scan(root)

    assert len(report.findings) == 2
    assert {finding.path for finding in report.findings} == {
        "package-lock.json",
        "sub/package-lock.json",
    }


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("CRITICAL", RiskLevel.CRITICAL),
        ("HIGH", RiskLevel.HIGH),
        ("MODERATE", RiskLevel.MEDIUM),
        ("MEDIUM", RiskLevel.MEDIUM),
        ("LOW", RiskLevel.LOW),
        ("UNKNOWN", RiskLevel.MEDIUM),
    ],
)
def test_severity_mapping(tmp_path: Path, label: str, expected: RiskLevel) -> None:
    root = _root(tmp_path)
    package = _package(vulnerabilities=[_vuln(severity=label)])

    report = _scanner(_Runner(_payload([_result(packages=[package])]))).scan(root)

    assert report.findings[0].severity is expected


def test_missing_severity_defaults_to_medium(tmp_path: Path) -> None:
    root = _root(tmp_path)
    package = _package(vulnerabilities=[_vuln(severity=None)])

    report = _scanner(_Runner(_payload([_result(packages=[package])]))).scan(root)

    assert report.findings[0].severity is RiskLevel.MEDIUM


def test_cvss_only_advisory_is_not_guessed_as_critical(tmp_path: Path) -> None:
    root = _root(tmp_path)
    vulnerability = _vuln(severity=None)
    vulnerability["severity"] = [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ]
    package = _package(vulnerabilities=[vulnerability])

    report = _scanner(_Runner(_payload([_result(packages=[package])]))).scan(root)

    assert report.findings[0].severity is RiskLevel.MEDIUM


def test_worst_severity_wins_within_a_group(tmp_path: Path) -> None:
    root = _root(tmp_path)
    vulnerabilities = [
        _vuln(GHSA, severity="MODERATE"),
        _vuln("GO-2021-0053", severity="CRITICAL"),
    ]
    package = _package(vulnerabilities=vulnerabilities, groups=[{"ids": [GHSA, "GO-2021-0053"]}])

    report = _scanner(_Runner(_payload([_result(packages=[package])]))).scan(root)

    assert report.findings[0].severity is RiskLevel.CRITICAL


def test_command_uses_v2_scan_source_and_a_private_report_file(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = _Runner(_payload())

    _scanner(runner).scan(root)

    argv, timeout = runner.calls[0]
    assert argv[0] == "osv-scanner"
    assert argv[1:3] == ("scan", "source")
    assert argv[argv.index("--recursive") + 1] == str(root.resolve())
    assert argv[argv.index("--format") + 1] == "json"
    report_path = Path(argv[argv.index("--output-file") + 1])
    assert not str(report_path).startswith(str(root))
    assert "--no-git" not in argv
    assert timeout == 30.0


def test_missing_binary_raises_unavailable(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = _Runner(result=CommandResult(argv=(), returncode=None, stderr="executable not found"))

    with pytest.raises(OsvUnavailable, match="not found"):
        _scanner(runner).scan(root)


def test_timeout_returns_error(tmp_path: Path) -> None:
    root = _root(tmp_path)
    runner = _Runner(result=CommandResult(argv=(), timed_out=True))

    report = _scanner(runner).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "timed out" in (report.error or "")


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
    monkeypatch.setattr(osv_module, "MAX_REPORT_BYTES", 8)

    report = _scanner(_Runner(_payload([_result()]))).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "too large" in (report.error or "")


@pytest.mark.parametrize("payload", ["{}", "[]", '"text"'])
def test_unexpected_report_shape_returns_error(tmp_path: Path, payload: str) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(payload)).scan(root)

    assert report.status is ScanStatus.ERROR
    assert "shape" in (report.error or "")


def test_null_results_is_treated_as_empty(tmp_path: Path) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner('{"results": null}')).scan(root)

    assert report.status is ScanStatus.SCANNED
    assert report.findings == []


def test_path_outside_root_is_ignored(tmp_path: Path) -> None:
    root = _root(tmp_path)
    results = [_result("/etc/package-lock.json"), _result("../escape/package-lock.json")]

    report = _scanner(_Runner(_payload(results))).scan(root)

    assert report.findings == []


def test_lockfile_under_tests_is_suppressed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "tests").mkdir()
    (root / "tests" / "package-lock.json").write_text("{}\n", encoding="utf-8")

    report = _scanner(_Runner(_payload([_result("tests/package-lock.json")]))).scan(root)

    assert report.risk is RiskLevel.NONE
    assert report.effective_findings == []
    assert len(report.suppressed_findings) == 1


def test_policy_suppress_globs_are_applied(tmp_path: Path) -> None:
    root = _root(tmp_path)

    report = _scanner(_Runner(_payload([_result()]))).scan(
        root, suppress_globs=("package-lock.json",)
    )

    assert report.findings[0].suppressed is True
    assert "policy suppression" in (report.findings[0].suppression_reason or "")


@pytest.mark.parametrize("rule", [GHSA, f"osv:{GHSA}", "GO-2021-0053"])
def test_disabled_rule_is_dropped(tmp_path: Path, rule: str) -> None:
    root = _root(tmp_path)
    vulnerabilities = [_vuln(GHSA), _vuln("GO-2021-0053", summary="", severity=None)]
    package = _package(vulnerabilities=vulnerabilities, groups=[{"ids": [GHSA, "GO-2021-0053"]}])

    report = _scanner(_Runner(_payload([_result(packages=[package])]))).scan(
        root, disabled_rules=frozenset({rule})
    )

    assert report.findings == []


@pytest.mark.parametrize("rule", [GHSA, f"osv:{GHSA}", "GO-2021-0053"])
def test_severity_override_is_applied(tmp_path: Path, rule: str) -> None:
    root = _root(tmp_path)
    vulnerabilities = [_vuln(GHSA), _vuln("GO-2021-0053", summary="", severity=None)]
    package = _package(vulnerabilities=vulnerabilities, groups=[{"ids": [GHSA, "GO-2021-0053"]}])

    report = _scanner(_Runner(_payload([_result(packages=[package])]))).scan(
        root, severity_overrides={rule: RiskLevel.LOW}
    )

    assert report.findings[0].severity is RiskLevel.LOW


def test_max_findings_truncates(tmp_path: Path) -> None:
    root = _root(tmp_path)
    first = _result(packages=[_package(vulnerabilities=[_vuln(GHSA)])])
    second = _result(
        packages=[_package(vulnerabilities=[_vuln("GHSA-other-0000-0000")])],
        path="sub/package-lock.json",
    )
    (root / "sub").mkdir()
    (root / "sub" / "package-lock.json").write_text("{}\n", encoding="utf-8")

    report = _scanner(_Runner(_payload([first, second]))).scan(
        root, limits=ScanLimits(max_findings=1)
    )

    assert len(report.findings) == 1
    assert report.truncated is True


def test_entries_without_groups_fall_back_to_vulnerabilities(tmp_path: Path) -> None:
    root = _root(tmp_path)
    package = _package()
    del package["groups"]

    report = _scanner(_Runner(_payload([_result(packages=[package])]))).scan(root)

    assert len(report.findings) == 1


def test_malformed_entries_are_ignored(tmp_path: Path) -> None:
    root = _root(tmp_path)
    results = [
        None,
        {},
        {"source": {"path": "package-lock.json"}, "packages": "nope"},
        {"source": {"path": "package-lock.json"}, "packages": [None, {"package": {}}]},
        _result(),
    ]

    report = _scanner(_Runner(_payload(results))).scan(root)

    assert len(report.findings) == 1


def test_non_directory_root_returns_error_without_running(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    target.write_text("x", encoding="utf-8")
    runner = _Runner(_payload())

    report = _scanner(runner).scan(target)

    assert report.status is ScanStatus.ERROR
    assert "not exist" in (report.error or "")
    assert runner.calls == []


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
    with pytest.raises(OsvError):
        OsvOptions(**kwargs)


def test_default_argv_enables_no_resolve(tmp_path: Path) -> None:
    """By default osv-scanner must not reach out to a package registry."""
    root = _root(tmp_path)
    runner = _Runner(_payload())

    _scanner(runner).scan(root)

    argv = runner.calls[0][0]
    assert "--no-resolve" in argv
    assert "--offline" not in argv
    assert "--local-db" not in argv


def test_resolve_opt_out_removes_no_resolve_flag(tmp_path: Path) -> None:
    """Users can opt back into transitive resolution explicitly."""
    root = _root(tmp_path)
    runner = _Runner(_payload())
    scanner = OsvScanner(
        OsvOptions(process_timeout=30.0, no_resolve=False),
        runner=runner,
    )

    scanner.scan(root)

    argv = runner.calls[0][0]
    assert "--no-resolve" not in argv


def test_offline_db_injects_offline_and_local_db_flags(tmp_path: Path) -> None:
    """Offline mode passes both --offline and --local-db <path>."""
    root = _root(tmp_path)
    db = tmp_path / "osv-db"
    db.mkdir()
    runner = _Runner(_payload())
    scanner = OsvScanner(
        OsvOptions(process_timeout=30.0, offline_db=db),
        runner=runner,
    )

    scanner.scan(root)

    argv = runner.calls[0][0]
    assert "--offline" in argv
    idx = argv.index("--local-db")
    assert argv[idx + 1] == str(db)
    # offline implies no-resolve; the adapter should still emit the flag so the
    # command line is self-describing even if osv-scanner's defaults change.
    assert "--no-resolve" in argv


def test_options_reject_offline_with_resolve_enabled() -> None:
    """Offline matching has no registry to resolve against; refuse the combo."""
    with pytest.raises(OsvError, match="offline"):
        OsvOptions(process_timeout=30.0, no_resolve=False, offline_db=Path("/tmp/db"))


def _package_entry(
    name: str = "example",
    version: str = "1.3.1",
    ecosystem: str = "npm",
    *,
    dev: bool | None = None,
    optional: bool | None = None,
) -> dict:
    pkg: dict = {"name": name, "version": version, "ecosystem": ecosystem}
    if dev is not None:
        pkg["dev"] = dev
    if optional is not None:
        pkg["optional"] = optional
    return {
        "package": pkg,
        "vulnerabilities": [_vuln()],
        "groups": [{"ids": [GHSA]}],
    }


def test_npm_dev_dependency_is_tagged_development(tmp_path: Path) -> None:
    root = _root(tmp_path)
    results = [_result(packages=[_package_entry(dev=True)])]
    report = _scanner(_Runner(_payload(results))).scan(root)

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.scope == "development"
    assert "Development-only dependency" in finding.message


def test_npm_production_dependency_is_tagged_production(tmp_path: Path) -> None:
    root = _root(tmp_path)
    results = [_result(packages=[_package_entry(dev=False)])]
    report = _scanner(_Runner(_payload(results))).scan(root)

    assert report.findings[0].scope == "production"
    assert "Production dependency" in report.findings[0].message


def test_npm_optional_dependency_counts_as_development(tmp_path: Path) -> None:
    root = _root(tmp_path)
    results = [_result(packages=[_package_entry(optional=True)])]
    report = _scanner(_Runner(_payload(results))).scan(root)

    assert report.findings[0].scope == "development"


def test_mixed_prod_and_dev_packages_mark_advisory_as_production(tmp_path: Path) -> None:
    """If any affected package is prod, the advisory stays production-scoped."""
    root = _root(tmp_path)
    packages = [_package_entry(name="prod-pkg", dev=False), _package_entry(name="dev-pkg", dev=True)]
    results = [_result(packages=packages)]
    report = _scanner(_Runner(_payload(results))).scan(root)

    # Both packages share one advisory (same GHSA + lockfile); aggregated scope wins.
    assert len(report.findings) == 1
    assert report.findings[0].scope == "production"


def test_pip_dev_requirements_file_is_tagged_development(tmp_path: Path) -> None:
    root = tmp_path / "pip-tree"
    root.mkdir()
    (root / "requirements-dev.txt").write_text("example==1.0\n", encoding="utf-8")
    results = [
        _result(
            path="requirements-dev.txt",
            packages=[_package_entry(ecosystem="PyPI")],
        )
    ]
    report = _scanner(_Runner(_payload(results))).scan(root)

    assert report.findings[0].scope == "development"


def test_unknown_ecosystem_scope_is_none(tmp_path: Path) -> None:
    """Without a known signal we must not guess."""
    root = tmp_path / "cargo-tree"
    root.mkdir()
    (root / "Cargo.lock").write_text("", encoding="utf-8")
    results = [
        _result(path="Cargo.lock", packages=[_package_entry(ecosystem="crates.io")])
    ]
    report = _scanner(_Runner(_payload(results))).scan(root)

    assert report.findings[0].scope is None


def _vuln_with_cvss(
    score: float | None = 7.5,
    vector: str | None = None,
    source: str | None = "NVD",
    severity_label: str | None = "MODERATE",
) -> dict:
    vuln = _vuln(severity=severity_label)
    cvss: dict = {}
    if score is not None:
        cvss["score"] = score
    if vector is not None:
        cvss["vectorString"] = vector
    if source is not None:
        cvss["type"] = source
    vuln["database_specific"] = {**(vuln.get("database_specific") or {}), "cvss": cvss}
    return vuln


def test_cvss_score_is_shown_alongside_advisory_severity(tmp_path: Path) -> None:
    root = _root(tmp_path)
    results = [_result(packages=[_package(vulnerabilities=[_vuln_with_cvss()])])]
    report = _scanner(_Runner(_payload(results))).scan(root)

    finding = report.findings[0]
    # Severity still comes from the advisory label, not the CVSS score.
    assert finding.severity is RiskLevel.MEDIUM
    assert "CVSS 7.5 (NVD)" in (finding.evidence or "")
    assert "Advisory severity MODERATE; CVSS 7.5 (NVD)" in finding.message


def test_cvss_vector_only_is_rendered_when_score_missing(tmp_path: Path) -> None:
    root = _root(tmp_path)
    vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    results = [_result(packages=[_package(vulnerabilities=[_vuln_with_cvss(score=None, vector=vector)])])]
    report = _scanner(_Runner(_payload(results))).scan(root)

    finding = report.findings[0]
    assert f"CVSS vector: {vector}" in (finding.evidence or "")


def test_no_cvss_data_leaves_evidence_unchanged(tmp_path: Path) -> None:
    root = _root(tmp_path)
    results = [_result(packages=[_package(vulnerabilities=[_vuln(severity="HIGH")])])]
    report = _scanner(_Runner(_payload(results))).scan(root)

    finding = report.findings[0]
    assert "CVSS" not in (finding.evidence or "")
    assert "CVSS" not in finding.message
