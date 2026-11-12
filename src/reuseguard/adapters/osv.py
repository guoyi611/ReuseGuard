"""OSV adapter: turn an osv-scanner JSON report into ReuseGuard findings.

osv-scanner extracts packages from lockfiles and matches them against the OSV
database (``api.osv.dev``). It reads files only; it never executes the
repository. This adapter targets the v2 command line (``scan source``); a v1
binary fails with a clear scan error instead of being silently skipped.

Three details drive the implementation:

* Exit status 1 means "vulnerabilities were found", not "the scan failed".
  Statuses 0 and 1 are successful scans, 128 means no package source was found,
  and anything else is an error.
* One advisory can appear under several IDs (GHSA / CVE / GHSA / GO / RUSTSEC).
  osv-scanner groups those aliases under ``groups``; the group is reported as one
  finding instead of one finding per alias.
* The advisory's own severity label is used when present. CVSS vectors are not
  re-scored locally, so an advisory that only carries a vector is recorded as
  medium rather than guessed at.

A repository without a lockfile produces no findings and is marked as incomplete
coverage. That is deliberate: "no lockfile" must never read as "no vulnerable
dependencies".
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding, RiskLevel, ScanReport, ScanStatus
from .process import CommandRunner, run_command
from .scanner import ScanLimits, relative_to_root, suppression_reason

DEFAULT_OSV_BINARY = "osv-scanner"
DEFAULT_PROCESS_TIMEOUT = 300.0
MAX_REPORT_BYTES = 16 * 1024 * 1024

_EXIT_CLEAN = 0
_EXIT_FINDINGS = 1
_EXIT_NO_PACKAGES = 128
_RULE_PREFIX = "osv:"
_MAX_ERROR_TAIL = 1500
_MAX_DESCRIPTION = 160
_MAX_MESSAGE = 400
_MAX_EVIDENCE = 200
_MAX_AFFECTED = 5

_SEVERITY_MAP = {
    "CRITICAL": RiskLevel.CRITICAL,
    "HIGH": RiskLevel.HIGH,
    "MODERATE": RiskLevel.MEDIUM,
    "MEDIUM": RiskLevel.MEDIUM,
    "LOW": RiskLevel.LOW,
}


class OsvError(Exception):
    """osv-scanner failed to run, returned invalid output, or was misconfigured."""


class OsvUnavailable(OsvError):
    """The osv-scanner executable is not installed or not on PATH."""


@dataclass(frozen=True)
class OsvOptions:
    """How to invoke osv-scanner for one repository snapshot.

    ``no_resolve`` defaults to True so osv-scanner only trusts what the lockfile
    already records; without it, incomplete manifests trigger registry lookups
    that widen the network boundary silently. ``offline_db`` opts into fully
    offline matching against a pre-downloaded OSV database; when set, the
    adapter passes both ``--offline`` and ``--local-db`` and refuses to also
    enable transitive resolution (there is no registry to resolve against).
    """

    binary: str = DEFAULT_OSV_BINARY
    process_timeout: float = DEFAULT_PROCESS_TIMEOUT
    no_resolve: bool = True
    offline_db: Path | None = None

    def __post_init__(self) -> None:
        if not self.binary.strip():
            raise OsvError("osv-scanner binary must not be empty")
        if not 10.0 <= self.process_timeout <= 3600.0:
            raise OsvError("osv-scanner process timeout must be between 10 and 3600 seconds")
        if self.offline_db is not None and not self.no_resolve:
            raise OsvError(
                "--osv-offline cannot be combined with transitive resolution; "
                "there is no registry to resolve against in offline mode"
            )


@dataclass
class _Advisory:
    """One advisory as it applies to a lockfile, aggregated across packages."""

    ids: tuple[str, ...]
    lockfile: str
    summary: str = ""
    severity: RiskLevel = RiskLevel.NONE
    ecosystem: str = ""
    packages: list[str] | None = None
    scope: str | None = None

    def __post_init__(self) -> None:
        if self.packages is None:
            self.packages = []


class OsvScanner:
    """Run osv-scanner once over a snapshot and normalize its report."""

    def __init__(
        self,
        options: OsvOptions,
        *,
        runner: CommandRunner = run_command,
    ) -> None:
        self.options = options
        self._runner = runner

    def scan(
        self,
        root: Path,
        *,
        limits: ScanLimits | None = None,
        disabled_rules: frozenset[str] = frozenset(),
        severity_overrides: dict[str, RiskLevel] | None = None,
        suppress_globs: tuple[str, ...] = (),
    ) -> ScanReport:
        limits = limits or ScanLimits()
        overrides = severity_overrides or {}

        if not root.is_dir():
            return ScanReport(
                status=ScanStatus.ERROR,
                scanner="osv",
                error=f"snapshot directory does not exist: {root}",
            )
        root_resolved = root.resolve()

        with tempfile.TemporaryDirectory(prefix="reuseguard-osv-") as directory:
            report_path = Path(directory) / "osv.json"
            argv = self._build_argv(root_resolved, report_path)
            result = self._runner(argv, timeout=self.options.process_timeout)

            if result.timed_out:
                return ScanReport(
                    status=ScanStatus.ERROR,
                    scanner="osv",
                    error=f"osv-scanner timed out after {self.options.process_timeout:g}s",
                )
            if result.returncode is None:
                raise OsvUnavailable(result.stderr.strip() or "osv-scanner executable not found")
            if result.returncode == _EXIT_NO_PACKAGES:
                # Nothing to check is not the same as nothing to worry about.
                return ScanReport(
                    status=ScanStatus.SCANNED,
                    scanner="osv",
                    files_scanned=0,
                    truncated=True,
                )
            if result.returncode not in {_EXIT_CLEAN, _EXIT_FINDINGS}:
                return _command_error(result.returncode, result.stderr, result.stdout)

            payload, read_error = _read_report(report_path)
            if read_error is not None:
                return ScanReport(status=ScanStatus.ERROR, scanner="osv", error=read_error)

        results = _results(payload)
        if results is None:
            return ScanReport(
                status=ScanStatus.ERROR,
                scanner="osv",
                error="unexpected osv-scanner report shape: expected a 'results' list",
            )

        advisories = _collect_advisories(results, root=root_resolved)
        findings: list[Finding] = []
        truncated = False

        for advisory in advisories.values():
            finding = _to_finding(
                advisory,
                disabled_rules=disabled_rules,
                overrides=overrides,
                suppress_globs=suppress_globs,
            )
            if finding is None:
                continue
            if len(findings) >= limits.max_findings:
                truncated = True
                break
            findings.append(finding)

        risk = RiskLevel.NONE
        for finding in findings:
            if not finding.suppressed and finding.severity.rank > risk.rank:
                risk = finding.severity

        # osv-scanner does not report how many files it read; the merged report
        # keeps the file count of the scanner that does (see merge_scan_reports).
        return ScanReport(
            status=ScanStatus.SCANNED,
            risk=risk,
            findings=findings,
            files_scanned=0,
            bytes_scanned=0,
            truncated=truncated,
            scanner="osv",
        )

    def _build_argv(self, root: Path, report_path: Path) -> list[str]:
        argv = [
            self.options.binary,
            "scan",
            "source",
            "--recursive",
            str(root),
            "--format",
            "json",
            "--output-file",
            str(report_path),
        ]
        if self.options.no_resolve:
            argv.append("--no-resolve")
        if self.options.offline_db is not None:
            argv.extend(["--offline", "--local-db", str(self.options.offline_db)])
        return argv


def _collect_advisories(
    results: list, *, root: Path
) -> dict[tuple[str, frozenset[str]], _Advisory]:
    """Group aliases and packages so one advisory yields one finding per lockfile."""
    advisories: dict[tuple[str, frozenset[str]], _Advisory] = {}

    for result in results:
        if not isinstance(result, dict):
            continue
        source = result.get("source")
        source = source if isinstance(source, dict) else {}
        lockfile = relative_to_root(source.get("path"), root)
        if lockfile is None:
            continue

        packages = result.get("packages")
        if not isinstance(packages, list):
            continue
        for entry in packages:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package")
            package = package if isinstance(package, dict) else {}
            name = package.get("name")
            name = name.strip()[:120] if isinstance(name, str) and name.strip() else ""
            version = package.get("version")
            version = version.strip()[:80] if isinstance(version, str) else ""
            ecosystem = package.get("ecosystem")
            ecosystem = ecosystem.strip()[:40] if isinstance(ecosystem, str) else ""
            if not name:
                continue
            label = f"{name}@{version}" if version else name

            scope = _classify_scope(package, lockfile)
            entries = _package_advisories(entry)
            for ids, vulnerabilities in entries:
                key = (lockfile, frozenset(ids))
                advisory = advisories.get(key)
                if advisory is None:
                    advisory = _Advisory(ids=tuple(ids), lockfile=lockfile)
                    advisories[key] = advisory
                if label not in advisory.packages:
                    advisory.packages.append(label)
                if not advisory.ecosystem and ecosystem:
                    advisory.ecosystem = ecosystem
                if not advisory.summary:
                    advisory.summary = _summary(vulnerabilities)
                for vulnerability in vulnerabilities:
                    severity = _severity(vulnerability)
                    if severity.rank > advisory.severity.rank:
                        advisory.severity = severity
                # Scope aggregation: any production package makes the advisory
                # production-scoped; unknown scopes leave the advisory untagged
                # rather than guessed. Pure-development advisories are tagged
                # so reports can surface them separately without hiding them.
                if scope == "production":
                    advisory.scope = "production"
                elif scope == "development" and advisory.scope is None:
                    advisory.scope = "development"

    for advisory in advisories.values():
        if advisory.severity is RiskLevel.NONE:
            advisory.severity = RiskLevel.MEDIUM
    return advisories


def _classify_scope(package: dict, lockfile: str) -> str | None:
    """Best-effort classifier for dependency scope.

    Returns ``"development"`` or ``"production"`` only when the lockfile format
    gives us an explicit signal (npm's ``dev``/``optional`` flags, pip's
    ``-dev``/``-test`` requirements filename). Unknown ecosystems return
    ``None`` so we do not guess and accidentally downgrade a real production
    dependency.
    """
    if not isinstance(package, dict):
        return None
    name_lower = lockfile.lower()
    # npm package-lock.json: packages[].dev or packages[].optional mark non-prod
    if name_lower.endswith("package-lock.json"):
        if package.get("dev") is True or package.get("optional") is True:
            return "development"
        return "production"
    # pip requirements files: conventional naming distinguishes dev/test deps
    if name_lower.endswith((".txt", ".in")):
        base = name_lower.rsplit("/", 1)[-1]
        if any(token in base for token in ("-dev", "-test", "-tests", "dev-", "test-")):
            return "development"
        return "production"
    return None


def _package_advisories(entry: dict) -> list[tuple[list[str], list[dict]]]:
    """Return ``(ids, vulnerabilities)`` pairs, using osv-scanner's groups when present."""
    vulnerabilities = entry.get("vulnerabilities")
    vulnerabilities = vulnerabilities if isinstance(vulnerabilities, list) else []
    by_id = {}
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        vuln_id = vulnerability.get("id")
        if isinstance(vuln_id, str) and vuln_id.strip():
            by_id[vuln_id.strip()] = vulnerability

    groups = entry.get("groups")
    units: list[list[str]] = []
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, dict):
                continue
            ids = group.get("ids")
            if not isinstance(ids, list):
                continue
            clean = [item.strip() for item in ids if isinstance(item, str) and item.strip()]
            if clean:
                units.append(clean)
    if not units:
        units = [[vuln_id] for vuln_id in by_id]

    return [(ids, [by_id[vuln_id] for vuln_id in ids if vuln_id in by_id]) for ids in units]


def _to_finding(
    advisory: _Advisory,
    *,
    disabled_rules: frozenset[str],
    overrides: dict[str, RiskLevel],
    suppress_globs: tuple[str, ...],
) -> Finding | None:
    primary = advisory.ids[0]
    rule_id = f"{_RULE_PREFIX}{primary}"
    if primary in disabled_rules or rule_id in disabled_rules:
        return None
    if any(
        alias in disabled_rules or f"{_RULE_PREFIX}{alias}" in disabled_rules
        for alias in advisory.ids[1:]
    ):
        return None

    severity = overrides.get(rule_id)
    if severity is None:
        for alias in advisory.ids:
            if alias in overrides:
                severity = overrides[alias]
                break
            if f"{_RULE_PREFIX}{alias}" in overrides:
                severity = overrides[f"{_RULE_PREFIX}{alias}"]
                break
    if severity is None:
        severity = advisory.severity

    packages = advisory.packages or []
    shown = ", ".join(packages[:_MAX_AFFECTED])
    if len(packages) > _MAX_AFFECTED:
        shown += f", and {len(packages) - _MAX_AFFECTED} more"

    aliases = [alias for alias in advisory.ids[1:] if alias]
    detail = f"Affects {shown}."
    if aliases:
        detail += f" Also tracked as {', '.join(aliases[:3])}."
    summary = advisory.summary or "Known vulnerable dependency"
    message = f"{summary} {detail}"[:_MAX_MESSAGE]

    ecosystem = f" ({advisory.ecosystem})" if advisory.ecosystem else ""
    evidence = (f"{'; '.join(packages[:3])}{ecosystem} · https://osv.dev/vulnerability/{primary}")[
        :_MAX_EVIDENCE
    ]

    reason = suppression_reason(advisory.lockfile, suppress_globs)
    scope = advisory.scope
    if scope == "development":
        message = f"Development-only dependency. {message}"[:_MAX_MESSAGE]
    elif scope == "production":
        message = f"Production dependency. {message}"[:_MAX_MESSAGE]
    return Finding(
        rule_id=rule_id,
        title=summary[:_MAX_DESCRIPTION],
        severity=severity,
        category="dependency",
        path=advisory.lockfile,
        line=None,
        message=message,
        evidence=evidence,
        suppressed=reason is not None,
        suppression_reason=reason,
        scope=scope,
    )


def _summary(vulnerabilities: list[dict]) -> str:
    for vulnerability in vulnerabilities:
        summary = vulnerability.get("summary")
        if isinstance(summary, str) and summary.strip():
            return " ".join(summary.split())
    return ""


def _severity(vulnerability: dict) -> RiskLevel:
    for key in ("database_specific", "ecosystem_specific"):
        specific = vulnerability.get(key)
        if not isinstance(specific, dict):
            continue
        value = specific.get("severity")
        if isinstance(value, str):
            mapped = _SEVERITY_MAP.get(value.strip().upper())
            if mapped is not None:
                return mapped
    # A CVSS vector is not re-scored locally: too easy to get wrong, and a wrong
    # "critical" would be worse than an honest "medium".
    return RiskLevel.MEDIUM


def _results(payload: object) -> list | None:
    if payload is None:
        return []
    if not isinstance(payload, dict):
        return None
    results = payload.get("results")
    if results is None and "results" in payload:
        return []
    if isinstance(results, list):
        return results
    return None


def _read_report(path: Path) -> tuple[object, str | None]:
    """Read and parse the JSON report, with bounds on what is accepted."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"osv-scanner did not write a report: {exc}"
    if size > MAX_REPORT_BYTES:
        return None, f"osv-scanner report is too large to parse ({size} bytes)"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"could not read the osv-scanner report: {exc}"
    try:
        return json.loads(text), None
    except json.JSONDecodeError as exc:
        return None, f"could not parse osv-scanner JSON report: {exc}"


def _command_error(returncode: int, stderr: str, stdout: str) -> ScanReport:
    detail = _tail(stderr) or _tail(stdout) or "no output"
    return ScanReport(
        status=ScanStatus.ERROR,
        scanner="osv",
        error=f"osv-scanner exited with status {returncode}: {detail}",
    )


def _tail(value: str, limit: int = _MAX_ERROR_TAIL) -> str:
    text = (value or "").strip()
    return text[-limit:] if text else ""
