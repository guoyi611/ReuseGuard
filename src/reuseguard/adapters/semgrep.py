"""Semgrep adapter: parse Semgrep JSON into ReuseGuard's unified schema.

Semgrep is invoked as an argv list with ``shell=False`` and an explicit process
timeout. ReuseGuard never uses ``--config auto``: the rule source must be a
local path supplied by the user (or a repository-pinned config), so a scan never
fetches rules from the network implicitly.

Findings are mapped onto :class:`reuseguard.models.Finding` and pass through the
same documentation/test suppression policy as the built-in scanner. Semgrep
itself only reads files; this adapter never executes repository code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding, RiskLevel, ScanReport, ScanStatus
from .process import CommandRunner, run_command
from .scanner import ScanLimits, suppression_reason

DEFAULT_SEMGREP_BINARY = "semgrep"
DEFAULT_RULE_TIMEOUT = 30.0
DEFAULT_PROCESS_TIMEOUT = 300.0
DEFAULT_MAX_MEMORY_MB = 1024
_MAX_ERROR_TAIL = 1500
_MAX_SCANNED_FOR_SIZE = 5000
_SEVERITY_MAP = {
    "ERROR": RiskLevel.HIGH,
    "WARNING": RiskLevel.MEDIUM,
    "INFO": RiskLevel.LOW,
}


class SemgrepError(Exception):
    """Semgrep failed to run, returned invalid output, or was misconfigured."""


class SemgrepUnavailable(SemgrepError):
    """The Semgrep executable is not installed or not on PATH."""


@dataclass(frozen=True)
class SemgrepOptions:
    """How to invoke Semgrep for one repository snapshot."""

    config: Path
    binary: str = DEFAULT_SEMGREP_BINARY
    rule_timeout: float = DEFAULT_RULE_TIMEOUT
    process_timeout: float = DEFAULT_PROCESS_TIMEOUT
    max_memory_mb: int = DEFAULT_MAX_MEMORY_MB

    def __post_init__(self) -> None:
        if not self.binary.strip():
            raise SemgrepError("semgrep binary must not be empty")
        if not 1.0 <= self.rule_timeout <= 300.0:
            raise SemgrepError("semgrep rule timeout must be between 1 and 300 seconds")
        if not 10.0 <= self.process_timeout <= 3600.0:
            raise SemgrepError("semgrep process timeout must be between 10 and 3600 seconds")
        if not 128 <= self.max_memory_mb <= 8192:
            raise SemgrepError("semgrep memory limit must be between 128 and 8192 MB")


class SemgrepScanner:
    """Run Semgrep once over a snapshot and normalize its results."""

    def __init__(
        self,
        options: SemgrepOptions,
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
                scanner="semgrep",
                error=f"snapshot directory does not exist: {root}",
            )
        if not self.options.config.exists():
            return ScanReport(
                status=ScanStatus.ERROR,
                scanner="semgrep",
                error=f"semgrep config path does not exist: {self.options.config}",
            )

        argv = self._build_argv(root, limits)
        result = self._runner(argv, timeout=self.options.process_timeout)

        if result.timed_out:
            return ScanReport(
                status=ScanStatus.ERROR,
                scanner="semgrep",
                error=f"semgrep timed out after {self.options.process_timeout:g}s",
            )
        if result.returncode is None:
            raise SemgrepUnavailable(result.stderr.strip() or "semgrep executable not found")
        if result.returncode != 0:
            detail = _tail(result.stderr) or _tail(result.stdout) or "no output"
            return ScanReport(
                status=ScanStatus.ERROR,
                scanner="semgrep",
                error=f"semgrep exited with status {result.returncode}: {detail}",
            )

        payload = _parse_payload(result.stdout)
        if payload is None:
            detail = _tail(result.stderr) or "no JSON on stdout"
            return ScanReport(
                status=ScanStatus.ERROR,
                scanner="semgrep",
                error=f"could not parse semgrep JSON output: {detail}",
            )

        raw_results = payload.get("results")
        if not isinstance(raw_results, list):
            return ScanReport(
                status=ScanStatus.ERROR,
                scanner="semgrep",
                error="semgrep JSON output has no 'results' list",
            )

        root_resolved = root.resolve()
        findings: list[Finding] = []
        seen: set[tuple[str, str, int]] = set()
        truncated = False

        for raw in raw_results:
            if not isinstance(raw, dict):
                continue
            finding = _to_finding(
                raw,
                root=root_resolved,
                disabled_rules=disabled_rules,
                overrides=overrides,
                suppress_globs=suppress_globs,
            )
            if finding is None:
                continue
            key = (finding.rule_id, finding.path, finding.line or 0)
            if key in seen:
                continue
            seen.add(key)
            if len(findings) >= limits.max_findings:
                truncated = True
                break
            findings.append(finding)

        scanned = _path_list(payload, "scanned")
        skipped = _path_list(payload, "skipped")
        errors = payload.get("errors")
        if skipped:
            truncated = True
        if errors:
            # Semgrep reports parse/timeout errors here. Unknown coverage is
            # incomplete coverage, so the verdict must not treat it as clean.
            truncated = True

        risk = RiskLevel.NONE
        for finding in findings:
            if not finding.suppressed and finding.severity.rank > risk.rank:
                risk = finding.severity

        return ScanReport(
            status=ScanStatus.SCANNED,
            risk=risk,
            findings=findings,
            files_scanned=len(scanned),
            files_skipped=len(skipped),
            bytes_scanned=_sum_sizes(root_resolved, scanned),
            truncated=truncated,
            scanner="semgrep",
        )

    def _build_argv(self, root: Path, limits: ScanLimits) -> list[str]:
        return [
            self.options.binary,
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            # A repository-controlled .gitignore must not hide files from us.
            "--no-git-ignore",
            "--config",
            str(self.options.config),
            "--timeout",
            str(int(self.options.rule_timeout)),
            "--max-target-bytes",
            str(limits.max_file_bytes),
            "--max-memory",
            str(self.options.max_memory_mb),
            "--jobs",
            "1",
            str(root),
        ]


def _to_finding(
    raw: dict,
    *,
    root: Path,
    disabled_rules: frozenset[str],
    overrides: dict[str, RiskLevel],
    suppress_globs: tuple[str, ...],
) -> Finding | None:
    rule_id = raw.get("check_id")
    if not isinstance(rule_id, str) or not rule_id:
        return None
    if rule_id in disabled_rules:
        return None

    relative = _relative_path(raw.get("path"), root)
    if relative is None:
        return None

    extra = raw.get("extra")
    extra = extra if isinstance(extra, dict) else {}
    metadata = extra.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    severity = _severity(extra, metadata)
    severity = overrides.get(rule_id, severity)

    line = _start_line(raw.get("start"))
    message = extra.get("message")
    if not isinstance(message, str) or not message.strip():
        message = f"Semgrep rule {rule_id} matched."
    evidence = extra.get("lines")
    evidence = evidence.strip()[:200] if isinstance(evidence, str) else None

    category = metadata.get("category")
    category = category if isinstance(category, str) and category else "semgrep"

    reason = suppression_reason(relative, suppress_globs)
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        category=category,
        path=relative,
        line=line,
        message=message.strip()[:400],
        evidence=evidence,
        suppressed=reason is not None,
        suppression_reason=reason,
    )


def _severity(extra: dict, metadata: dict) -> RiskLevel:
    meta_severity = metadata.get("severity")
    if isinstance(meta_severity, str) and meta_severity.lower() == "critical":
        return RiskLevel.CRITICAL
    raw = extra.get("severity")
    if isinstance(raw, str):
        mapped = _SEVERITY_MAP.get(raw.upper())
        if mapped is not None:
            return mapped
    return RiskLevel.LOW


def _relative_path(raw: object, root: Path) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        return None
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return None


def _start_line(value: object) -> int | None:
    if not isinstance(value, dict):
        return None
    line = value.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return None
    return line


def _path_list(payload: dict, key: str) -> list:
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        return []
    value = paths.get(key)
    return value if isinstance(value, list) else []


def _sum_sizes(root: Path, paths: list) -> int:
    total = 0
    for entry in paths[:_MAX_SCANNED_FOR_SIZE]:
        if not isinstance(entry, str):
            continue
        candidate = Path(entry)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            resolved = candidate.resolve()
            if resolved.is_relative_to(root) and resolved.is_file():
                total += resolved.stat().st_size
        except OSError:
            continue
    return total


def _parse_payload(stdout: str) -> dict | None:
    text = (stdout or "").strip()
    candidates = [text]
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def _tail(value: str, limit: int = _MAX_ERROR_TAIL) -> str:
    text = (value or "").strip()
    return text[-limit:] if text else ""
