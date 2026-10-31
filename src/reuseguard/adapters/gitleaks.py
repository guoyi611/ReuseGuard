"""gitleaks adapter: turn a secret-scan report into ReuseGuard findings.

gitleaks scans a directory snapshot for credentials. It never executes anything
from the repository, and this adapter only reads the JSON report it writes.

Three repository-controlled inputs would otherwise let the scanned code decide
what counts as a finding, so the adapter closes them:

* ``<source>/.gitleaks.toml`` is normally picked up automatically and can
  replace or allowlist the whole rule set. The adapter always passes an explicit
  ``--config`` that extends the rules compiled into the gitleaks binary.
* ``.gitleaksignore`` is read from the *current* directory by default. The
  adapter points ``--gitleaks-ignore-path`` at a private empty directory.
* ``# gitleaks:allow`` comments are respected by default. The adapter passes
  ``--ignore-gitleaks-allow`` and records such lines like any other finding.

Secret values are never copied into a :class:`~reuseguard.models.Finding`. The
tool is asked to redact, and the adapter redacts again from the ``Secret`` field
so that an older gitleaks release that ignores ``--redact`` still cannot leak a
credential into a report.
"""

from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding, RiskLevel, ScanReport, ScanStatus
from .process import CommandRunner, run_command
from .scanner import ScanLimits, relative_to_root, suppression_reason

DEFAULT_GITLEAKS_BINARY = "gitleaks"
DEFAULT_PROCESS_TIMEOUT = 300.0
MAX_REPORT_BYTES = 16 * 1024 * 1024

# Written to a private temporary directory and passed with --config. Extending
# the built-in rule set keeps the default detection rules while ignoring any
# .gitleaks.toml that ships inside the scanned repository.
_POLICY_CONFIG = """\
title = "ReuseGuard secret-scanning policy"
# Never let a scanned repository decide what counts as a secret.
[extend]
useDefault = true
"""

_REDACTION_MARKER = "[REDACTED]"
# gitleaks returns 126 when it does not recognise a flag or subcommand.
_EXIT_CODE_UNKNOWN_FLAG = 126
_RULE_PREFIX = "gitleaks:"
_MAX_ERROR_TAIL = 1500
_MAX_EVIDENCE = 200
_MAX_MESSAGE = 400
_MAX_DESCRIPTION = 160
_MAX_RULE_ID = 200

# Rules for well-known credential families (and private keys) are high risk.
# Entropy-based catch-all rules such as generic-api-key stay at medium risk.
_HIGH_RISK_MARKERS = (
    "private-key",
    "privatekey",
    "aws",
    "gcp",
    "google",
    "azure",
    "github",
    "gitlab",
    "slack",
    "stripe",
    "twilio",
    "sendgrid",
    "openai",
    "anthropic",
    "huggingface",
    "npm",
    "pypi",
    "jwt",
    "oauth",
    "pat",
    "heroku",
    "shopify",
    "discord",
    "telegram",
    "digitalocean",
    "databricks",
    "hashicorp",
    "vault",
    "clojars",
    "snyk",
    "age-secret-key",
)

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class GitleaksError(Exception):
    """gitleaks failed to run, returned invalid output, or was misconfigured."""


class GitleaksUnavailable(GitleaksError):
    """The gitleaks executable is not installed or not on PATH."""


@dataclass(frozen=True)
class GitleaksOptions:
    """How to invoke gitleaks for one repository snapshot."""

    binary: str = DEFAULT_GITLEAKS_BINARY
    process_timeout: float = DEFAULT_PROCESS_TIMEOUT

    def __post_init__(self) -> None:
        if not self.binary.strip():
            raise GitleaksError("gitleaks binary must not be empty")
        if not 10.0 <= self.process_timeout <= 3600.0:
            raise GitleaksError("gitleaks process timeout must be between 10 and 3600 seconds")


class GitleaksScanner:
    """Run gitleaks once over a snapshot and normalize its report."""

    def __init__(
        self,
        options: GitleaksOptions,
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
                scanner="gitleaks",
                error=f"snapshot directory does not exist: {root}",
            )
        root_resolved = root.resolve()

        with tempfile.TemporaryDirectory(prefix="reuseguard-gitleaks-") as directory:
            workspace = Path(directory)
            config = workspace / "reuseguard-gitleaks.toml"
            config.write_text(_POLICY_CONFIG, encoding="utf-8")
            report_path = workspace / "report.json"

            argv = self._build_argv(root_resolved, workspace, config, report_path, limits)
            result = self._runner(argv, timeout=self.options.process_timeout)

            if result.timed_out:
                return ScanReport(
                    status=ScanStatus.ERROR,
                    scanner="gitleaks",
                    error=f"gitleaks timed out after {self.options.process_timeout:g}s",
                )
            if result.returncode is None:
                raise GitleaksUnavailable(result.stderr.strip() or "gitleaks executable not found")
            if result.returncode != 0:
                return _command_error(result.returncode, result.stderr, result.stdout)

            payload, read_error = _read_report(report_path)
            if read_error is not None:
                return ScanReport(status=ScanStatus.ERROR, scanner="gitleaks", error=read_error)

        entries = _leaks(payload)
        if entries is None:
            return ScanReport(
                status=ScanStatus.ERROR,
                scanner="gitleaks",
                error="unexpected gitleaks report shape: expected a list of findings",
            )

        findings: list[Finding] = []
        seen: set[tuple[str, str, int]] = set()
        truncated = False

        for raw in entries:
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

        risk = RiskLevel.NONE
        for finding in findings:
            if not finding.suppressed and finding.severity.rank > risk.rank:
                risk = finding.severity

        # gitleaks does not report how many files it examined; the merged report
        # keeps the file count of the scanner that does (see merge_scan_reports).
        return ScanReport(
            status=ScanStatus.SCANNED,
            risk=risk,
            findings=findings,
            files_scanned=0,
            bytes_scanned=0,
            truncated=truncated,
            scanner="gitleaks",
        )

    def _build_argv(
        self,
        root: Path,
        workspace: Path,
        config: Path,
        report_path: Path,
        limits: ScanLimits,
    ) -> list[str]:
        return [
            self.options.binary,
            "dir",
            str(root),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            # Pin the rule set so the snapshot's .gitleaks.toml cannot rewrite
            # or allowlist it.
            "--config",
            str(config),
            # Read .gitleaksignore from a private empty directory, not the cwd.
            "--gitleaks-ignore-path",
            str(workspace),
            # A `# gitleaks:allow` comment inside the snapshot must not hide a hit.
            "--ignore-gitleaks-allow",
            # Leaks belong in the report; only real failures should change the
            # process exit code.
            "--exit-code",
            "0",
            # Ask for redaction and also redact ourselves; never trust one layer.
            "--redact",
            "--no-banner",
            "--no-color",
            "--max-target-megabytes",
            str(_max_target_megabytes(limits)),
        ]


def _leaks(payload: object) -> list | None:
    """Return the list of leaks, or ``None`` when the report shape is unusable."""
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        leaks = payload.get("leaks")
        if isinstance(leaks, list):
            return leaks
    return None


def _to_finding(
    raw: dict,
    *,
    root: Path,
    disabled_rules: frozenset[str],
    overrides: dict[str, RiskLevel],
    suppress_globs: tuple[str, ...],
) -> Finding | None:
    rule = raw.get("RuleID")
    if not isinstance(rule, str) or not rule.strip():
        return None
    rule = rule.strip()[:_MAX_RULE_ID]
    rule_id = f"{_RULE_PREFIX}{rule}"
    if rule in disabled_rules or rule_id in disabled_rules:
        return None

    relative = relative_to_root(raw.get("File"), root)
    if relative is None:
        return None

    secret = raw.get("Secret")
    secret = secret if isinstance(secret, str) else ""
    match = raw.get("Match")
    match = match if isinstance(match, str) else ""

    description = raw.get("Description")
    description = description.strip()[:_MAX_DESCRIPTION] if isinstance(description, str) else ""
    title = description or rule

    severity = overrides.get(rule_id)
    if severity is None:
        severity = overrides.get(rule, _severity(rule))

    message = f"{title}. The secret value is redacted in this report."
    reason = suppression_reason(relative, suppress_globs)
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category="secret",
        path=relative,
        line=_start_line(raw.get("StartLine")),
        message=message[:_MAX_MESSAGE],
        evidence=_redacted_evidence(match, secret),
        suppressed=reason is not None,
        suppression_reason=reason,
    )


def _severity(rule_id: str) -> RiskLevel:
    lowered = rule_id.lower()
    if lowered.startswith("generic"):
        return RiskLevel.MEDIUM
    if any(marker in lowered for marker in _HIGH_RISK_MARKERS):
        return RiskLevel.HIGH
    return RiskLevel.MEDIUM


def _redacted_evidence(match: str, secret: str) -> str | None:
    """Return a single-line, secret-free excerpt of the matched text.

    The match line is only rendered when gitleaks also told us which value it
    considered secret: without that value there is nothing to redact, so the
    safer choice is to omit the excerpt entirely.
    """
    if not match or not secret:
        return None
    if len(secret) < 4:
        # Too short to redact reliably; keep no context rather than risk leaking it.
        return _REDACTION_MARKER
    # Redact across the whole match before truncating: cutting first could split
    # one occurrence and let a partial secret through.
    text = match.replace(secret, _REDACTION_MARKER)
    text = _CONTROL_CHARS.sub(" ", text)
    text = " ".join(text.split())
    if not text:
        return None
    if secret in text:  # pragma: no cover - defensive, replace() is exhaustive
        return _REDACTION_MARKER
    return text[:_MAX_EVIDENCE]


def _start_line(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def _read_report(path: Path) -> tuple[object, str | None]:
    """Read and parse the JSON report, with bounds on what is accepted."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"gitleaks did not write a report: {exc}"
    if size > MAX_REPORT_BYTES:
        return None, f"gitleaks report is too large to parse ({size} bytes)"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"could not read the gitleaks report: {exc}"
    try:
        return json.loads(text), None
    except json.JSONDecodeError as exc:
        return None, f"could not parse gitleaks JSON report: {exc}"


def _command_error(returncode: int, stderr: str, stdout: str) -> ScanReport:
    detail = _tail(stderr) or _tail(stdout) or "no output"
    if returncode == _EXIT_CODE_UNKNOWN_FLAG:
        detail = (
            f"gitleaks rejected the command line (exit 126); this adapter needs a "
            f"gitleaks release that provides the 'dir' command. {detail}"
        )
    return ScanReport(
        status=ScanStatus.ERROR,
        scanner="gitleaks",
        error=f"gitleaks exited with status {returncode}: {detail}",
    )


def _max_target_megabytes(limits: ScanLimits) -> int:
    """Mirror the per-file limit, rounded up because gitleaks counts whole MB."""
    megabytes = -(-limits.max_file_bytes // (1024 * 1024))
    return max(1, megabytes)


def _tail(value: str, limit: int = _MAX_ERROR_TAIL) -> str:
    text = (value or "").strip()
    return text[-limit:] if text else ""
