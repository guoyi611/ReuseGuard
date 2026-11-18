"""Data structures shared by every ReuseGuard stage.

The models in this module deliberately contain no I/O. Stages translate their
own inputs into these types so that the pipeline, report renderer, and tests
never depend on a specific external tool.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

_RISK_LEVELS = ("none", "low", "medium", "high", "critical")
_DECISION_LEVELS = ("use", "inspect", "avoid")
_CONFIDENCE_LEVELS = ("low", "medium", "high")

_REPO_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


class RiskLevel(str, Enum):
    """How dangerous the effective findings of a static scan are."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RISK_LEVELS.index(self.value)


class Decision(str, Enum):
    """The final, deliberately coarse recommendation."""

    USE = "use"
    INSPECT = "inspect"
    AVOID = "avoid"

    @property
    def rank(self) -> int:
        return _DECISION_LEVELS.index(self.value)


class Confidence(str, Enum):
    """How much evidence supports a verdict."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_LEVELS.index(self.value)


@dataclass(frozen=True, order=True)
class RepoRef:
    """A validated ``owner/name`` pair on github.com.

    Parsing is intentionally strict: ReuseGuard never fetches the URL a user
    typed. It extracts a canonical owner/name pair and builds every later URL
    from those two validated components, which also closes the obvious SSRF
    door (``https://github.com@evil.example/...``).
    """

    owner: str
    name: str

    def __post_init__(self) -> None:
        for value, label in ((self.owner, "owner"), (self.name, "repository name")):
            if not _REPO_NAME.fullmatch(value) or value in {".", ".."}:
                raise ValueError(f"invalid GitHub {label}: {value!r}")

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def url(self) -> str:
        return f"https://github.com/{self.full_name}"

    @classmethod
    def parse(cls, value: str) -> RepoRef:
        """Accept ``owner/repo``, a github.com URL, or an SSH clone URL."""
        raw = value.strip()
        if not raw:
            raise ValueError("empty repository reference")

        if raw.lower().startswith("git@"):
            host, separator, path = raw[4:].partition(":")
            if not separator or host.lower() != "github.com":
                raise ValueError("only github.com SSH URLs are supported")
            parts = [part for part in path.split("/") if part]
            if len(parts) != 2:
                raise ValueError(f"expected git@github.com:owner/repo.git, got {value!r}")
            return cls(parts[0], _strip_git_suffix(parts[1]))

        if "://" not in raw:
            if raw.lower().startswith(("github.com/", "www.github.com/")):
                raw = "https://" + raw
            else:
                parts = [part for part in raw.split("/") if part]
                if len(parts) == 2:
                    return cls(parts[0], _strip_git_suffix(parts[1]))
                raise ValueError(f"expected a github.com URL or owner/repo, got {value!r}")

        parsed = urlparse(raw)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("only http(s) GitHub URLs are supported")
        if (parsed.hostname or "").lower() not in {"github.com", "www.github.com"}:
            raise ValueError("only github.com repository URLs are supported")

        parts = [unquote(part) for part in parsed.path.split("/") if part]
        if len(parts) < 2:
            raise ValueError(f"expected https://github.com/owner/repo, got {value!r}")
        return cls(parts[0], _strip_git_suffix(parts[1]))


def _strip_git_suffix(value: str) -> str:
    return value[:-4] if value.lower().endswith(".git") else value


@dataclass
class RepoMeta:
    """The subset of GitHub repository metadata the pipeline needs."""

    full_name: str
    html_url: str
    description: str | None = None
    stars: int = 0
    forks: int = 0
    language: str | None = None
    topics: list[str] = field(default_factory=list)
    license_spdx: str | None = None
    pushed_at: datetime | None = None
    created_at: datetime | None = None
    archived: bool = False
    fork: bool = False
    default_branch: str = "HEAD"
    size_kb: int = 0
    open_issues: int = 0

    @property
    def ref(self) -> RepoRef:
        return RepoRef.parse(self.full_name)

    @property
    def owner(self) -> str:
        return self.full_name.split("/", 1)[0]

    @property
    def name(self) -> str:
        return self.full_name.split("/", 1)[1]


@dataclass
class Similarity:
    """A transparent 0-100 similarity score with its components."""

    total: float
    topics: float = 0.0
    keywords: float = 0.0
    language: float = 0.0
    recency: float = 0.0
    popularity: float = 0.0


@dataclass
class Candidate:
    """A repository selected for assessment."""

    repo: RepoMeta
    role: str = "alternative"
    similarity: Similarity | None = None
    recalled_by: str | None = None

    @property
    def is_seed(self) -> bool:
        return self.role == "seed"


class FilterStatus(str, Enum):
    PASSED = "passed"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"
    DISABLED = "disabled"


@dataclass
class FilterResult:
    """The outcome of the reputation-filter stage."""

    status: FilterStatus
    score: float | None = None
    checked_at: str | None = None
    source: str = "api"
    checks: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


class ScanStatus(str, Enum):
    SCANNED = "scanned"
    SKIPPED = "skipped"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class Finding:
    """One static-analysis match, before or after false-positive control.

    ``scope`` is an optional dependency classifier used by the OSV adapter to
    distinguish production from development dependencies. Other scanners leave
    it as ``None``. It does not influence severity or verdict; it exists so
    reports can surface noisy dev-only findings separately without hiding them.
    """

    rule_id: str
    title: str
    severity: RiskLevel
    category: str
    path: str
    message: str
    line: int | None = None
    evidence: str | None = None
    suppressed: bool = False
    suppression_reason: str | None = None
    scope: str | None = None


@dataclass
class ScanReport:
    """The outcome of the static-scan stage."""

    status: ScanStatus
    risk: RiskLevel = RiskLevel.NONE
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    truncated: bool = False
    scanner: str = "builtin-patterns"
    error: str | None = None

    @property
    def effective_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if not finding.suppressed]

    @property
    def suppressed_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.suppressed]

    def counts(self) -> dict[str, int]:
        counts = {level.value: 0 for level in RiskLevel}
        for finding in self.effective_findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def summary(self) -> str:
        if self.status != ScanStatus.SCANNED:
            return self.error or f"scan {self.status.value}"
        effective = len(self.effective_findings)
        suppressed = len(self.suppressed_findings)
        detail = f"{effective} finding{'s' if effective != 1 else ''}"
        if suppressed:
            detail += f", {suppressed} suppressed"
        return f"{self.risk.value} risk · {detail} · {self.files_scanned} files"


def merge_scan_reports(reports: Sequence[ScanReport]) -> ScanReport:
    """Combine additive scanner reports without over-claiming coverage.

    Scanners observe different things (patterns, secrets, dependencies), so a
    secret scan is *added* to the pattern scan instead of replacing it.

    File counts use the widest single scanner, not a sum: summing would count the
    same file once per scanner and overstate how much of the snapshot was read.
    Any failing scanner makes the merged report an error, because silently
    returning the surviving results would hide a coverage gap.
    """
    if not reports:
        raise ValueError("at least one scan report is required")
    if len(reports) == 1:
        return reports[0]

    scanned = [report for report in reports if report.status is ScanStatus.SCANNED]
    if not scanned:
        return reports[0]

    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for report in scanned:
        for finding in report.findings:
            key = (finding.rule_id, finding.path, finding.line or 0)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

    risk = RiskLevel.NONE
    for finding in findings:
        if not finding.suppressed and finding.severity.rank > risk.rank:
            risk = finding.severity

    errors = [report for report in reports if report.status is ScanStatus.ERROR]
    error = None
    if errors:
        detail = "; ".join(
            f"{report.scanner}: {report.error or 'unknown error'}" for report in errors
        )
        error = f"one or more scanners failed: {detail}"

    names = list(dict.fromkeys(report.scanner for report in reports if report.scanner))
    return ScanReport(
        status=ScanStatus.ERROR if errors else ScanStatus.SCANNED,
        risk=risk,
        findings=findings,
        files_scanned=max(report.files_scanned for report in scanned),
        files_skipped=max(report.files_skipped for report in scanned),
        bytes_scanned=max(report.bytes_scanned for report in scanned),
        truncated=any(report.truncated for report in reports),
        scanner="+".join(names),
        error=error,
    )


class SandboxStatus(str, Enum):
    """The outcome of the opt-in isolation probe."""

    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class SandboxReport:
    """Evidence from one container run.

    The current probe verifies the containment configuration (read-only mount,
    disabled network, resource limits). It does not execute repository code, so
    a completed run is not evidence that the repository is harmless.
    """

    status: SandboxStatus
    image: str | None = None
    container: str | None = None
    exit_code: int | None = None
    duration_seconds: float = 0.0
    timed_out: bool = False
    oom_suspected: bool = False
    containment_ok: bool | None = None
    mount_target: str = "/src"
    network: str = "none"
    memory_mb: int | None = None
    cpus: float | None = None
    pids_limit: int | None = None
    timeout_seconds: float | None = None
    probe: dict[str, Any] = field(default_factory=dict)
    stdout_tail: str | None = None
    stderr_tail: str | None = None
    error: str | None = None
    command: list[str] = field(default_factory=list)


class BehaviorMode(str, Enum):
    """Which behavior phases the user asked for; ``OFF`` never runs anything."""

    OFF = "off"
    IMPORT = "import"
    TEST = "test"
    ALL = "all"


class BehaviorStatus(str, Enum):
    """The outcome of one behavior-probe run (design section 9.3).

    These values describe what the probe was able to observe, never whether the
    repository is harmless: ``COMPLETED`` means "every requested phase ran and
    evidence was collected", not "the code is safe".
    """

    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    REFUSED = "refused"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    ERROR = "error"
    PARTIAL = "partial"
    INTEGRITY_FAILURE = "integrity_failure"


class BehaviorPhaseStatus(str, Enum):
    """The outcome of a single behavior phase (design section 4.5)."""

    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    OOM = "oom"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    KILLED = "killed"
    SKIPPED_UNSUPPORTED = "skipped_unsupported"
    SKIPPED_TOOL_MISSING = "skipped_tool_missing"
    SKIPPED_CACHE_MISSING = "skipped_cache_missing"
    NOT_RUN = "not_run"
    DOCKER_ERROR = "docker_error"


class TrustLevel(str, Enum):
    """How much an evidence item can be relied on (design section 9.1)."""

    HOST_OBSERVED = "host_observed"
    HOST_SAMPLED = "host_sampled"
    PROXY_OBSERVED = "proxy_observed"
    UNTRUSTED_REPO_OUTPUT = "untrusted_repo_output"
    UNAVAILABLE = "unavailable"


@dataclass
class CapturedStream:
    """A bounded tail of one output stream.

    Repository output is always ``UNTRUSTED_REPO_OUTPUT``: it is a clue, never
    a fact. ``bytes`` counts what was produced, not what was kept.
    """

    tail: str = ""
    bytes: int = 0
    truncated: bool = False
    trust: TrustLevel = TrustLevel.UNTRUSTED_REPO_OUTPUT


@dataclass
class ToolPreflight:
    """Result of checking that the image actually contains the phase tool.

    A missing tool is recorded here so it is not misread as a failing test.
    """

    argv: list[str] = field(default_factory=list)
    exit_code: int | None = None
    stderr_tail: str | None = None


@dataclass
class BehaviorPhase:
    """One fixed-argv phase executed in its own container."""

    name: str
    argv: list[str] = field(default_factory=list)
    cwd: str = "/work/repo"
    exit_code: int | None = None
    docker_exit_code: int | None = None
    signal: int | None = None
    status: BehaviorPhaseStatus = BehaviorPhaseStatus.NOT_RUN
    timed_out: bool = False
    oom_killed: bool = False
    duration_seconds: float = 0.0
    stdout: CapturedStream = field(default_factory=CapturedStream)
    stderr: CapturedStream = field(default_factory=CapturedStream)
    tool_preflight: ToolPreflight | None = None
    error: str | None = None


@dataclass
class ProcessSample:
    """One process seen by host-side sampling; short-lived processes may be missed."""

    pid: int
    ppid: int | None = None
    uid: int | None = None
    comm: str = ""
    cmdline: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    samples: int = 1


@dataclass
class ProcessEvidence:
    """The sampled process table for one run."""

    samples: list[ProcessSample] = field(default_factory=list)
    sampled: bool = False
    interval_ms: int | None = None
    unique: int = 0
    truncated: bool = False
    trust: TrustLevel = TrustLevel.HOST_SAMPLED
    note: str | None = None


@dataclass
class FileChange:
    """One final-state file difference under ``<workdir>``.

    Only final state is observable: creating and deleting a file inside one
    phase leaves no trace.
    """

    path: str
    type: str = "file"
    size: int = 0
    mode: str | None = None
    sha256: str | None = None
    content_verified: bool = False
    phase: str | None = None


@dataclass
class FileEvidence:
    """Final-state file differences for one run."""

    created: list[FileChange] = field(default_factory=list)
    modified: list[FileChange] = field(default_factory=list)
    deleted: list[FileChange] = field(default_factory=list)
    truncated: bool = False
    trust: TrustLevel = TrustLevel.HOST_OBSERVED
    note: str | None = None


@dataclass
class NetworkEvidence:
    """What the host can observe about the container network.

    With ``--network none`` an empty ``connections`` list means "no egress
    capability", not "no connection was attempted": failed attempts cannot be
    enumerated.
    """

    mode: str = "none"
    egress_possible: bool = False
    connections: list[str] = field(default_factory=list)
    listening_sockets: list[str] = field(default_factory=list)
    trust: TrustLevel = TrustLevel.HOST_OBSERVED
    note: str | None = None


@dataclass
class ResourceUsage:
    """Sampled peaks; never a complete account of what the code did."""

    peak_memory_bytes: int | None = None
    peak_pids: int | None = None
    cpu_seconds: float | None = None
    oom_killed: bool = False
    oom_suspected: bool = False
    trust: TrustLevel = TrustLevel.HOST_SAMPLED


@dataclass
class IntegrityEvidence:
    """Checks that the isolation actually behaved as planned.

    ``tamper_possible`` is always True: observed code can delete or overwrite
    its own traces before the host inspects final state.
    """

    preflight_ok: bool | None = None
    canary_ok: bool | None = None
    unexpected_docker_objects: list[str] = field(default_factory=list)
    tamper_possible: bool = True
    notes: list[str] = field(default_factory=list)


@dataclass
class BehaviorImage:
    """The digest-pinned image a behavior run used."""

    reference: str
    repo_digest: str | None = None
    image_id: str | None = None
    os: str | None = None
    architecture: str | None = None
    digest_verified: bool | None = None


@dataclass
class BehaviorLimits:
    """Limits one behavior run was planned with (design section 12.1)."""

    total_timeout_seconds: float = 300.0
    phase_timeout_seconds: float = 120.0
    max_output_bytes: int = 65536
    max_work_bytes: int = 512 * 1024 * 1024
    max_work_files: int = 50000


@dataclass
class BehaviorReport:
    """Evidence from one behavior-probe run.

    The probe executes repository code inside a disposable, digest-pinned
    container. A report is a record of one run of one snapshot on one machine;
    ``COMPLETED`` in particular is not evidence of safety.
    """

    status: BehaviorStatus
    schema: str = "reuseguard.behavior/1"
    run_id: str | None = None
    tool_version: str | None = None
    protocol_version: int = 1
    platform: dict[str, Any] = field(default_factory=dict)
    image: BehaviorImage | None = None
    container: dict[str, Any] = field(default_factory=dict)
    limits: BehaviorLimits = field(default_factory=BehaviorLimits)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    phases: list[BehaviorPhase] = field(default_factory=list)
    processes: ProcessEvidence = field(default_factory=ProcessEvidence)
    files: FileEvidence = field(default_factory=FileEvidence)
    network: NetworkEvidence = field(default_factory=NetworkEvidence)
    resources: ResourceUsage = field(default_factory=ResourceUsage)
    integrity: IntegrityEvidence = field(default_factory=IntegrityEvidence)
    truncations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def executed(self) -> bool:
        """True only when at least one phase really ran repository code.

        ``refused`` / ``unavailable`` / ``disabled`` reports leave every phase
        at ``not_run``, so callers can avoid implying a dynamic check happened.
        """
        return any(
            phase.status not in {BehaviorPhaseStatus.NOT_RUN, BehaviorPhaseStatus.DOCKER_ERROR}
            for phase in self.phases
        )


@dataclass
class Verdict:
    """A recommendation plus the evidence and caveats behind it.

    ``withheld`` is a presentation flag, not a different decision: discovery
    mode keeps the computed decision in JSON for auditability but hides it from
    the Markdown report because no static scan was performed.
    """

    decision: Decision
    confidence: Confidence
    reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    withheld: bool = False


@dataclass
class Assessment:
    """Everything ReuseGuard knows about one repository.

    ``sandbox`` is the containment probe (isolated but never executes
    repository code). ``behavior`` is the behavior probe, which does execute
    repository code and is therefore ``None`` unless explicitly requested.
    """

    candidate: Candidate
    filter: FilterResult
    scan: ScanReport
    verdict: Verdict
    sandbox: SandboxReport | None = None
    behavior: BehaviorReport | None = None


@dataclass
class Report:
    """The complete result of one pipeline run."""

    tool_version: str
    generated_at: datetime
    seed: RepoMeta | None
    assessments: list[Assessment]
    recall_queries: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    demo: bool = False
    workdir: str | None = None
    query: str | None = None
    discover_only: bool = False
    schema_version: int = 1

    def counts(self) -> dict[str, int]:
        counts = {decision.value: 0 for decision in Decision}
        for assessment in self.assessments:
            counts[assessment.verdict.decision.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        data = to_jsonable(self)
        if not isinstance(data, dict):  # pragma: no cover - defensive
            raise TypeError("report did not serialize to an object")
        data["counts"] = self.counts()
        return data


def to_jsonable(value: Any) -> Any:
    """Recursively convert dataclasses, enums, datetimes, and paths to JSON types."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: to_jsonable(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return value
