"""Planning-time validation for the opt-in behavior probe (M4).

This module only validates *requests*. It never invokes Docker and never
executes repository code; container orchestration arrives in later steps
(design sections 5 and 14). What lives here now:

1. The numeric bounds from design section 12.1, shared by the CLI parser and
   the YAML policy loader so both reject the same out-of-range values with the
   same wording.
2. Strict image-reference validation. Behavior evidence is only meaningful if
   the image is pinned by digest, so a tag (including ``:latest``) is refused
   before anything is planned.
3. ``BehaviorLimits`` / ``BehaviorOptions``: a frozen snapshot of the requested
   run, ready for the pipeline to consume.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from ..models import BehaviorMode

MIN_TOTAL_TIMEOUT_SECONDS = 30.0
MAX_TOTAL_TIMEOUT_SECONDS = 1800.0
DEFAULT_TOTAL_TIMEOUT_SECONDS = 300.0

MIN_PHASE_TIMEOUT_SECONDS = 10.0
MAX_PHASE_TIMEOUT_SECONDS = 900.0
DEFAULT_PHASE_TIMEOUT_SECONDS = 120.0

MIN_MEMORY_MB = 128
MAX_MEMORY_MB = 4096
DEFAULT_MEMORY_MB = 512

MIN_CPUS = 0.1
MAX_CPUS = 4.0
DEFAULT_CPUS = 1.0

MIN_PIDS = 16
MAX_PIDS = 512
DEFAULT_PIDS = 128

MIN_MAX_WORK_MB = 64
MAX_MAX_WORK_MB = 4096
DEFAULT_MAX_WORK_MB = 512

MIN_MAX_WORK_FILES = 1000
MAX_MAX_WORK_FILES = 200000
DEFAULT_MAX_WORK_FILES = 50000

#: Design section 4.4 executes with a fixed argv, so the label set is closed.
BEHAVIOR_PHASES: tuple[str, ...] = ("import", "test")

# An OCI/Docker reference whose tag may contain dots, but never a digest.
_IMAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]*$")
_DIGEST_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9_][A-Za-z0-9._-]*)?" r"@sha256:[0-9a-f]{64}$"
)


class BehaviorConfigError(Exception):
    """A behavior-probe request is unacceptable; nothing may be executed."""


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


def validate_total_timeout(value: float) -> float:
    return behavior_number(
        value, MIN_TOTAL_TIMEOUT_SECONDS, MAX_TOTAL_TIMEOUT_SECONDS, "behavior timeout"
    )


def validate_phase_timeout(value: float) -> float:
    return behavior_number(
        value,
        MIN_PHASE_TIMEOUT_SECONDS,
        MAX_PHASE_TIMEOUT_SECONDS,
        "behavior phase timeout",
    )


def validate_memory_mb(value: int) -> int:
    return behavior_int(value, MIN_MEMORY_MB, MAX_MEMORY_MB, "behavior memory")


def validate_cpus(value: float) -> float:
    return behavior_number(value, MIN_CPUS, MAX_CPUS, "behavior CPUs")


def validate_pids(value: int) -> int:
    return behavior_int(value, MIN_PIDS, MAX_PIDS, "behavior PID limit")


def validate_max_work_mb(value: int) -> int:
    return behavior_int(value, MIN_MAX_WORK_MB, MAX_MAX_WORK_MB, "behavior work-dir size limit")


def validate_max_work_files(value: int) -> int:
    return behavior_int(
        value, MIN_MAX_WORK_FILES, MAX_MAX_WORK_FILES, "behavior work-dir file limit"
    )


def behavior_int(value: int, minimum: int, maximum: int, label: str) -> int:
    """Validate an integer bound; shared by the CLI, YAML loader, and tests."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise BehaviorConfigError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise BehaviorConfigError(f"{label} must be between {minimum} and {maximum}")
    return value


def behavior_number(value: float, minimum: float, maximum: float, label: str) -> float:
    """Validate a numeric bound (used for both seconds and CPU shares)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BehaviorConfigError(f"{label} must be a number")
    if not math.isfinite(value):
        raise BehaviorConfigError(f"{label} must be a finite number")
    if not minimum <= value <= maximum:
        raise BehaviorConfigError(f"{label} must be between {minimum:g} and {maximum:g}")
    return float(value)


# ---------------------------------------------------------------------------
# Image references
# ---------------------------------------------------------------------------


def validate_image_reference(reference: str) -> str:
    """Accept only ``name[:tag]@sha256:<64 lowercase hex>`` references.

    Tags-only references are rejected on purpose (design section 5.1): a tag can
    be re-pointed after review, so it cannot identify what was executed. The
    reference is returned verbatim (not stripped) so the recorded evidence is
    exactly what was passed to ``docker``.
    """
    text = reference or ""
    if not text.strip():
        raise BehaviorConfigError("behavior image is required and must be pinned by digest")
    if not _IMAGE_PATTERN.fullmatch(text):
        raise BehaviorConfigError(f"invalid behavior image reference {reference!r}")
    if "@sha256:" not in text:
        raise BehaviorConfigError(
            f"behavior image {reference!r} must be pinned by digest, "
            "for example python@sha256:<64 hex>; tags are refused because they can move"
        )
    if not _DIGEST_PATTERN.fullmatch(text):
        raise BehaviorConfigError(
            f"invalid digest in behavior image {reference!r}; expected "
            "name@sha256:<64 lowercase hex characters>"
        )
    return text


def normalize_image_reference(reference: str) -> str:
    """Return the comparison form of a validated reference (lowercase)."""
    return validate_image_reference(reference).lower()


def behavior_image(reference: str) -> str:
    """Validate a digest-pinned image reference (short alias used by config)."""
    return validate_image_reference(reference)


# ---------------------------------------------------------------------------
# Cross-cutting request rules (design section 12.1)
# ---------------------------------------------------------------------------


def behavior_requested(mode: str | BehaviorMode) -> bool:
    """True when anything other than ``off`` (including a bare flag) was asked for."""
    return _as_mode(mode) is not BehaviorMode.OFF


def resolve_behavior_mode(
    requested: str | BehaviorMode,
    *,
    scan_enabled: bool,
    image: str | None,
    settings_supplied: bool,
    image_from_cli: bool = True,
) -> BehaviorMode:
    """Validate one behavior request before anything is planned.

    The rules come from design section 12.1 and exist so a user can never end up
    believing code ran (or will run) when it did not:

    - a behavior run needs a snapshot, so it is mutually exclusive with
      ``--no-scan``;
    - turning it on always requires an explicit digest-pinned image;
    - per-run knobs and the image on their own are a usage error, not a
      silent no-op. ``image_from_cli=False`` means the image came from the YAML
      policy, which may pin it for later use without enabling anything;
    - nothing here looks at the sandbox mode: ``--sandbox auto`` never enables
      behavior probing, because that would automate executing untrusted code.
    """
    mode = _as_mode(requested)
    if mode is BehaviorMode.OFF:
        if image is not None and image_from_cli:
            raise BehaviorConfigError(
                "--behavior-image requires --behavior; the image alone does not enable "
                "a behavior run"
            )
        if settings_supplied:
            raise BehaviorConfigError(
                "--behavior-* options require --behavior; they do not enable a run on their own"
            )
        return mode

    if not scan_enabled:
        raise BehaviorConfigError(
            "behavior probing needs a snapshot, so it cannot be combined with --no-scan "
            "or features.scan: false"
        )
    if image is None:
        raise BehaviorConfigError(
            "--behavior requires --behavior-image IMAGE@sha256:<digest>; ReuseGuard never "
            "picks an image or pulls one for you"
        )
    validate_image_reference(image)
    return mode


def _as_mode(value: str | BehaviorMode) -> BehaviorMode:
    if isinstance(value, BehaviorMode):
        return value
    try:
        return BehaviorMode(value)
    except ValueError as exc:
        raise BehaviorConfigError(f"invalid behavior mode {value!r}") from exc


# ---------------------------------------------------------------------------
# Planning objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BehaviorLimits:
    """Validated limits for one behavior run (design section 12.1)."""

    total_timeout_seconds: float = DEFAULT_TOTAL_TIMEOUT_SECONDS
    phase_timeout_seconds: float = DEFAULT_PHASE_TIMEOUT_SECONDS
    memory_mb: int = DEFAULT_MEMORY_MB
    cpus: float = DEFAULT_CPUS
    pids: int = DEFAULT_PIDS
    max_work_mb: int = DEFAULT_MAX_WORK_MB
    max_work_files: int = DEFAULT_MAX_WORK_FILES

    def __post_init__(self) -> None:
        validate_total_timeout(self.total_timeout_seconds)
        validate_phase_timeout(self.phase_timeout_seconds)
        validate_memory_mb(self.memory_mb)
        validate_cpus(self.cpus)
        validate_pids(self.pids)
        validate_max_work_mb(self.max_work_mb)
        validate_max_work_files(self.max_work_files)


@dataclass(frozen=True)
class BehaviorOptions:
    """A validated, frozen description of a requested behavior run.

    ``mode`` is never ``off`` here: constructing an option object means the user
    explicitly asked for a run, which is why the image is mandatory.
    """

    mode: BehaviorMode
    image: str
    limits: BehaviorLimits = BehaviorLimits()
    keep_workdir: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.mode, BehaviorMode):
            raise BehaviorConfigError(f"invalid behavior mode {self.mode!r}")
        if self.mode is BehaviorMode.OFF:
            raise BehaviorConfigError("behavior mode is off; no run is planned")
        validate_image_reference(self.image)

    @property
    def phases(self) -> tuple[str, ...]:
        """The phase names this run may execute, in fixed order."""
        if self.mode is BehaviorMode.ALL:
            return BEHAVIOR_PHASES
        return (self.mode.value,)
