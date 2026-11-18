"""Tests for the M4 behavior-probe data contract, CLI knobs, and config boundary.

Everything here is offline: no Docker command is executed and no repository code
is run. The tests only pin the shapes, defaults, and validation rules that
implementation steps 2-6 will rely on.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from reuseguard.adapters.behavior import (
    DEFAULT_CPUS,
    DEFAULT_MAX_WORK_FILES,
    DEFAULT_MAX_WORK_MB,
    DEFAULT_MEMORY_MB,
    DEFAULT_PHASE_TIMEOUT_SECONDS,
    DEFAULT_PIDS,
    DEFAULT_TOTAL_TIMEOUT_SECONDS,
    BehaviorConfigError,
    BehaviorLimits,
    BehaviorOptions,
    normalize_image_reference,
    validate_cpus,
    validate_image_reference,
    validate_max_work_files,
    validate_max_work_mb,
    validate_memory_mb,
    validate_phase_timeout,
    validate_pids,
    validate_total_timeout,
)
from reuseguard.models import (
    Assessment,
    BehaviorImage,
    BehaviorLimitsInfo,
    BehaviorMode,
    BehaviorPhase,
    BehaviorPhaseStatus,
    BehaviorReport,
    BehaviorStatus,
    Candidate,
    CapturedStream,
    Confidence,
    Decision,
    FileChange,
    FileEvidence,
    FilterResult,
    FilterStatus,
    IntegrityEvidence,
    NetworkEvidence,
    ProcessEvidence,
    ProcessSample,
    RepoMeta,
    Report,
    ResourceUsage,
    ScanReport,
    ScanStatus,
    ToolPreflight,
    TrustLevel,
    Verdict,
    to_jsonable,
)

# ---------------------------------------------------------------------------
# Enum values are the JSON contract; changing one is a breaking change.
# ---------------------------------------------------------------------------


def test_behavior_status_values_match_the_design_document() -> None:
    assert {status.value for status in BehaviorStatus} == {
        "disabled",
        "unavailable",
        "refused",
        "completed",
        "timeout",
        "error",
        "partial",
        "integrity_failure",
    }


def test_behavior_phase_status_values_match_the_design_document() -> None:
    assert {status.value for status in BehaviorPhaseStatus} == {
        "completed",
        "failed",
        "timeout",
        "oom",
        "resource_exhausted",
        "killed",
        "skipped_unsupported",
        "skipped_tool_missing",
        "skipped_cache_missing",
        "not_run",
        "docker_error",
    }


def test_trust_levels_match_the_design_document() -> None:
    assert {level.value for level in TrustLevel} == {
        "host_observed",
        "host_sampled",
        "proxy_observed",
        "untrusted_repo_output",
        "unavailable",
    }


def test_behavior_mode_defaults_cover_off_import_test_all() -> None:
    assert [mode.value for mode in BehaviorMode] == ["off", "import", "test", "all"]


# ---------------------------------------------------------------------------
# Defaults: an unexecuted report must not claim anything was observed.
# ---------------------------------------------------------------------------


def test_report_defaults_are_conservative() -> None:
    report = BehaviorReport(status=BehaviorStatus.UNAVAILABLE)

    assert report.schema == "reuseguard.behavior/1"
    assert report.protocol_version == 1
    assert report.image is None
    assert report.phases == []
    # Nothing ran, so no evidence item may claim host observation.
    assert report.processes.samples == []
    assert report.processes.trust is TrustLevel.HOST_SAMPLED
    assert report.files.created == []
    assert report.files.trust is TrustLevel.HOST_OBSERVED
    assert report.network.mode == "none"
    assert report.network.egress_possible is False
    assert report.resources.oom_killed is False
    # Egress being unavailable says nothing about attempts; evidence can be tampered.
    assert report.integrity.tamper_possible is True
    assert report.executed is False


def test_stream_default_trust_is_untrusted_repo_output() -> None:
    stream = CapturedStream()

    assert stream.trust is TrustLevel.UNTRUSTED_REPO_OUTPUT
    assert stream.truncated is False


def test_limits_defaults_match_the_cli_defaults() -> None:
    limits = BehaviorLimits()
    limits = BehaviorLimitsInfo()
    assert limits.total_timeout_seconds == 300.0
    assert limits.phase_timeout_seconds == 120.0
    assert limits.max_output_bytes == 65536
    assert limits.max_work_bytes == 512 * 1024 * 1024
    assert limits.max_work_files == 50000


def test_phase_defaults_are_not_run() -> None:
    phase = BehaviorPhase(name="import")

    assert phase.status is BehaviorPhaseStatus.NOT_RUN
    assert phase.timed_out is False
    assert phase.oom_killed is False
    assert phase.cwd == "/work/repo"
    assert phase.exit_code is None


def test_executed_only_counts_phases_that_ran() -> None:
    not_run = BehaviorReport(
        status=BehaviorStatus.REFUSED,
        phases=[BehaviorPhase(name="import"), BehaviorPhase(name="test")],
    )
    docker_failed = BehaviorReport(
        status=BehaviorStatus.ERROR,
        phases=[BehaviorPhase(name="import", status=BehaviorPhaseStatus.DOCKER_ERROR)],
    )
    completed = BehaviorReport(
        status=BehaviorStatus.COMPLETED,
        phases=[BehaviorPhase(name="import", status=BehaviorPhaseStatus.COMPLETED)],
    )

    assert not_run.executed is False
    assert docker_failed.executed is False
    assert completed.executed is True


# ---------------------------------------------------------------------------
# Serialization: the JSON schema in section 9.2 has to round-trip.
# ---------------------------------------------------------------------------


def _full_report() -> Report:
    started = datetime(2026, 11, 1, 7, 0, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 11, 1, 7, 0, 42, tzinfo=timezone.utc)
    behavior = BehaviorReport(
        status=BehaviorStatus.PARTIAL,
        run_id="01J9Z8YQ3K7V5M2C4R6T8W0XAB",
        tool_version="0.7.1",
        platform={"os": "linux", "architecture": "amd64", "docker": "27.3.1"},
        image=BehaviorImage(
            reference="python@sha256:" + "0" * 64,
            repo_digest="python@sha256:" + "0" * 64,
            image_id="sha256:" + "a" * 64,
            os="linux",
            architecture="amd64",
            digest_verified=True,
        ),
        container={
            "runtime": "runc",
            "user": "65534:65534",
            "network_mode": "none",
            "readonly_rootfs": True,
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "pids_limit": 128,
            "memory_mb": 512,
            "cpus": 1.0,
            "preflight_ok": True,
        },
        limits=BehaviorLimitsInfo(),
        started_at=started,
        finished_at=finished,
        duration_seconds=42.1,
        phases=[
            BehaviorPhase(
                name="import",
                argv=["python", "-E", "-s", "-c", "import demo"],
                exit_code=0,
                docker_exit_code=0,
                status=BehaviorPhaseStatus.COMPLETED,
                duration_seconds=1.2,
                stdout=CapturedStream(tail="hello from import\n", bytes=17),
                stderr=CapturedStream(),
                tool_preflight=ToolPreflight(argv=["python", "-c", "import sys"], exit_code=0),
            ),
            BehaviorPhase(
                name="test",
                argv=["python", "-m", "pytest", "-q"],
                exit_code=137,
                docker_exit_code=137,
                signal=9,
                status=BehaviorPhaseStatus.OOM,
                oom_killed=True,
                duration_seconds=8.4,
                stderr=CapturedStream(tail="Killed", bytes=7, truncated=True),
            ),
        ],
        processes=ProcessEvidence(
            sampled=True,
            interval_ms=250,
            unique=2,
            samples=[
                ProcessSample(
                    pid=7,
                    ppid=1,
                    uid=65534,
                    comm="python3",
                    cmdline="python -E -s -c import demo",
                    first_seen=started,
                    last_seen=finished,
                    samples=3,
                )
            ],
            note="Sampled from the host; short-lived processes may be missed.",
        ),
        files=FileEvidence(
            created=[
                FileChange(
                    path="repo/demo.pyc",
                    type="file",
                    size=120,
                    mode="0644",
                    sha256="f00d",
                    content_verified=True,
                    phase="import",
                )
            ],
            note="Only final-state differences are observable.",
        ),
        network=NetworkEvidence(
            mode="none",
            egress_possible=False,
            note="With --network none, failed connection attempts cannot be enumerated.",
        ),
        resources=ResourceUsage(
            peak_memory_bytes=48234496,
            peak_pids=2,
            cpu_seconds=0.42,
            oom_killed=True,
            oom_suspected=True,
        ),
        integrity=IntegrityEvidence(
            preflight_ok=True,
            canary_ok=True,
            notes=["Evidence is collected by the host."],
        ),
        truncations=["phases[1].stderr"],
        warnings=["Process list is unavailable on this platform."],
    )
    repo = RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed")
    return Report(
        tool_version="0.7.1",
        generated_at=finished,
        seed=repo,
        assessments=[
            Assessment(
                candidate=Candidate(repo=repo),
                filter=FilterResult(status=FilterStatus.PASSED, score=8.0),
                scan=ScanReport(status=ScanStatus.SCANNED, files_scanned=3),
                verdict=Verdict(decision=Decision.INSPECT, confidence=Confidence.MEDIUM),
                behavior=behavior,
            )
        ],
    )


def test_report_serializes_behavior_evidence_as_json() -> None:
    payload = json.loads(json.dumps(_full_report().to_dict()))

    behavior = payload["assessments"][0]["behavior"]
    assert behavior["status"] == "partial"
    assert behavior["schema"] == "reuseguard.behavior/1"
    assert behavior["image"]["reference"].startswith("python@sha256:")
    assert behavior["image"]["digest_verified"] is True
    assert behavior["started_at"] == "2026-11-01T07:00:00+00:00"
    assert [phase["name"] for phase in behavior["phases"]] == ["import", "test"]
    assert behavior["phases"][0]["stdout"]["trust"] == "untrusted_repo_output"
    assert behavior["phases"][1]["status"] == "oom"
    assert behavior["phases"][1]["oom_killed"] is True
    assert behavior["phases"][1]["stderr"]["truncated"] is True
    assert behavior["processes"]["trust"] == "host_sampled"
    assert behavior["processes"]["samples"][0]["pid"] == 7
    assert behavior["files"]["created"][0]["path"] == "repo/demo.pyc"
    assert behavior["network"]["egress_possible"] is False
    assert behavior["resources"]["oom_suspected"] is True
    assert behavior["integrity"]["tamper_possible"] is True
    assert behavior["truncations"] == ["phases[1].stderr"]


def test_assessment_without_behavior_serializes_as_null() -> None:
    repo = RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed")
    report = Report(
        tool_version="0.7.1",
        generated_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
        seed=repo,
        assessments=[
            Assessment(
                candidate=Candidate(repo=repo),
                filter=FilterResult(status=FilterStatus.PASSED),
                scan=ScanReport(status=ScanStatus.SCANNED),
                verdict=Verdict(decision=Decision.INSPECT, confidence=Confidence.LOW),
            )
        ],
    )

    data = report.to_dict()

    assert "behavior" in data["assessments"][0]
    assert data["assessments"][0]["behavior"] is None


def test_integrity_evidence_defaults_do_not_claim_a_verified_isolation() -> None:
    evidence = IntegrityEvidence()

    assert evidence.preflight_ok is None
    assert evidence.canary_ok is None
    # Observed code can delete its own traces: this flag is never False.
    assert evidence.tamper_possible is True


def test_to_jsonable_keeps_nested_enums_and_datetimes_as_strings() -> None:
    moment = datetime(2026, 11, 1, 7, 0, tzinfo=timezone.utc)
    data = to_jsonable(
        BehaviorReport(
            status=BehaviorStatus.REFUSED,
            started_at=moment,
            image=BehaviorImage(reference="python@sha256:" + "0" * 64, digest_verified=False),
        )
    )

    assert data["status"] == "refused"
    assert data["started_at"] == "2026-11-01T07:00:00+00:00"
    assert data["image"]["digest_verified"] is False
    assert data["phases"] == []


# ---------------------------------------------------------------------------
# Image references: report-only unless pinned by digest.
# ---------------------------------------------------------------------------

_DIGEST = "sha256:" + "0123456789abcdef" * 4
_PINNED = f"python@sha256:{'0123456789abcdef' * 4}"


def test_pinned_reference_is_accepted_unchanged() -> None:
    # Returned verbatim: the evidence must match what was passed to docker.
    assert validate_image_reference(_PINNED) == _PINNED
    assert validate_image_reference(_PINNED) == _PINNED


def test_reference_with_tag_and_digest_is_accepted() -> None:
    reference = "ghcr.io/acme/runner:3.12" + "@" + _DIGEST

    assert validate_image_reference(reference) == reference


@pytest.mark.parametrize(
    "reference",
    [
        "python:3.12-slim",
        "python",
        "python:latest",
        "ghcr.io/acme/runner:3.12",
        "python@sha256:" + "0" * 63,
        "python@sha256:" + "A" * 64,
        "python@sha512:" + "0" * 64,
        "python@sha256",
        "@sha256:" + "0" * 64,
        "python @sha256:" + "0" * 64,
        "python" + "@sha256:" + "0" * 64 + "\t",
        "python;rm@sha256:" + "0" * 64,
        "",
        "   ",
    ],
)
def test_reference_without_a_valid_digest_is_rejected(reference: str) -> None:
    with pytest.raises(BehaviorConfigError):
        validate_image_reference(reference)


def test_tag_rejection_says_the_tag_can_move() -> None:
    with pytest.raises(BehaviorConfigError) as excinfo:
        validate_image_reference("python:3.12-slim")

    message = str(excinfo.value)
    assert "pinned by digest" in message
    assert "tags are refused because they can move" in message


def test_image_names_are_case_insensitive_for_comparison() -> None:
    upper = "Python@sha256:" + _PINNED[-64:]
    lower = "python@sha256:" + _PINNED[-64:]

    assert normalize_image_reference(upper) == normalize_image_reference(lower)


# ---------------------------------------------------------------------------
# Bounds from design section 12.1.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("validator", "value", "low", "high", "label"),
    [
        (validate_total_timeout, 30, 30, 1800, "behavior timeout"),
        (validate_phase_timeout, 10, 10, 900, "behavior phase timeout"),
        (validate_memory_mb, 128, 128, 4096, "behavior memory"),
        (validate_cpus, 0.1, 0.1, 4.0, "behavior CPUs"),
        (validate_pids, 16, 16, 512, "behavior PID limit"),
        (validate_max_work_mb, 64, 64, 4096, "behavior work-dir size limit"),
        (validate_max_work_files, 1000, 1000, 200000, "behavior work-dir file limit"),
    ],
)
def test_boundaries_are_inclusive(validator, value, low: float, high: float, label: str) -> None:
    assert validator(value) == value
    assert validator(low) == low
    assert validator(high) == high

    for out_of_range in (low - 1 if isinstance(low, int) else 0.05, high + 1):
        with pytest.raises(BehaviorConfigError) as excinfo:
            validator(out_of_range)
        assert label in str(excinfo.value)


def test_cpu_limit_accepts_fractional_values_below_one() -> None:
    assert validate_cpus(0.5) == 0.5
    with pytest.raises(BehaviorConfigError):
        validate_cpus(0.05)


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_non_finite_numbers_are_rejected(value: float) -> None:
    with pytest.raises(BehaviorConfigError):
        validate_cpus(value)


def test_booleans_are_not_numbers_here() -> None:
    with pytest.raises(BehaviorConfigError):
        validate_memory_mb(True)  # type: ignore[arg-type]
    with pytest.raises(BehaviorConfigError):
        validate_cpus(True)  # type: ignore[arg-type]


def test_limits_defaults_match_the_documented_values() -> None:
    limits = BehaviorLimits()

    assert limits.total_timeout_seconds == DEFAULT_TOTAL_TIMEOUT_SECONDS == 300.0
    assert limits.phase_timeout_seconds == DEFAULT_PHASE_TIMEOUT_SECONDS == 120.0
    assert limits.memory_mb == DEFAULT_MEMORY_MB == 512
    assert limits.cpus == DEFAULT_CPUS == 1.0
    assert limits.pids == DEFAULT_PIDS == 128
    assert limits.max_work_mb == DEFAULT_MAX_WORK_MB == 512
    assert limits.max_work_files == DEFAULT_MAX_WORK_FILES == 50000


def test_invalid_limits_cannot_be_constructed() -> None:
    with pytest.raises(BehaviorConfigError):
        BehaviorLimits(memory_mb=64)


# ---------------------------------------------------------------------------
# BehaviorOptions: an option object means "run this", so it must be complete.
# ---------------------------------------------------------------------------


def test_options_reject_the_off_mode_and_require_an_image() -> None:
    with pytest.raises(BehaviorConfigError):
        BehaviorOptions(mode=BehaviorMode.OFF, image=_PINNED)
    with pytest.raises(BehaviorConfigError):
        BehaviorOptions(mode=BehaviorMode.IMPORT, image="python:3.12-slim")


def test_options_expand_all_into_the_fixed_phase_order() -> None:
    limits = BehaviorLimits(total_timeout_seconds=600)
    options = BehaviorOptions(
        mode=BehaviorMode.ALL, image=_PINNED, limits=limits, keep_workdir=True
    )

    assert options.phases == ("import", "test")
    assert options.limits is limits
    assert options.keep_workdir is True
    assert BehaviorOptions(mode=BehaviorMode.TEST, image=_PINNED).phases == ("test",)
    assert BehaviorOptions(mode=BehaviorMode.IMPORT, image=_PINNED).phases == ("import",)
