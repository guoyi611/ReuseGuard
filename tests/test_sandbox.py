"""Tests for the sandbox safety kernel.

No test starts Docker or executes repository code. Every external command goes
through :class:`tests.fakes.FakeCommandRunner`; the single real subprocess test
only asserts that a missing executable is handled.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reuseguard.adapters.sandbox import (
    DEFAULT_IMAGE,
    DEFAULT_MEMORY_MB,
    DEFAULT_PIDS_LIMIT,
    DEFAULT_TIMEOUT_SECONDS,
    CommandResult,
    SandboxConfigError,
    SandboxLimits,
    build_plan,
    detect_docker,
    parse_probe_output,
    run_command,
    run_probe,
)
from reuseguard.models import SandboxStatus
from tests.fakes import FakeCommandRunner


def probe_payload(**overrides) -> dict:
    payload = {
        "python": "3.11.9",
        "files": 3,
        "bytes": 120,
        "symlinks": 0,
        "executables": 0,
        "errors": [],
        "src_writable": False,
        "tmp_writable": True,
        "network_reachable": False,
        "network_target": "1.1.1.1:443",
        "src_entries": 2,
    }
    payload.update(overrides)
    return payload


def probe_stdout(payload: dict | None = None, *, prefix: str = "") -> str:
    body = json.dumps(probe_payload() if payload is None else payload, sort_keys=True)
    return f"{prefix}REUSEGUARD_PROBE {body}\n"


def _ok(stdout: str = "", returncode: int = 0, duration: float = 1.0) -> CommandResult:
    return CommandResult(argv=(), returncode=returncode, stdout=stdout, duration_seconds=duration)


# --- Docker detection -------------------------------------------------------


def test_detect_docker_reports_version() -> None:
    runner = FakeCommandRunner([_ok("27.3.1\n")])

    status = detect_docker(runner=runner)

    assert status.available is True
    assert status.version == "27.3.1"
    assert status.reason is None
    argv, timeout = runner.calls[0]
    assert argv == ("docker", "info", "--format", "{{.ServerVersion}}")
    assert timeout == 5.0


def test_detect_docker_handles_missing_executable() -> None:
    runner = FakeCommandRunner(
        [CommandResult(argv=(), returncode=None, stderr="executable not found")]
    )

    status = detect_docker(runner=runner)

    assert status.available is False
    assert "not found" in (status.reason or "")


def test_detect_docker_handles_daemon_error() -> None:
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=1,
                stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
            )
        ]
    )

    status = detect_docker(runner=runner)

    assert status.available is False
    assert "status 1" in (status.reason or "")
    assert "Cannot connect" in (status.reason or "")


def test_detect_docker_handles_timeout() -> None:
    runner = FakeCommandRunner([CommandResult(argv=(), timed_out=True)])

    status = detect_docker(runner=runner)

    assert status.available is False
    assert "timed out" in (status.reason or "")


def test_detect_docker_rejects_empty_version() -> None:
    runner = FakeCommandRunner([_ok("   \n")])

    status = detect_docker(runner=runner)

    assert status.available is False
    assert "empty version" in (status.reason or "")


def test_detect_docker_rejects_invalid_executable_name() -> None:
    status = detect_docker(docker="docker;rm")

    assert status.available is False
    assert "invalid docker executable" in (status.reason or "")


# --- Hardened command line --------------------------------------------------


def _pair(argv: tuple[str, ...], flag: str) -> str | None:
    for index, value in enumerate(argv[:-1]):
        if value == flag:
            return argv[index + 1]
    return None


def test_build_plan_hardens_the_container(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

    plan = build_plan(tmp_path, container_name="reuseguard-sandbox-test")
    argv = plan.argv

    assert argv[:2] == ("docker", "run")
    assert _pair(argv, "--name") == "reuseguard-sandbox-test"
    assert _pair(argv, "--network") == "none"
    assert "--read-only" in argv
    assert _pair(argv, "--tmpfs") == "/tmp:rw,noexec,nosuid,size=64m"
    assert _pair(argv, "--cap-drop") == "ALL"
    assert _pair(argv, "--security-opt") == "no-new-privileges:true"
    assert _pair(argv, "--user") == "65534:65534"
    assert _pair(argv, "--pids-limit") == str(DEFAULT_PIDS_LIMIT)
    assert _pair(argv, "--memory") == f"{DEFAULT_MEMORY_MB}m"
    assert _pair(argv, "--memory-swap") == f"{DEFAULT_MEMORY_MB}m"
    assert _pair(argv, "--cpus") == "0.5"
    assert _pair(argv, "--ulimit") == "nofile=256:256"
    assert _pair(argv, "--workdir") == "/src"
    assert _pair(argv, "--entrypoint") == "python3"
    assert "--pull=never" in argv
    assert _pair(argv, "--mount") == (f"type=bind,source={tmp_path.resolve()},target=/src,readonly")
    assert DEFAULT_IMAGE in argv
    assert argv[-2] == "-c"
    assert "REUSEGUARD_PROBE" in argv[-1]

    assert "--privileged" not in argv
    assert not any("docker.sock" in part for part in argv)
    assert "--volume" not in argv
    assert "-v" not in argv
    assert plan.mount_target == "/src"
    assert plan.source == tmp_path.resolve()


def test_build_plan_uses_custom_limits(tmp_path: Path) -> None:
    limits = SandboxLimits(
        image="my-registry.example:5000/tools/probe@sha256:abc",
        memory_mb=512,
        cpus=1.5,
        pids_limit=128,
        timeout_seconds=45,
    )

    plan = build_plan(tmp_path, limits=limits, container_name="reuseguard-sandbox-x")

    assert _pair(plan.argv, "--memory") == "512m"
    assert _pair(plan.argv, "--cpus") == "1.5"
    assert _pair(plan.argv, "--pids-limit") == "128"
    assert plan.limits.timeout_seconds == 45


def test_build_plan_rejects_missing_source(tmp_path: Path) -> None:
    with pytest.raises(SandboxConfigError, match="not accessible"):
        build_plan(tmp_path / "missing")


def test_build_plan_rejects_file_source(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    target.write_text("x", encoding="utf-8")

    with pytest.raises(SandboxConfigError, match="not a directory"):
        build_plan(target)


def test_build_plan_rejects_filesystem_root() -> None:
    with pytest.raises(SandboxConfigError, match="filesystem root"):
        build_plan(Path(Path.cwd().anchor))


def test_build_plan_rejects_home_directory() -> None:
    with pytest.raises(SandboxConfigError, match="user home"):
        build_plan(Path.home())


def test_build_plan_rejects_comma_in_path(tmp_path: Path) -> None:
    target = tmp_path / "a,b"
    target.mkdir()

    with pytest.raises(SandboxConfigError, match="commas"):
        build_plan(target)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"image": "-v"},
        {"image": "python:3.11 slim"},
        {"image": ""},
        {"memory_mb": 32},
        {"memory_mb": 8192},
        {"cpus": 0.05},
        {"cpus": 8.0},
        {"pids_limit": 8},
        {"pids_limit": 4096},
        {"timeout_seconds": 0.5},
        {"timeout_seconds": 3600},
    ],
)
def test_sandbox_limits_reject_unsafe_values(kwargs: dict) -> None:
    with pytest.raises(SandboxConfigError):
        SandboxLimits(**kwargs)


def test_sandbox_limits_defaults_are_conservative() -> None:
    limits = SandboxLimits()

    assert limits.image == DEFAULT_IMAGE
    assert limits.memory_mb == DEFAULT_MEMORY_MB
    assert limits.pids_limit == DEFAULT_PIDS_LIMIT
    assert limits.timeout_seconds == DEFAULT_TIMEOUT_SECONDS


# --- Probe execution --------------------------------------------------------


def test_run_probe_completes_and_verifies_containment(tmp_path: Path) -> None:
    runner = FakeCommandRunner(
        [
            _ok(
                probe_stdout(prefix="container boot noise\n"),
                duration=2.4,
            )
        ]
    )

    report = run_probe(tmp_path, runner=runner)

    assert report.status is SandboxStatus.COMPLETED
    assert report.containment_ok is True
    assert report.exit_code == 0
    assert report.duration_seconds == 2.4
    assert report.image == DEFAULT_IMAGE
    assert report.mount_target == "/src"
    assert report.network == "none"
    assert report.memory_mb == DEFAULT_MEMORY_MB
    assert report.probe["files"] == 3
    assert "REUSEGUARD_PROBE" in (report.stdout_tail or "")
    argv, timeout = runner.calls[0]
    assert timeout == DEFAULT_TIMEOUT_SECONDS + 5.0
    assert argv[0] == "docker"
    assert argv[1] == "run"


def test_run_probe_flags_writable_mount(tmp_path: Path) -> None:
    runner = FakeCommandRunner([_ok(probe_stdout(probe_payload(src_writable=True)))])

    report = run_probe(tmp_path, runner=runner)

    assert report.status is SandboxStatus.COMPLETED
    assert report.containment_ok is False


def test_run_probe_flags_reachable_network(tmp_path: Path) -> None:
    runner = FakeCommandRunner([_ok(probe_stdout(probe_payload(network_reachable=True)))])

    report = run_probe(tmp_path, runner=runner)

    assert report.containment_ok is False


def test_run_probe_flags_unreadable_mount(tmp_path: Path) -> None:
    runner = FakeCommandRunner([_ok(probe_stdout(probe_payload(src_entries=None)))])

    report = run_probe(tmp_path, runner=runner)

    assert report.containment_ok is False


def test_run_probe_reports_timeout_and_kills_container(tmp_path: Path) -> None:
    plan = build_plan(tmp_path, container_name="reuseguard-sandbox-timeout")
    runner = FakeCommandRunner(
        [
            CommandResult(argv=(), timed_out=True),
            _ok(""),
        ]
    )

    report = run_probe(tmp_path, runner=runner, plan=plan)

    assert report.status is SandboxStatus.TIMEOUT
    assert report.timed_out is True
    assert report.containment_ok is None
    assert "timeout" in (report.error or "")
    assert "cleanup" not in (report.error or "")
    assert runner.calls[1][0] == ("docker", "rm", "-f", "reuseguard-sandbox-timeout")


def test_run_probe_reports_failed_cleanup(tmp_path: Path) -> None:
    plan = build_plan(tmp_path, container_name="reuseguard-sandbox-timeout")
    runner = FakeCommandRunner(
        [
            CommandResult(argv=(), timed_out=True),
            CommandResult(argv=(), returncode=1, stderr="no such container"),
        ]
    )

    report = run_probe(tmp_path, runner=runner, plan=plan)

    assert report.status is SandboxStatus.TIMEOUT
    assert "cleanup: failed" in (report.error or "")


def test_run_probe_reports_nonzero_exit(tmp_path: Path) -> None:
    runner = FakeCommandRunner(
        [
            CommandResult(
                argv=(),
                returncode=137,
                stderr="Killed",
                duration_seconds=3.0,
            )
        ]
    )

    report = run_probe(tmp_path, runner=runner)

    assert report.status is SandboxStatus.ERROR
    assert report.exit_code == 137
    assert "status 137" in (report.error or "")
    assert report.stderr_tail == "Killed"
    assert report.containment_ok is None


def test_run_probe_requires_machine_readable_output(tmp_path: Path) -> None:
    runner = FakeCommandRunner([_ok("hello from the container\n")])

    report = run_probe(tmp_path, runner=runner)

    assert report.status is SandboxStatus.ERROR
    assert "machine-readable" in (report.error or "")


def test_parse_probe_output_uses_the_last_valid_line() -> None:
    stdout = (
        probe_stdout(probe_payload(files=1))
        + "some trailing log line\n"
        + probe_stdout(probe_payload(files=9))
    )

    payload = parse_probe_output(stdout)

    assert payload is not None
    assert payload["files"] == 9


def test_parse_probe_output_rejects_invalid_json_and_non_objects() -> None:
    assert parse_probe_output("REUSEGUARD_PROBE {not json}\n") is None
    assert parse_probe_output("REUSEGUARD_PROBE [1, 2]\n") is None
    assert parse_probe_output("") is None


def test_run_command_handles_missing_executable() -> None:
    result = run_command(["reuseguard-no-such-executable-xyz"], timeout=1.0)

    assert result.returncode is None
    assert result.timed_out is False
    assert "not found" in result.stderr
