"""Isolation scaffolding for the opt-in dynamic-verification stage.

This module deliberately does **not** execute code from the repository under
test. It does three narrower things:

1. Detect whether a Docker daemon is reachable.
2. Build a hardened ``docker run`` command line from an allow-list of flags.
3. Run a fixed containment probe inside that container: the probe only stats
   files under the read-only mount and checks that ``/src`` is not writable and
   that the network namespace is disconnected.

The probe is ReuseGuard's own code. A completed run is evidence that the
container configuration behaved as expected for one run; it is not evidence
that the repository is harmless. Every external command is executed as an argv
list with ``shell=False`` and an explicit timeout.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..models import SandboxReport, SandboxStatus
from .process import CommandRunner, run_command

DEFAULT_IMAGE = "python:3.11-slim"
DEFAULT_MEMORY_MB = 256
DEFAULT_CPUS = 0.5
DEFAULT_PIDS_LIMIT = 64
DEFAULT_TIMEOUT_SECONDS = 20.0
SANDBOX_MODES = ("off", "auto", "all")

MOUNT_TARGET = "/src"
_TMPFS_MOUNT = "/tmp:rw,noexec,nosuid,size=64m"
_PROBE_PREFIX = "REUSEGUARD_PROBE "
_MAX_CAPTURE_CHARS = 2000
_KILL_TIMEOUT_SECONDS = 10.0
_KILL_GRACE_SECONDS = 5.0
_IMAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]*$")
_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")


class SandboxError(Exception):
    """The sandbox could not be planned or executed."""


class SandboxConfigError(SandboxError):
    """The requested mount source or limits are not acceptable."""


@dataclass(frozen=True)
class DockerStatus:
    """Whether a Docker daemon answered, and why not if it did not."""

    available: bool
    version: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class SandboxLimits:
    """Resource limits applied to one sandbox run."""

    image: str = DEFAULT_IMAGE
    memory_mb: int = DEFAULT_MEMORY_MB
    cpus: float = DEFAULT_CPUS
    pids_limit: int = DEFAULT_PIDS_LIMIT
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if not _IMAGE_PATTERN.fullmatch(self.image):
            raise SandboxConfigError(
                f"invalid sandbox image {self.image!r}; use a registry reference such as "
                "python:3.11-slim"
            )
        if not 64 <= self.memory_mb <= 4096:
            raise SandboxConfigError("sandbox memory must be between 64 and 4096 MB")
        if not 0.1 <= self.cpus <= 4.0:
            raise SandboxConfigError("sandbox CPUs must be between 0.1 and 4.0")
        if not 16 <= self.pids_limit <= 1024:
            raise SandboxConfigError("sandbox PID limit must be between 16 and 1024")
        if not 1.0 <= self.timeout_seconds <= 600.0:
            raise SandboxConfigError("sandbox timeout must be between 1 and 600 seconds")


@dataclass(frozen=True)
class SandboxPlan:
    """A reviewed command line, ready to run or to display without running."""

    argv: tuple[str, ...]
    source: Path
    limits: SandboxLimits
    container_name: str
    mount_target: str = MOUNT_TARGET

    @property
    def command_preview(self) -> str:
        """A human-readable rendering that never goes through a shell."""
        return " ".join(_quote(part) for part in self.argv)


def detect_docker(
    *,
    runner: CommandRunner = run_command,
    docker: str = "docker",
    timeout: float = 5.0,
) -> DockerStatus:
    """Return whether a Docker daemon is reachable without side effects."""
    if not _NAME_PATTERN.fullmatch(docker):
        return DockerStatus(available=False, reason=f"invalid docker executable {docker!r}")

    result = runner([docker, "info", "--format", "{{.ServerVersion}}"], timeout=timeout)
    if result.timed_out:
        return DockerStatus(available=False, reason="docker info timed out")
    if result.returncode is None:
        return DockerStatus(
            available=False,
            reason=result.stderr.strip() or "docker executable not found",
        )
    if result.returncode != 0:
        detail = _tail(result.stderr) or _tail(result.stdout) or "no output"
        return DockerStatus(
            available=False,
            reason=f"docker info exited with status {result.returncode}: {detail}",
        )

    version = result.stdout.strip() or None
    if version is None:
        return DockerStatus(available=False, reason="docker info returned an empty version")
    return DockerStatus(available=True, version=version)


def build_plan(
    source: Path,
    *,
    limits: SandboxLimits | None = None,
    docker: str = "docker",
    container_name: str | None = None,
) -> SandboxPlan:
    """Build the hardened ``docker run`` argv for ``source``.

    The source directory is mounted read-only at ``/src``. The container gets no
    network, no Linux capabilities, no new privileges, a read-only root
    filesystem, a small no-exec ``/tmp``, and hard memory / CPU / PID / file
    descriptor limits. The Docker socket is never mounted and ``--privileged``
    is never used.
    """
    limits = limits or SandboxLimits()
    if not _NAME_PATTERN.fullmatch(docker):
        raise SandboxConfigError(f"invalid docker executable {docker!r}")

    resolved = _validated_source(source)
    name = container_name or f"reuseguard-sandbox-{uuid.uuid4().hex[:12]}"
    if not _NAME_PATTERN.fullmatch(name):
        raise SandboxConfigError(f"invalid container name {name!r}")

    argv = (
        docker,
        "run",
        "--rm",
        "--name",
        name,
        # Never pull implicitly: the image must already be present locally.
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        _TMPFS_MOUNT,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--user",
        "65534:65534",
        "--pids-limit",
        str(limits.pids_limit),
        "--memory",
        f"{limits.memory_mb}m",
        "--memory-swap",
        f"{limits.memory_mb}m",
        "--cpus",
        f"{limits.cpus:g}",
        "--ulimit",
        "nofile=256:256",
        "--workdir",
        MOUNT_TARGET,
        "--mount",
        f"type=bind,source={resolved},target={MOUNT_TARGET},readonly",
        "--entrypoint",
        "python3",
        limits.image,
        "-I",
        "-c",
        _PROBE_SCRIPT,
    )
    return SandboxPlan(
        argv=argv,
        source=resolved,
        limits=limits,
        container_name=name,
    )


def run_probe(
    source: Path,
    *,
    limits: SandboxLimits | None = None,
    docker: str = "docker",
    runner: CommandRunner = run_command,
    plan: SandboxPlan | None = None,
) -> SandboxReport:
    """Run the fixed containment probe in a hardened container.

    The probe never imports, installs, or otherwise executes repository code.
    A timeout kills the container by name before returning.
    """
    limits = limits or SandboxLimits()
    plan = plan or build_plan(source, limits=limits, docker=docker)

    result = runner(plan.argv, timeout=limits.timeout_seconds + _KILL_GRACE_SECONDS)

    common = {
        "image": plan.limits.image,
        "container": plan.container_name,
        "duration_seconds": result.duration_seconds,
        "mount_target": plan.mount_target,
        "network": "none",
        "memory_mb": plan.limits.memory_mb,
        "cpus": plan.limits.cpus,
        "pids_limit": plan.limits.pids_limit,
        "timeout_seconds": plan.limits.timeout_seconds,
        "command": list(plan.argv),
    }

    if result.timed_out:
        kill_detail = _kill_container(plan.container_name, docker=docker, runner=runner)
        error = f"probe exceeded the {plan.limits.timeout_seconds:g}s timeout"
        if kill_detail:
            error += f"; container cleanup: {kill_detail}"
        return SandboxReport(
            status=SandboxStatus.TIMEOUT,
            timed_out=True,
            stdout_tail=_tail(result.stdout),
            stderr_tail=_tail(result.stderr),
            error=error,
            **common,
        )

    if result.returncode != 0:
        detail = _tail(result.stderr) or _tail(result.stdout) or "no output"
        return SandboxReport(
            status=SandboxStatus.ERROR,
            exit_code=result.returncode,
            stdout_tail=_tail(result.stdout),
            stderr_tail=_tail(result.stderr),
            error=f"docker run exited with status {result.returncode}: {detail}",
            **common,
        )

    payload = parse_probe_output(result.stdout)
    if payload is None:
        return SandboxReport(
            status=SandboxStatus.ERROR,
            exit_code=result.returncode,
            stdout_tail=_tail(result.stdout),
            stderr_tail=_tail(result.stderr),
            error="the container did not emit a machine-readable probe result",
            **common,
        )

    containment_ok = (
        payload.get("src_writable") is False
        and payload.get("network_reachable") is False
        and payload.get("src_entries") is not None
    )
    return SandboxReport(
        status=SandboxStatus.COMPLETED,
        exit_code=result.returncode,
        oom_suspected=result.returncode == 137,
        containment_ok=containment_ok,
        probe=payload,
        stdout_tail=_tail(result.stdout),
        stderr_tail=_tail(result.stderr),
        **common,
    )


def parse_probe_output(stdout: str) -> dict | None:
    """Extract the last ``REUSEGUARD_PROBE {json}`` line from container output."""
    for line in reversed(stdout.splitlines()):
        if line.startswith(_PROBE_PREFIX):
            try:
                payload = json.loads(line[len(_PROBE_PREFIX) :])
            except json.JSONDecodeError:
                return None
            return payload if isinstance(payload, dict) else None
    return None


def _validated_source(source: Path) -> Path:
    raw = str(source)
    if "," in raw or "\n" in raw or "\r" in raw:
        raise SandboxConfigError(
            "the sandbox source path must not contain commas or newlines; "
            "Docker mounts cannot represent them safely"
        )
    try:
        resolved = source.resolve(strict=True)
    except OSError as exc:
        raise SandboxConfigError(f"sandbox source is not accessible: {source}") from exc
    if not resolved.is_dir():
        raise SandboxConfigError(f"sandbox source is not a directory: {resolved}")
    if resolved.parent == resolved:
        raise SandboxConfigError("refusing to mount a filesystem root into the sandbox")

    try:
        home = Path.home().resolve()
    except OSError:  # pragma: no cover - defensive on exotic filesystems
        home = None
    if home is not None and (resolved == home or home.is_relative_to(resolved)):
        raise SandboxConfigError(
            "refusing to mount the user home directory or one of its ancestors"
        )
    return resolved


def _kill_container(container: str, *, docker: str, runner: CommandRunner) -> str:
    """Best-effort cleanup after a timeout; never raises."""
    try:
        result = runner([docker, "rm", "-f", container], timeout=_KILL_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask the timeout
        return f"failed ({exc})"
    if result.timed_out:
        return "failed (docker rm timed out)"
    if result.returncode not in (0, None):
        return f"failed (exit {result.returncode})"
    return ""


def _tail(value: str, limit: int = _MAX_CAPTURE_CHARS) -> str | None:
    text = (value or "").strip()
    if not text:
        return None
    return text[-limit:]


def _quote(value: str) -> str:
    if value and all(character.isalnum() or character in "._-/:@=+," for character in value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


# The probe is fixed, reviewed code. It only reads directory metadata and tests
# the mount and network configuration; it never imports or runs repository files.
_PROBE_SCRIPT = r"""
import json
import os
import socket
import sys

result = {
    "python": sys.version.split()[0],
    "files": 0,
    "bytes": 0,
    "symlinks": 0,
    "executables": 0,
    "errors": [],
    "src_writable": None,
    "tmp_writable": None,
    "network_reachable": None,
    "network_target": "1.1.1.1:443",
}

root = "/src"
max_entries = 20000
scanned = 0

try:
    result["src_entries"] = len(os.listdir(root))
except OSError as exc:
    result["src_entries"] = None
    result["errors"].append("cannot list /src: " + type(exc).__name__)


def _walk_error(exc):
    result["errors"].append("walk failed: " + type(exc).__name__)


for dirpath, dirnames, filenames in os.walk(root, onerror=_walk_error):
    for name in filenames:
        scanned += 1
        if scanned > max_entries:
            result["errors"].append("file scan truncated at 20000 entries")
            break
        path = os.path.join(dirpath, name)
        try:
            info = os.lstat(path)
        except OSError:
            result["errors"].append("stat failed: " + path)
            continue
        result["files"] += 1
        result["bytes"] += info.st_size
        if os.path.islink(path):
            result["symlinks"] += 1
        elif info.st_mode & 0o111:
            result["executables"] += 1
    if scanned > max_entries:
        break

try:
    with open("/src/.reuseguard-probe-write", "ab"):
        pass
    result["src_writable"] = True
except OSError:
    result["src_writable"] = False

try:
    with open("/tmp/.reuseguard-probe", "wb") as handle:
        handle.write(b"ok")
    result["tmp_writable"] = True
except OSError:
    result["tmp_writable"] = False

sock = socket.socket()
sock.settimeout(2.0)
try:
    sock.connect(("1.1.1.1", 443))
    result["network_reachable"] = True
except OSError as exc:
    result["network_reachable"] = False
    result["network_error"] = type(exc).__name__
finally:
    sock.close()

print("REUSEGUARD_PROBE " + json.dumps(result, sort_keys=True))
"""
