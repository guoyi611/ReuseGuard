"""A tiny, injectable subprocess boundary.

Adapters that shell out (sandbox, Semgrep, and later OSV/gitleaks) all use this
module so that every external command is executed as an argv list with
``shell=False``, a hard timeout, and captured output that tests can replace with
a fake runner.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class CommandResult:
    """The result of one local command invocation."""

    argv: tuple[str, ...]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_seconds: float = 0.0


class CommandRunner(Protocol):
    """Callable that executes an argv list and never uses a shell."""

    def __call__(self, argv: Sequence[str], *, timeout: float) -> CommandResult: ...


def run_command(argv: Sequence[str], *, timeout: float) -> CommandResult:
    """Run a local command without a shell, capturing bounded output."""
    started = time.monotonic()
    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(
            argv=tuple(argv),
            returncode=None,
            stderr="executable not found",
            duration_seconds=round(time.monotonic() - started, 2),
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=tuple(argv),
            returncode=None,
            stdout=_as_text(exc.stdout),
            stderr=_as_text(exc.stderr),
            timed_out=True,
            duration_seconds=round(time.monotonic() - started, 2),
        )
    except OSError as exc:
        return CommandResult(
            argv=tuple(argv),
            returncode=None,
            stderr=f"could not start command: {exc}",
            duration_seconds=round(time.monotonic() - started, 2),
        )

    return CommandResult(
        argv=tuple(argv),
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        duration_seconds=round(time.monotonic() - started, 2),
    )


def _as_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
