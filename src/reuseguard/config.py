"""Runtime settings, policy-file loading, and credential resolution."""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import __version__
from .adapters.sandbox import (
    DEFAULT_CPUS,
    DEFAULT_IMAGE,
    DEFAULT_MEMORY_MB,
    DEFAULT_PIDS_LIMIT,
    DEFAULT_TIMEOUT_SECONDS,
    SANDBOX_MODES,
)
from .adapters.scanner import KNOWN_RULE_IDS
from .models import RiskLevel

DEFAULT_USER_AGENT = f"reuseguard/{__version__}"

_POLICY_VERSION = 1
_TOP_LEVEL_KEYS = {"version", "thresholds", "limits", "features", "rules", "suppress"}
_THRESHOLD_KEYS = {"scorecard_min", "use_scorecard_min"}
_LIMIT_KEYS = {
    "max_candidates",
    "min_stars",
    "max_repo_mb",
    "max_files",
    "max_file_kb",
    "max_scan_mb",
    "timeout",
}
_FEATURE_KEYS = {"recall", "scorecard", "scan"}
_RULE_KEYS = {"disable", "severity"}
_SUPPRESS_KEYS = {"paths"}


class ConfigError(Exception):
    """A policy file is unreadable, malformed, or uses unknown keys."""


@dataclass(frozen=True)
class Policy:
    """Optional policy overrides loaded from YAML.

    ``None`` means "not specified"; the CLI decides whether to use a built-in
    default or an explicit command-line value.
    """

    scorecard_min: float | None = None
    use_scorecard_min: float | None = None
    max_candidates: int | None = None
    min_stars: int | None = None
    max_repo_mb: int | None = None
    max_files: int | None = None
    max_file_kb: int | None = None
    max_scan_mb: int | None = None
    timeout: float | None = None
    recall: bool | None = None
    scorecard: bool | None = None
    scan: bool | None = None
    disabled_rules: frozenset[str] = frozenset()
    severity_overrides: dict[str, RiskLevel] = field(default_factory=dict)
    suppress_paths: tuple[str, ...] = ()


def load_policy(path: Path) -> Policy:
    """Load and validate a YAML policy file.

    Unknown keys and unknown rule IDs are hard errors: a typo in a policy file
    should never silently weaken a security decision.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"could not read policy file {path}: {exc}") from exc

    try:
        payload = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc

    if payload is None:
        return Policy()
    if not isinstance(payload, dict):
        raise ConfigError("policy file must contain a YAML mapping at the top level")

    _reject_unknown(payload, _TOP_LEVEL_KEYS, "top-level")
    version = payload.get("version", _POLICY_VERSION)
    if version != _POLICY_VERSION:
        raise ConfigError(f"unsupported policy version {version!r}; expected {_POLICY_VERSION}")

    thresholds = _section(payload, "thresholds", _THRESHOLD_KEYS)
    limits = _section(payload, "limits", _LIMIT_KEYS)
    features = _section(payload, "features", _FEATURE_KEYS)
    rules = _section(payload, "rules", _RULE_KEYS)
    suppress = _section(payload, "suppress", _SUPPRESS_KEYS)

    disabled = _rule_ids(rules.get("disable", []), "rules.disable")
    overrides = _severity_overrides(rules.get("severity", {}))

    return Policy(
        scorecard_min=_number(
            thresholds.get("scorecard_min"),
            "thresholds.scorecard_min",
            minimum=0,
            maximum=10,
        ),
        use_scorecard_min=_number(
            thresholds.get("use_scorecard_min"),
            "thresholds.use_scorecard_min",
            minimum=0,
            maximum=10,
        ),
        max_candidates=_integer(
            limits.get("max_candidates"),
            "limits.max_candidates",
            minimum=0,
            maximum=50,
        ),
        min_stars=_integer(limits.get("min_stars"), "limits.min_stars", minimum=0),
        max_repo_mb=_integer(limits.get("max_repo_mb"), "limits.max_repo_mb", minimum=1),
        max_files=_integer(limits.get("max_files"), "limits.max_files", minimum=1),
        max_file_kb=_integer(limits.get("max_file_kb"), "limits.max_file_kb", minimum=1),
        max_scan_mb=_integer(limits.get("max_scan_mb"), "limits.max_scan_mb", minimum=1),
        timeout=_number(limits.get("timeout"), "limits.timeout", minimum=0.001),
        recall=_boolean(features.get("recall"), "features.recall"),
        scorecard=_boolean(features.get("scorecard"), "features.scorecard"),
        scan=_boolean(features.get("scan"), "features.scan"),
        disabled_rules=disabled,
        severity_overrides=overrides,
        suppress_paths=_string_list(suppress.get("paths", []), "suppress.paths"),
    )


def resolve_github_token(*, allow_gh_cli: bool = True) -> str | None:
    """Resolve a GitHub token from the environment, then optionally from ``gh``.

    Using an authenticated token raises the REST limit from 60 to 5,000 requests
    per hour and is strongly recommended. The token is never written to a report
    or printed.
    """
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name, "").strip()
        if value:
            return value

    if allow_gh_cli and shutil.which("gh"):
        try:
            completed = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        token = completed.stdout.strip()
        if completed.returncode == 0 and token:
            return token
    return None


@dataclass(frozen=True)
class Settings:
    """All knobs that influence a pipeline run."""

    token: str | None = None
    timeout: float = 20.0
    max_candidates: int = 5
    min_stars: int = 50
    max_repo_mb: int = 150
    max_files: int = 2000
    max_file_kb: int = 1024
    max_scan_mb: int = 20
    scorecard_min: float = 2.0
    use_scorecard_min: float = 5.0
    enable_recall: bool = True
    enable_scorecard: bool = True
    enable_scan: bool = True
    discover_only: bool = False
    semgrep_config: str | None = None
    semgrep_timeout: float = 300.0
    semgrep_rule_timeout: float = 30.0
    enable_gitleaks: bool = False
    gitleaks_timeout: float = 300.0
    gitleaks_config: str | None = None
    enable_osv: bool = False
    osv_timeout: float = 300.0
    osv_no_resolve: bool = True
    osv_offline_db: str | None = None
    sandbox_mode: str = "off"
    sandbox_image: str = DEFAULT_IMAGE
    sandbox_timeout: float = DEFAULT_TIMEOUT_SECONDS
    sandbox_memory_mb: int = DEFAULT_MEMORY_MB
    sandbox_cpus: float = DEFAULT_CPUS
    sandbox_pids_limit: int = DEFAULT_PIDS_LIMIT
    keep_workdir: bool = False
    disabled_rules: frozenset[str] = frozenset()
    severity_overrides: dict[str, RiskLevel] = field(default_factory=dict)
    suppress_paths: tuple[str, ...] = ()
    config_path: str | None = None
    user_agent: str = DEFAULT_USER_AGENT

    def __post_init__(self) -> None:
        if self.sandbox_mode not in SANDBOX_MODES:
            raise ValueError(
                f"invalid sandbox mode {self.sandbox_mode!r}; expected one of "
                f"{', '.join(SANDBOX_MODES)}"
            )

    def public_dict(self) -> dict[str, Any]:
        """Serialize settings without leaking the token."""
        data = {
            field.name: getattr(self, field.name)
            for field in dataclasses.fields(self)
            if field.name != "token"
        }
        data["token_configured"] = bool(self.token)
        data["disabled_rules"] = sorted(self.disabled_rules)
        data["severity_overrides"] = {
            rule_id: severity.value for rule_id, severity in self.severity_overrides.items()
        }
        data["suppress_paths"] = list(self.suppress_paths)
        return data


def _section(payload: dict[str, Any], key: str, allowed: set[str]) -> dict[str, Any]:
    value = payload.get(key, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be a mapping")
    _reject_unknown(value, allowed, key)
    return value


def _reject_unknown(payload: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ConfigError(f"unknown {context} key(s): {', '.join(unknown)}")


def _rule_ids(value: Any, context: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{context} must be a list of rule IDs")
    unknown = sorted(set(value) - KNOWN_RULE_IDS)
    if unknown:
        raise ConfigError(f"unknown rule ID(s) in {context}: {', '.join(unknown)}")
    return frozenset(value)


def _severity_overrides(value: Any) -> dict[str, RiskLevel]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError("rules.severity must be a mapping of rule ID to severity")
    overrides: dict[str, RiskLevel] = {}
    for rule_id, severity in value.items():
        if not isinstance(rule_id, str) or rule_id not in KNOWN_RULE_IDS:
            raise ConfigError(f"unknown rule ID in rules.severity: {rule_id!r}")
        if not isinstance(severity, str):
            raise ConfigError(f"severity for {rule_id} must be a string")
        try:
            overrides[rule_id] = RiskLevel(severity.lower())
        except ValueError as exc:
            raise ConfigError(
                f"invalid severity {severity!r} for {rule_id}; "
                "expected low, medium, high, or critical"
            ) from exc
    return overrides


def _string_list(value: Any, context: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{context} must be a list of glob patterns")
    return tuple(value)


def _number(
    value: Any,
    context: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{context} must be a number")
    number = float(value)
    if minimum is not None and number < minimum:
        raise ConfigError(f"{context} must be at least {minimum}")
    if maximum is not None and number > maximum:
        raise ConfigError(f"{context} must be at most {maximum}")
    return number


def _integer(
    value: Any,
    context: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{context} must be an integer")
    if minimum is not None and value < minimum:
        raise ConfigError(f"{context} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{context} must be at most {maximum}")
    return value


def _boolean(value: Any, context: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ConfigError(f"{context} must be true or false")
    return value
