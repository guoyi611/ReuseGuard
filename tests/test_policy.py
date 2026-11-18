"""Tests for YAML policy loading and policy-driven CLI settings."""

from __future__ import annotations

from pathlib import Path

import pytest

from reuseguard import cli
from reuseguard.config import ConfigError, Settings, load_policy
from reuseguard.demo import build_demo_report
from reuseguard.models import RiskLevel
from tests.test_cli import _DummyClient


def _write_policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "reuseguard.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_full_policy(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
version: 1
thresholds:
  scorecard_min: 3.0
  use_scorecard_min: 6.0
limits:
  max_candidates: 2
  min_stars: 10
  max_repo_mb: 20
  max_files: 50
  max_file_kb: 128
  max_scan_mb: 2
  timeout: 5.0
features:
  recall: false
  scorecard: true
  scan: true
rules:
  disable:
    - generic-secret
  severity:
    py-eval-exec: high
suppress:
  paths:
    - "src/generated/**"
""",
    )

    policy = load_policy(path)

    assert policy.scorecard_min == 3.0
    assert policy.use_scorecard_min == 6.0
    assert policy.max_candidates == 2
    assert policy.min_stars == 10
    assert policy.timeout == 5.0
    assert policy.recall is False
    assert policy.scorecard is True
    assert policy.disabled_rules == frozenset({"generic-secret"})
    assert policy.severity_overrides["py-eval-exec"] is RiskLevel.HIGH
    assert policy.suppress_paths == ("src/generated/**",)


def test_empty_policy_uses_defaults(tmp_path: Path) -> None:
    policy = load_policy(_write_policy(tmp_path, ""))

    assert policy.max_candidates is None
    assert policy.disabled_rules == frozenset()
    assert policy.severity_overrides == {}


@pytest.mark.parametrize(
    "text",
    [
        "thresholds: []\n",
        "unknown_section: {}\n",
        "rules:\n  disable: [not-a-rule]\n",
        "rules:\n  severity: {py-eval-exec: severe}\n",
        "limits:\n  max_files: -1\n",
        "features:\n  scan: 1\n",
        "version: 2\n",
    ],
)
def test_invalid_policy_is_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_policy(_write_policy(tmp_path, text))


def test_cli_applies_policy_and_keeps_flag_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(
        tmp_path,
        """
limits:
  max_candidates: 2
  min_stars: 10
thresholds:
  use_scorecard_min: 6.0
features:
  scan: true
rules:
  disable: [generic-secret]
suppress:
  paths: ["src/generated/**"]
""",
    )
    captured: dict[str, Settings] = {}

    class _CapturePipeline:
        def __init__(self, settings, _github, _scorecard) -> None:
            captured["settings"] = settings

        def run(self, _ref):
            return build_demo_report()

    monkeypatch.setattr(cli, "GitHubClient", _DummyClient)
    monkeypatch.setattr(cli, "ScorecardClient", _DummyClient)
    monkeypatch.setattr(cli, "Pipeline", _CapturePipeline)
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(
        [
            "check",
            "acme/seed",
            "--config",
            str(path),
            "--no-scan",
            "--min-stars",
            "99",
            "--quiet",
        ]
    )

    assert code == 0
    settings = captured["settings"]
    assert settings.max_candidates == 2
    assert settings.min_stars == 99
    assert settings.timeout == 20.0
    assert settings.use_scorecard_min == 6.0
    assert settings.enable_scan is False
    assert settings.disabled_rules == frozenset({"generic-secret"})
    assert settings.suppress_paths == ("src/generated/**",)
    assert settings.config_path == str(path)
    assert settings.severity_overrides == {}


def test_cli_rejects_invalid_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_policy(tmp_path, "rules:\n  disable: [not-a-rule]\n")
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(["check", "acme/seed", "--config", str(path)])

    assert code == 2


# ---------------------------------------------------------------------------
# External rule IDs (gitleaks:, osv:, semgrep: prefixes)
# ---------------------------------------------------------------------------


def test_external_rule_ids_in_disable(tmp_path: Path) -> None:
    """External scanner rule IDs with known prefixes are accepted in rules.disable."""
    path = _write_policy(
        tmp_path,
        """
rules:
  disable:
    - gitleaks:aws-access-token
    - osv:GHSA-abcd-1234-wxyz
    - semgrep:python.lang.security.eval-detected
""",
    )
    policy = load_policy(path)
    assert policy.disabled_rules == frozenset(
        {
            "gitleaks:aws-access-token",
            "osv:GHSA-abcd-1234-wxyz",
            "semgrep:python.lang.security.eval-detected",
        }
    )


def test_external_rule_ids_in_severity(tmp_path: Path) -> None:
    """External scanner rule IDs with known prefixes are accepted in rules.severity."""
    path = _write_policy(
        tmp_path,
        """
rules:
  severity:
    gitleaks:private-key: high
    osv:CVE-2024-12345: critical
    semgrep:javascript.express.security.audit.xss: medium
""",
    )
    policy = load_policy(path)
    assert policy.severity_overrides["gitleaks:private-key"] is RiskLevel.HIGH
    assert policy.severity_overrides["osv:CVE-2024-12345"] is RiskLevel.CRITICAL
    assert (
        policy.severity_overrides["semgrep:javascript.express.security.audit.xss"]
        is RiskLevel.MEDIUM
    )


def test_mixed_builtin_and_external_rules(tmp_path: Path) -> None:
    """Built-in and external rule IDs can coexist in the same policy."""
    path = _write_policy(
        tmp_path,
        """
rules:
  disable:
    - generic-secret
    - gitleaks:generic-api-key
  severity:
    py-eval-exec: high
    osv:GHSA-xxxx-yyyy-zzzz: low
""",
    )
    policy = load_policy(path)
    assert policy.disabled_rules == frozenset({"generic-secret", "gitleaks:generic-api-key"})
    assert policy.severity_overrides["py-eval-exec"] is RiskLevel.HIGH
    assert policy.severity_overrides["osv:GHSA-xxxx-yyyy-zzzz"] is RiskLevel.LOW


@pytest.mark.parametrize(
    "text",
    [
        # Unknown prefix
        "rules:\n  disable: [unknown-tool:some-rule]\n",
        # Bare colon without known prefix
        "rules:\n  disable: [custom:rule]\n",
        # Empty prefix (starts with colon)
        "rules:\n  disable: [:some-rule]\n",
        # Unknown prefix in severity
        "rules:\n  severity: {bandit:B101: high}\n",
        # Typo in known prefix
        "rules:\n  disable: [gitleak:aws-access-token]\n",
    ],
)
def test_unknown_external_prefix_is_rejected(tmp_path: Path, text: str) -> None:
    """Rule IDs with unknown prefixes are rejected as ConfigError."""
    with pytest.raises(ConfigError):
        load_policy(_write_policy(tmp_path, text))


def test_external_rule_with_invalid_severity_is_rejected(tmp_path: Path) -> None:
    """External rule IDs still require valid severity values."""
    with pytest.raises(ConfigError):
        load_policy(
            _write_policy(
                tmp_path,
                "rules:\n  severity: {gitleaks:aws-access-token: severe}\n",
            )
        )


def test_merge_scan_reports_dedup_unaffected_by_external_ids(tmp_path: Path) -> None:
    """merge_scan_reports() deduplication works correctly with external rule IDs.

    This verifies that external rule IDs don't break the existing dedup logic.
    The merge function operates on ScanReport/Finding objects, not config, so
    this is a sanity check that the pipeline still works end-to-end.
    """
    from reuseguard.models import Finding, RiskLevel, ScanReport, ScanStatus, merge_scan_reports

    report_a = ScanReport(
        status=ScanStatus.SCANNED,
        risk=RiskLevel.HIGH,
        findings=[
            Finding(
                rule_id="gitleaks:aws-access-token",
                title="AWS token",
                severity=RiskLevel.HIGH,
                category="secret",
                path="src/config.py",
                line=10,
                message="found",
            ),
        ],
        files_scanned=5,
        scanner="gitleaks",
    )
    report_b = ScanReport(
        status=ScanStatus.SCANNED,
        risk=RiskLevel.HIGH,
        findings=[
            Finding(
                rule_id="gitleaks:aws-access-token",
                title="AWS token",
                severity=RiskLevel.HIGH,
                category="secret",
                path="src/config.py",
                line=10,
                message="found again",
            ),
        ],
        files_scanned=3,
        scanner="builtin-patterns",
    )
    merged = merge_scan_reports([report_a, report_b])
    # Same (rule_id, path, line) should be deduplicated to one finding
    assert len(merged.findings) == 1
    assert merged.findings[0].rule_id == "gitleaks:aws-access-token"


# ---------------------------------------------------------------------------
# Behavior section (M4): limits may be tuned, the run may never be enabled.
# ---------------------------------------------------------------------------

_PINNED_IMAGE = "python@sha256:" + "0123456789abcdef" * 4


def test_behavior_section_accepts_pinned_image_and_limits(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        f"""
behavior:
  image: "{_PINNED_IMAGE}"
  timeout_seconds: 600
  phase_timeout_seconds: 240
  memory_mb: 1024
  cpus: 2.5
  pids: 256
  max_work_mb: 1024
  max_work_files: 10000
""",
    )

    behavior = load_policy(path).behavior

    assert behavior.image == _PINNED_IMAGE
    assert behavior.timeout_seconds == 600.0
    assert behavior.phase_timeout_seconds == 240.0
    assert behavior.memory_mb == 1024
    assert behavior.cpus == 2.5
    assert behavior.pids == 256
    assert behavior.max_work_mb == 1024
    assert behavior.max_work_files == 10000
    assert behavior.empty is False


def test_behavior_section_is_absent_by_default(tmp_path: Path) -> None:
    assert load_policy(_write_policy(tmp_path, "limits:\n  max_files: 10\n")).behavior.empty


@pytest.mark.parametrize(
    "text",
    [
        # Enabling execution of untrusted code is never a policy decision.
        "behavior:\n  enabled: true\n",
        "behavior:\n  enabled: false\n",
        "behavior:\n  mode: all\n",
        "behavior:\n  keep_workdir: true\n",
        "behavior:\n  keep_work_dir: true\n",
        # Unknown keys are still typos, not silent no-ops.
        "behavior:\n  timeout: 600\n",
        "behavior:\n  image_sha: x\n",
        # The image has to be pinned by digest, exactly like the CLI flag.
        "behavior:\n  image: python:3.12-slim\n",
        "behavior:\n  image: python\n",
        "behavior:\n  image: 42\n",
        # Bounds are the documented ones, not arbitrary.
        "behavior:\n  timeout_seconds: 5\n",
        "behavior:\n  timeout_seconds: 3600\n",
        "behavior:\n  phase_timeout_seconds: 1\n",
        "behavior:\n  memory_mb: 64\n",
        "behavior:\n  cpus: 8\n",
        "behavior:\n  pids: 4\n",
        "behavior:\n  max_work_mb: 8192\n",
        "behavior:\n  max_work_files: 10\n",
        # Types must be explicit.
        "behavior:\n  memory_mb: 512.5\n",
        "behavior:\n  memory_mb: true\n",
        "behavior:\n  timeout_seconds: fast\n",
        "behavior: [1, 2]\n",
        "behavior: enabled\n",
    ],
)
def test_behavior_section_rejects_enabling_and_invalid_values(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_policy(_write_policy(tmp_path, text))


def test_behavior_enabled_error_explains_the_rule(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_policy(_write_policy(tmp_path, "behavior:\n  enabled: true\n"))

    message = str(excinfo.value)
    assert "behavior.enabled" in message
    assert "--behavior" in message


def test_cli_applies_behavior_policy_limits_and_keeps_flag_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(
        tmp_path,
        f"""
behavior:
  image: "{_PINNED_IMAGE}"
  timeout_seconds: 600
  phase_timeout_seconds: 240
  memory_mb: 1024
  cpus: 2.5
  max_work_files: 10000
""",
    )
    captured: dict[str, Settings] = {}

    class _CapturePipeline:
        def __init__(self, settings, _github, _scorecard) -> None:
            captured["settings"] = settings

        def run(self, _ref):
            return build_demo_report()

    monkeypatch.setattr(cli, "GitHubClient", _DummyClient)
    monkeypatch.setattr(cli, "ScorecardClient", _DummyClient)
    monkeypatch.setattr(cli, "Pipeline", _CapturePipeline)
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(
        [
            "check",
            "acme/seed",
            "--config",
            str(path),
            # The policy pins the image, so the flag is optional here.
            "--behavior",
            "import",
            "--behavior-memory-mb",
            "2048",
            "--quiet",
        ]
    )

    assert code == 0
    settings = captured["settings"]
    assert settings.behavior_mode == "import"
    assert settings.behavior_image == _PINNED_IMAGE
    assert settings.behavior_timeout == 600.0
    assert settings.behavior_phase_timeout == 240.0
    # Explicit CLI value wins over YAML.
    assert settings.behavior_memory_mb == 2048
    assert settings.behavior_cpus == 2.5
    assert settings.behavior_max_work_files == 10000
    # Unset in YAML and on the CLI: the built-in default still applies.
    assert settings.behavior_pids == 128
    assert settings.behavior_max_work_mb == 512


def test_cli_behavior_image_flag_overrides_the_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = "ghcr.io/acme/runner@sha256:" + "fedcba9876543210" * 4
    path = _write_policy(tmp_path, f'behavior:\n  image: "{_PINNED_IMAGE}"\n')
    captured: dict[str, Settings] = {}

    class _CapturePipeline:
        def __init__(self, settings, _github, _scorecard) -> None:
            captured["settings"] = settings

        def run(self, _ref):
            return build_demo_report()

    monkeypatch.setattr(cli, "GitHubClient", _DummyClient)
    monkeypatch.setattr(cli, "ScorecardClient", _DummyClient)
    monkeypatch.setattr(cli, "Pipeline", _CapturePipeline)
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    code = cli.main(
        [
            "check",
            "acme/seed",
            "--config",
            str(path),
            "--behavior",
            "--behavior-image",
            other,
            "--quiet",
        ]
    )

    assert code == 0
    assert captured["settings"].behavior_image == other


def test_behavior_policy_alone_does_not_enable_a_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_policy(
        tmp_path,
        f'behavior:\n  image: "{_PINNED_IMAGE}"\n  timeout_seconds: 600\n',
    )
    captured: dict[str, Settings] = {}

    class _CapturePipeline:
        def __init__(self, settings, _github, _scorecard) -> None:
            captured["settings"] = settings

        def run(self, _ref):
            return build_demo_report()

    monkeypatch.setattr(cli, "GitHubClient", _DummyClient)
    monkeypatch.setattr(cli, "ScorecardClient", _DummyClient)
    monkeypatch.setattr(cli, "Pipeline", _CapturePipeline)
    monkeypatch.setattr(cli, "resolve_github_token", lambda **_kwargs: None)

    assert cli.main(["check", "acme/seed", "--config", str(path), "--quiet"]) == 0

    settings = captured["settings"]
    assert settings.behavior_mode == "off"
    assert settings.behavior_image is None
