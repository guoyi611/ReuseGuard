"""The orchestration pipeline.

The pipeline owns sequencing, timeouts, temporary directories, and the decision
to skip expensive work. It knows nothing about GitHub JSON or regexes; adapters
and stages do that work.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import stat
import tempfile
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import httpx

from . import __version__
from .adapters.github import GitHubClient
from .adapters.gitleaks import (
    GitleaksError,
    GitleaksOptions,
    GitleaksScanner,
    GitleaksUnavailable,
)
from .adapters.osv import (
    OsvError,
    OsvOptions,
    OsvScanner,
    OsvUnavailable,
)
from .adapters.sandbox import (
    CommandRunner,
    DockerStatus,
    SandboxError,
    SandboxLimits,
    detect_docker,
    run_command,
    run_probe,
)
from .adapters.scanner import ScanLimits, scan_directory
from .adapters.scorecard import ScorecardClient
from .adapters.semgrep import (
    SemgrepError,
    SemgrepOptions,
    SemgrepScanner,
    SemgrepUnavailable,
)
from .adapters.snapshot import Snapshot, SnapshotError, SnapshotTooLarge, fetch_snapshot
from .config import Settings
from .models import (
    Assessment,
    Candidate,
    FilterResult,
    FilterStatus,
    RepoMeta,
    RepoRef,
    Report,
    RiskLevel,
    SandboxReport,
    SandboxStatus,
    ScanReport,
    ScanStatus,
    merge_scan_reports,
)
from .stages.recall import recall_idea, recall_similar
from .stages.reputation import evaluate_reputation
from .stages.verdict import add_sandbox_caveat, decide

logger = logging.getLogger("reuseguard")


class Pipeline:
    """Run recall, reputation filtering, static scanning, and aggregation."""

    def __init__(
        self,
        settings: Settings,
        github: GitHubClient,
        scorecard: ScorecardClient,
        *,
        snapshot_client: httpx.Client | None = None,
        scan_fn: Callable[..., ScanReport] = scan_directory,
        snapshot_fn: Callable[..., Snapshot] = fetch_snapshot,
        sandbox_runner: CommandRunner = run_command,
        sandbox_detect: Callable[..., DockerStatus] = detect_docker,
        semgrep_runner: CommandRunner = run_command,
        gitleaks_runner: CommandRunner = run_command,
        osv_runner: CommandRunner = run_command,
    ) -> None:
        self.settings = settings
        self.github = github
        self.scorecard = scorecard
        self._snapshot_client = snapshot_client
        self._scan_fn = scan_fn
        self._snapshot_fn = snapshot_fn
        self._sandbox_runner = sandbox_runner
        self._sandbox_detect = sandbox_detect
        self._semgrep_runner = semgrep_runner
        self._gitleaks_runner = gitleaks_runner
        self._osv_runner = osv_runner

    def run(self, seed_ref: RepoRef) -> Report:
        started = time.monotonic()
        warnings: list[str] = []

        logger.info("Fetching metadata for %s", seed_ref.full_name)
        seed = self.github.get_repo(seed_ref)
        candidates: list[Candidate] = [Candidate(repo=seed, role="seed")]
        queries: list[str] = []

        if self.settings.enable_recall and self.settings.max_candidates > 0:
            logger.info("Searching GitHub for similar repositories")
            recall = recall_similar(
                seed,
                self.github,
                limit=self.settings.max_candidates,
                min_stars=self.settings.min_stars,
            )
            queries = recall.queries
            warnings.extend(recall.warnings)
            candidates.extend(recall.candidates)
            logger.info(
                "Found %d alternative(s) using %d search queries",
                len(recall.candidates),
                len(recall.queries),
            )

        return self._execute(
            candidates,
            started=started,
            warnings=warnings,
            queries=queries,
            seed=seed,
            query=None,
        )

    def run_idea(self, idea: str, *, language: str | None = None) -> Report:
        """Run discovery from a natural-language requirement instead of a seed repo."""
        started = time.monotonic()
        warnings: list[str] = []

        logger.info("Searching GitHub for repositories matching an idea")
        recall = recall_idea(
            idea,
            self.github,
            limit=self.settings.max_candidates,
            min_stars=self.settings.min_stars,
            language=language,
            strict=self.settings.strict_idea,
        )
        warnings.extend(recall.warnings)
        if not recall.candidates:
            warnings.append("No candidate repositories were found for this idea.")
        logger.info(
            "Found %d candidate(s) using %d search queries",
            len(recall.candidates),
            len(recall.queries),
        )

        return self._execute(
            recall.candidates,
            started=started,
            warnings=warnings,
            queries=recall.queries,
            seed=None,
            query=idea,
        )

    def _execute(
        self,
        candidates: list[Candidate],
        *,
        started: float,
        warnings: list[str],
        queries: list[str],
        seed: RepoMeta | None,
        query: str | None,
    ) -> Report:
        workdir = Path(tempfile.mkdtemp(prefix="reuseguard-"))
        # The sandbox runs as an unprivileged user, so the snapshot chain must be
        # traversable. Nothing in the snapshot is world-writable.
        with contextlib.suppress(OSError):
            os.chmod(workdir, 0o755)
        logger.debug("Working directory: %s", workdir)

        active_client = self._snapshot_client
        owns_client = active_client is None
        if active_client is None:
            active_client = httpx.Client(
                timeout=httpx.Timeout(self.settings.timeout),
                follow_redirects=True,
            )

        try:
            assessments: list[Assessment] = []
            for index, candidate in enumerate(candidates, start=1):
                logger.info(
                    "[%d/%d] %s",
                    index,
                    len(candidates),
                    candidate.repo.full_name,
                )
                filter_result = evaluate_reputation(
                    candidate.repo,
                    self.scorecard,
                    enabled=self.settings.enable_scorecard,
                    min_score=self.settings.scorecard_min,
                )
                if filter_result.status is FilterStatus.SKIPPED:
                    logger.info("  reputation filter rejected the repository")
                scan, snapshot_root = self._scan(
                    candidate.repo, workdir, filter_result, warnings, active_client
                )
                sandbox = self._maybe_sandbox(
                    candidate.repo, snapshot_root, scan, filter_result, warnings
                )
                verdict = decide(
                    candidate.repo,
                    filter_result,
                    scan,
                    use_scorecard_min=self.settings.use_scorecard_min,
                )
                add_sandbox_caveat(verdict, sandbox)
                if self.settings.discover_only:
                    # Display-only: keep the computed decision for JSON audit,
                    # but do not present it as a verdict without a scan.
                    verdict.withheld = True
                logger.info(
                    "  -> %s (scan: %s, scorecard: %s)",
                    verdict.decision.value.upper(),
                    scan.risk.value,
                    f"{filter_result.score:.1f}" if filter_result.score is not None else "n/a",
                )
                assessments.append(
                    Assessment(
                        candidate=candidate,
                        filter=filter_result,
                        scan=scan,
                        verdict=verdict,
                        sandbox=sandbox,
                    )
                )

            elapsed = round(time.monotonic() - started, 2)
            return Report(
                tool_version=__version__,
                generated_at=datetime.now(timezone.utc),
                seed=seed,
                assessments=assessments,
                recall_queries=queries,
                warnings=warnings,
                settings=self.settings.public_dict(),
                elapsed_seconds=elapsed,
                workdir=str(workdir) if self.settings.keep_workdir else None,
                query=query,
                discover_only=self.settings.discover_only,
            )
        finally:
            if owns_client:
                active_client.close()
            if not self.settings.keep_workdir:
                remove_tree(workdir)
            else:
                logger.info("Kept working directory: %s", workdir)

    def _scan(
        self,
        repo: RepoMeta,
        workdir: Path,
        filter_result: FilterResult,
        warnings: list[str],
        client: httpx.Client,
    ) -> tuple[ScanReport, Path | None]:
        """Return the static scan and the snapshot root it examined, if any."""
        if not self.settings.enable_scan:
            return (
                ScanReport(
                    status=ScanStatus.DISABLED,
                    error="Static scanning disabled with --no-scan.",
                ),
                None,
            )
        if filter_result.status is FilterStatus.SKIPPED:
            return (
                ScanReport(
                    status=ScanStatus.SKIPPED,
                    error="Skipped because the reputation filter rejected the repository.",
                ),
                None,
            )

        destination = workdir / repo.full_name.replace("/", "__")
        try:
            snapshot = self._snapshot_fn(
                repo,
                destination,
                max_repo_mb=self.settings.max_repo_mb,
                timeout=self.settings.timeout,
                user_agent=self.settings.user_agent,
                client=client,
            )
        except SnapshotTooLarge as exc:
            return ScanReport(status=ScanStatus.SKIPPED, error=str(exc)), None
        except (SnapshotError, OSError) as exc:
            return ScanReport(status=ScanStatus.ERROR, error=str(exc)), None
        except Exception as exc:  # noqa: BLE001 - one bad candidate must not abort the run
            logger.debug("snapshot failed for %s", repo.full_name, exc_info=True)
            return ScanReport(status=ScanStatus.ERROR, error=f"snapshot failed: {exc}"), None

        if snapshot.stats.skipped_unsafe:
            warnings.append(
                f"{repo.full_name}: skipped {snapshot.stats.skipped_unsafe} unsafe archive "
                "member(s) during extraction."
            )
        if snapshot.stats.truncated:
            warnings.append(
                f"{repo.full_name}: snapshot extraction hit a size or file-count limit."
            )

        limits = ScanLimits(
            max_files=self.settings.max_files,
            max_file_bytes=self.settings.max_file_kb * 1024,
            max_total_bytes=self.settings.max_scan_mb * 1024 * 1024,
        )

        scans: list[ScanReport] = []

        if self.settings.semgrep_config:
            try:
                scanner = SemgrepScanner(
                    SemgrepOptions(
                        config=Path(self.settings.semgrep_config),
                        process_timeout=self.settings.semgrep_timeout,
                        rule_timeout=self.settings.semgrep_rule_timeout,
                    ),
                    runner=self._semgrep_runner,
                )
                semgrep_scan = scanner.scan(
                    snapshot.root,
                    limits=limits,
                    disabled_rules=self.settings.disabled_rules,
                    severity_overrides=self.settings.severity_overrides,
                    suppress_globs=self.settings.suppress_paths,
                )
            except SemgrepUnavailable as exc:
                logger.warning("  semgrep unavailable: %s", exc)
                warnings.append(
                    f"{repo.full_name}: semgrep is unavailable ({exc}); "
                    "used the built-in scanner instead."
                )
            except SemgrepError as exc:
                logger.warning("  semgrep failed: %s", exc)
                return (
                    ScanReport(status=ScanStatus.ERROR, scanner="semgrep", error=str(exc)),
                    snapshot.root,
                )
            else:
                scans.append(semgrep_scan)

        if not scans:
            try:
                scan = self._scan_fn(
                    snapshot.root,
                    limits=limits,
                    disabled_rules=self.settings.disabled_rules,
                    severity_overrides=self.settings.severity_overrides,
                    suppress_globs=self.settings.suppress_paths,
                )
            except Exception as exc:  # noqa: BLE001 - a scanner bug must not crash the run
                logger.debug("scanner failed for %s", repo.full_name, exc_info=True)
                return ScanReport(status=ScanStatus.ERROR, error=f"scanner failed: {exc}"), None
            scans.append(scan)

        if self.settings.enable_gitleaks:
            # Secret scanning is additive: it never replaces the scanner above,
            # because secrets and install hooks are different evidence.
            try:
                gitleaks = GitleaksScanner(
                    GitleaksOptions(process_timeout=self.settings.gitleaks_timeout),
                    runner=self._gitleaks_runner,
                )
                scans.append(
                    gitleaks.scan(
                        snapshot.root,
                        limits=limits,
                        disabled_rules=self.settings.disabled_rules,
                        severity_overrides=self.settings.severity_overrides,
                        suppress_globs=self.settings.suppress_paths,
                    )
                )
            except GitleaksUnavailable as exc:
                logger.warning("  gitleaks unavailable: %s", exc)
                warnings.append(
                    f"{repo.full_name}: gitleaks is unavailable ({exc}); "
                    "secret scanning was skipped."
                )
            except GitleaksError as exc:
                logger.warning("  gitleaks failed: %s", exc)
                scans.append(
                    ScanReport(status=ScanStatus.ERROR, scanner="gitleaks", error=str(exc))
                )
            except Exception as exc:  # noqa: BLE001 - a scanner bug must not crash the run
                logger.debug("gitleaks failed for %s", repo.full_name, exc_info=True)
                scans.append(
                    ScanReport(
                        status=ScanStatus.ERROR,
                        scanner="gitleaks",
                        error=f"gitleaks failed: {exc}",
                    )
                )

        if self.settings.enable_osv:
            # Dependency scanning is additive as well: a vulnerable package and a
            # dangerous pattern are different evidence about the same snapshot.
            try:
                osv = OsvScanner(
                    OsvOptions(process_timeout=self.settings.osv_timeout),
                    runner=self._osv_runner,
                )
                osv_scan = osv.scan(
                    snapshot.root,
                    limits=limits,
                    disabled_rules=self.settings.disabled_rules,
                    severity_overrides=self.settings.severity_overrides,
                    suppress_globs=self.settings.suppress_paths,
                )
                scans.append(osv_scan)
                if osv_scan.truncated and not osv_scan.findings:
                    # osv-scanner found no lockfile or other package source.
                    warnings.append(
                        f"{repo.full_name}: osv-scanner found no lockfile or package "
                        "source; dependency coverage is empty."
                    )
            except OsvUnavailable as exc:
                logger.warning("  osv-scanner unavailable: %s", exc)
                warnings.append(
                    f"{repo.full_name}: osv-scanner is unavailable ({exc}); "
                    "dependency scanning was skipped."
                )
            except OsvError as exc:
                logger.warning("  osv-scanner failed: %s", exc)
                scans.append(ScanReport(status=ScanStatus.ERROR, scanner="osv", error=str(exc)))
            except Exception as exc:  # noqa: BLE001 - a scanner bug must not crash the run
                logger.debug("osv-scanner failed for %s", repo.full_name, exc_info=True)
                scans.append(
                    ScanReport(
                        status=ScanStatus.ERROR,
                        scanner="osv",
                        error=f"osv-scanner failed: {exc}",
                    )
                )

        return merge_scan_reports(scans), snapshot.root

    def _maybe_sandbox(
        self,
        repo: RepoMeta,
        snapshot_root: Path | None,
        scan: ScanReport,
        filter_result: FilterResult,
        warnings: list[str],
    ) -> SandboxReport | None:
        """Run the opt-in containment probe, subject to the trigger policy.

        This never executes code from the repository: see
        :mod:`reuseguard.adapters.sandbox`. Sandbox evidence is recorded for one
        run only and does not change the verdict.
        """
        mode = self.settings.sandbox_mode
        if mode == "off":
            return None
        if scan.status is not ScanStatus.SCANNED or snapshot_root is None:
            return None
        if filter_result.status is FilterStatus.SKIPPED:
            return None
        if mode == "auto" and scan.risk not in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            logger.debug("sandbox skipped for %s: risk is %s", repo.full_name, scan.risk.value)
            return None

        try:
            limits = SandboxLimits(
                image=self.settings.sandbox_image,
                memory_mb=self.settings.sandbox_memory_mb,
                cpus=self.settings.sandbox_cpus,
                pids_limit=self.settings.sandbox_pids_limit,
                timeout_seconds=self.settings.sandbox_timeout,
            )
        except SandboxError as exc:
            warnings.append(f"{repo.full_name}: sandbox configuration is invalid: {exc}")
            return SandboxReport(status=SandboxStatus.ERROR, error=str(exc))

        availability = self._sandbox_detect(runner=self._sandbox_runner)
        if not availability.available:
            reason = availability.reason or "Docker is not available"
            logger.warning("  sandbox unavailable: %s", reason)
            warnings.append(f"{repo.full_name}: sandbox unavailable ({reason}).")
            return SandboxReport(
                status=SandboxStatus.UNAVAILABLE,
                image=limits.image,
                error=reason,
            )

        logger.info("  running sandbox containment probe (%s)", limits.image)
        try:
            sandbox = run_probe(snapshot_root, limits=limits, runner=self._sandbox_runner)
        except SandboxError as exc:
            warnings.append(f"{repo.full_name}: sandbox could not start: {exc}")
            return SandboxReport(
                status=SandboxStatus.ERROR,
                image=limits.image,
                error=str(exc),
            )
        except Exception as exc:  # noqa: BLE001 - a sandbox bug must not abort the run
            logger.debug("sandbox failed for %s", repo.full_name, exc_info=True)
            warnings.append(f"{repo.full_name}: sandbox failed: {exc}")
            return SandboxReport(
                status=SandboxStatus.ERROR,
                image=limits.image,
                error=f"sandbox failed: {exc}",
            )

        if sandbox.status is not SandboxStatus.COMPLETED:
            warnings.append(
                f"{repo.full_name}: sandbox probe did not complete "
                f"({sandbox.status.value}): {sandbox.error or 'no detail'}."
            )
        elif sandbox.containment_ok is not True:
            warnings.append(
                f"{repo.full_name}: sandbox containment checks did not pass; "
                "treat the run as untrusted."
            )
        return sandbox


def remove_tree(path: Path) -> None:
    """Remove a temporary tree, tolerating read-only files on Windows."""
    if not path.exists():
        return

    def _on_error(function, target, _exception) -> None:
        try:
            os.chmod(target, stat.S_IWRITE)
            function(target)
        except OSError:
            pass

    shutil.rmtree(path, onerror=_on_error)
