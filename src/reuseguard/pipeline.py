"""The orchestration pipeline.

The pipeline owns sequencing, timeouts, temporary directories, and the decision
to skip expensive work. It knows nothing about GitHub JSON or regexes; adapters
and stages do that work.
"""

from __future__ import annotations

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
from .adapters.scanner import ScanLimits, scan_directory
from .adapters.scorecard import ScorecardClient
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
    ScanReport,
    ScanStatus,
)
from .stages.recall import recall_idea, recall_similar
from .stages.reputation import evaluate_reputation
from .stages.verdict import decide

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
    ) -> None:
        self.settings = settings
        self.github = github
        self.scorecard = scorecard
        self._snapshot_client = snapshot_client
        self._scan_fn = scan_fn
        self._snapshot_fn = snapshot_fn

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
                scan = self._scan(candidate.repo, workdir, filter_result, warnings, active_client)
                verdict = decide(
                    candidate.repo,
                    filter_result,
                    scan,
                    use_scorecard_min=self.settings.use_scorecard_min,
                )
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
    ) -> ScanReport:
        if not self.settings.enable_scan:
            return ScanReport(
                status=ScanStatus.DISABLED,
                error="Static scanning disabled with --no-scan.",
            )
        if filter_result.status is FilterStatus.SKIPPED:
            return ScanReport(
                status=ScanStatus.SKIPPED,
                error="Skipped because the reputation filter rejected the repository.",
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
            return ScanReport(status=ScanStatus.SKIPPED, error=str(exc))
        except (SnapshotError, OSError) as exc:
            return ScanReport(status=ScanStatus.ERROR, error=str(exc))
        except Exception as exc:  # noqa: BLE001 - one bad candidate must not abort the run
            logger.debug("snapshot failed for %s", repo.full_name, exc_info=True)
            return ScanReport(status=ScanStatus.ERROR, error=f"snapshot failed: {exc}")

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
        try:
            return self._scan_fn(
                snapshot.root,
                limits=limits,
                disabled_rules=self.settings.disabled_rules,
                severity_overrides=self.settings.severity_overrides,
                suppress_globs=self.settings.suppress_paths,
            )
        except Exception as exc:  # noqa: BLE001 - a scanner bug must not crash the run
            logger.debug("scanner failed for %s", repo.full_name, exc_info=True)
            return ScanReport(status=ScanStatus.ERROR, error=f"scanner failed: {exc}")


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
