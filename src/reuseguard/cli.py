"""Command-line interface for ReuseGuard."""

from __future__ import annotations

import argparse
import contextlib
import logging
import shutil
import sys
from pathlib import Path
from typing import Any

import httpx

from . import __version__
from .adapters.github import GitHubClient, GitHubError, GitHubNotFound, GitHubRateLimit
from .adapters.sandbox import (
    DEFAULT_IMAGE,
    DEFAULT_TIMEOUT_SECONDS,
    SandboxConfigError,
    SandboxLimits,
)
from .adapters.scorecard import ScorecardClient
from .config import ConfigError, Policy, Settings, load_policy, resolve_github_token
from .demo import build_demo_report
from .models import RepoRef, Report
from .pipeline import Pipeline
from .report import render

logger = logging.getLogger("reuseguard")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reuseguard",
        description=(
            "Vet an open-source repository and its alternatives before reusing them. "
            "ReuseGuard chains GitHub recall, OpenSSF Scorecard, and a read-only static scan."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="store_true", help="show debug logging")
    common.add_argument("-q", "--quiet", action="store_true", help="only show warnings and errors")

    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser(
        "check",
        parents=[common],
        help="assess a repository, or discover repositories from an idea",
        description=(
            "Assess a GitHub repository and rank similar alternatives, or discover "
            "candidates from a natural-language requirement."
        ),
    )
    check.add_argument(
        "url",
        nargs="?",
        help="GitHub URL, owner/repo, or git@github.com:owner/repo.git",
    )
    check.add_argument(
        "--idea",
        metavar="TEXT",
        help="describe what you want to build instead of providing a seed URL",
    )
    check.add_argument(
        "--language",
        metavar="LANG",
        help="optional primary language filter when using --idea",
    )
    check.add_argument(
        "--limit",
        type=_non_negative_int,
        default=None,
        metavar="N",
        help="maximum number of candidates to assess (default: 5)",
    )
    check.add_argument(
        "--min-stars",
        type=_non_negative_int,
        default=None,
        metavar="N",
        help="minimum star count for recalled candidates (default: 50)",
    )
    check.add_argument(
        "--no-recall",
        action="store_true",
        help="assess only the seed repository (URL mode)",
    )
    check.add_argument(
        "--no-scorecard",
        action="store_true",
        help="disable the OpenSSF Scorecard reputation gate",
    )
    check.add_argument(
        "--no-scan",
        action="store_true",
        help="disable snapshot download and static scanning",
    )
    check.add_argument(
        "--discover-only",
        action="store_true",
        help=(
            "list candidates without verdicts; requires --no-scan. Markdown hides the "
            "verdict column, while JSON keeps the decision and marks it as withheld"
        ),
    )
    check.add_argument(
        "--semgrep-config",
        type=Path,
        metavar="PATH",
        help=(
            "scan with Semgrep using a local rules file or directory; "
            "neither Semgrep's remote config nor --config auto is ever used"
        ),
    )
    check.add_argument(
        "--semgrep-timeout",
        type=_semgrep_timeout,
        default=None,
        metavar="SECONDS",
        help="overall Semgrep process limit, 10-3600 (default: 300)",
    )
    check.add_argument(
        "--gitleaks",
        action="store_true",
        help=(
            "also scan the snapshot for hard-coded secrets with gitleaks, using the "
            "rules built into that binary; results are added to the static scan"
        ),
    )
    check.add_argument(
        "--gitleaks-timeout",
        type=_gitleaks_timeout,
        default=None,
        metavar="SECONDS",
        help="overall gitleaks process limit, 10-3600 (default: 300)",
    )
    check.add_argument(
        "--osv",
        action="store_true",
        help=(
            "also check lockfiles for known vulnerable dependencies with osv-scanner; "
            "this queries the public OSV database over the network"
        ),
    )
    check.add_argument(
        "--osv-timeout",
        type=_osv_timeout,
        default=None,
        metavar="SECONDS",
        help="overall osv-scanner process limit, 10-3600 (default: 300)",
    )
    check.add_argument(
        "--osv-resolve",
        action="store_true",
        default=False,
        help=(
            "allow osv-scanner to resolve transitive dependencies via the package "
            "registry when a lockfile is incomplete; by default ReuseGuard passes "
            "--no-resolve so only what the lockfile already records is queried"
        ),
    )
    check.add_argument(
        "--osv-offline",
        type=Path,
        metavar="DB_PATH",
        help=(
            "match against a pre-downloaded OSV database instead of querying "
            "api.osv.dev; DB_PATH must be a local directory produced by "
            "`osv-scanner --download-offline-databases`. Implies --no-resolve."
        ),
    )
    check.add_argument(
        "--sandbox",
        nargs="?",
        const="all",
        choices=("off", "auto", "all"),
        default=None,
        metavar="{off,auto,all}",
        help=(
            "run the opt-in isolation probe: 'auto' for high/critical static risk, "
            "'all' for every scanned candidate, 'off' to disable (default: off)"
        ),
    )
    check.add_argument(
        "--sandbox-image",
        metavar="IMAGE",
        help="container image for the sandbox; must already be present locally",
    )
    check.add_argument(
        "--sandbox-timeout",
        type=_sandbox_timeout,
        default=None,
        metavar="SECONDS",
        help="wall-clock limit for one sandbox run, 1-600 (default: 20)",
    )
    check.add_argument(
        "--no-gh-token",
        action="store_true",
        help="do not read a token from the gh CLI (environment variables still apply)",
    )
    check.add_argument(
        "--config",
        type=Path,
        metavar="PATH",
        help="load thresholds, limits, suppression paths, and rule policy from YAML",
    )
    check.add_argument(
        "--scorecard-min",
        type=_non_negative_float,
        default=None,
        metavar="SCORE",
        help="Scorecard score below which a repository is skipped (default: 2.0)",
    )
    check.add_argument(
        "--timeout",
        type=_positive_float,
        default=None,
        metavar="SECONDS",
        help="network timeout per request (default: 20)",
    )
    check.add_argument(
        "--max-repo-mb",
        type=_positive_int,
        default=None,
        metavar="MB",
        help="maximum repository size to download (default: 150)",
    )
    check.add_argument(
        "--max-files",
        type=_positive_int,
        default=None,
        metavar="N",
        help="maximum files to scan per repository (default: 2000)",
    )
    check.add_argument(
        "--max-file-kb",
        type=_positive_int,
        default=None,
        metavar="KB",
        help="maximum size of a single scanned file (default: 1024)",
    )
    check.add_argument(
        "--max-scan-mb",
        type=_positive_int,
        default=None,
        metavar="MB",
        help="maximum total bytes to scan per repository (default: 20)",
    )
    check.add_argument(
        "--keep-workdir",
        action="store_true",
        help="keep downloaded snapshots for inspection",
    )
    check.add_argument(
        "--format",
        choices=("md", "json"),
        default="md",
        help="report format (default: md)",
    )
    check.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="write the report to PATH instead of stdout",
    )
    check.add_argument(
        "--fail-on",
        choices=("never", "inspect", "avoid"),
        default="never",
        help="exit with status 3 if any verdict reaches this level (default: never)",
    )

    demo = subparsers.add_parser(
        "demo",
        parents=[common],
        help="render a fictional demo report without network access",
        description="Render a deterministic demo report. No network access is used.",
    )
    demo.add_argument("--format", choices=("md", "json"), default="md")
    demo.add_argument("-o", "--output", metavar="PATH", help="write the report to PATH")

    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_output_encoding()
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(verbose=getattr(args, "verbose", False), quiet=getattr(args, "quiet", False))

    if args.command == "demo":
        report = build_demo_report()
        _emit(report, args.format, args.output)
        return 0

    return _run_check(args)


def _run_check(args: argparse.Namespace) -> int:
    idea = (args.idea or "").strip()
    ref: RepoRef | None = None

    if idea and args.url:
        print("error: provide either a repository URL or --idea, not both", file=sys.stderr)
        return 2
    if not idea and not args.url:
        print("error: provide a repository URL or --idea TEXT", file=sys.stderr)
        return 2
    if idea and args.no_recall:
        print("error: --no-recall is only valid with a seed repository", file=sys.stderr)
        return 2
    if not idea and args.language:
        print("error: --language is only valid with --idea", file=sys.stderr)
        return 2

    try:
        policy = load_policy(args.config) if args.config else Policy()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.config:
        logger.debug("Loaded policy from %s", args.config)

    limit = _pick(args.limit, policy.max_candidates, 5)
    min_stars = _pick(args.min_stars, policy.min_stars, 50)
    max_repo_mb = _pick(args.max_repo_mb, policy.max_repo_mb, 150)
    max_files = _pick(args.max_files, policy.max_files, 2000)
    max_file_kb = _pick(args.max_file_kb, policy.max_file_kb, 1024)
    max_scan_mb = _pick(args.max_scan_mb, policy.max_scan_mb, 20)
    timeout = _pick(args.timeout, policy.timeout, 20.0)
    scorecard_min = _pick(args.scorecard_min, policy.scorecard_min, 2.0)
    use_scorecard_min = _pick(None, policy.use_scorecard_min, 5.0)
    enable_recall = bool(_pick(None, policy.recall, True)) and not args.no_recall
    enable_scorecard = bool(_pick(None, policy.scorecard, True)) and not args.no_scorecard
    enable_scan = bool(_pick(None, policy.scan, True)) and not args.no_scan

    if args.discover_only and enable_scan:
        print(
            "error: --discover-only requires static scanning to be disabled; use --no-scan",
            file=sys.stderr,
        )
        return 2

    sandbox_mode = args.sandbox or "off"
    if sandbox_mode == "off" and (args.sandbox_image or args.sandbox_timeout is not None):
        print(
            "error: --sandbox-image and --sandbox-timeout require --sandbox",
            file=sys.stderr,
        )
        return 2
    if sandbox_mode != "off" and not enable_scan:
        print(
            "error: --sandbox requires static scanning; remove --no-scan "
            "or set features.scan: true",
            file=sys.stderr,
        )
        return 2

    semgrep_timeout = _pick(args.semgrep_timeout, None, 300.0)
    if args.semgrep_config is None and args.semgrep_timeout is not None:
        print("error: --semgrep-timeout requires --semgrep-config", file=sys.stderr)
        return 2
    if args.semgrep_config is not None:
        if not enable_scan:
            print(
                "error: --semgrep-config requires static scanning; remove --no-scan",
                file=sys.stderr,
            )
            return 2
        if not args.semgrep_config.exists():
            print(
                f"error: semgrep config path does not exist: {args.semgrep_config}",
                file=sys.stderr,
            )
            return 2
        if not shutil.which("semgrep"):
            logger.warning(
                "Semgrep was not found on PATH; ReuseGuard will fall back to the "
                "built-in scanner and record a warning."
            )

    gitleaks_timeout = _pick(args.gitleaks_timeout, None, 300.0)
    if args.gitleaks_timeout is not None and not args.gitleaks:
        print("error: --gitleaks-timeout requires --gitleaks", file=sys.stderr)
        return 2
    if args.gitleaks:
        if not enable_scan:
            print(
                "error: --gitleaks requires static scanning; remove --no-scan",
                file=sys.stderr,
            )
            return 2
        if not shutil.which("gitleaks"):
            logger.warning(
                "gitleaks was not found on PATH; secret scanning will be skipped and "
                "a warning recorded."
            )

    osv_timeout = _pick(args.osv_timeout, None, 300.0)
    osv_no_resolve = not args.osv_resolve
    osv_offline_db: Path | None = args.osv_offline
    if args.osv_resolve and args.osv_offline is not None:
        print(
            "error: --osv-resolve cannot be combined with --osv-offline; "
            "offline mode has no registry to resolve against",
            file=sys.stderr,
        )
        return 2
    if args.osv_offline is not None and not args.osv:
        print("error: --osv-offline requires --osv", file=sys.stderr)
        return 2
    if args.osv_resolve and not args.osv:
        print("error: --osv-resolve requires --osv", file=sys.stderr)
        return 2
    if osv_offline_db is not None:
        if not osv_offline_db.exists():
            print(
                f"error: osv offline database path does not exist: {osv_offline_db}",
                file=sys.stderr,
            )
            return 2
        if not osv_offline_db.is_dir():
            print(
                f"error: osv offline database path must be a directory: {osv_offline_db}",
                file=sys.stderr,
            )
            return 2
    if args.osv_timeout is not None and not args.osv:
        print("error: --osv-timeout requires --osv", file=sys.stderr)
        return 2
    if args.osv:
        if not enable_scan:
            print(
                "error: --osv requires static scanning; remove --no-scan",
                file=sys.stderr,
            )
            return 2
        if not shutil.which("osv-scanner"):
            logger.warning(
                "osv-scanner was not found on PATH; dependency scanning will be skipped "
                "and a warning recorded."
            )

    try:
        sandbox_limits = SandboxLimits(
            image=args.sandbox_image or DEFAULT_IMAGE,
            timeout_seconds=_pick(args.sandbox_timeout, None, DEFAULT_TIMEOUT_SECONDS),
        )
    except SandboxConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if sandbox_mode != "off" and not shutil.which("docker"):
        logger.warning(
            "Docker was not found on PATH; the sandbox probe will report as unavailable."
        )

    if idea and limit == 0:
        print("error: --limit must be at least 1 when using --idea", file=sys.stderr)
        return 2

    if args.url:
        try:
            ref = RepoRef.parse(args.url)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    token = None if args.no_gh_token else resolve_github_token(allow_gh_cli=True)
    if token is None:
        token = resolve_github_token(allow_gh_cli=False)
    if token:
        logger.debug("Using an authenticated GitHub token")
    else:
        logger.warning(
            "No GitHub token found; unauthenticated requests are limited to 60/hour "
            "(10 searches/minute). Set GITHUB_TOKEN or run `gh auth login`."
        )

    settings = Settings(
        token=token,
        timeout=timeout,
        max_candidates=limit,
        min_stars=min_stars,
        max_repo_mb=max_repo_mb,
        max_files=max_files,
        max_file_kb=max_file_kb,
        max_scan_mb=max_scan_mb,
        scorecard_min=scorecard_min,
        use_scorecard_min=use_scorecard_min,
        enable_recall=enable_recall,
        enable_scorecard=enable_scorecard,
        enable_scan=enable_scan,
        discover_only=args.discover_only,
        semgrep_config=str(args.semgrep_config) if args.semgrep_config else None,
        semgrep_timeout=semgrep_timeout,
        enable_gitleaks=args.gitleaks,
        gitleaks_timeout=gitleaks_timeout,
        enable_osv=args.osv,
        osv_timeout=osv_timeout,
        osv_no_resolve=osv_no_resolve,
        osv_offline_db=str(osv_offline_db) if osv_offline_db is not None else None,
        sandbox_mode=sandbox_mode,
        sandbox_image=sandbox_limits.image,
        sandbox_timeout=sandbox_limits.timeout_seconds,
        keep_workdir=args.keep_workdir,
        disabled_rules=policy.disabled_rules,
        severity_overrides=policy.severity_overrides,
        suppress_paths=policy.suppress_paths,
        config_path=str(args.config) if args.config else None,
    )

    try:
        with (
            GitHubClient(
                token=token,
                timeout=timeout,
                user_agent=settings.user_agent,
            ) as github,
            ScorecardClient(
                timeout=timeout,
                user_agent=settings.user_agent,
            ) as scorecard,
        ):
            pipeline = Pipeline(settings, github, scorecard)
            if idea:
                logger.info("Discovering repositories for an idea")
                report = pipeline.run_idea(idea, language=args.language)
            else:
                assert ref is not None
                report = pipeline.run(ref)
    except GitHubNotFound:
        name = ref.full_name if ref is not None else "repository"
        print(f"error: {name} was not found or is not public", file=sys.stderr)
        return 1
    except GitHubRateLimit as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except GitHubError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(f"error: network request failed: {exc}", file=sys.stderr)
        return 1

    _emit(report, args.format, args.output)
    return _exit_code(report, args.fail_on)


def _emit(report: Report, fmt: str, output: str | None) -> None:
    text = render(report, fmt)
    if output and output != "-":
        path = Path(output)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        logger.info("Report written to %s", path)
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def _exit_code(report: Report, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = 1 if fail_on == "inspect" else 2
    worst = max((assessment.verdict.decision.rank for assessment in report.assessments), default=0)
    if worst >= threshold:
        logger.warning("Exit status 3: a verdict met the --fail-on %s threshold", fail_on)
        return 3
    return 0


def _configure_logging(*, verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        stream=sys.stderr,
        force=True,
    )
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _configure_output_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(OSError, ValueError):
                reconfigure(encoding="utf-8", errors="replace")


def _pick(cli_value: Any, policy_value: Any, default: Any) -> Any:
    """CLI explicitly set > YAML policy > built-in default."""
    if cli_value is not None:
        return cli_value
    if policy_value is not None:
        return policy_value
    return default


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")
    return parsed


def _positive_int(value: str) -> int:
    parsed = _non_negative_int(value)
    if parsed == 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected a number, got {value!r}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")
    return parsed


def _positive_float(value: str) -> float:
    parsed = _non_negative_float(value)
    if parsed == 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _sandbox_timeout(value: str) -> float:
    parsed = _positive_float(value)
    if not 1.0 <= parsed <= 600.0:
        raise argparse.ArgumentTypeError("sandbox timeout must be between 1 and 600 seconds")
    return parsed


def _semgrep_timeout(value: str) -> float:
    parsed = _positive_float(value)
    if not 10.0 <= parsed <= 3600.0:
        raise argparse.ArgumentTypeError("semgrep timeout must be between 10 and 3600 seconds")
    return parsed


def _gitleaks_timeout(value: str) -> float:
    parsed = _positive_float(value)
    if not 10.0 <= parsed <= 3600.0:
        raise argparse.ArgumentTypeError("gitleaks timeout must be between 10 and 3600 seconds")
    return parsed


def _osv_timeout(value: str) -> float:
    parsed = _positive_float(value)
    if not 10.0 <= parsed <= 3600.0:
        raise argparse.ArgumentTypeError("osv-scanner timeout must be between 10 and 3600 seconds")
    return parsed
