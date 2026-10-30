"""Stage 2: reputation filtering using precomputed OpenSSF Scorecard data."""

from __future__ import annotations

from ..adapters.scorecard import ScorecardClient, ScorecardError, ScorecardNotFound
from ..models import FilterResult, FilterStatus, RepoMeta

# A project needs at least this score to be eligible for a USE verdict.
# It is deliberately not a hard skip: lower scores still get scanned, then the
# verdict engine decides whether a human should look first.
USE_SCORE_THRESHOLD = 5.0


def evaluate_reputation(
    repo: RepoMeta,
    client: ScorecardClient,
    *,
    enabled: bool = True,
    min_score: float = 2.0,
) -> FilterResult:
    """Apply the reputation gate and preserve every reason for the report."""
    if not enabled:
        return FilterResult(
            status=FilterStatus.DISABLED,
            reasons=["OpenSSF Scorecard filter disabled with --no-scorecard."],
        )

    try:
        payload = client.fetch(repo.ref)
    except ScorecardNotFound as exc:
        return FilterResult(
            status=FilterStatus.UNKNOWN,
            error=str(exc),
            reasons=[
                "OpenSSF Scorecard has no public record for this repository.",
                "Maintenance and project-practice signals could not be checked.",
            ],
        )
    except ScorecardError as exc:
        return FilterResult(
            status=FilterStatus.UNKNOWN,
            error=str(exc),
            reasons=[f"OpenSSF Scorecard data is unavailable: {exc}"],
        )

    checks: dict[str, float] = {}
    for check in payload.get("checks", []):
        if not isinstance(check, dict):
            continue
        name = check.get("name")
        score = check.get("score")
        if isinstance(name, str) and isinstance(score, (int, float)) and 0 <= score <= 10:
            checks[name] = float(score)

    score = float(payload["score"])
    checked_at = payload.get("date") if isinstance(payload.get("date"), str) else None

    if score < 0:
        return FilterResult(
            status=FilterStatus.UNKNOWN,
            score=None,
            checked_at=checked_at,
            checks=checks,
            error="OpenSSF Scorecard did not produce a score for this repository.",
            reasons=["OpenSSF Scorecard did not produce a score for this repository."],
        )

    warnings: list[str] = []
    if repo.archived:
        warnings.append("Repository is archived; it receives no maintenance.")
    if repo.fork:
        warnings.append("Repository is a fork; verify it has no unreviewed modifications.")

    maintained = checks.get("Maintained")
    vulnerabilities = checks.get("Vulnerabilities")
    if maintained == 0:
        warnings.append("Maintained check scored 0.")
    if vulnerabilities == 0:
        warnings.append("Vulnerabilities check scored 0.")
    for name in ("Dangerous-Workflow", "Token-Permissions", "Binary-Artifacts"):
        if checks.get(name) == 0:
            warnings.append(f"{name} check scored 0.")

    reasons = [f"OpenSSF Scorecard score: {score:.1f}/10."]
    skip_reasons: list[str] = []
    if maintained == 0 and vulnerabilities == 0:
        skip_reasons.append("Maintained and Vulnerabilities checks both scored 0.")
    if score < min_score:
        skip_reasons.append(f"Score {score:.1f} is below the {min_score:.1f} skip threshold.")

    if skip_reasons:
        return FilterResult(
            status=FilterStatus.SKIPPED,
            score=score,
            checked_at=checked_at,
            checks=checks,
            reasons=[*reasons, *skip_reasons],
            warnings=warnings,
        )

    return FilterResult(
        status=FilterStatus.PASSED,
        score=score,
        checked_at=checked_at,
        checks=checks,
        reasons=[
            *reasons,
            f"Score and maintenance signals clear the {min_score:.1f} gate.",
        ],
        warnings=warnings,
    )
