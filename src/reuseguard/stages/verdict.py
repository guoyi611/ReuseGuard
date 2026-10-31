"""Stage 5: turn filter and scan evidence into one explained verdict.

The rules are intentionally conservative and boring. A project only receives
USE when the reputation gate passed, the static scan covered the snapshot, and
nothing medium-or-worse was found. Every other path returns INSPECT or AVOID
with the specific reason attached.
"""

from __future__ import annotations

from ..models import (
    Confidence,
    Decision,
    FilterResult,
    FilterStatus,
    Finding,
    RepoMeta,
    RiskLevel,
    SandboxReport,
    SandboxStatus,
    ScanReport,
    ScanStatus,
    Verdict,
)

_USE_SCORECARD_MIN = 5.0


def decide(
    repo: RepoMeta,
    filter_result: FilterResult,
    scan: ScanReport,
    *,
    use_scorecard_min: float = _USE_SCORECARD_MIN,
) -> Verdict:
    base_limitations = [
        "Static analysis cannot prove the absence of malicious code.",
        *_scanner_limitations(scan),
    ]

    if filter_result.status is FilterStatus.SKIPPED:
        return Verdict(
            decision=Decision.AVOID,
            confidence=Confidence.HIGH if filter_result.score is not None else Confidence.MEDIUM,
            reasons=[
                "The reputation filter rejected this repository.",
                *filter_result.reasons,
            ],
            limitations=[
                *base_limitations,
                "The repository was not downloaded or scanned after the reputation rejection.",
            ],
        )

    if scan.status is ScanStatus.DISABLED:
        return Verdict(
            decision=Decision.INSPECT,
            confidence=Confidence.LOW,
            reasons=[
                "Static scanning was disabled, so there is no code-level evidence.",
                *filter_result.reasons,
            ],
            limitations=[*base_limitations, "No static scan was performed."],
        )

    if scan.status in {ScanStatus.SKIPPED, ScanStatus.ERROR}:
        return Verdict(
            decision=Decision.INSPECT,
            confidence=Confidence.LOW,
            reasons=[
                f"Static scan did not complete: {scan.error or scan.status.value}.",
                *filter_result.reasons,
            ],
            limitations=[*base_limitations, "No static scan evidence is available."],
        )

    effective = sorted(
        scan.effective_findings,
        key=lambda finding: (-finding.severity.rank, finding.path, finding.line or 0),
    )
    top_findings = [_format_finding(finding) for finding in effective[:3]]

    if scan.risk is RiskLevel.CRITICAL:
        return Verdict(
            decision=Decision.AVOID,
            confidence=Confidence.HIGH,
            reasons=["Static scan found critical-risk patterns.", *top_findings],
            limitations=[
                *base_limitations,
                "A reported pattern can still be a false positive; inspect the evidence before dismissing it.",
            ],
        )

    if scan.risk is RiskLevel.HIGH:
        return Verdict(
            decision=Decision.AVOID,
            confidence=Confidence.MEDIUM,
            reasons=["Static scan found high-risk patterns.", *top_findings],
            limitations=[
                *base_limitations,
                "Review the flagged files before deciding whether the findings are acceptable.",
            ],
        )

    if scan.risk is RiskLevel.MEDIUM:
        return Verdict(
            decision=Decision.INSPECT,
            confidence=Confidence.MEDIUM,
            reasons=[
                "Static scan found medium-risk patterns that need human review.",
                *top_findings,
            ],
            limitations=[
                *base_limitations,
                "Medium findings are context-dependent and were not executed.",
            ],
        )

    if scan.files_scanned == 0:
        return Verdict(
            decision=Decision.INSPECT,
            confidence=Confidence.LOW,
            reasons=["No scannable text files were found in the snapshot."],
            limitations=[*base_limitations, "Scan coverage was effectively empty."],
        )

    reasons: list[str] = []
    if scan.risk is RiskLevel.LOW:
        count = len(effective)
        reasons.append(f"{count} low-risk finding{'s' if count != 1 else ''}; none are blocking.")
    reasons.append(
        f"Static scan covered {scan.files_scanned} files with no medium-or-higher findings."
    )

    if repo.archived:
        return Verdict(
            decision=Decision.INSPECT,
            confidence=Confidence.MEDIUM,
            reasons=[
                "Repository is archived and receives no maintenance.",
                *reasons,
            ],
            limitations=[
                *base_limitations,
                "Unmaintained code can accumulate unfixed vulnerabilities.",
            ],
        )

    if scan.truncated:
        return Verdict(
            decision=Decision.INSPECT,
            confidence=Confidence.MEDIUM,
            reasons=[
                "The static scan hit a file or size limit, so coverage is incomplete.",
                *reasons,
            ],
            limitations=[*base_limitations, "Some files were not scanned."],
        )

    if filter_result.status is FilterStatus.DISABLED:
        return Verdict(
            decision=Decision.INSPECT,
            confidence=Confidence.MEDIUM,
            reasons=[
                "The reputation filter was disabled, so maintenance signals were not assessed.",
                *reasons,
            ],
            limitations=[*base_limitations, "No Scorecard evidence is available."],
        )

    if filter_result.status is FilterStatus.UNKNOWN:
        return Verdict(
            decision=Decision.INSPECT,
            confidence=Confidence.MEDIUM,
            reasons=[
                "OpenSSF Scorecard data is unavailable, so project health is unconfirmed.",
                *reasons,
            ],
            limitations=[*base_limitations, "No Scorecard evidence is available."],
        )

    if filter_result.score is None or filter_result.score < use_scorecard_min:
        score_text = "unknown" if filter_result.score is None else f"{filter_result.score:.1f}/10"
        return Verdict(
            decision=Decision.INSPECT,
            confidence=Confidence.MEDIUM,
            reasons=[
                f"Scorecard score {score_text} is below the "
                f"{use_scorecard_min:.1f}/10 USE threshold.",
                *reasons,
            ],
            limitations=[
                *base_limitations,
                "A low Scorecard score reflects project practice, not a specific vulnerability.",
            ],
        )

    reasons.append(
        f"Reputation gate passed with a Scorecard score of {filter_result.score:.1f}/10."
    )
    if repo.fork:
        reasons.append("Repository is a fork; verify the delta against its upstream.")

    return Verdict(
        decision=Decision.USE,
        confidence=Confidence.HIGH,
        reasons=reasons,
        limitations=[
            *base_limitations,
            "Scorecard measures project practice; it is not a code audit.",
            "Sandbox verification is opt-in and does not execute repository code.",
        ],
    )


def add_sandbox_caveat(verdict: Verdict, sandbox: SandboxReport | None) -> Verdict:
    """Attach sandbox caveats without changing the decision.

    The current probe validates container containment; it does not execute
    repository code, so it must never strengthen a verdict.
    """
    if sandbox is None:
        return verdict

    if sandbox.status is SandboxStatus.COMPLETED:
        verdict.limitations.append(
            "Sandbox evidence covers one container run of the containment probe; "
            "it does not execute repository code and is not a safety proof."
        )
        if sandbox.containment_ok is not True:
            verdict.limitations.append(
                "The sandbox containment checks did not pass; do not rely on this run."
            )
    elif sandbox.status is SandboxStatus.UNAVAILABLE:
        verdict.limitations.append(
            "Sandbox verification was requested but no Docker daemon was available."
        )
    else:
        verdict.limitations.append(
            f"Sandbox verification did not complete ({sandbox.status.value})."
        )
    return verdict


def _format_finding(finding: Finding) -> str:
    location = f"{finding.path}:{finding.line}" if finding.line else finding.path
    return f"{finding.severity.value.upper()}: {finding.title} ({location})"


def _scanner_limitations(scan: ScanReport) -> list[str]:
    """Add caveats for the coverage of whatever scanners actually ran."""
    scanners = set(scan.scanner.split("+"))
    limitations: list[str] = []
    if "gitleaks" in scanners:
        limitations.append(
            "Secret scanning ran gitleaks' built-in rules over the default-branch snapshot; "
            "it did not inspect git history, releases, or runtime configuration, and a clean "
            "result is not evidence that no credential was ever committed."
        )
    return limitations
