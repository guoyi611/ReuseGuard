"""A deliberately small, dependency-free static risk scanner.

The scanner is not meant to replace Semgrep, CodeQL, or a dedicated malware
detector. It catches the patterns that matter most when deciding whether to
reuse a repository: install-time hooks, obfuscated execution, Trojan Source
Unicode, embedded credentials, and obvious shell-execution paths.

Two design choices keep the signal usable:

* Files under documentation, tests, examples, and fixtures are still scanned,
  but their findings are marked as *suppressed* and do not affect the risk
  level. README install snippets are the classic false positive.
* Vendored dependencies and generated output are skipped. They are not the
  project's own code, and including them drowns the report in third-party
  findings.
"""

from __future__ import annotations

import codecs
import fnmatch
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from re import Pattern

from ..models import Finding, RiskLevel, ScanReport, ScanStatus

_TEXT_EXTENSIONS = frozenset(
    {
        ".py",
        ".pyw",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".sh",
        ".bash",
        ".zsh",
        ".ksh",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".rb",
        ".php",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".kts",
        ".cs",
        ".lua",
        ".pl",
        ".r",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".tf",
        ".md",
        ".rst",
        ".txt",
        ".pth",
        ".html",
        ".htm",
        ".vue",
        ".svelte",
    }
)

_SPECIAL_NAMES = frozenset(
    {
        ".env",
        ".npmrc",
        ".pypirc",
        "Dockerfile",
        "Containerfile",
        "Makefile",
        "GNUmakefile",
        "Procfile",
        "setup.py",
        "package.json",
    }
)

_LOCKFILES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
        "composer.lock",
        "Gemfile.lock",
        "go.sum",
        "bun.lockb",
    }
)
_LOCKFILES_LOWER = frozenset(name.lower() for name in _LOCKFILES)

_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "bower_components",
        "vendor",
        "third_party",
        "dist",
        "build",
        "target",
        "out",
        "bin",
        "obj",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "coverage",
        ".next",
        ".nuxt",
        ".svelte-kit",
        "site-packages",
    }
)

_DOC_DIRS = frozenset(
    {
        "docs",
        "doc",
        "documentation",
        "examples",
        "example",
        "samples",
        "sample",
        "tests",
        "test",
        "testing",
        "spec",
        "specs",
        "__tests__",
        "fixtures",
        "fixture",
        "testdata",
        "test_data",
        "test-fixtures",
        "bench",
        "benchmarks",
        "e2e",
    }
)


@dataclass(frozen=True)
class ScanLimits:
    """Hard limits that keep a hostile snapshot from exhausting the scanner."""

    max_files: int = 2000
    max_file_bytes: int = 1024 * 1024
    max_total_bytes: int = 20 * 1024 * 1024
    max_findings: int = 500


@dataclass(frozen=True)
class PatternRule:
    id: str
    title: str
    severity: RiskLevel
    category: str
    pattern: Pattern[str]
    extensions: frozenset[str] | None = None
    message: str = ""


_PY = frozenset({".py", ".pyw"})
_JS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"})

_PATTERN_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "py-eval-exec",
        "Dynamic code execution",
        RiskLevel.MEDIUM,
        "execution",
        re.compile(r"(?<!\.)(?<!def )\b(?:eval|exec)\s*\(", re.MULTILINE),
        _PY,
        "eval()/exec() can turn data into code.",
    ),
    PatternRule(
        "py-shell-true",
        "Subprocess with shell=True",
        RiskLevel.MEDIUM,
        "execution",
        re.compile(
            r"subprocess\.(?:run|call|Popen|check_call|check_output)\s*\([^\n]{0,400}?shell\s*=\s*True",
            re.MULTILINE,
        ),
        _PY,
        "Shell interpretation makes argument injection easier.",
    ),
    PatternRule(
        "py-os-command",
        "OS command execution",
        RiskLevel.MEDIUM,
        "execution",
        re.compile(r"\bos\.(?:system|popen|spawn\w*)\s*\(", re.MULTILINE),
        _PY,
        "os.system/os.popen execute a shell command.",
    ),
    PatternRule(
        "py-unsafe-deserialize",
        "Unsafe deserialization",
        RiskLevel.MEDIUM,
        "execution",
        re.compile(r"\b(?:pickle|cPickle|dill|joblib)\.loads?\s*\(", re.MULTILINE),
        _PY,
        "Deserializing untrusted data can execute arbitrary code.",
    ),
    PatternRule(
        "py-marshal-loads",
        "Unsafe marshal deserialization",
        RiskLevel.HIGH,
        "execution",
        re.compile(r"\bmarshal\.loads\s*\(", re.MULTILINE),
        _PY,
        "marshal is not a safe format for untrusted input.",
    ),
    PatternRule(
        "py-encoded-exec",
        "Encoded payload execution",
        RiskLevel.CRITICAL,
        "obfuscation",
        re.compile(
            r"(?<!\.)(?<!def )\b(?:exec|eval)\s*\(\s*(?:base64|codecs|binascii|zlib|gzip)\.",
            re.MULTILINE,
        ),
        _PY,
        "Decoding and executing a payload is a common malware pattern.",
    ),
    PatternRule(
        "js-eval",
        "Dynamic code execution",
        RiskLevel.MEDIUM,
        "execution",
        re.compile(r"(?<!\.)\beval\s*\(", re.MULTILINE),
        _JS,
        "eval() can turn data into code.",
    ),
    PatternRule(
        "js-new-function",
        "Dynamic Function constructor",
        RiskLevel.MEDIUM,
        "execution",
        re.compile(r"\bnew\s+Function\s*\(", re.MULTILINE),
        _JS,
        "The Function constructor executes a string as code.",
    ),
    PatternRule(
        "js-child-process",
        "Node child_process import",
        RiskLevel.MEDIUM,
        "execution",
        re.compile(
            r"(?:require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)"
            r"|from\s+['\"](?:node:)?child_process['\"])",
            re.MULTILINE,
        ),
        _JS,
        "child_process can execute arbitrary commands.",
    ),
    PatternRule(
        "js-encoded-eval",
        "Encoded eval payload",
        RiskLevel.CRITICAL,
        "obfuscation",
        re.compile(r"\beval\s*\(\s*(?:atob|Buffer\.from)\s*\(", re.MULTILINE),
        _JS,
        "Decoding and evaluating a payload is a common malware pattern.",
    ),
    PatternRule(
        "download-pipe-shell",
        "Download piped into an interpreter",
        RiskLevel.HIGH,
        "install-hook",
        re.compile(
            r"\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?"
            r"(?:(?:ba|z|da|k)?sh|python3?|node|perl|ruby)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        None,
        "Remote content is executed without inspection or integrity checking.",
    ),
    PatternRule(
        "powershell-download-exec",
        "PowerShell download-and-execute",
        RiskLevel.HIGH,
        "execution",
        re.compile(
            r"(?:\bIEX\b|\bInvoke-Expression\b)[^\n]{0,120}"
            r"(?:Net\.WebClient|Invoke-WebRequest|\biwr\b|DownloadString)",
            re.IGNORECASE | re.MULTILINE,
        ),
        None,
        "Downloading and evaluating remote PowerShell is a common loader.",
    ),
    PatternRule(
        "powershell-encoded",
        "Encoded PowerShell command",
        RiskLevel.HIGH,
        "obfuscation",
        re.compile(
            r"\bpowershell(?:\.exe)?\b[^\n]{0,200}\s-(?:enc|encodedcommand)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        None,
        "Encoded commands hide intent from reviewers.",
    ),
    PatternRule(
        "unicode-bidi",
        "Unicode bidirectional control characters",
        RiskLevel.HIGH,
        "unicode",
        re.compile(r"[\u202a-\u202e\u2066-\u2069]", re.MULTILINE),
        None,
        "Bidirectional overrides can disguise code as comments (Trojan Source).",
    ),
    PatternRule(
        "private-key",
        "Embedded private key material",
        RiskLevel.MEDIUM,
        "secret",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----", re.MULTILINE),
        None,
        "A private key in source is usually a test key, but verify it is not a real one.",
    ),
    PatternRule(
        "aws-access-key",
        "Possible AWS access key",
        RiskLevel.HIGH,
        "secret",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", re.MULTILINE),
        None,
        "Credential-shaped string found in source.",
    ),
    PatternRule(
        "github-token",
        "Possible GitHub token",
        RiskLevel.HIGH,
        "secret",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", re.MULTILINE),
        None,
        "Credential-shaped string found in source.",
    ),
    PatternRule(
        "slack-token",
        "Possible Slack token",
        RiskLevel.HIGH,
        "secret",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", re.MULTILINE),
        None,
        "Credential-shaped string found in source.",
    ),
    PatternRule(
        "generic-secret",
        "Hard-coded secret-like assignment",
        RiskLevel.LOW,
        "secret",
        re.compile(
            r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*"
            r"['\"][^'\"\s]{8,}['\"]",
            re.MULTILINE,
        ),
        None,
        "A credential-like value is assigned in source; verify whether it is real.",
    ),
    PatternRule(
        "rm-rf-root",
        "Destructive recursive delete",
        RiskLevel.MEDIUM,
        "destructive",
        re.compile(r"\brm\s+-rf\s+/(?:\s|$|['\"])", re.MULTILINE),
        None,
        "A recursive delete of the filesystem root is almost never legitimate.",
    ),
    PatternRule(
        "chmod-777",
        "World-writable permissions",
        RiskLevel.LOW,
        "permissions",
        re.compile(r"\bchmod\s+(?:-R\s+)?777\b", re.MULTILINE),
        None,
        "World-writable permissions weaken isolation.",
    ),
)

KNOWN_RULE_IDS = frozenset(rule.id for rule in _PATTERN_RULES) | frozenset(
    {
        "npm-lifecycle",
        "pth-startup-code",
        "vscode-folder-open",
        "ci-pwn-request",
        "ci-write-all",
        "docker-add-url",
        "setup-cmdclass",
    }
)

_INSTALL_PIPE = re.compile(
    r"\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?"
    r"(?:(?:ba|z|da|k)?sh|python3?|node|perl|ruby)\b",
    re.IGNORECASE,
)
_INSTALL_INLINE = re.compile(
    r"\b(?:node|python3?|bash|sh|powershell|pwsh)\b[^\n]{0,60}\s-(?:e|c|enc|encodedcommand)\b",
    re.IGNORECASE,
)
_WORKFLOW_PR_HEAD = re.compile(
    r"github\.event\.pull_request\.(?:head|head\.sha|head\.ref)", re.MULTILINE
)


def scan_directory(
    root: Path,
    *,
    limits: ScanLimits | None = None,
    disabled_rules: frozenset[str] = frozenset(),
    severity_overrides: dict[str, RiskLevel] | None = None,
    suppress_globs: tuple[str, ...] = (),
) -> ScanReport:
    """Scan ``root`` and return a report. The directory is never executed.

    ``disabled_rules`` and ``severity_overrides`` implement policy-file knobs;
    ``suppress_globs`` extends the built-in documentation/test suppression.
    """
    limits = limits or ScanLimits()
    overrides = severity_overrides or {}
    if not root.is_dir():
        return ScanReport(
            status=ScanStatus.ERROR,
            scanner="builtin-patterns",
            error=f"snapshot directory does not exist: {root}",
        )

    findings: list[Finding] = []
    files_scanned = 0
    files_skipped = 0
    bytes_scanned = 0
    truncated = False
    seen: set[tuple[str, str, int]] = set()

    def add(
        rule_id: str,
        title: str,
        severity: RiskLevel,
        category: str,
        path: str,
        line: int | None,
        message: str,
        evidence: str | None = None,
    ) -> None:
        nonlocal truncated
        if rule_id in disabled_rules:
            return
        severity = overrides.get(rule_id, severity)
        key = (rule_id, path, line or 0)
        if key in seen:
            return
        seen.add(key)
        if len(findings) >= limits.max_findings:
            truncated = True
            return
        reason = _suppression_reason(path, suppress_globs)
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                category=category,
                path=path,
                line=line,
                message=message,
                evidence=evidence,
                suppressed=reason is not None,
                suppression_reason=reason,
            )
        )

    stop = False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in _EXCLUDED_DIRS and not (Path(dirpath) / name).is_symlink()
        )
        for filename in sorted(filenames):
            if stop:
                break
            path = Path(dirpath) / filename
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if not _is_candidate(relative, path.name):
                continue
            if files_scanned >= limits.max_files:
                truncated = True
                stop = True
                break

            try:
                size = path.stat().st_size
            except OSError:
                files_skipped += 1
                continue
            if size > limits.max_file_bytes:
                files_skipped += 1
                continue
            if bytes_scanned + size > limits.max_total_bytes:
                truncated = True
                stop = True
                break

            try:
                decoded = _read_text(path)
            except OSError:
                files_skipped += 1
                continue
            if decoded is None:
                files_skipped += 1
                continue
            text = decoded
            if _looks_generated(path.name, text):
                files_skipped += 1
                continue

            files_scanned += 1
            bytes_scanned += size
            _scan_text(relative, path.name, text, add)

    risk = RiskLevel.NONE
    for finding in findings:
        if not finding.suppressed and finding.severity.rank > risk.rank:
            risk = finding.severity

    return ScanReport(
        status=ScanStatus.SCANNED,
        risk=risk,
        findings=findings,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        bytes_scanned=bytes_scanned,
        truncated=truncated,
        scanner="builtin-patterns",
    )


def _read_text(path: Path) -> str | None:
    data = path.read_bytes()
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def _looks_generated(name: str, text: str) -> bool:
    """Skip minified vendor bundles: they are not the project's own source.

    A generated bundle can contain Unicode escape tables that look like Trojan
    Source characters. Scanning it produces noise that hides real findings.
    """
    lowered = name.lower()
    if lowered.startswith(("vendor-", "vendor.", "chunk-", "bundle-")):
        return True
    if Path(lowered).suffix not in {".js", ".mjs", ".cjs", ".css"}:
        return False
    lines = text.splitlines()
    if not lines:
        return False
    longest = max(len(line) for line in lines)
    return longest > 2000 and len(text) / len(lines) > 200


def _is_candidate(relative: str, name: str) -> bool:
    lowered = name.lower()
    if lowered in _LOCKFILES_LOWER:
        return False
    if lowered.endswith((".min.js", ".min.css", ".map")):
        return False
    if Path(relative).suffix.lower() in _TEXT_EXTENSIONS:
        return True
    if name in _SPECIAL_NAMES or name.startswith(("Dockerfile.", "Containerfile.", "Makefile.")):
        return True
    return name.startswith(".env")


def _is_placeholder_secret(value: str) -> bool:
    """Ignore the credential-shaped examples used throughout documentation."""
    upper = value.upper()
    if "EXAMPLE" in upper:
        return True
    return len(set(upper)) <= 3


def _scan_text(
    relative: str,
    name: str,
    text: str,
    add: Callable[..., None],
) -> None:
    suffix = Path(relative).suffix.lower()

    for rule in _PATTERN_RULES:
        if rule.extensions is not None and suffix not in rule.extensions:
            continue
        for index, match in enumerate(rule.pattern.finditer(text)):
            if index >= 10:
                break
            if rule.category == "secret" and _is_placeholder_secret(match.group(0)):
                continue
            line = text.count("\n", 0, match.start()) + 1
            add(
                rule.id,
                rule.title,
                rule.severity,
                rule.category,
                relative,
                line,
                rule.message,
                _evidence(text, match.start()),
            )

    if name == "package.json":
        _scan_package_json(relative, text, add)
    elif suffix == ".pth":
        _scan_pth(relative, text, add)
    elif _is_vscode_tasks(relative):
        _scan_vscode_tasks(relative, text, add)
    elif relative.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}:
        _scan_workflow(relative, text, add)
    elif name.lower().startswith(("dockerfile", "containerfile")):
        _scan_dockerfile(relative, text, add)
    elif name == "setup.py":
        _scan_setup_py(relative, text, add)


def _scan_package_json(relative: str, text: str, add: Callable[..., None]) -> None:
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return
    if not isinstance(payload, dict):
        return
    scripts = payload.get("scripts")
    if not isinstance(scripts, dict):
        return

    for phase in ("preinstall", "install", "postinstall", "prepare"):
        command = scripts.get(phase)
        if not isinstance(command, str) or not command.strip():
            continue
        dangerous = bool(_INSTALL_PIPE.search(command) or _INSTALL_INLINE.search(command))
        add(
            "npm-lifecycle",
            "npm install-time lifecycle script",
            RiskLevel.HIGH if dangerous else RiskLevel.MEDIUM,
            "install-hook",
            relative,
            _line_of(text, f'"{phase}"'),
            f"`{phase}` runs automatically during install: {command[:180]}",
            command[:200],
        )


def _scan_pth(relative: str, text: str, add: Callable[..., None]) -> None:
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("import ", "import\t")) or "exec(" in line:
            add(
                "pth-startup-code",
                "Executable .pth startup hook",
                RiskLevel.HIGH,
                "startup-hook",
                relative,
                number,
                "Python executes import lines in .pth files at interpreter startup.",
                line[:200],
            )


def _scan_vscode_tasks(relative: str, text: str, add: Callable[..., None]) -> None:
    for match in re.finditer(r'"runOn"\s*:\s*"folderOpen"', text):
        add(
            "vscode-folder-open",
            "VS Code task runs on folder open",
            RiskLevel.HIGH,
            "editor-hook",
            relative,
            text.count("\n", 0, match.start()) + 1,
            "Opening the repository in VS Code can execute this task automatically.",
            _evidence(text, match.start()),
        )


def _scan_workflow(relative: str, text: str, add: Callable[..., None]) -> None:
    if (
        re.search(r"^\s*pull_request_target\s*:", text, re.MULTILINE)
        and "actions/checkout" in text
        and _WORKFLOW_PR_HEAD.search(text)
    ):
        add(
            "ci-pwn-request",
            "pull_request_target checks out untrusted code",
            RiskLevel.CRITICAL,
            "ci",
            relative,
            _line_of(text, "pull_request_target"),
            "A privileged workflow checks out the pull request head, enabling pwn-request attacks.",
        )

    match = re.search(r"^\s*permissions\s*:\s*write-all\s*$", text, re.MULTILINE)
    if match:
        add(
            "ci-write-all",
            "Workflow grants write-all permissions",
            RiskLevel.MEDIUM,
            "ci",
            relative,
            text.count("\n", 0, match.start()) + 1,
            "Over-broad workflow permissions increase the impact of a compromised step.",
            _evidence(text, match.start()),
        )


def _scan_dockerfile(relative: str, text: str, add: Callable[..., None]) -> None:
    for match in re.finditer(r"^\s*ADD\s+https?://", text, re.MULTILINE):
        add(
            "docker-add-url",
            "Docker ADD from a remote URL",
            RiskLevel.MEDIUM,
            "build",
            relative,
            text.count("\n", 0, match.start()) + 1,
            "Remote build inputs are not integrity-checked by default.",
            _evidence(text, match.start()),
        )


def _scan_setup_py(relative: str, text: str, add: Callable[..., None]) -> None:
    for match in re.finditer(r"\bcmdclass\s*=", text):
        add(
            "setup-cmdclass",
            "Custom setup.py command class",
            RiskLevel.MEDIUM,
            "install-hook",
            relative,
            text.count("\n", 0, match.start()) + 1,
            "Custom install commands can run arbitrary code during package installation.",
            _evidence(text, match.start()),
        )


def _is_vscode_tasks(relative: str) -> bool:
    parts = relative.split("/")
    return len(parts) >= 2 and parts[-2] == ".vscode" and parts[-1] == "tasks.json"


def _suppression_reason(relative: str, suppress_globs: tuple[str, ...] = ()) -> str | None:
    for pattern in suppress_globs:
        if fnmatch.fnmatch(relative, pattern):
            return f"matches policy suppression pattern `{pattern}`"
    parts = relative.lower().split("/")
    if any(_is_context_dir(part) for part in parts[:-1]):
        return "documentation, test, or example path"
    name = parts[-1]
    if name.startswith(("readme", "changelog", "contributing", "security", "license")):
        return "documentation file"
    if name.endswith((".md", ".rst", ".txt")):
        return "documentation file"
    if name.startswith(("test_", "tests_", "spec_")) or name.endswith(
        ("_test.py", "_tests.py", "_spec.py")
    ):
        return "test file"
    if name in {"test.py", "tests.py", "conftest.py"}:
        return "test file"
    return None


def _is_context_dir(part: str) -> bool:
    if part in _DOC_DIRS:
        return True
    if part.startswith(("test_", "tests_", "test-", "tests-")):
        return True
    return part.endswith(("_test", "_tests", "-test", "-tests"))


def _line_of(text: str, needle: str) -> int | None:
    index = text.find(needle)
    if index < 0:
        return None
    return text.count("\n", 0, index) + 1


def _evidence(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end < 0:
        end = len(text)
    line = text[start:end].strip()
    line = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", line)
    return line[:200]
