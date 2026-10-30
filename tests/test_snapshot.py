"""Tests for safe snapshot download and extraction."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import httpx
import pytest

from reuseguard.adapters.snapshot import (
    SnapshotError,
    SnapshotTooLarge,
    extract_tarball,
    fetch_snapshot,
    safe_member_path,
)
from tests.fakes import make_repo


def _tar_bytes(entries: list[tuple[str, bytes, bytes, str]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content, kind, linkname in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            elif kind == tarfile.SYMTYPE or kind == tarfile.LNKTYPE:
                info.linkname = linkname
                tar.addfile(info)
    return buffer.getvalue()


def test_safe_member_path_accepts_normal_paths() -> None:
    assert safe_member_path("repo-main/src/app.py") == Path("repo-main/src/app.py")
    assert safe_member_path("./repo-main/README.md") == Path("repo-main/README.md")


@pytest.mark.parametrize(
    "name",
    [
        "",
        "/etc/passwd",
        "../evil.txt",
        "repo-main/../../evil.txt",
        "repo-main\\..\\evil.txt",
        "C:/Windows/evil.txt",
        "repo-main/..\\evil.txt",
        "repo-main/CON",
        "repo-main/name.",
    ],
)
def test_safe_member_path_rejects_unsafe_names(name: str) -> None:
    assert safe_member_path(name) is None


def test_extract_tarball_skips_links_and_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "repo.tar.gz"
    archive.write_bytes(
        _tar_bytes(
            [
                ("repo-main/README.md", b"# demo\n", tarfile.REGTYPE, ""),
                ("repo-main/src/app.py", b"x = 1\n", tarfile.REGTYPE, ""),
                ("repo-main/link", b"", tarfile.SYMTYPE, "/etc/passwd"),
                ("repo-main/hardlink", b"", tarfile.LNKTYPE, "repo-main/README.md"),
                ("../evil.txt", b"evil\n", tarfile.REGTYPE, ""),
                ("/tmp/evil.txt", b"evil\n", tarfile.REGTYPE, ""),
            ]
        )
    )
    destination = tmp_path / "tree"

    stats = extract_tarball(archive, destination)

    assert stats.files == 2
    assert stats.skipped_non_regular == 2
    assert stats.skipped_unsafe >= 1
    assert (destination / "repo-main/README.md").read_text(encoding="utf-8") == "# demo\n"
    assert (destination / "repo-main/src/app.py").exists()
    assert not (tmp_path / "evil.txt").exists()


def test_fetch_snapshot_downloads_and_selects_the_root(tmp_path: Path) -> None:
    archive = _tar_bytes(
        [
            ("repo-main/README.md", b"# demo\n", tarfile.REGTYPE, ""),
            ("repo-main/app.py", b"x = 1\n", tarfile.REGTYPE, ""),
        ]
    )
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(
            200,
            content=archive,
            headers={"content-type": "application/x-gzip"},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    repo = make_repo(size_kb=10, default_branch="main")
    destination = tmp_path / "snapshot"

    snapshot = fetch_snapshot(repo, destination, client=client)

    assert requested and "codeload.github.com" in requested[0]
    assert "refs/heads/main" in requested[0]
    assert snapshot.root.name == "repo-main"
    assert (snapshot.root / "README.md").read_text(encoding="utf-8") == "# demo\n"
    assert snapshot.archive_bytes == len(archive)
    assert not (destination / "snapshot.tar.gz").exists()


def test_fetch_snapshot_rejects_oversized_repo_before_download(tmp_path: Path) -> None:
    repo = make_repo(size_kb=200 * 1024)

    with pytest.raises(SnapshotTooLarge):
        fetch_snapshot(repo, tmp_path / "snapshot", max_repo_mb=1)

    assert not (tmp_path / "snapshot").exists()


def test_fetch_snapshot_reports_missing_archive(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))

    with pytest.raises(SnapshotError):
        fetch_snapshot(make_repo(), tmp_path / "snapshot", client=client)
