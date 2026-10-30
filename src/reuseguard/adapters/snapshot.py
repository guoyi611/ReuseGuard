"""Download and safely unpack a read-only GitHub source snapshot.

ReuseGuard deliberately does not run ``git clone``: cloning can invoke hooks and
honour repository-local configuration, and it leaves a ``.git`` directory whose
object store the scanner would have to trust. Instead we download the archive
GitHub generates for the default branch over HTTPS and unpack it with explicit
limits, refusing symlinks, hardlinks, device nodes, absolute paths, and any path
that escapes the destination directory.

The extracted files are treated as untrusted data. Nothing in this module
executes them.
"""

from __future__ import annotations

import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx

from ..config import DEFAULT_USER_AGENT
from ..models import RepoMeta

_MAX_PATH_LENGTH = 240
_MAX_PER_FILE_BYTES = 5 * 1024 * 1024
_MAX_EXTRACT_FILES = 20_000
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class SnapshotError(Exception):
    """A repository snapshot could not be downloaded or unpacked."""


class SnapshotTooLarge(SnapshotError):
    """The repository exceeds the configured size limit."""


@dataclass
class ExtractionStats:
    files: int = 0
    bytes: int = 0
    skipped_non_regular: int = 0
    skipped_unsafe: int = 0
    skipped_large: int = 0
    errors: int = 0
    truncated: bool = False


@dataclass
class Snapshot:
    root: Path
    stats: ExtractionStats
    archive_bytes: int


def fetch_snapshot(
    repo: RepoMeta,
    destination: Path,
    *,
    max_repo_mb: int = 150,
    timeout: float = 20.0,
    user_agent: str = DEFAULT_USER_AGENT,
    client: httpx.Client | None = None,
) -> Snapshot:
    """Download and extract ``repo`` into ``destination``.

    The caller owns ``destination`` and is responsible for deleting it. Splitting
    cleanup out lets ``--keep-workdir`` retain a failed snapshot for diagnosis.
    """
    max_repo_bytes = max_repo_mb * 1024 * 1024
    if repo.size_kb * 1024 > max_repo_bytes:
        raise SnapshotTooLarge(
            f"repository is about {repo.size_kb / 1024:.1f} MB, above the "
            f"{max_repo_mb} MB --max-repo-mb limit"
        )

    destination.mkdir(parents=True, exist_ok=False)
    archive = destination / "snapshot.tar.gz"
    tree = destination / "tree"
    tree.mkdir()

    branch = repo.default_branch or "HEAD"
    url = (
        "https://codeload.github.com/"
        f"{quote(repo.owner, safe='')}/{quote(repo.name, safe='')}"
        f"/tar.gz/refs/heads/{quote(branch, safe='/')}"
    )

    archive_bytes = _download(
        url,
        archive,
        max_bytes=max_repo_bytes,
        timeout=timeout,
        user_agent=user_agent,
        client=client,
    )

    max_extract_bytes = min(200, max(50, max_repo_mb * 2)) * 1024 * 1024
    stats = extract_tarball(archive, tree, max_extract_bytes=max_extract_bytes)
    archive.unlink(missing_ok=True)

    return Snapshot(root=_select_root(tree), stats=stats, archive_bytes=archive_bytes)


def extract_tarball(
    archive: Path,
    destination: Path,
    *,
    max_extract_bytes: int = 100 * 1024 * 1024,
) -> ExtractionStats:
    """Extract regular files from ``archive`` without ever following links."""
    destination.mkdir(parents=True, exist_ok=True)
    stats = ExtractionStats()

    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if stats.files >= _MAX_EXTRACT_FILES:
                    stats.truncated = True
                    break
                if not member.isfile():
                    if not member.isdir():
                        stats.skipped_non_regular += 1
                    continue
                if member.size > _MAX_PER_FILE_BYTES:
                    stats.skipped_large += 1
                    continue
                if member.size < 0:
                    stats.skipped_unsafe += 1
                    continue
                if stats.bytes + member.size > max_extract_bytes:
                    stats.truncated = True
                    break

                relative = safe_member_path(member.name)
                if relative is None:
                    stats.skipped_unsafe += 1
                    continue

                target = destination / relative
                if not _is_within(destination, target):
                    stats.skipped_unsafe += 1
                    continue
                if target.exists() or target.is_symlink():
                    stats.skipped_unsafe += 1
                    continue

                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = tar.extractfile(member)
                    if source is None:
                        stats.skipped_unsafe += 1
                        continue
                    with source, target.open("xb") as handle:
                        shutil.copyfileobj(source, handle, length=64 * 1024)
                except (OSError, tarfile.TarError):
                    stats.errors += 1
                    continue

                stats.files += 1
                stats.bytes += member.size
    except (tarfile.TarError, OSError) as exc:
        raise SnapshotError(f"could not unpack repository archive: {exc}") from exc

    return stats


def safe_member_path(name: str) -> Path | None:
    """Return a safe relative path, or ``None`` if the member must be skipped."""
    if not name or "\x00" in name:
        return None
    # Tar paths are POSIX. A backslash is a separator on Windows, so normalise
    # before checking for traversal.
    normalised = name.replace("\\", "/")
    pure = PurePosixPath(normalised)
    if pure.is_absolute():
        return None

    parts = [part for part in pure.parts if part not in {"", "."}]
    if not parts or len(parts) > 64:
        return None
    if any(part == ".." for part in parts):
        return None
    if any(":" in part for part in parts):
        return None
    if any(part.rstrip(" .") != part for part in parts):
        return None
    for part in parts:
        if part.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
            return None

    joined = "/".join(parts)
    if len(joined) > _MAX_PATH_LENGTH:
        return None
    return Path(*parts)


def _is_within(root: Path, target: Path) -> bool:
    try:
        return target.resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError):
        return False


def _select_root(tree: Path) -> Path:
    entries = list(tree.iterdir())
    if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
        return entries[0]
    return tree


def _download(
    url: str,
    archive: Path,
    *,
    max_bytes: int,
    timeout: float,
    user_agent: str,
    client: httpx.Client | None,
) -> int:
    owns_client = client is None
    active_client = client or httpx.Client(
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
    )
    total = 0
    try:
        with active_client.stream(
            "GET",
            url,
            headers={"User-Agent": user_agent, "Accept": "application/x-gzip"},
            follow_redirects=True,
        ) as response:
            if response.status_code == 404:
                raise SnapshotError(
                    "repository archive not found (the default branch may be empty)"
                )
            if response.status_code >= 400:
                raise SnapshotError(f"archive download returned HTTP {response.status_code}")

            content_length = response.headers.get("content-length")
            if content_length and content_length.isdigit() and int(content_length) > max_bytes:
                raise SnapshotTooLarge(
                    f"archive is larger than the {max_bytes // (1024 * 1024)} MB limit"
                )

            with archive.open("wb") as handle:
                for chunk in response.iter_bytes(chunk_size=256 * 1024):
                    total += len(chunk)
                    if total > max_bytes:
                        raise SnapshotTooLarge(
                            f"archive exceeded the {max_bytes // (1024 * 1024)} MB limit"
                        )
                    handle.write(chunk)
    except httpx.HTTPError as exc:
        raise SnapshotError(f"archive download failed: {exc}") from exc
    finally:
        if owns_client:
            active_client.close()
    return total
