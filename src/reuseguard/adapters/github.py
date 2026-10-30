"""GitHub REST API adapter."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..config import DEFAULT_USER_AGENT
from ..models import RepoMeta, RepoRef

_API_VERSION = "2022-11-28"
_RETRY_STATUS = {502, 503, 504}


class GitHubError(Exception):
    """A GitHub API call failed."""


class GitHubNotFound(GitHubError):
    """The repository does not exist or is not visible to the current token."""


class GitHubRateLimit(GitHubError):
    """The REST or search rate limit was exhausted."""


class GitHubClient:
    """Small, synchronous GitHub REST client.

    Only public metadata and search endpoints are used. Repository contents are
    never fetched through this client; snapshots use a separate read-only path.
    """

    def __init__(
        self,
        *,
        token: str | None = None,
        timeout: float = 20.0,
        user_agent: str = DEFAULT_USER_AGENT,
        base_url: str = "https://api.github.com",
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": user_agent,
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
        )

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def get_repo(self, ref: RepoRef) -> RepoMeta:
        payload = self._get_json(f"/repos/{ref.owner}/{ref.name}")
        if not isinstance(payload, dict) or "full_name" not in payload:
            raise GitHubError(f"unexpected repository payload for {ref.full_name}")
        return _to_repo_meta(payload)

    def search_repositories(self, query: str, *, per_page: int = 20) -> list[RepoMeta]:
        payload = self._get_json(
            "/search/repositories",
            params={
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": max(1, min(per_page, 100)),
            },
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise GitHubError("unexpected search payload")
        repositories: list[RepoMeta] = []
        for item in payload["items"]:
            if isinstance(item, dict) and item.get("full_name"):
                repositories.append(_to_repo_meta(item))
        return repositories

    def _get_json(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        url = f"{self.base_url}{path}"
        response: httpx.Response | None = None
        last_error: Exception | None = None

        for attempt in range(2):
            try:
                response = self._client.get(url, params=params, headers=self._headers)
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt == 0:
                    time.sleep(0.4)
                    continue
                raise GitHubError(f"GitHub request failed: {exc}") from exc

            if response.status_code in _RETRY_STATUS and attempt == 0:
                time.sleep(0.6)
                continue
            break

        if response is None:  # pragma: no cover - defensive
            raise GitHubError(f"GitHub request failed: {last_error}")

        if response.status_code == 404:
            raise GitHubNotFound("repository not found (or not visible to the configured token)")

        if response.status_code in {403, 429}:
            remaining = response.headers.get("x-ratelimit-remaining")
            if remaining == "0" or response.status_code == 429:
                raise GitHubRateLimit(_rate_limit_message(response))
            raise GitHubError(_error_message(response))

        if response.status_code >= 400:
            raise GitHubError(_error_message(response))

        try:
            return response.json()
        except ValueError as exc:
            raise GitHubError("GitHub returned a non-JSON response") from exc


def _rate_limit_message(response: httpx.Response) -> str:
    reset = response.headers.get("x-ratelimit-reset")
    when = "an unknown time"
    if reset and reset.isdigit():
        when = datetime.fromtimestamp(int(reset), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"GitHub API rate limit exceeded (resets at {when}). "
        "Set GITHUB_TOKEN or GH_TOKEN, or wait and retry."
    )


def _error_message(response: httpx.Response) -> str:
    detail = ""
    try:
        payload = response.json()
        if isinstance(payload, dict) and payload.get("message"):
            detail = f": {payload['message']}"
    except ValueError:
        pass
    return f"GitHub API returned HTTP {response.status_code}{detail}"


def _to_repo_meta(item: dict[str, Any]) -> RepoMeta:
    license_info = item.get("license")
    license_spdx = None
    if isinstance(license_info, dict):
        candidate = license_info.get("spdx_id")
        if isinstance(candidate, str) and candidate not in {"NOASSERTION", "NONE"}:
            license_spdx = candidate

    topics = item.get("topics")
    if not isinstance(topics, list):
        topics = []

    return RepoMeta(
        full_name=str(item["full_name"]),
        html_url=str(item.get("html_url") or f"https://github.com/{item['full_name']}"),
        description=item.get("description") if isinstance(item.get("description"), str) else None,
        stars=_as_int(item.get("stargazers_count")),
        forks=_as_int(item.get("forks_count")),
        language=item.get("language") if isinstance(item.get("language"), str) else None,
        topics=[topic for topic in topics if isinstance(topic, str)],
        license_spdx=license_spdx,
        pushed_at=_parse_datetime(item.get("pushed_at")),
        created_at=_parse_datetime(item.get("created_at")),
        archived=bool(item.get("archived")),
        fork=bool(item.get("fork")),
        default_branch=str(item.get("default_branch") or "HEAD"),
        size_kb=_as_int(item.get("size")),
        open_issues=_as_int(item.get("open_issues_count")),
    )


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
