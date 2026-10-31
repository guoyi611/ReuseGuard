"""OpenSSF Scorecard API adapter."""

from __future__ import annotations

import time
from typing import Any

import httpx

from ..config import DEFAULT_USER_AGENT
from ..models import RepoRef

_RETRY_STATUS = {502, 503, 504}


class ScorecardError(Exception):
    """Scorecard data could not be retrieved or parsed."""


class ScorecardNotFound(ScorecardError):
    """The repository is not in the public Scorecard dataset."""


class ScorecardClient:
    """Fetch precomputed OpenSSF Scorecard results.

    ReuseGuard does not run Scorecard itself. It reads the public,
    precomputed results, which keeps the pipeline fast and avoids executing
    third-party build steps.
    """

    def __init__(
        self,
        *,
        timeout: float = 20.0,
        user_agent: str = DEFAULT_USER_AGENT,
        base_url: str = "https://api.securityscorecards.dev",
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._headers = {"Accept": "application/json", "User-Agent": user_agent}
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
        )

    def __enter__(self) -> ScorecardClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def fetch(self, ref: RepoRef) -> dict[str, Any]:
        url = f"{self.base_url}/projects/github.com/{ref.owner}/{ref.name}"
        response: httpx.Response | None = None
        last_error: Exception | None = None

        for attempt in range(2):
            try:
                response = self._client.get(url, headers=self._headers)
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt == 0:
                    time.sleep(0.4)
                    continue
                raise ScorecardError(f"Scorecard request failed: {exc}") from exc

            if response.status_code in _RETRY_STATUS and attempt == 0:
                time.sleep(0.6)
                continue
            break

        if response is None:  # pragma: no cover - defensive
            raise ScorecardError(f"Scorecard request failed: {last_error}")

        if response.status_code in {404, 410}:
            raise ScorecardNotFound("repository is not in the OpenSSF Scorecard dataset")
        if response.status_code >= 400:
            raise ScorecardError(f"Scorecard API returned HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise ScorecardError("Scorecard API returned a non-JSON response") from exc

        if not isinstance(payload, dict):
            raise ScorecardError("Scorecard API returned an unexpected payload")
        if not isinstance(payload.get("score"), (int, float)):
            raise ScorecardError("Scorecard payload has no numeric score")
        if not isinstance(payload.get("checks"), list):
            raise ScorecardError("Scorecard payload has no checks list")
        return payload
