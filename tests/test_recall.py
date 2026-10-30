"""Tests for query construction, similarity scoring, and recall."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from reuseguard.adapters.github import GitHubRateLimit
from reuseguard.models import RepoMeta
from reuseguard.stages.recall import (
    build_queries,
    extract_keywords,
    recall_similar,
    score_similarity,
)
from tests.fakes import FakeGitHub, make_repo

NOW = datetime(2026, 10, 30, tzinfo=timezone.utc)


def test_build_queries_uses_topics_language_and_stars() -> None:
    seed = make_repo(
        topics=["http", "client", "python"],
        language="Python",
        description="A typed HTTP client with retries",
    )

    queries = build_queries(seed, min_stars=100)

    assert queries[0] == "topic:http language:Python stars:>=100 fork:false"
    assert "topic:client" not in " ".join(queries)
    assert any("language:Python" in query for query in queries)
    assert all("stars:>=100" in query for query in queries)
    assert len(queries) <= 3


def test_build_queries_falls_back_to_name_without_topics_or_keywords() -> None:
    seed = make_repo(topics=[], language=None, description="")

    queries = build_queries(seed)

    assert queries == ["seed stars:>=50 fork:false"]


def test_extract_keywords_removes_noise_and_language() -> None:
    seed = make_repo(
        description="A simple Python library for HTTP retries and connection pooling",
        language="Python",
    )

    keywords = extract_keywords(seed)

    assert "python" not in keywords
    assert "simple" not in keywords
    assert "library" not in keywords
    assert "http" in keywords
    assert len(keywords) <= 4


def test_similarity_of_identical_repository_is_100() -> None:
    repo = make_repo(pushed_at=NOW - timedelta(days=1), stars=100_000)

    similarity = score_similarity(repo, repo, now=NOW)

    assert similarity.total == 100.0
    assert similarity.topics == 40.0
    assert similarity.language == 20.0


def test_similarity_penalises_different_language_and_stale_push() -> None:
    seed = make_repo(language="Python")
    candidate = make_repo(
        full_name="acme/other",
        language="Go",
        topics=["http", "client"],
        stars=1,
        pushed_at=NOW - timedelta(days=2000),
    )

    similarity = score_similarity(seed, candidate, now=NOW)

    assert similarity.language == 0.0
    assert similarity.recency == 0.0
    assert similarity.total == 41.2


def test_recall_deduplicates_excludes_seed_and_respects_limit() -> None:
    seed = make_repo()
    duplicate = make_repo(full_name="acme/one", stars=500)
    second = make_repo(full_name="acme/two", stars=100)
    github = FakeGitHub(seed, results=[seed, duplicate, duplicate, second])

    result = recall_similar(seed, github, limit=1, now=NOW)

    assert [candidate.repo.full_name for candidate in result.candidates] == ["acme/one"]
    assert result.candidates[0].similarity is not None
    assert result.queries


def test_recall_stops_when_rate_limited() -> None:
    seed = make_repo()
    github = FakeGitHub(seed, search_error=GitHubRateLimit("slow down"))

    result = recall_similar(seed, github, limit=5, now=NOW)

    assert result.candidates == []
    assert any("stopped early" in warning.lower() for warning in result.warnings)


def test_recall_with_zero_limit_does_no_search() -> None:
    seed = make_repo()
    github = FakeGitHub(seed, results=[make_repo(full_name="acme/one")])

    result = recall_similar(seed, github, limit=0, now=NOW)

    assert result.candidates == []
    assert github.queries == []


def test_score_similarity_handles_missing_topics_and_language() -> None:
    seed = RepoMeta(full_name="acme/seed", html_url="https://github.com/acme/seed")
    candidate = RepoMeta(full_name="acme/other", html_url="https://github.com/acme/other")

    similarity = score_similarity(seed, candidate, now=NOW)

    assert similarity.topics == 0.0
    assert similarity.language == 10.0
