"""Tests for query construction, similarity scoring, and recall."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from reuseguard.adapters.github import GitHubRateLimit
from reuseguard.models import RepoMeta
from reuseguard.stages.recall import (
    build_idea_queries,
    build_queries,
    extract_idea_keywords,
    extract_keywords,
    recall_idea,
    recall_similar,
    score_idea_similarity,
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


def test_extract_idea_keywords_drops_stopwords() -> None:
    keywords = extract_idea_keywords(
        "I want a fast HTTP client for Python with retries and connection pooling",
        limit=5,
    )

    assert "http" in keywords
    assert "client" in keywords
    assert "want" not in keywords


def test_extract_idea_keywords_keeps_short_allowlisted_terms() -> None:
    keywords = extract_idea_keywords("AI 2D pixel art generator")

    assert "ai" in keywords
    assert "2d" in keywords
    assert "pixel" in keywords


def test_extract_idea_keywords_keeps_c_family_terms() -> None:
    keywords = extract_idea_keywords("C++ and C# developer tooling")

    assert "c++" in keywords
    assert "c#" in keywords


def test_extract_idea_keywords_does_not_open_arbitrary_short_words() -> None:
    keywords = extract_idea_keywords("ok xy ab q zz")

    assert keywords == []


def test_build_idea_queries_keeps_short_terms_in_both_variants() -> None:
    queries = build_idea_queries("AI 2D pixel art generator")

    assert queries[0].startswith("ai 2d pixel art ")
    assert queries[1].startswith("ai 2d ")


def test_build_idea_queries_uses_broad_and_narrow_variants() -> None:
    queries = build_idea_queries(
        "A fast HTTP client with retries",
        language="Python",
        min_stars=100,
    )

    assert len(queries) == 2
    assert queries[0].startswith("http client retries language:Python")
    assert queries[1].startswith("http client language:Python")
    assert all("stars:>=100" in query and "fork:false" in query for query in queries)


def test_build_idea_queries_falls_back_to_raw_text() -> None:
    queries = build_idea_queries("做一个网络客户端", language="Python")

    assert queries
    assert "language:Python" in queries[0]


def test_score_idea_similarity_rewards_keyword_coverage() -> None:
    candidate = make_repo(
        full_name="acme/http",
        description="A fast HTTP client with retries",
        language="Python",
        stars=1000,
        pushed_at=NOW - timedelta(days=2),
    )

    similarity = score_idea_similarity(
        ["http", "client"],
        candidate,
        language="Python",
        now=NOW,
    )

    assert similarity.keywords == 40.0
    assert similarity.language == 20.0
    assert similarity.total > 80.0


def test_recall_idea_ranks_matching_candidates_without_a_seed() -> None:
    matching = make_repo(
        full_name="acme/http",
        description="A fast HTTP client",
        language="Python",
    )
    unrelated = make_repo(
        full_name="acme/db",
        description="A database driver",
        language="Go",
        topics=["database"],
    )
    github = FakeGitHub(matching, results=[unrelated, matching])

    result = recall_idea(
        "fast HTTP client",
        github,
        limit=2,
        language="Python",
        now=NOW,
    )

    assert [candidate.repo.full_name for candidate in result.candidates] == [
        "acme/http",
        "acme/db",
    ]
    assert all(candidate.role == "candidate" for candidate in result.candidates)
    assert result.candidates[0].similarity is not None
    assert result.candidates[0].similarity.keywords > 0.0
