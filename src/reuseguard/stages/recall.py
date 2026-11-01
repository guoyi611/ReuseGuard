"""Stage 1: turn a seed repository into a ranked list of alternatives.

The recall strategy is transparent on purpose. Instead of one opaque query, it
builds a handful of GitHub Search queries from the seed's topics, primary
language, and description keywords, then ranks the union with a documented
four-component score (topics 40, language 20, recency 20, popularity 20).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..adapters.github import GitHubClient, GitHubError, GitHubRateLimit
from ..models import Candidate, RepoMeta, Similarity

_MAX_QUERY_LENGTH = 256

_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "can",
        "for",
        "from",
        "has",
        "have",
        "in",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "that",
        "the",
        "this",
        "to",
        "use",
        "using",
        "was",
        "with",
        "you",
        "your",
        "based",
        "built",
        "want",
        "wanna",
        "need",
        "needs",
        "looking",
        "find",
        "finding",
        "something",
        "anything",
        "easy",
        "fast",
        "free",
        "lightweight",
        "minimal",
        "modern",
        "open",
        "project",
        "simple",
        "small",
        "source",
        "tool",
        "tools",
        "framework",
        "library",
        "libraries",
    }
)

# Short search terms that are meaningful on their own. The ordinary keyword
# regex below requires at least three characters, which silently dropped
# "AI", "2D", "3D", "C#", and "C++". Keeping an explicit allowlist avoids
# opening the door to arbitrary two-character noise such as "ok" or "my".
_SHORT_KEYWORDS = frozenset(
    {
        "2d",
        "3d",
        "ai",
        "ar",
        "c",
        "c#",
        "c++",
        "f#",
        "go",
        "js",
        "ml",
        "r",
        "ts",
        "ui",
        "ux",
        "vr",
    }
)

_SHORT_KEYWORD_PATTERN = "|".join(
    re.escape(keyword) for keyword in sorted(_SHORT_KEYWORDS, key=len, reverse=True)
)
_KEYWORD_TOKEN_PATTERN = re.compile(
    rf"(?<![a-z0-9])(?:{_SHORT_KEYWORD_PATTERN})(?![a-z0-9])|[a-z][a-z0-9-]{{2,}}"
)

_GENERIC_TOPICS = frozenset(
    {
        "api",
        "api-client",
        "app",
        "application",
        "awesome",
        "c",
        "c++",
        "cli",
        "client",
        "developer-tools",
        "development",
        "framework",
        "go",
        "hacktoberfest",
        "java",
        "javascript",
        "json",
        "library",
        "open-source",
        "oss",
        "productivity",
        "python",
        "rest",
        "rust",
        "server",
        "tool",
        "tools",
        "typescript",
        "web",
        "web-framework",
    }
)


@dataclass
class RecallResult:
    queries: list[str] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def build_queries(seed: RepoMeta, *, min_stars: int = 50, max_queries: int = 3) -> list[str]:
    """Build a small, deduplicated set of GitHub Search queries.

    Multi-topic AND queries are deliberately avoided: GitHub treats qualifiers
    as conjunctive, so ``topic:client topic:cookies`` finds almost nothing. The
    primary topic is the one that best describes the seed, and a second
    hyphenated topic is used only when it adds specificity.
    """
    qualifiers = [f"stars:>={max(0, min_stars)}", "fork:false"]
    language = f"language:{seed.language}" if seed.language else None
    topics = _select_topics(seed)
    keywords = extract_keywords(seed)

    queries: list[str] = []
    if topics:
        parts = [f"topic:{topics[0]}"]
        if language:
            parts.append(language)
        parts.extend(qualifiers)
        queries.append(" ".join(parts))

        secondary = next((topic for topic in topics[1:] if "-" in topic), None)
        if secondary:
            parts = [f"topic:{secondary}"]
            if language:
                parts.append(language)
            parts.extend(qualifiers)
            queries.append(" ".join(parts))

    if keywords:
        parts = list(keywords)
        if language:
            parts.append(language)
        parts.extend(qualifiers)
        queries.append(" ".join(parts))

    if not queries:
        queries.append(" ".join([seed.name, *qualifiers]))

    return _finalize_queries(queries, max_queries=max_queries)


def extract_keywords(seed: RepoMeta, *, limit: int = 4) -> list[str]:
    """Extract a few ASCII search terms from the description and repository name."""
    source = " ".join(
        filter(
            None,
            [
                seed.description or "",
                seed.name.replace("-", " ").replace("_", " "),
            ],
        )
    )
    return _extract_keywords_from_text(source, limit=limit, exclude={seed.language or ""})


def extract_idea_keywords(idea: str, *, limit: int = 5) -> list[str]:
    """Extract ASCII search terms from a free-form requirement description."""
    return _extract_keywords_from_text(idea, limit=limit, filter_generic=False)


def _extract_keywords_from_text(
    text: str,
    *,
    limit: int,
    exclude: set[str] | None = None,
    filter_generic: bool = True,
) -> list[str]:
    excluded = {item.lower() for item in (exclude or set()) if item}
    keywords: list[str] = []
    seen: set[str] = set()
    for token in _KEYWORD_TOKEN_PATTERN.findall(text.lower()):
        if token in _STOPWORDS or token in excluded:
            continue
        if filter_generic and token in _GENERIC_TOPICS:
            continue
        if token in seen:
            continue
        seen.add(token)
        keywords.append(token)
        if len(keywords) >= limit:
            break
    return keywords


def build_idea_queries(
    idea: str,
    *,
    language: str | None = None,
    min_stars: int = 50,
    max_queries: int = 3,
) -> list[str]:
    """Build search queries from a natural-language requirement.

    GitHub search treats bare terms as conjunctive, so a long sentence can
    return nothing. The first query uses up to four keywords; a second, broader
    query drops to the two strongest terms.
    """
    qualifiers = [f"stars:>={max(0, min_stars)}", "fork:false"]
    language_qualifier = f"language:{language}" if language else None
    keywords = [
        keyword
        for keyword in extract_idea_keywords(idea, limit=5)
        if keyword != (language or "").lower()
    ]
    queries: list[str] = []

    if keywords:
        for count in (4, 2):
            terms = keywords[:count]
            if not terms:
                continue
            parts = list(terms)
            if language_qualifier:
                parts.append(language_qualifier)
            parts.extend(qualifiers)
            queries.append(" ".join(parts))
    else:
        fallback = " ".join(re.sub(r"[^\w\s-]", " ", idea, flags=re.UNICODE).split())
        if fallback:
            parts = [fallback[:120]]
            if language_qualifier:
                parts.append(language_qualifier)
            parts.extend(qualifiers)
            queries.append(" ".join(parts))

    return _finalize_queries(queries, max_queries=max_queries)


def recall_idea(
    idea: str,
    client: GitHubClient,
    *,
    limit: int,
    min_stars: int = 50,
    language: str | None = None,
    now: datetime | None = None,
) -> RecallResult:
    """Search for repositories that match a free-form requirement."""
    if limit <= 0:
        return RecallResult()

    queries = build_idea_queries(idea, language=language, min_stars=min_stars)
    if not queries:
        return RecallResult(warnings=["No usable search terms were extracted from the idea."])

    found: dict[str, RepoMeta] = {}
    warnings: list[str] = []
    per_page = min(50, max(10, limit * 3))

    for query in queries:
        try:
            results = client.search_repositories(query, per_page=per_page)
        except GitHubRateLimit as exc:
            warnings.append(f"GitHub search stopped early: {exc}")
            break
        except GitHubError as exc:
            warnings.append(f"Search failed for `{query}`: {exc}")
            continue
        for repository in results:
            found.setdefault(repository.full_name, repository)

    moment = now or datetime.now(timezone.utc)
    keywords = [
        keyword
        for keyword in extract_idea_keywords(idea, limit=5)
        if keyword != (language or "").lower()
    ]
    candidates = [
        Candidate(
            repo=repository,
            role="candidate",
            similarity=score_idea_similarity(
                keywords,
                repository,
                language=language,
                now=moment,
            ),
        )
        for repository in found.values()
    ]
    candidates.sort(
        key=lambda candidate: (
            -(candidate.similarity.total if candidate.similarity else 0.0),
            -candidate.repo.stars,
            candidate.repo.full_name,
        )
    )
    return RecallResult(queries=queries, candidates=candidates[:limit], warnings=warnings)


def score_idea_similarity(
    keywords: list[str],
    candidate: RepoMeta,
    *,
    language: str | None = None,
    now: datetime | None = None,
) -> Similarity:
    """Score how well a candidate matches a requirement's keywords.

    Keyword coverage is 40 points, language 20, recency 20, and popularity 20.
    With no language filter, the language component is a neutral 10.
    """
    moment = now or datetime.now(timezone.utc)
    searchable = " ".join(
        [
            candidate.full_name,
            candidate.description or "",
            " ".join(candidate.topics),
        ]
    ).lower()
    tokens = set(re.findall(r"[a-z0-9+#.-]+", searchable))

    matched = sum(1 for keyword in keywords if keyword in tokens)
    keyword_score = 40.0 * matched / len(keywords) if keywords else 0.0

    if language:
        language_score = 20.0 if (candidate.language or "").lower() == language.lower() else 0.0
    else:
        language_score = 10.0

    recency_score = _recency_component(candidate, moment)
    popularity_score = _popularity_component(candidate)
    total = round(keyword_score + language_score + recency_score + popularity_score, 1)

    return Similarity(
        total=total,
        keywords=round(keyword_score, 1),
        language=round(language_score, 1),
        recency=round(recency_score, 1),
        popularity=round(popularity_score, 1),
    )


def recall_similar(
    seed: RepoMeta,
    client: GitHubClient,
    *,
    limit: int,
    min_stars: int = 50,
    now: datetime | None = None,
) -> RecallResult:
    """Search for alternatives and rank them by similarity to ``seed``."""
    if limit <= 0:
        return RecallResult()

    queries = build_queries(seed, min_stars=min_stars)
    found: dict[str, RepoMeta] = {}
    warnings: list[str] = []
    per_page = min(50, max(10, limit * 3))

    for query in queries:
        try:
            results = client.search_repositories(query, per_page=per_page)
        except GitHubRateLimit as exc:
            warnings.append(f"GitHub search stopped early: {exc}")
            break
        except GitHubError as exc:
            warnings.append(f"Search failed for `{query}`: {exc}")
            continue
        for repository in results:
            if repository.full_name.lower() == seed.full_name.lower():
                continue
            found.setdefault(repository.full_name, repository)

    moment = now or datetime.now(timezone.utc)
    candidates = [
        Candidate(
            repo=repository,
            role="alternative",
            similarity=score_similarity(seed, repository, now=moment),
        )
        for repository in found.values()
    ]
    candidates.sort(
        key=lambda candidate: (
            -(candidate.similarity.total if candidate.similarity else 0.0),
            -candidate.repo.stars,
            candidate.repo.full_name,
        )
    )
    return RecallResult(queries=queries, candidates=candidates[:limit], warnings=warnings)


def score_similarity(
    seed: RepoMeta,
    candidate: RepoMeta,
    *,
    now: datetime | None = None,
) -> Similarity:
    """Score 0-100 using topic overlap (40), language (20), recency (20), stars (20)."""
    moment = now or datetime.now(timezone.utc)

    topic_score = 0.0
    seed_topics = {topic.lower() for topic in seed.topics}
    candidate_topics = {topic.lower() for topic in candidate.topics}
    if seed_topics and candidate_topics:
        union = seed_topics | candidate_topics
        topic_score = 40.0 * len(seed_topics & candidate_topics) / len(union)

    if seed.language and candidate.language:
        language_score = 20.0 if seed.language.lower() == candidate.language.lower() else 0.0
    else:
        language_score = 10.0

    recency_score = _recency_component(candidate, moment)
    popularity_score = _popularity_component(candidate)
    total = round(topic_score + language_score + recency_score + popularity_score, 1)

    return Similarity(
        total=total,
        topics=round(topic_score, 1),
        language=round(language_score, 1),
        recency=round(recency_score, 1),
        popularity=round(popularity_score, 1),
    )


def _recency_component(candidate: RepoMeta, moment: datetime) -> float:
    if candidate.pushed_at is None:
        return 0.0
    pushed = candidate.pushed_at
    if pushed.tzinfo is None:
        pushed = pushed.replace(tzinfo=timezone.utc)
    days = max(0, (moment - pushed).days)
    return 20.0 * max(0.0, 1.0 - days / 1095.0)


def _popularity_component(candidate: RepoMeta) -> float:
    return 20.0 * min(1.0, math.log10(max(candidate.stars, 1) + 1) / 5.0)


def _finalize_queries(queries: list[str], *, max_queries: int) -> list[str]:
    unique: list[str] = []
    for query in queries:
        query = " ".join(query.split())
        if len(query) > _MAX_QUERY_LENGTH:
            query = query[:_MAX_QUERY_LENGTH].rsplit(" ", 1)[0]
        if query and query not in unique:
            unique.append(query)
    return unique[:max_queries]


def _select_topics(seed: RepoMeta) -> list[str]:
    """Rank usable topics by how well they describe the seed.

    A topic that appears in the description is the strongest signal, followed
    by one that appears in the repository name, then a hyphenated (and usually
    more specific) topic. Shorter topics win ties because they are more likely
    to be a broad domain term such as ``http`` rather than a project nickname.
    """
    description_tokens = set(re.findall(r"[a-z0-9-]+", (seed.description or "").lower()))
    name_tokens = set(re.findall(r"[a-z0-9-]+", seed.name.lower().replace("_", "-")))
    topics = _clean_topics(seed.topics)

    def rank(topic: str) -> tuple[int, int]:
        if topic in description_tokens:
            return (0, len(topic))
        if topic in name_tokens:
            return (1, len(topic))
        if "-" in topic:
            return (2, len(topic))
        return (3, len(topic))

    return sorted(topics, key=rank)


def _clean_topics(topics: list[str]) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for topic in topics:
        value = topic.strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,49}", value):
            continue
        if value in _GENERIC_TOPICS or value in seen:
            continue
        seen.add(value)
        cleaned.append(value)
    return cleaned
