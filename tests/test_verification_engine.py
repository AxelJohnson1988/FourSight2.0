"""Tests for gpam.verification_engine — Phase 2A similarity, diversity, fetch pipeline."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from gpam.memory_block import MemoryBlock, MemoryStatus
from gpam.verification_engine import (
    EngineResult,
    SourceResult,
    VerificationEngine,
    _domain_entropy,
    _extract_text,
    _tfidf_cosine_mean,
)
from gpam.verified_memory_gate import VmgPolicy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _block(
    sources: list[str] | None = None,
    entropy_score: float = 0.5,
) -> MemoryBlock:
    if sources is None:
        sources = [
            "https://alpha.com/doc",
            "https://beta.org/doc",
            "https://gamma.net/doc",
        ]
    return MemoryBlock(
        id="MB-20260428-AAAA",
        title="Test",
        summary="A deterministic summary for testing.",
        sources=sources,
        confidence_score=0.9,
        entropy_score=entropy_score,
        tags=["test"],
        created_at="2026-04-28T00:00:00Z",
        status=MemoryStatus.UNVERIFIED,
        hash="",
    ).with_hash()


def _mock_fetcher(body: str):
    """Return a fetcher callable that always returns *body*."""
    def fetcher(url: str, timeout: int) -> str:  # noqa: ARG001
        return body
    return fetcher


def _failing_fetcher(url: str, timeout: int) -> str:  # noqa: ARG001
    raise ConnectionError("Simulated network failure")


# ---------------------------------------------------------------------------
# _tfidf_cosine_mean
# ---------------------------------------------------------------------------


def test_similarity_identical_texts() -> None:
    texts = ["the quick brown fox", "the quick brown fox"]
    score = _tfidf_cosine_mean(texts)
    assert score == pytest.approx(1.0, abs=1e-9)


def test_similarity_completely_different_texts() -> None:
    texts = ["apple orange mango", "quantum physics relativity"]
    score = _tfidf_cosine_mean(texts)
    assert 0.0 <= score < 0.5


def test_similarity_returns_zero_for_single_text() -> None:
    assert _tfidf_cosine_mean(["just one text"]) == 0.0


def test_similarity_returns_zero_for_empty_list() -> None:
    assert _tfidf_cosine_mean([]) == 0.0


def test_similarity_three_similar_texts() -> None:
    texts = [
        "neural networks learn patterns from data",
        "machine learning discovers patterns in datasets",
        "deep learning finds patterns using training data",
    ]
    score = _tfidf_cosine_mean(texts)
    assert score > 0.0  # similar vocabulary should produce positive similarity


def test_similarity_is_bounded() -> None:
    texts = ["hello world", "hello there", "world here"]
    score = _tfidf_cosine_mean(texts)
    assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# _domain_entropy
# ---------------------------------------------------------------------------


def test_entropy_all_different_domains() -> None:
    urls = ["https://a.com/x", "https://b.org/x", "https://c.net/x"]
    entropy = _domain_entropy(urls)
    assert entropy == pytest.approx(1.0, abs=1e-9)


def test_entropy_all_same_domain_returns_zero() -> None:
    urls = ["https://same.com/1", "https://same.com/2", "https://same.com/3"]
    entropy = _domain_entropy(urls)
    assert entropy == pytest.approx(0.0, abs=1e-9)


def test_entropy_empty_returns_zero() -> None:
    assert _domain_entropy([]) == 0.0


def test_entropy_single_url_returns_zero() -> None:
    assert _domain_entropy(["https://only.com/page"]) == 0.0


def test_entropy_partial_diversity() -> None:
    """2 domains among 4 URLs → entropy between 0 and 1."""
    urls = [
        "https://a.com/1", "https://a.com/2",
        "https://b.com/1", "https://b.com/2",
    ]
    entropy = _domain_entropy(urls)
    assert 0.0 < entropy < 1.0


def test_entropy_strips_www_prefix() -> None:
    """www.example.com and example.com should be treated as the same domain."""
    urls = ["https://www.example.com/1", "https://example.com/2"]
    entropy = _domain_entropy(urls)
    assert entropy == pytest.approx(0.0, abs=1e-9)


def test_entropy_is_bounded() -> None:
    urls = ["https://x.com", "https://y.com", "https://x.com"]
    entropy = _domain_entropy(urls)
    assert 0.0 <= entropy <= 1.0


# ---------------------------------------------------------------------------
# _extract_text
# ---------------------------------------------------------------------------


def test_extract_text_strips_html_tags() -> None:
    html = "<html><body><p>Hello world</p></body></html>"
    text = _extract_text(html)
    assert "Hello world" in text
    assert "<p>" not in text


def test_extract_text_skips_script_content() -> None:
    html = "<html><body><script>alert('xss')</script><p>Safe</p></body></html>"
    text = _extract_text(html)
    assert "Safe" in text
    assert "alert" not in text


def test_extract_text_skips_style_content() -> None:
    html = "<html><head><style>.cls { color: red; }</style></head><body>Content</body></html>"
    text = _extract_text(html)
    assert "Content" in text
    assert "color" not in text


def test_extract_text_handles_plain_text() -> None:
    plain = "No HTML here, just plain text."
    text = _extract_text(plain)
    assert "plain text" in text


# ---------------------------------------------------------------------------
# fetch_sources
# ---------------------------------------------------------------------------


def test_fetch_sources_success() -> None:
    engine = VerificationEngine(
        fetcher=_mock_fetcher("<html><body>Test content</body></html>")
    )
    block = _block()
    results = engine.fetch_sources([str(u) for u in block.sources])
    assert len(results) == 3
    assert all(r.error is None for r in results)
    assert all("Test content" in r.text for r in results)


def test_fetch_sources_records_domain() -> None:
    engine = VerificationEngine(fetcher=_mock_fetcher("<p>x</p>"))
    results = engine.fetch_sources(["https://example.com/page"])
    assert results[0].domain == "example.com"


def test_fetch_sources_handles_network_error() -> None:
    engine = VerificationEngine(fetcher=_failing_fetcher)
    results = engine.fetch_sources(["https://unreachable.example.com/"])
    assert len(results) == 1
    assert results[0].error is not None
    assert results[0].text == ""


def test_fetch_sources_partial_failure() -> None:
    """One failing URL should not abort the others."""
    call_count = 0

    def selective_fetcher(url: str, timeout: int) -> str:
        nonlocal call_count
        call_count += 1
        if "bad" in url:
            raise ConnectionError("bad host")
        return "<p>OK</p>"

    engine = VerificationEngine(fetcher=selective_fetcher)
    results = engine.fetch_sources([
        "https://good.com/page",
        "https://bad.example.com/page",
        "https://good.org/page",
    ])
    assert call_count == 3
    successes = [r for r in results if r.error is None]
    failures = [r for r in results if r.error is not None]
    assert len(successes) == 2
    assert len(failures) == 1


def test_custom_fetcher_injection() -> None:
    """Verify the fetcher is called with the right URL and timeout."""
    calls: list[tuple[str, int]] = []

    def recording_fetcher(url: str, timeout: int) -> str:
        calls.append((url, timeout))
        return "<p>content</p>"

    engine = VerificationEngine(fetcher=recording_fetcher, timeout=30)
    engine.fetch_sources(["https://example.com/test"])
    assert len(calls) == 1
    assert calls[0][0] == "https://example.com/test"
    assert calls[0][1] == 30


# ---------------------------------------------------------------------------
# verify_block — full pipeline
# ---------------------------------------------------------------------------


def test_verify_block_returns_engine_result() -> None:
    engine = VerificationEngine(
        fetcher=_mock_fetcher("<p>consistent content across all sources</p>")
    )
    block = _block()
    result = engine.verify_block(block)
    assert isinstance(result, EngineResult)


def test_verify_block_counts_successful_fetches() -> None:
    engine = VerificationEngine(fetcher=_mock_fetcher("<p>text</p>"))
    block = _block()
    result = engine.verify_block(block)
    assert result.successful_fetch_count == 3


def test_verify_block_handles_all_fetch_failures() -> None:
    engine = VerificationEngine(fetcher=_failing_fetcher)
    block = _block()
    result = engine.verify_block(block)
    assert result.successful_fetch_count == 0
    assert result.similarity_score == 0.0
    # Should be REJECTED because similarity is 0.0 < 0.85
    assert result.vmg_result.status == MemoryStatus.REJECTED


def test_verify_block_diversity_computed_from_urls() -> None:
    """domain_entropy should be 1.0 for three distinct domains."""
    engine = VerificationEngine(fetcher=_mock_fetcher("<p>content</p>"))
    block = _block(sources=[
        "https://alpha.com/doc",
        "https://beta.org/doc",
        "https://gamma.net/doc",
    ])
    result = engine.verify_block(block)
    assert result.domain_entropy == pytest.approx(1.0, abs=1e-9)


def test_verify_block_does_not_mutate_input() -> None:
    """verify_block must not modify the input block's status."""
    engine = VerificationEngine(fetcher=_mock_fetcher("<p>text</p>"))
    block = _block()
    original_status = block.status
    engine.verify_block(block)
    assert block.status == original_status


def test_verify_block_rejected_for_mirrored_domains() -> None:
    """All sources from same domain → INSUFFICIENT_SOURCE_DIVERSITY."""
    engine = VerificationEngine(fetcher=_mock_fetcher("<p>text</p>"))
    block = _block(sources=[
        "https://same.com/p1",
        "https://same.com/p2",
        "https://same.com/p3",
    ])
    result = engine.verify_block(block)
    assert result.vmg_result.status == MemoryStatus.REJECTED
    assert "INSUFFICIENT_SOURCE_DIVERSITY" in result.vmg_result.reason_codes


def test_verify_block_uses_custom_policy() -> None:
    """A very lenient policy should allow a block through even with low similarity."""
    engine = VerificationEngine(
        fetcher=_mock_fetcher("<p>content</p>")
    )
    block = _block()
    lenient_policy = VmgPolicy(
        min_sources=1,
        min_similarity=0.0,
        min_entropy=0.0,
        require_source_diversity=False,
    )
    result = engine.verify_block(block, policy=lenient_policy)
    assert result.vmg_result.status == MemoryStatus.VERIFIED
