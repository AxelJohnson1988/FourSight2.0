"""Phase 2A — Verification Engine: multi-source fetch, similarity, domain diversity.

This module adds live verification capability on top of the Phase 1 VMG.
It is the only component in the ``gpam`` package that makes network calls.

Architecture
------------
* :class:`VerificationEngine` is the single entry point.
* It accepts an injectable *fetcher* callable so all network I/O can be
  replaced in tests without monkeypatching ``requests``.
* Text similarity is computed with stdlib-only TF-IDF cosine similarity (no
  scikit-learn, no heavy ML deps).
* Domain diversity is Shannon entropy normalised to [0.0, 1.0].
* The engine does NOT mutate the input block.  It returns an
  :class:`EngineResult` whose caller may use to update the block via
  ``model_copy`` before persisting.

Speed / sovereignty tradeoff
----------------------------
* Phase 2A: public web only.  Warden / Tailscale reach is Phase 3.
* "Speed is allowed only if it does not alter truth pathways."
  → The engine flags anomalies; the VMG makes the final decision.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, List, Optional
from urllib.parse import urlparse

from gpam.memory_block import MemoryBlock, MemoryStatus
from gpam.verified_memory_gate import VmgPolicy, VmgResult, verified_memory_gate

# ---------------------------------------------------------------------------
# HTML text extraction (stdlib only)
# ---------------------------------------------------------------------------

_SKIP_TAGS = frozenset({"script", "style", "head", "noscript", "svg"})
_MAX_TEXT_BYTES = 50_000  # cap per source to keep similarity tractable


class _TextExtractor(HTMLParser):
    """Minimal HTML → plain text extractor; strips script/style/head content."""

    def __init__(self) -> None:
        super().__init__()
        self._texts: List[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: object) -> None:  # type: ignore[override]
        if tag.lower() in _SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            stripped = data.strip()
            if stripped:
                self._texts.append(stripped)

    def get_text(self) -> str:
        return " ".join(self._texts)


def _extract_text(raw: str) -> str:
    """Extract plain text from HTML *raw*, capped at ``_MAX_TEXT_BYTES`` chars."""
    parser = _TextExtractor()
    try:
        parser.feed(raw)
        return parser.get_text()[:_MAX_TEXT_BYTES]
    except Exception:  # noqa: BLE001
        return raw[:_MAX_TEXT_BYTES]


# ---------------------------------------------------------------------------
# TF-IDF cosine similarity (stdlib only)
# ---------------------------------------------------------------------------


def _tokenize(text: str) -> List[str]:
    """Lowercase word tokenisation using ``re.findall``."""
    return re.findall(r"\w+", text.lower())


def _tfidf_cosine_mean(texts: List[str]) -> float:
    """Return the mean pairwise TF-IDF cosine similarity across *texts*.

    Returns ``0.0`` if fewer than two texts are provided.

    Parameters
    ----------
    texts:
        List of plain-text strings to compare.

    Returns
    -------
    float
        Mean cosine similarity in [0.0, 1.0].
    """
    if len(texts) < 2:
        return 0.0

    tokenized = [_tokenize(t) for t in texts]
    n = len(tokenized)

    # Document frequency
    df: dict[str, int] = {}
    for tokens in tokenized:
        for tok in set(tokens):
            df[tok] = df.get(tok, 0) + 1

    # Smoothed IDF (sklearn-style): log((N+1)/(df+1)) + 1
    # Prevents IDF=0 when all documents share a term (handles identical-text case).
    idf: dict[str, float] = {
        tok: math.log((n + 1) / (freq + 1)) + 1.0 for tok, freq in df.items()
    }

    def _tfidf_vec(tokens: List[str]) -> dict[str, float]:
        tf = Counter(tokens)
        total = len(tokens) or 1
        return {tok: (count / total) * idf.get(tok, 0.0) for tok, count in tf.items()}

    vecs = [_tfidf_vec(tokens) for tokens in tokenized]

    def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
        dot = sum(a.get(tok, 0.0) * b.get(tok, 0.0) for tok in a)
        mag_a = math.sqrt(sum(v * v for v in a.values()))
        mag_b = math.sqrt(sum(v * v for v in b.values()))
        if mag_a == 0.0 or mag_b == 0.0:
            return 0.0
        return dot / (mag_a * mag_b)

    pairs = [(i, j) for i in range(n) for j in range(i + 1, n)]
    if not pairs:
        return 0.0
    return sum(_cosine(vecs[i], vecs[j]) for i, j in pairs) / len(pairs)


# ---------------------------------------------------------------------------
# Domain diversity (Shannon entropy)
# ---------------------------------------------------------------------------


def _extract_domain(url: str) -> str:
    """Return lowercase hostname from *url*, stripping a leading ``www.``."""
    hostname = (urlparse(url).hostname or "").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname.strip(".")


def _domain_entropy(urls: List[str]) -> float:
    """Normalised Shannon entropy of the domain distribution of *urls*.

    Returns ``0.0`` for an empty list or when all URLs share the same domain.
    Returns ``1.0`` when every URL comes from a distinct domain.

    Parameters
    ----------
    urls:
        Source URL strings.

    Returns
    -------
    float
        Entropy in [0.0, 1.0].
    """
    if not urls:
        return 0.0
    domains = [_extract_domain(u) for u in urls]
    n = len(domains)
    counts = Counter(domains)
    raw_entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    max_entropy = math.log2(n) if n > 1 else 1.0
    return raw_entropy / max_entropy if max_entropy > 0.0 else 0.0


# ---------------------------------------------------------------------------
# Default fetcher (uses requests; injectable for tests)
# ---------------------------------------------------------------------------

#: Type alias for the fetcher callable injected into :class:`VerificationEngine`.
Fetcher = Callable[[str, int], str]


def _default_fetcher(url: str, timeout: int) -> str:
    """Fetch *url* and return the response body as a string.

    Raises on HTTP errors (4xx/5xx) so callers can record the failure.
    """
    import requests  # imported lazily so the module loads without requests installed

    headers = {"User-Agent": "phoenix-gpam-verifier/1.0"}
    response = requests.get(url, timeout=timeout, headers=headers)
    response.raise_for_status()
    return response.text


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceResult:
    """Outcome of fetching a single source URL.

    Attributes
    ----------
    url:
        The URL that was fetched.
    text:
        Extracted plain text (empty string on error).
    domain:
        Hostname extracted from *url*.
    error:
        ``None`` on success; exception message on failure.
    """

    url: str
    text: str
    domain: str
    error: Optional[str]


@dataclass(frozen=True)
class EngineResult:
    """Full output of :meth:`VerificationEngine.verify_block`.

    Attributes
    ----------
    source_results:
        One :class:`SourceResult` per source URL in the block.
    similarity_score:
        Mean pairwise TF-IDF cosine similarity across successfully fetched sources.
    domain_entropy:
        Normalised Shannon entropy of the source domain distribution.
    vmg_result:
        The :class:`~gpam.verified_memory_gate.VmgResult` from running the VMG.
    successful_fetch_count:
        Number of sources that were fetched without error.
    """

    source_results: List[SourceResult]
    similarity_score: float
    domain_entropy: float
    vmg_result: VmgResult
    successful_fetch_count: int = field(default=0)


# ---------------------------------------------------------------------------
# VerificationEngine
# ---------------------------------------------------------------------------


class VerificationEngine:
    """Phase 2A: multi-source fetcher + similarity + diversity + VMG.

    This is the only class in ``gpam`` that makes network calls.  Inject a
    custom *fetcher* to replace HTTP calls in tests.

    Parameters
    ----------
    fetcher:
        ``(url: str, timeout: int) -> str`` callable.  Defaults to a
        ``requests.get``-based implementation.
    timeout:
        Per-request timeout in seconds (default: 10).

    Examples
    --------
    >>> def mock_fetch(url, timeout):
    ...     return "<html><body>The quick brown fox jumps.</body></html>"
    >>> engine = VerificationEngine(fetcher=mock_fetch)
    >>> from gpam.memory_block import MemoryBlock, MemoryStatus
    >>> mb = MemoryBlock(
    ...     id="MB-20260428-AAAA",
    ...     title="Fox",
    ...     summary="The quick brown fox jumps.",
    ...     sources=[
    ...         "https://a.com/fox",
    ...         "https://b.org/fox",
    ...         "https://c.net/fox",
    ...     ],
    ...     confidence_score=0.9,
    ...     entropy_score=0.5,
    ...     tags=["test"],
    ...     created_at="2026-04-28T00:00:00Z",
    ...     status=MemoryStatus.UNVERIFIED,
    ...     hash="",
    ... ).with_hash()
    >>> result = engine.verify_block(mb)
    >>> result.vmg_result.status.value in ("VERIFIED", "REJECTED")
    True
    """

    def __init__(
        self,
        *,
        fetcher: Optional[Fetcher] = None,
        timeout: int = 10,
    ) -> None:
        self._fetcher: Fetcher = fetcher or _default_fetcher
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_sources(self, urls: List[str]) -> List[SourceResult]:
        """Fetch each URL and extract plain text.

        Network errors are caught and recorded in :attr:`SourceResult.error`
        rather than propagated, so a single unreachable source does not abort
        the pipeline.

        Parameters
        ----------
        urls:
            List of URL strings to fetch.

        Returns
        -------
        List[SourceResult]
            One result per URL, in the same order.
        """
        results: List[SourceResult] = []
        for url in urls:
            domain = _extract_domain(url)
            try:
                raw = self._fetcher(url, self._timeout)
                text = _extract_text(raw)
                results.append(SourceResult(url=url, text=text, domain=domain, error=None))
            except Exception as exc:  # noqa: BLE001
                results.append(
                    SourceResult(url=url, text="", domain=domain, error=str(exc))
                )
        return results

    def compute_similarity(self, texts: List[str]) -> float:
        """Return mean pairwise TF-IDF cosine similarity across *texts*.

        Parameters
        ----------
        texts:
            Plain-text strings (typically extracted from fetched source pages).

        Returns
        -------
        float
            Score in [0.0, 1.0]; ``0.0`` if fewer than two texts are provided.
        """
        return _tfidf_cosine_mean(texts)

    def compute_domain_diversity(self, urls: List[str]) -> float:
        """Return normalised Shannon entropy of the domain distribution of *urls*.

        Parameters
        ----------
        urls:
            Source URL strings.

        Returns
        -------
        float
            Score in [0.0, 1.0]; ``0.0`` for an empty list or all-same domain.
        """
        return _domain_entropy(urls)

    def verify_block(
        self,
        block: MemoryBlock,
        *,
        policy: VmgPolicy = VmgPolicy(),
    ) -> EngineResult:
        """Full Phase 2A verification pipeline for *block*.

        Steps:

        1. Fetch every source URL in the block.
        2. Extract plain text from successfully fetched pages.
        3. Compute mean pairwise TF-IDF cosine similarity across fetched texts.
        4. Compute normalised domain diversity entropy across all source URLs.
        5. Build an updated block that carries the computed ``entropy_score``.
        6. Run the VMG with the computed similarity score.

        The input *block* is **not mutated**.  Use
        ``block.model_copy(update={"entropy_score": result.domain_entropy,
        "status": result.vmg_result.status})`` to persist the outcome.

        Parameters
        ----------
        block:
            Block to verify.  ``block.sources`` determines which URLs are fetched.
        policy:
            VMG acceptance thresholds.

        Returns
        -------
        EngineResult
            Complete result including per-source fetch outcomes, computed scores,
            and the VMG decision.
        """
        source_strings = [str(u) for u in block.sources]

        # 1–2. Fetch and extract text
        source_results = self.fetch_sources(source_strings)
        successful = [r for r in source_results if r.error is None]
        texts = [r.text for r in successful if r.text]

        # 3. Similarity across successfully fetched texts
        similarity = self.compute_similarity(texts)

        # 4. Domain diversity across ALL source URLs (not just fetched ones)
        diversity = self.compute_domain_diversity(source_strings)

        # 5. Build a transient block with the computed entropy_score for VMG
        block_for_vmg = block.model_copy(update={"entropy_score": diversity})

        # 6. Run the VMG
        vmg_result = verified_memory_gate(
            block=block_for_vmg,
            similarity_score=similarity,
            policy=policy,
        )

        return EngineResult(
            source_results=source_results,
            similarity_score=similarity,
            domain_entropy=diversity,
            vmg_result=vmg_result,
            successful_fetch_count=len(successful),
        )
