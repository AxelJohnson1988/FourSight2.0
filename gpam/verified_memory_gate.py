"""Verified Memory Gate (VMG) — deterministic acceptance/rejection of MemoryBlocks.

Phase 1 notes
-------------
* The VMG is a *pure function* — it does not mutate the block, make network
  calls, or read from disk.
* ``similarity_score`` is accepted as a pre-computed input from an upstream
  verifier (Phase 1) or from :class:`~gpam.verification_engine.VerificationEngine`
  (Phase 2A).
* ``entropy_score`` is read from the block itself; set by the builder in Phase 1
  or recomputed by the engine in Phase 2A.

Reason codes
------------
INSUFFICIENT_SOURCES
    ``len(block.sources) < policy.min_sources``
LOW_SEMANTIC_AGREEMENT
    ``similarity_score < policy.min_similarity``
LOW_ENTROPY
    ``block.entropy_score < policy.min_entropy``
INSUFFICIENT_SOURCE_DIVERSITY
    Fewer unique domains than the minimum source count (mirrors/content farms).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse

from gpam.memory_block import MemoryBlock, MemoryStatus


@dataclass(frozen=True)
class VmgResult:
    """Outcome of a Verified Memory Gate evaluation.

    Attributes
    ----------
    status:
        ``VERIFIED`` when all gates pass; ``REJECTED`` otherwise.
    reason_codes:
        Empty list on success; one or more reason strings on rejection.
    """

    status: MemoryStatus
    reason_codes: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class VmgPolicy:
    """Configurable VMG thresholds.

    Attributes
    ----------
    min_sources:
        Minimum number of independent source URLs (default: 3).
    min_similarity:
        Minimum semantic agreement score across sources (default: 0.85).
    min_entropy:
        Minimum domain entropy score on the block (default: 0.10).
    require_source_diversity:
        When ``True``, also checks that the number of unique domains equals at
        least ``min(len(sources), min_sources)`` — prevents mirrored content
        farms from gaming the source count (default: ``True``).
    """

    min_sources: int = 3
    min_similarity: float = 0.85
    min_entropy: float = 0.10
    require_source_diversity: bool = True


def _domain(url: str) -> str:
    """Extract the lowercase hostname from *url*, stripping a leading ``www.``."""
    hostname = (urlparse(url).hostname or "").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname.strip(".")


def verified_memory_gate(
    *,
    block: MemoryBlock,
    similarity_score: float,
    policy: VmgPolicy = VmgPolicy(),
) -> VmgResult:
    """Run the Verified Memory Gate against *block*.

    This is a pure function — it does **not** mutate *block*.

    Parameters
    ----------
    block:
        The :class:`~gpam.memory_block.MemoryBlock` to evaluate.
    similarity_score:
        Semantic agreement score across sources, in [0.0, 1.0].  Supplied by
        the caller (Phase 1) or computed by
        :class:`~gpam.verification_engine.VerificationEngine` (Phase 2A).
    policy:
        Acceptance thresholds.  Defaults to :class:`VmgPolicy`.

    Returns
    -------
    VmgResult
        ``status=VERIFIED`` if all gates pass; ``status=REJECTED`` with one or
        more ``reason_codes`` otherwise.

    Examples
    --------
    >>> from gpam.memory_block import MemoryBlock, MemoryStatus
    >>> mb = MemoryBlock(
    ...     id="MB-20260428-AAAA",
    ...     title="T", summary="S",
    ...     sources=["https://a.com/x", "https://b.com/x", "https://c.com/x"],
    ...     confidence_score=0.9, entropy_score=0.5,
    ...     tags=[], created_at="2026-04-28T00:00:00Z",
    ...     status=MemoryStatus.UNVERIFIED, hash="",
    ... ).with_hash()
    >>> res = verified_memory_gate(block=mb, similarity_score=0.9)
    >>> res.status
    <MemoryStatus.VERIFIED: 'VERIFIED'>
    """
    reasons: List[str] = []

    if len(block.sources) < policy.min_sources:
        reasons.append("INSUFFICIENT_SOURCES")

    if similarity_score < policy.min_similarity:
        reasons.append("LOW_SEMANTIC_AGREEMENT")

    if block.entropy_score < policy.min_entropy:
        reasons.append("LOW_ENTROPY")

    if policy.require_source_diversity:
        source_strings = [str(u) for u in block.sources]
        unique_domains = {_domain(u) for u in source_strings}
        required_unique = min(len(block.sources), policy.min_sources)
        if len(unique_domains) < required_unique:
            reasons.append("INSUFFICIENT_SOURCE_DIVERSITY")

    if reasons:
        return VmgResult(status=MemoryStatus.REJECTED, reason_codes=reasons)

    return VmgResult(status=MemoryStatus.VERIFIED, reason_codes=[])
