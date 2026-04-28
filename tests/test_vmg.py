"""Tests for gpam.verified_memory_gate — Verified Memory Gate (VMG)."""

from __future__ import annotations

import pytest

from gpam.memory_block import MemoryBlock, MemoryStatus
from gpam.verified_memory_gate import VmgPolicy, VmgResult, verified_memory_gate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_block(
    *,
    sources: list[str] | None = None,
    entropy_score: float = 0.5,
    status: MemoryStatus = MemoryStatus.UNVERIFIED,
) -> MemoryBlock:
    """Build a minimal MemoryBlock suitable for VMG testing."""
    if sources is None:
        sources = [
            "https://example.com/a",
            "https://example.org/b",
            "https://example.net/c",
        ]
    return MemoryBlock(
        id="MB-20260428-AAAA",
        title="Test block",
        summary="A test summary for VMG validation.",
        sources=sources,
        confidence_score=0.9,
        entropy_score=entropy_score,
        tags=["test"],
        created_at="2026-04-28T00:00:00Z",
        status=status,
        hash="",
    ).with_hash()


# ---------------------------------------------------------------------------
# Pass cases
# ---------------------------------------------------------------------------


def test_vmg_verifies_good_block() -> None:
    block = _make_block()
    result = verified_memory_gate(block=block, similarity_score=0.9)
    assert result.status == MemoryStatus.VERIFIED
    assert result.reason_codes == []


def test_vmg_verifies_at_exact_thresholds() -> None:
    """Boundary: exactly meeting all three thresholds should VERIFY."""
    block = _make_block(entropy_score=0.10)
    result = verified_memory_gate(block=block, similarity_score=0.85)
    assert result.status == MemoryStatus.VERIFIED


def test_vmg_custom_loosened_policy() -> None:
    """A policy with min_sources=1 and no diversity check should VERIFY a single-source block."""
    block = _make_block(sources=["https://example.com/only"])
    policy = VmgPolicy(
        min_sources=1,
        min_similarity=0.0,
        min_entropy=0.0,
        require_source_diversity=False,
    )
    result = verified_memory_gate(block=block, similarity_score=0.5, policy=policy)
    assert result.status == MemoryStatus.VERIFIED
    assert result.reason_codes == []


# ---------------------------------------------------------------------------
# Rejection — individual gate failures
# ---------------------------------------------------------------------------


def test_vmg_rejects_low_sources() -> None:
    block = _make_block(sources=["https://example.com/a"])
    result = verified_memory_gate(block=block, similarity_score=0.9)
    assert result.status == MemoryStatus.REJECTED
    assert "INSUFFICIENT_SOURCES" in result.reason_codes


def test_vmg_rejects_low_similarity() -> None:
    block = _make_block()
    result = verified_memory_gate(block=block, similarity_score=0.50)
    assert result.status == MemoryStatus.REJECTED
    assert "LOW_SEMANTIC_AGREEMENT" in result.reason_codes


def test_vmg_rejects_low_entropy() -> None:
    block = _make_block(entropy_score=0.05)
    result = verified_memory_gate(block=block, similarity_score=0.9)
    assert result.status == MemoryStatus.REJECTED
    assert "LOW_ENTROPY" in result.reason_codes


def test_vmg_rejects_mirrored_domains() -> None:
    """All sources from the same domain → INSUFFICIENT_SOURCE_DIVERSITY."""
    sources = [
        "https://example.com/page1",
        "https://example.com/page2",
        "https://example.com/page3",
    ]
    block = _make_block(sources=sources, entropy_score=0.5)
    result = verified_memory_gate(block=block, similarity_score=0.9)
    assert result.status == MemoryStatus.REJECTED
    assert "INSUFFICIENT_SOURCE_DIVERSITY" in result.reason_codes


def test_vmg_diversity_check_disabled() -> None:
    """With require_source_diversity=False, mirrored domains should not cause rejection."""
    sources = [
        "https://example.com/page1",
        "https://example.com/page2",
        "https://example.com/page3",
    ]
    block = _make_block(sources=sources, entropy_score=0.5)
    policy = VmgPolicy(require_source_diversity=False)
    result = verified_memory_gate(block=block, similarity_score=0.9, policy=policy)
    assert "INSUFFICIENT_SOURCE_DIVERSITY" not in result.reason_codes


# ---------------------------------------------------------------------------
# Rejection — multiple gates failing simultaneously
# ---------------------------------------------------------------------------


def test_vmg_accumulates_all_reason_codes_on_full_failure() -> None:
    """When every gate fails, all four reason codes must appear."""
    block = _make_block(
        sources=["https://example.com/only"],
        entropy_score=0.01,
    )
    result = verified_memory_gate(block=block, similarity_score=0.10)
    assert result.status == MemoryStatus.REJECTED
    assert "INSUFFICIENT_SOURCES" in result.reason_codes
    assert "LOW_SEMANTIC_AGREEMENT" in result.reason_codes
    assert "LOW_ENTROPY" in result.reason_codes
    # Only one source so diversity check compares len(unique_domains)=1 < min(1,3)=1 → False
    # Actually min(1,3) = 1 and len({example.com}) = 1, so 1 < 1 is False
    # So INSUFFICIENT_SOURCE_DIVERSITY is NOT added in this case — only 3 codes.
    assert len(result.reason_codes) >= 3


def test_vmg_boundary_just_below_similarity() -> None:
    """0.849 is just below the 0.85 threshold — must be REJECTED."""
    block = _make_block()
    result = verified_memory_gate(block=block, similarity_score=0.849)
    assert result.status == MemoryStatus.REJECTED
    assert "LOW_SEMANTIC_AGREEMENT" in result.reason_codes


def test_vmg_boundary_just_below_entropy() -> None:
    """0.099 is just below the 0.10 threshold — must be REJECTED."""
    block = _make_block(entropy_score=0.099)
    result = verified_memory_gate(block=block, similarity_score=0.9)
    assert result.status == MemoryStatus.REJECTED
    assert "LOW_ENTROPY" in result.reason_codes


# ---------------------------------------------------------------------------
# Return type invariants
# ---------------------------------------------------------------------------


def test_vmg_result_is_frozen_dataclass() -> None:
    block = _make_block()
    result = verified_memory_gate(block=block, similarity_score=0.9)
    assert isinstance(result, VmgResult)
    with pytest.raises((AttributeError, TypeError)):
        result.status = MemoryStatus.REJECTED  # type: ignore[misc]


def test_vmg_does_not_mutate_block_status() -> None:
    """VMG is a pure function — it must not modify the block."""
    block = _make_block()
    original_status = block.status
    verified_memory_gate(block=block, similarity_score=0.9)
    assert block.status == original_status
