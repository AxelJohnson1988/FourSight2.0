"""Tests for gpam.vl_llm.commitment_gate (PCG, Invariant I1)."""

from __future__ import annotations

import pytest

from gpam.vl_llm.commitment_gate import (
    ClaimMetrics,
    CommitmentGate,
    CommitmentPolicy,
    CommitmentResult,
)


def _metrics(**kwargs) -> ClaimMetrics:
    """Build ClaimMetrics with sensible defaults; override via kwargs."""
    defaults = dict(
        confidence=0.8,
        source_count=3,
        diversity_score=0.7,
        evidence_ids=["e1", "e2", "e3"],
    )
    defaults.update(kwargs)
    return ClaimMetrics(**defaults)


# ---------------------------------------------------------------------------
# Passing cases
# ---------------------------------------------------------------------------


def test_pcg_passes_all_thresholds() -> None:
    gate = CommitmentGate()
    result = gate.evaluate(_metrics())
    assert result.passed is True
    assert result.reason_codes == []


def test_pcg_passes_at_exact_min_confidence() -> None:
    gate = CommitmentGate(CommitmentPolicy(min_confidence=0.6))
    result = gate.evaluate(_metrics(confidence=0.6))
    assert result.passed is True


def test_pcg_passes_at_exact_min_sources() -> None:
    gate = CommitmentGate(CommitmentPolicy(min_sources=1))
    result = gate.evaluate(_metrics(source_count=1))
    assert result.passed is True


def test_pcg_passes_with_diversity_disabled() -> None:
    gate = CommitmentGate(CommitmentPolicy(min_diversity=0.0))
    result = gate.evaluate(_metrics(diversity_score=0.0))
    assert result.passed is True


# ---------------------------------------------------------------------------
# Failing cases — individual reason codes
# ---------------------------------------------------------------------------


def test_pcg_fails_low_confidence() -> None:
    gate = CommitmentGate()
    result = gate.evaluate(_metrics(confidence=0.1))
    assert result.passed is False
    assert "LOW_CONFIDENCE" in result.reason_codes


def test_pcg_fails_insufficient_sources() -> None:
    gate = CommitmentGate(CommitmentPolicy(min_sources=3))
    result = gate.evaluate(_metrics(source_count=1))
    assert result.passed is False
    assert "INSUFFICIENT_SOURCES" in result.reason_codes


def test_pcg_fails_low_diversity() -> None:
    gate = CommitmentGate(CommitmentPolicy(min_diversity=0.5))
    result = gate.evaluate(_metrics(diversity_score=0.1))
    assert result.passed is False
    assert "LOW_DIVERSITY" in result.reason_codes


def test_pcg_fails_no_evidence_when_required() -> None:
    gate = CommitmentGate(CommitmentPolicy(require_evidence=True))
    result = gate.evaluate(_metrics(evidence_ids=[]))
    assert result.passed is False
    assert "NO_EVIDENCE" in result.reason_codes


def test_pcg_passes_no_evidence_when_not_required() -> None:
    gate = CommitmentGate(CommitmentPolicy(require_evidence=False))
    result = gate.evaluate(_metrics(evidence_ids=[]))
    assert result.passed is True


# ---------------------------------------------------------------------------
# Multiple simultaneous failures
# ---------------------------------------------------------------------------


def test_pcg_collects_multiple_reason_codes() -> None:
    gate = CommitmentGate(CommitmentPolicy(min_confidence=0.9, min_sources=5))
    result = gate.evaluate(_metrics(confidence=0.1, source_count=0, evidence_ids=[]))
    assert len(result.reason_codes) >= 2
    assert "LOW_CONFIDENCE" in result.reason_codes
    assert "INSUFFICIENT_SOURCES" in result.reason_codes


# ---------------------------------------------------------------------------
# Diversity check skipped when diversity_score is None
# ---------------------------------------------------------------------------


def test_pcg_skips_diversity_check_when_none() -> None:
    gate = CommitmentGate(CommitmentPolicy(min_diversity=0.9))
    # diversity_score=None → check disabled regardless of min_diversity.
    result = gate.evaluate(_metrics(diversity_score=None))
    assert result.passed is True


# ---------------------------------------------------------------------------
# CommitmentResult helper
# ---------------------------------------------------------------------------


def test_commitment_result_passed_property() -> None:
    assert CommitmentResult(status="PASS", reason_codes=[]).passed is True
    assert CommitmentResult(status="FAIL", reason_codes=["X"]).passed is False
