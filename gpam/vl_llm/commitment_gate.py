"""Propositional Commitment Gate (PCG) — claim acceptance rule (§3.4, Step D).

Invariant I1 — No Unjustified Assertion
  A claim MUST NOT be marked ACCEPTED unless it passes the PCG AND the
  decision record is written to PAL.  This module enforces the PCG check;
  the pipeline is responsible for the PAL write.

The PCG is a pure function: same inputs always produce the same result.
It extends the existing VMG logic (gpam/verified_memory_gate.py) to
operate at claim level (confidence + sourceCount + diversityScore).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommitmentPolicy:
    """Thresholds that a claim's metrics must meet to pass the PCG (§3.4).

    Parameters
    ----------
    min_confidence:
        Minimum justification confidence in [0.0, 1.0].
    min_sources:
        Minimum number of distinct evidence sources.
    min_diversity:
        Minimum source domain diversity score in [0.0, 1.0].
        Set to 0.0 to disable diversity enforcement.
    require_evidence:
        If ``True``, a claim with no evidence IDs is rejected even if
        ``min_sources == 0``.
    """

    min_confidence: float = 0.60
    min_sources: int = 1
    min_diversity: float = 0.0
    require_evidence: bool = True


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimMetrics:
    """Caller-supplied quality metrics for a candidate claim (§3.4).

    Parameters
    ----------
    confidence:
        Justification confidence in [0.0, 1.0].  Pass
        ``Justification.confidence`` here (already evidence-scaled).
    source_count:
        Number of distinct evidence sources backing this claim.
    diversity_score:
        Source domain diversity in [0.0, 1.0].  ``None`` disables the
        diversity check regardless of policy.
    evidence_ids:
        List of evidence IDs attached to this claim.
    """

    confidence: float
    source_count: int
    diversity_score: Optional[float] = None
    evidence_ids: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommitmentResult:
    """Outcome of :meth:`CommitmentGate.evaluate` (§3.4).

    Attributes
    ----------
    status:
        ``"PASS"`` or ``"FAIL"``.
    reason_codes:
        Empty on PASS.  On FAIL, one or more of:
        ``LOW_CONFIDENCE``, ``INSUFFICIENT_SOURCES``, ``LOW_DIVERSITY``,
        ``NO_EVIDENCE``.
    """

    status: str  # "PASS" | "FAIL"
    reason_codes: List[str]

    @property
    def passed(self) -> bool:
        return self.status == "PASS"


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


class CommitmentGate:
    """Propositional Commitment Gate — evaluates whether a claim may be accepted.

    Parameters
    ----------
    policy:
        Threshold policy.  Defaults to :class:`CommitmentPolicy`.

    Examples
    --------
    >>> gate = CommitmentGate()
    >>> result = gate.evaluate(ClaimMetrics(confidence=0.8, source_count=3))
    >>> result.passed
    True
    >>> result = gate.evaluate(ClaimMetrics(confidence=0.3, source_count=0))
    >>> result.passed
    False
    >>> "LOW_CONFIDENCE" in result.reason_codes
    True
    """

    def __init__(self, policy: CommitmentPolicy = CommitmentPolicy()) -> None:
        self._policy = policy

    def evaluate(self, metrics: ClaimMetrics) -> CommitmentResult:
        """Run PCG against *metrics*.

        Parameters
        ----------
        metrics:
            Quality metrics for the candidate claim.

        Returns
        -------
        CommitmentResult
            ``status="PASS"`` only when all enabled thresholds are met.
        """
        reasons: List[str] = []
        p = self._policy

        # --- I1: No Unjustified Assertion ---
        if p.require_evidence and not metrics.evidence_ids:
            reasons.append("NO_EVIDENCE")

        if metrics.confidence < p.min_confidence:
            reasons.append("LOW_CONFIDENCE")

        if metrics.source_count < p.min_sources:
            reasons.append("INSUFFICIENT_SOURCES")

        if (
            p.min_diversity > 0.0
            and metrics.diversity_score is not None
            and metrics.diversity_score < p.min_diversity
        ):
            reasons.append("LOW_DIVERSITY")

        return CommitmentResult(
            status="PASS" if not reasons else "FAIL",
            reason_codes=reasons,
        )
