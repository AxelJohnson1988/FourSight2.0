"""Semantic drift detection using cosine similarity on word-frequency vectors.

Thresholds (configurable, defaults match the Warden specification):

    > 0.95        → SAFE
    0.80 – 0.95   → WARNING
    < 0.80        → BLOCK

Cosine similarity is computed over term-frequency (bag-of-words) vectors
derived from whitespace-tokenised, lower-cased text.  No external
dependencies are required.

Usage::

    from warden.drift import evaluate_drift, DriftStatus

    result = evaluate_drift(raw_input, processed_output)
    if result.status == DriftStatus.BLOCK:
        print(f"Drift blocked — score {result.score:.4f}")
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from enum import Enum


class DriftStatus(str, Enum):
    """Outcome of a drift evaluation."""

    SAFE = "safe"
    WARNING = "warning"
    BLOCK = "block"


@dataclass(frozen=True)
class DriftResult:
    """Immutable result of a single drift evaluation."""

    score: float
    """Cosine similarity in [0, 1]."""

    status: DriftStatus
    """Categorical outcome based on configured thresholds."""

    def is_blocked(self) -> bool:
        """Return ``True`` when the status is :attr:`DriftStatus.BLOCK`."""
        return self.status == DriftStatus.BLOCK


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def cosine_similarity(text_a: str, text_b: str) -> float:
    """Return the cosine similarity in [0, 1] between two text strings.

    Both strings are tokenised by whitespace and lower-cased before computing
    term-frequency vectors.  Special cases:

    * Both empty → ``1.0`` (identical)
    * One empty  → ``0.0`` (maximally different)
    """
    vec_a = _vectorize(text_a)
    vec_b = _vectorize(text_b)
    all_words = set(vec_a) | set(vec_b)

    if not all_words:
        return 1.0  # both empty → identical

    dot = sum(vec_a[w] * vec_b[w] for w in all_words)
    mag_a = math.sqrt(sum(v * v for v in vec_a.values()))
    mag_b = math.sqrt(sum(v * v for v in vec_b.values()))

    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0

    return dot / (mag_a * mag_b)


def evaluate_drift(
    text_a: str,
    text_b: str,
    *,
    safe_threshold: float = 0.95,
    warn_threshold: float = 0.80,
) -> DriftResult:
    """Compute semantic drift between *text_a* (raw) and *text_b* (processed).

    Parameters
    ----------
    text_a:
        Raw / pre-normalisation text (Channel A).
    text_b:
        Post-normalisation text (Channel B).
    safe_threshold:
        Cosine similarity above which content is SAFE (default ``0.95``).
    warn_threshold:
        Score at or above which a WARNING is issued; below → BLOCK
        (default ``0.80``).

    Returns
    -------
    DriftResult
        Contains the numeric *score* and the categorical *status*.
    """
    score = cosine_similarity(text_a, text_b)

    if score > safe_threshold:
        status = DriftStatus.SAFE
    elif score >= warn_threshold:
        status = DriftStatus.WARNING
    else:
        status = DriftStatus.BLOCK

    return DriftResult(score=round(score, 6), status=status)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _vectorize(text: str) -> Counter:
    """Return a term-frequency Counter for *text*."""
    return Counter(text.lower().split())
