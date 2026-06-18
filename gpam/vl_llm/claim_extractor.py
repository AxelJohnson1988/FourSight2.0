"""Claim Extractor — LLM text → structured Claim + Relation set (§3.2, Step B).

This module implements a heuristic extractor that works without an LLM
(no external network calls, fully testable).  Every extracted claim starts
at ``DRAFT`` status — the PCG decides acceptance.

Heuristics used
---------------
1. Sentence splitting — each non-trivial sentence becomes a candidate claim.
2. Implication detection — sentences containing signals like "therefore",
   "implies", "if ... then" are split into antecedent/consequent pairs and
   recorded as IMPLIES relations.
3. Contradiction detection — signals like "however", "but", "contradicts",
   "in contrast" between adjacent sentences create CONTRADICTS relations.

All claim IDs are derived deterministically via ``claim_id_for(text, scope)``
so the same sentence always produces the same ID (Invariant I6).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from gpam.vl_llm.types import (
    Claim,
    ClaimRelation,
    ClaimStatus,
    RelationType,
    claim_id_for,
)

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExtractionResult:
    """Output of :meth:`ClaimExtractor.extract`.

    Attributes
    ----------
    claims:
        Extracted claim objects.  All have ``status=DRAFT``.
    relations:
        Detected implication and contradiction edges between claims.
    """

    claims: List[Claim]
    relations: List[ClaimRelation]


# ---------------------------------------------------------------------------
# Sentence splitting
# ---------------------------------------------------------------------------

_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")
_MIN_CLAIM_WORDS = 4  # Ignore sentence fragments shorter than this.


def _split_sentences(text: str) -> List[str]:
    """Split *text* into sentences.  Very short fragments are discarded."""
    raw = _SENTENCE_RE.split(text.strip())
    return [s.strip() for s in raw if len(s.split()) >= _MIN_CLAIM_WORDS]


# ---------------------------------------------------------------------------
# Relation signals
# ---------------------------------------------------------------------------

_IMPLIES_SIGNALS = re.compile(
    r"\b(therefore|thus|hence|implies?|it follows|consequently|so\b|"
    r"if\b.+?\bthen\b|because|since|due to)\b",
    re.IGNORECASE,
)

_CONTRADICTS_SIGNALS = re.compile(
    r"\b(however|but\b|yet\b|although|nevertheless|contradicts?|"
    r"in contrast|on the other hand|despite|even though)\b",
    re.IGNORECASE,
)


def _has_implication(sentence: str) -> bool:
    return bool(_IMPLIES_SIGNALS.search(sentence))


def _has_contradiction(sentence: str) -> bool:
    return bool(_CONTRADICTS_SIGNALS.search(sentence))


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------


class ClaimExtractor:
    """Heuristic extractor: raw LLM text → structured claims + relations (§3.2).

    Parameters
    ----------
    default_scope:
        Default scope dict applied to all claims when no per-sentence scope
        is provided.  Should include at least ``{"domain": "..."}`` so claims
        from different domains don't share IDs.

    Examples
    --------
    >>> extractor = ClaimExtractor({"domain": "legal", "case": "ruby-tuesday"})
    >>> result = extractor.extract("The patient arrived. Therefore she was admitted.")
    >>> len(result.claims)
    2
    >>> result.relations[0].relation_type.value
    'implies'
    """

    def __init__(self, default_scope: Optional[Dict[str, str]] = None) -> None:
        self._default_scope: Dict[str, str] = default_scope or {}

    def extract(self, text: str, scope: Optional[Dict[str, str]] = None) -> ExtractionResult:
        """Extract claims and relations from *text*.

        Parameters
        ----------
        text:
            Raw LLM output (Step A).  Treated as untrusted draft.
        scope:
            Per-call scope override.  Merged with ``default_scope``
            (call-level values take precedence).

        Returns
        -------
        ExtractionResult
            Claims all start as ``DRAFT``.  Relations are detected
            heuristically — no acceptance is implied.
        """
        merged_scope: Dict[str, str] = {**self._default_scope, **(scope or {})}
        sentences = _split_sentences(text)

        claims: List[Claim] = []
        relations: List[ClaimRelation] = []

        prev_claim: Optional[Claim] = None

        for sentence in sentences:
            cid = claim_id_for(sentence, merged_scope)
            claim = Claim(
                claim_id=cid,
                text=sentence,
                scope=merged_scope,
                status=ClaimStatus.DRAFT,
            )
            claims.append(claim)

            # Implication: this sentence itself contains a causal/inference signal.
            if _has_implication(sentence) and prev_claim is not None:
                relations.append(
                    ClaimRelation(
                        relation_type=RelationType.IMPLIES,
                        claim_a=prev_claim.claim_id,
                        claim_b=cid,
                    )
                )

            # Contradiction: this sentence contradicts the previous one.
            if _has_contradiction(sentence) and prev_claim is not None:
                relations.append(
                    ClaimRelation(
                        relation_type=RelationType.CONTRADICTS,
                        claim_a=prev_claim.claim_id,
                        claim_b=cid,
                    )
                )

            prev_claim = claim

        return ExtractionResult(claims=claims, relations=relations)
