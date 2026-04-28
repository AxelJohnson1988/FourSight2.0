"""Core types for the VL-LLM v0.1 Verification Layer.

Definitions map directly to the normative spec (§1):
  Claim          — structured proposition with deterministic ID (§1.1)
  EvidenceItem   — source-backed artifact with SHA-256 hash (§1.1)
  Justification  — claim → evidence linkage with computed confidence (§1.1)
  BeliefState    — persistent accepted-claim set + relations (§1.1)
  ClaimRelation  — typed edge between claims (implies / contradicts)

Canonical JSON (§1.3)
  All IDs are derived by sha256(CJ(fields)) where CJ sorts keys and
  uses compact separators — consistent with the existing GPAM ledger.

Invariant I6 — Deterministic Decision Hashing
  Every state transition uses canonical JSON before hashing so that
  two systems given identical inputs always produce identical hashes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional


# ---------------------------------------------------------------------------
# Canonical JSON (§1.3, Invariant I6)
# ---------------------------------------------------------------------------


def canonical_json(obj: object) -> str:
    """RFC 8785-style canonical JSON: sorted keys, compact separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_cj(obj: object) -> str:
    """Return sha256(CJ(obj)) as a 64-char hex string."""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Claim (§1.1)
# ---------------------------------------------------------------------------


class ClaimStatus(str, Enum):
    """Lifecycle states of a claim inside the belief system."""

    DRAFT = "DRAFT"           # LLM output, not yet evaluated
    ACCEPTED = "ACCEPTED"     # Passed PCG; written to PAL
    REJECTED = "REJECTED"     # Failed PCG
    UNDECIDED = "UNDECIDED"   # Contradiction detected; demoted
    RETRACTED = "RETRACTED"   # Explicitly withdrawn


@dataclass(frozen=True)
class Claim:
    """A structured proposition (§1.1).

    Parameters
    ----------
    claim_id:
        Stable deterministic ID = sha256(CJ({text, scope}))[:16].
        Derive via :func:`claim_id_for`.
    text:
        Human-readable statement of the claim.
    scope:
        Contextual metadata (domain, case_id, etc.) — not part of the
        claim's truth content but used for routing and grouping.
    status:
        Lifecycle state (default ``DRAFT``).
    predicate_form:
        Optional logical formalization, e.g. ``"swore_at(Ben, staff, T)"``
    """

    claim_id: str
    text: str
    scope: Dict[str, str]
    status: ClaimStatus = ClaimStatus.DRAFT
    predicate_form: Optional[str] = None


def claim_id_for(text: str, scope: Dict[str, str]) -> str:
    """Return the deterministic claim ID for a (text, scope) pair (§1.3/I6)."""
    return sha256_cj({"text": text, "scope": scope})[:16]


# ---------------------------------------------------------------------------
# Evidence Item (§1.1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceItem:
    """A source-backed artifact used to justify a claim (§1.1).

    Parameters
    ----------
    evidence_id:
        Deterministic ID = sha256(CJ({source_uri, artifact_hash}))[:16].
        Derive via :func:`evidence_id_for`.
    source_uri:
        URI of the originating document or URL.
    artifact_hash:
        sha256 of the raw artifact bytes or canonical text.
    extract:
        Optional verbatim excerpt (≤ 2 000 chars).
    retrieved_at:
        UTC ISO-8601 timestamp ending with ``Z``.
    """

    evidence_id: str
    source_uri: str
    artifact_hash: str
    extract: Optional[str] = None
    retrieved_at: str = ""


def evidence_id_for(source_uri: str, artifact_hash: str) -> str:
    """Return the deterministic evidence ID for a (source_uri, artifact_hash) pair."""
    return sha256_cj({"source_uri": source_uri, "artifact_hash": artifact_hash})[:16]


def artifact_hash_for(data: str | bytes) -> str:
    """Return sha256 of *data* (bytes or UTF-8 string)."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Justification (§1.1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Justification:
    """A claim's support set with computed confidence (§1.1).

    Confidence is NOT hand-waved — it is computed from evidence quality:
    ``confidence = base_confidence * (1 - 1/sqrt(max(1, evidence_count)))``

    Parameters
    ----------
    claim_id:
        The claim this justification supports.
    evidence_ids:
        IDs of :class:`EvidenceItem` objects in this support set.
    method:
        How the evidence was gathered: ``"vmg"``, ``"human"``, ``"tool"``.
    base_confidence:
        Raw caller-supplied confidence before evidence count scaling.
    source_count:
        Number of distinct sources (may differ from ``len(evidence_ids)``).
    diversity_score:
        Source domain diversity in [0, 1].
    """

    claim_id: str
    evidence_ids: List[str]
    method: str
    base_confidence: float
    source_count: int = 0
    diversity_score: float = 0.0

    @property
    def confidence(self) -> float:
        """Evidence-scaled confidence (§1.1 — computed, not hand-waved).

        Formula: ``base_confidence × n / (n + 1)``

        This is a Laplace-smoothed scaling: monotone increasing in evidence
        count, bounded above by ``base_confidence``, and zero when there is
        no evidence (``n = 0``).

        n=0 → 0.0   (no evidence, no confidence)
        n=1 → base × 0.500
        n=2 → base × 0.667
        n=3 → base × 0.750
        n=∞ → base × 1.000
        """
        n = len(self.evidence_ids)
        if n == 0:
            return 0.0
        return round(self.base_confidence * n / (n + 1), 6)


# ---------------------------------------------------------------------------
# Claim Relation (§3.2)
# ---------------------------------------------------------------------------


class RelationType(str, Enum):
    """Typed edge between two claims."""

    IMPLIES = "implies"
    CONTRADICTS = "contradicts"


@dataclass(frozen=True)
class ClaimRelation:
    """A directed relation between claim A and claim B."""

    relation_type: RelationType
    claim_a: str  # claim_id of the antecedent
    claim_b: str  # claim_id of the consequent / contradictee


# ---------------------------------------------------------------------------
# Belief State (§1.1)
# ---------------------------------------------------------------------------


@dataclass
class BeliefState:
    """Persistent set of accepted claims and their relations (§1.1).

    Formally: ``B ⊆ Claims × Justifications`` such that for each
    ``(C, J) ∈ B``, ``J.confidence >= threshold``.

    This is a *mutable* object — the pipeline updates it in-place
    across the A–F decision steps.
    """

    claims: Dict[str, Claim] = field(default_factory=dict)
    justifications: Dict[str, Justification] = field(default_factory=dict)
    relations: List[ClaimRelation] = field(default_factory=list)

    @property
    def accepted(self) -> FrozenSet[str]:
        """Frozenset of claim_ids with status ACCEPTED."""
        return frozenset(
            cid for cid, c in self.claims.items() if c.status == ClaimStatus.ACCEPTED
        )

    def accept(self, claim_id: str) -> None:
        """Transition *claim_id* to ACCEPTED (in-place)."""
        if claim_id in self.claims:
            c = self.claims[claim_id]
            self.claims[claim_id] = Claim(
                claim_id=c.claim_id,
                text=c.text,
                scope=c.scope,
                status=ClaimStatus.ACCEPTED,
                predicate_form=c.predicate_form,
            )

    def demote(self, claim_id: str, to: ClaimStatus = ClaimStatus.UNDECIDED) -> None:
        """Demote *claim_id* (e.g. on contradiction detection — Invariant I3)."""
        if claim_id in self.claims:
            c = self.claims[claim_id]
            self.claims[claim_id] = Claim(
                claim_id=c.claim_id,
                text=c.text,
                scope=c.scope,
                status=to,
                predicate_form=c.predicate_form,
            )

    def implies_edges(self) -> List[ClaimRelation]:
        return [r for r in self.relations if r.relation_type == RelationType.IMPLIES]

    def contradicts_edges(self) -> List[ClaimRelation]:
        return [r for r in self.relations if r.relation_type == RelationType.CONTRADICTS]
