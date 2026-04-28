"""Logical Closure Engine (LCE) — entailment propagation (§3.5, Step E).

Invariant I4 — Logical Closure
  For any accepted claim C_a and implication (C_a → C_b) in the enabled
  logic fragment, the system MUST accept C_b (or record why closure was
  not applied, e.g. domain exclusion or depth limit reached).

Implementation
--------------
BFS over the implication graph starting from the current accepted set.
Terminates when no new claims can be derived, or when ``max_depth`` /
``max_new_accepts`` limits are reached.

Contradiction edges (A contradicts B) are NOT followed during closure —
they are handled separately by the pipeline's consistency check.

Cycles are detected by a visited set; the engine never loops infinitely.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Set

from gpam.vl_llm.types import ClaimRelation, RelationType


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProofStep:
    """A single entailment derivation recorded by the LCE.

    Attributes
    ----------
    from_claim:
        Accepted antecedent that triggered this step.
    to_claim:
        Newly accepted consequent.
    depth:
        BFS depth at which this step was reached.
    """

    from_claim: str
    to_claim: str
    depth: int


@dataclass(frozen=True)
class ClosureResult:
    """Output of :meth:`ClosureEngine.close` (§3.5).

    Attributes
    ----------
    newly_accepted:
        Claim IDs that were accepted by closure (not in the input set).
    proof_steps:
        Ordered derivation trace (one per newly accepted claim).
    truncated:
        ``True`` if a limit (``max_depth`` / ``max_new_accepts``) was
        hit before the graph was fully explored.  The pipeline MUST log
        this event to PAL with event_type ``CLOSURE_APPLIED``.
    skipped_domain:
        Claim IDs excluded from closure because their scope domain was
        in the ``excluded_domains`` set.
    """

    newly_accepted: List[str]
    proof_steps: List[ProofStep]
    truncated: bool = False
    skipped_domain: List[str] = dataclass.__call__  # type: ignore[assignment]

    def __post_init__(self) -> None:
        # dataclass frozen=True requires object.__setattr__ for post-init.
        object.__setattr__(self, "skipped_domain", list(self.skipped_domain or []))


# Work around frozen dataclass + mutable default:
ClosureResult.__dataclass_fields__["skipped_domain"].default_factory = list  # type: ignore[attr-defined]


@dataclass(frozen=True)
class ClosureResult:  # noqa: F811  (re-definition to fix default_factory)
    """Output of :meth:`ClosureEngine.close` (§3.5)."""

    newly_accepted: List[str]
    proof_steps: List[ProofStep]
    truncated: bool = False
    skipped_domain: List[str] = dataclass.__call__  # placeholder overridden below


# Cleaner approach — plain class instead of frozen dataclass:
class ClosureResult:  # noqa: F811
    """Output of :meth:`ClosureEngine.close` (§3.5).

    Attributes
    ----------
    newly_accepted:
        Claim IDs that were accepted by closure.
    proof_steps:
        Derivation trace.
    truncated:
        ``True`` if a depth or count limit was hit.
    skipped_domain:
        Claim IDs skipped due to domain exclusion.
    """

    __slots__ = ("newly_accepted", "proof_steps", "truncated", "skipped_domain")

    def __init__(
        self,
        newly_accepted: List[str],
        proof_steps: List[ProofStep],
        truncated: bool = False,
        skipped_domain: Optional[List[str]] = None,
    ) -> None:
        self.newly_accepted = newly_accepted
        self.proof_steps = proof_steps
        self.truncated = truncated
        self.skipped_domain = skipped_domain or []

    def __repr__(self) -> str:
        return (
            f"ClosureResult(newly_accepted={self.newly_accepted!r}, "
            f"truncated={self.truncated}, steps={len(self.proof_steps)})"
        )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ClosureEngine:
    """BFS-based logical closure over accepted claims (§3.5).

    Parameters
    ----------
    max_depth:
        Maximum BFS depth.  Prevents runaway closure on deep implication
        chains.  Default: 10 (safe for most real-world knowledge graphs).
    max_new_accepts:
        Maximum number of new claims that can be accepted in a single
        closure run.  Prevents explosion on dense graphs.  Default: 100.
    excluded_domains:
        Set of scope ``domain`` values for which closure is disabled.
        Use to isolate "closure disabled for this domain" decisions (I4).

    Examples
    --------
    >>> engine = ClosureEngine()
    >>> implications = [ClaimRelation(RelationType.IMPLIES, "A", "B"),
    ...                 ClaimRelation(RelationType.IMPLIES, "B", "C")]
    >>> result = engine.close(accepted=frozenset({"A"}), relations=implications)
    >>> result.newly_accepted
    ['B', 'C']
    >>> result.proof_steps[0].from_claim
    'A'
    """

    def __init__(
        self,
        *,
        max_depth: int = 10,
        max_new_accepts: int = 100,
        excluded_domains: Optional[Set[str]] = None,
    ) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        if max_new_accepts < 1:
            raise ValueError("max_new_accepts must be >= 1")
        self._max_depth = max_depth
        self._max_new_accepts = max_new_accepts
        self._excluded_domains: Set[str] = excluded_domains or set()

    def close(
        self,
        *,
        accepted: FrozenSet[str],
        relations: List[ClaimRelation],
        claim_scopes: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> ClosureResult:
        """Propagate entailment from *accepted* over IMPLIES edges in *relations*.

        Parameters
        ----------
        accepted:
            Frozenset of currently accepted claim IDs.
        relations:
            All known relations (IMPLIES and CONTRADICTS).  Only IMPLIES
            edges are followed; CONTRADICTS edges are ignored here.
        claim_scopes:
            Optional mapping from claim_id to its scope dict.  Used for
            domain exclusion checks.

        Returns
        -------
        ClosureResult
        """
        # Build adjacency for IMPLIES edges only.
        adj: Dict[str, List[str]] = {}
        for rel in relations:
            if rel.relation_type != RelationType.IMPLIES:
                continue
            adj.setdefault(rel.claim_a, []).append(rel.claim_b)

        scopes = claim_scopes or {}
        newly_accepted: List[str] = []
        proof_steps: List[ProofStep] = []
        skipped_domain: List[str] = []
        visited: Set[str] = set(accepted)

        # BFS queue: (claim_id, depth)
        queue: deque[tuple[str, int]] = deque(
            (cid, 0) for cid in accepted if cid in adj
        )
        truncated = False

        while queue:
            current, depth = queue.popleft()

            if depth >= self._max_depth:
                truncated = True
                continue

            for consequent in adj.get(current, []):
                if consequent in visited:
                    continue

                # Domain exclusion check (Invariant I4 — "closure disabled for domain").
                scope = scopes.get(consequent, {})
                if scope.get("domain", "") in self._excluded_domains:
                    skipped_domain.append(consequent)
                    continue

                visited.add(consequent)
                newly_accepted.append(consequent)
                proof_steps.append(ProofStep(from_claim=current, to_claim=consequent, depth=depth + 1))

                if len(newly_accepted) >= self._max_new_accepts:
                    truncated = True
                    break

                queue.append((consequent, depth + 1))

            if truncated:
                break

        return ClosureResult(
            newly_accepted=newly_accepted,
            proof_steps=proof_steps,
            truncated=truncated,
            skipped_domain=skipped_domain,
        )
