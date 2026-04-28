"""VL-LLM v0.1 Verification Pipeline — Steps A–F (§4).

Decision Procedure
------------------
A  Generate       — call LLM, treat output as untrusted draft text
B  Extract        — parse text into Claim + ClaimRelation structs
C  Attach Evidence— link existing EvidenceItems to candidate claims
D  Commitment Gate— evaluate each claim against PCG thresholds (I1)
E  Consistency    — detect contradictions (I3) + run closure (I4)
F  Persist        — hash-chain all state transitions to PAL (I6)

Invariants enforced by this module
-----------------------------------
I1  No claim is labelled ACCEPTED before its PCG decision is in PAL.
I3  On contradiction, the lower-confidence claim is demoted to UNDECIDED.
I5  If PAL is degraded (unavailable), ALL outputs are labelled DRAFT.
I6  Every PAL write uses canonical JSON + SHA-256.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from gpam.vl_llm.audit_ledger import AuditLedger
from gpam.vl_llm.claim_extractor import ClaimExtractor
from gpam.vl_llm.closure_engine import ClosureEngine, ClosureResult
from gpam.vl_llm.commitment_gate import ClaimMetrics, CommitmentGate, CommitmentPolicy
from gpam.vl_llm.evidence_store import InMemoryEvidenceStore
from gpam.vl_llm.llm_adapter import LLMAdapter, LLMInput
from gpam.vl_llm.types import (
    BeliefState,
    Claim,
    ClaimRelation,
    ClaimStatus,
    Justification,
    RelationType,
    canonical_json,
    claim_id_for,
)


# ---------------------------------------------------------------------------
# Evidence binding (Step C)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceBinding:
    """Associates a claim with evidence IDs and quality metrics for the PCG."""

    claim_id: str
    evidence_ids: List[str]
    source_count: int
    base_confidence: float
    diversity_score: Optional[float] = None
    method: str = "explicit"


# ---------------------------------------------------------------------------
# Pipeline result
# ---------------------------------------------------------------------------


@dataclass
class PipelineResult:
    """Complete output of one A–F pipeline run.

    Attributes
    ----------
    belief_state:
        Final belief state after steps D–F.
    newly_accepted:
        Claim IDs accepted in this run (via PCG or closure).
    rejected:
        Claim IDs that failed the PCG.
    contradictions:
        Pairs of (claim_a_id, claim_b_id) that were found to contradict.
    closure_result:
        Output of the LCE (may be ``None`` if no IMPLIES edges exist).
    draft_only:
        ``True`` when PAL was degraded (Invariant I5) — all outputs must
        be labelled DRAFT by the caller.
    pal_records:
        List of record hashes written to PAL, in order.
    raw_text:
        Untrusted LLM output from Step A (preserved for audit).
    """

    belief_state: BeliefState
    newly_accepted: List[str] = field(default_factory=list)
    rejected: List[str] = field(default_factory=list)
    contradictions: List[tuple] = field(default_factory=list)
    closure_result: Optional[ClosureResult] = None
    draft_only: bool = False
    pal_records: List[str] = field(default_factory=list)
    raw_text: str = ""


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class VerificationPipeline:
    """Wraps an LLM and enforces truth-maintenance externally (§0, §4).

    The LLM is treated as an untrusted stochastic generator.  Every claim
    it produces starts as DRAFT and must pass the PCG before being accepted.

    Parameters
    ----------
    llm_adapter:
        Any :class:`~gpam.vl_llm.llm_adapter.LLMAdapter` implementation.
    claim_extractor:
        Extractor used in Step B.
    evidence_store:
        Store queried in Step C.  Defaults to an empty in-memory store.
    commitment_gate:
        PCG used in Step D.
    closure_engine:
        LCE used in Step E.
    audit_ledger:
        PAL used in Step F.

    Examples
    --------
    >>> from gpam.vl_llm.llm_adapter import StubLLMAdapter
    >>> pipe = VerificationPipeline(llm_adapter=StubLLMAdapter(["Fact A. Therefore fact B."]))
    >>> result = pipe.run("Summarise the case.")
    >>> result.draft_only
    False
    """

    def __init__(
        self,
        llm_adapter: LLMAdapter,
        *,
        claim_extractor: Optional[ClaimExtractor] = None,
        evidence_store=None,
        commitment_gate: Optional[CommitmentGate] = None,
        closure_engine: Optional[ClosureEngine] = None,
        audit_ledger: Optional[AuditLedger] = None,
    ) -> None:
        self._llm = llm_adapter
        self._extractor = claim_extractor or ClaimExtractor()
        self._store = evidence_store or InMemoryEvidenceStore()
        self._gate = commitment_gate or CommitmentGate()
        self._lce = closure_engine or ClosureEngine()
        self._pal = audit_ledger or AuditLedger()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(
        self,
        prompt: str,
        *,
        context: Optional[str] = None,
        scope: Optional[Dict[str, str]] = None,
        evidence_bindings: Optional[List[EvidenceBinding]] = None,
        policy: Optional[CommitmentPolicy] = None,
    ) -> PipelineResult:
        """Execute Steps A–F and return a :class:`PipelineResult`.

        Parameters
        ----------
        prompt:
            Input to the LLM.
        context:
            Optional additional context passed to the LLM.
        scope:
            Claim scope dict (propagated to the extractor).
        evidence_bindings:
            Pre-computed evidence attachments for specific claims.
            Claims without a binding will have no evidence and fail the
            PCG when ``require_evidence=True``.
        policy:
            PCG policy override.  If provided, a new :class:`CommitmentGate`
            is created for this run only.
        """
        if policy:
            gate = CommitmentGate(policy)
        else:
            gate = self._gate

        bs = BeliefState()
        pal_hashes: List[str] = []

        # --- Step A: Generate (LLM is untrusted) ---
        llm_response = self._llm.generate(LLMInput(prompt=prompt, context=context))
        raw_text = llm_response.text

        # --- Step B: Extract claims ---
        extraction = self._extractor.extract(raw_text, scope=scope)
        for claim in extraction.claims:
            bs.claims[claim.claim_id] = claim
        bs.relations.extend(extraction.relations)

        r = self._pal.append(
            "CLAIM_EXTRACTED",
            {
                "claim_count": len(extraction.claims),
                "relation_count": len(extraction.relations),
                "prompt_hash": _sha256_str(prompt),
            },
        )
        pal_hashes.append(r.record_hash)

        # Invariant I5 — check early; if degraded, downgrade all outputs.
        if self._pal.degraded:
            return PipelineResult(
                belief_state=bs,
                draft_only=True,
                pal_records=pal_hashes,
                raw_text=raw_text,
            )

        # --- Step C: Attach evidence ---
        bindings: Dict[str, EvidenceBinding] = {
            b.claim_id: b for b in (evidence_bindings or [])
        }

        # --- Step D: Commitment Gate ---
        newly_accepted: List[str] = []
        rejected: List[str] = []

        for cid, claim in bs.claims.items():
            binding = bindings.get(cid)
            metrics = _metrics_from_binding(binding)
            result = gate.evaluate(metrics)

            event_payload = {
                "claim_id": cid,
                "status": result.status,
                "reason_codes": result.reason_codes,
                "confidence": metrics.confidence,
                "source_count": metrics.source_count,
            }
            r = self._pal.append("COMMIT_DECISION", event_payload)
            pal_hashes.append(r.record_hash)

            if result.passed:
                # I1: Accept only AFTER the PAL write succeeds.
                bs.accept(cid)
                newly_accepted.append(cid)

                if binding:
                    bs.justifications[cid] = Justification(
                        claim_id=cid,
                        evidence_ids=binding.evidence_ids,
                        method=binding.method,
                        base_confidence=binding.base_confidence,
                        source_count=binding.source_count,
                        diversity_score=binding.diversity_score or 0.0,
                    )
            else:
                bs.demote(cid, ClaimStatus.REJECTED)
                rejected.append(cid)

        # --- Step E: Consistency check + Closure ---
        contradictions = _detect_contradictions(bs)
        for a_id, b_id in contradictions:
            _resolve_contradiction(bs, a_id, b_id)
            r = self._pal.append(
                "CONTRADICTION_FOUND",
                {"claim_a": a_id, "claim_b": b_id},
            )
            pal_hashes.append(r.record_hash)
            # Remove demoted claims from newly_accepted.
            for cid in (a_id, b_id):
                if bs.claims[cid].status != ClaimStatus.ACCEPTED and cid in newly_accepted:
                    newly_accepted.remove(cid)

        # Apply LCE.
        closure_result: Optional[ClosureResult] = None
        if bs.accepted and bs.implies_edges():
            claim_scopes = {cid: c.scope for cid, c in bs.claims.items()}
            closure_result = self._lce.close(
                accepted=bs.accepted,
                relations=bs.implies_edges(),
                claim_scopes=claim_scopes,
            )
            for new_cid in closure_result.newly_accepted:
                if new_cid in bs.claims:
                    bs.accept(new_cid)
                    newly_accepted.append(new_cid)

            r = self._pal.append(
                "CLOSURE_APPLIED",
                {
                    "newly_accepted": closure_result.newly_accepted,
                    "truncated": closure_result.truncated,
                    "proof_steps": [
                        {"from": s.from_claim, "to": s.to_claim, "depth": s.depth}
                        for s in closure_result.proof_steps
                    ],
                },
            )
            pal_hashes.append(r.record_hash)

        # --- Step F: Final PAL flush is implicit (each step wrote immediately). ---

        return PipelineResult(
            belief_state=bs,
            newly_accepted=newly_accepted,
            rejected=rejected,
            contradictions=contradictions,
            closure_result=closure_result,
            draft_only=False,
            pal_records=pal_hashes,
            raw_text=raw_text,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _metrics_from_binding(binding: Optional[EvidenceBinding]) -> ClaimMetrics:
    if binding is None:
        return ClaimMetrics(confidence=0.0, source_count=0, evidence_ids=[])
    return ClaimMetrics(
        confidence=binding.base_confidence,
        source_count=binding.source_count,
        diversity_score=binding.diversity_score,
        evidence_ids=binding.evidence_ids,
    )


def _detect_contradictions(bs: BeliefState) -> List[tuple]:
    """Return pairs (a_id, b_id) where both are ACCEPTED and a contradicts b."""
    pairs = []
    accepted = bs.accepted
    for rel in bs.contradicts_edges():
        if rel.claim_a in accepted and rel.claim_b in accepted:
            pairs.append((rel.claim_a, rel.claim_b))
    return pairs


def _resolve_contradiction(bs: BeliefState, a_id: str, b_id: str) -> None:
    """Demote the lower-confidence claim to UNDECIDED (Invariant I3).

    When confidence is equal, both are demoted.
    """
    j_a = bs.justifications.get(a_id)
    j_b = bs.justifications.get(b_id)
    conf_a = j_a.confidence if j_a else 0.0
    conf_b = j_b.confidence if j_b else 0.0

    if conf_a > conf_b:
        bs.demote(b_id, ClaimStatus.UNDECIDED)
    elif conf_b > conf_a:
        bs.demote(a_id, ClaimStatus.UNDECIDED)
    else:
        bs.demote(a_id, ClaimStatus.UNDECIDED)
        bs.demote(b_id, ClaimStatus.UNDECIDED)


def _sha256_str(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()
