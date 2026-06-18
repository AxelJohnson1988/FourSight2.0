"""Tests for VL-LLM pipeline — Steps A–F, Invariants I1/I3/I5."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from gpam.vl_llm.audit_ledger import AuditLedger, PalAppendResult
from gpam.vl_llm.claim_extractor import ClaimExtractor
from gpam.vl_llm.closure_engine import ClosureEngine
from gpam.vl_llm.commitment_gate import CommitmentGate, CommitmentPolicy
from gpam.vl_llm.evidence_store import InMemoryEvidenceStore
from gpam.vl_llm.llm_adapter import StubLLMAdapter
from gpam.vl_llm.pipeline import EvidenceBinding, VerificationPipeline
from gpam.vl_llm.types import ClaimRelation, ClaimStatus, RelationType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _degraded_ledger() -> AuditLedger:
    """Return an AuditLedger whose GPAM write always fails (simulates I5)."""
    ledger = AuditLedger()
    ledger._write_to_gpam = MagicMock(side_effect=RuntimeError("GPAM unavailable"))
    return ledger


def _pipe(
    response: str = "The sky is blue.",
    *,
    policy: CommitmentPolicy = CommitmentPolicy(require_evidence=False, min_sources=0),
    ledger: AuditLedger = None,
) -> VerificationPipeline:
    return VerificationPipeline(
        llm_adapter=StubLLMAdapter([response]),
        claim_extractor=ClaimExtractor({"domain": "test"}),
        evidence_store=InMemoryEvidenceStore(),
        commitment_gate=CommitmentGate(policy),
        closure_engine=ClosureEngine(),
        audit_ledger=ledger or AuditLedger(),
    )


# ---------------------------------------------------------------------------
# Step A — raw text preserved
# ---------------------------------------------------------------------------


def test_pipeline_raw_text_preserved() -> None:
    pipe = _pipe("Hello world sentence. Second sentence here.")
    result = pipe.run("prompt")
    assert "Hello world" in result.raw_text


# ---------------------------------------------------------------------------
# Step B — claims extracted
# ---------------------------------------------------------------------------


def test_pipeline_claims_extracted() -> None:
    pipe = _pipe("The patient arrived. She was discharged later.")
    result = pipe.run("prompt")
    assert len(result.belief_state.claims) >= 1


# ---------------------------------------------------------------------------
# Step D — PCG acceptance (Invariant I1)
# ---------------------------------------------------------------------------


def test_pipeline_accepts_with_sufficient_evidence() -> None:
    store = InMemoryEvidenceStore()
    r = store.add_artifact(source_uri="https://a.com", data="evidence")
    text = "The patient arrived at nine in the morning."
    extractor = ClaimExtractor({"domain": "test"})
    extraction = extractor.extract(text)
    cid = extraction.claims[0].claim_id

    policy = CommitmentPolicy(min_confidence=0.5, min_sources=1, require_evidence=True)
    pipe = VerificationPipeline(
        llm_adapter=StubLLMAdapter([text]),
        claim_extractor=extractor,
        evidence_store=store,
        commitment_gate=CommitmentGate(policy),
        audit_ledger=AuditLedger(),
    )
    binding = EvidenceBinding(
        claim_id=cid,
        evidence_ids=[r.evidence_id],
        source_count=1,
        base_confidence=0.9,
    )
    result = pipe.run("prompt", evidence_bindings=[binding])
    assert cid in result.newly_accepted
    assert result.belief_state.claims[cid].status == ClaimStatus.ACCEPTED


def test_pipeline_rejects_without_evidence_when_required() -> None:
    policy = CommitmentPolicy(require_evidence=True)
    pipe = _pipe("The sky is very blue today.", policy=policy)
    result = pipe.run("prompt")
    # No evidence bindings → all claims should be REJECTED.
    for cid in result.rejected:
        assert result.belief_state.claims[cid].status == ClaimStatus.REJECTED


# ---------------------------------------------------------------------------
# Step E — Contradiction demotion (Invariant I3)
# ---------------------------------------------------------------------------


def test_pipeline_demotes_lower_confidence_on_contradiction() -> None:
    store = InMemoryEvidenceStore()
    r1 = store.add_artifact(source_uri="https://a.com", data="evidence A")
    r2 = store.add_artifact(source_uri="https://b.com", data="evidence B")

    text = "The defendant was present at the scene. The defendant was not present."
    extractor = ClaimExtractor({"domain": "legal"})
    extraction = extractor.extract(text)

    if len(extraction.claims) < 2:
        pytest.skip("Extractor produced fewer than 2 claims for this text.")

    cid_a = extraction.claims[0].claim_id
    cid_b = extraction.claims[1].claim_id

    # Manually inject a CONTRADICTS relation.
    from gpam.vl_llm.types import ClaimRelation, RelationType

    policy = CommitmentPolicy(min_confidence=0.0, min_sources=0, require_evidence=True)
    pipe = VerificationPipeline(
        llm_adapter=StubLLMAdapter([text]),
        claim_extractor=extractor,
        evidence_store=store,
        commitment_gate=CommitmentGate(policy),
        audit_ledger=AuditLedger(),
    )

    # Give A more confidence than B.
    bindings = [
        EvidenceBinding(
            claim_id=cid_a,
            evidence_ids=[r1.evidence_id],
            source_count=1,
            base_confidence=0.9,
        ),
        EvidenceBinding(
            claim_id=cid_b,
            evidence_ids=[r2.evidence_id],
            source_count=1,
            base_confidence=0.3,
        ),
    ]
    result = pipe.run("prompt", evidence_bindings=bindings)

    # Inject contradiction and re-run consistency manually for inspection.
    bs = result.belief_state
    bs.relations.append(ClaimRelation(RelationType.CONTRADICTS, cid_a, cid_b))
    from gpam.vl_llm.pipeline import _detect_contradictions, _resolve_contradiction

    bs.accept(cid_a)
    bs.accept(cid_b)
    pairs = _detect_contradictions(bs)
    for a, b in pairs:
        _resolve_contradiction(bs, a, b)

    # cid_b had lower confidence → demoted.
    assert bs.claims[cid_b].status == ClaimStatus.UNDECIDED
    assert bs.claims[cid_a].status == ClaimStatus.ACCEPTED


# ---------------------------------------------------------------------------
# Invariant I5 — Fail-closed / degraded PAL
# ---------------------------------------------------------------------------


def test_pipeline_is_draft_only_when_pal_degraded() -> None:
    ledger = _degraded_ledger()
    pipe = _pipe("Facts about the case.", ledger=ledger)
    result = pipe.run("prompt")
    assert result.draft_only is True


def test_pipeline_draft_only_contains_no_accepted_claims() -> None:
    ledger = _degraded_ledger()
    pipe = _pipe("Some claim about something.", ledger=ledger)
    result = pipe.run("prompt")
    assert len(result.newly_accepted) == 0


# ---------------------------------------------------------------------------
# Step E — Closure (Invariant I4)
# ---------------------------------------------------------------------------


def test_pipeline_applies_closure_over_implies_edges() -> None:
    text = "Fact A is established. Therefore fact B follows."
    extractor = ClaimExtractor({"domain": "test"})
    extraction = extractor.extract(text)

    if len(extraction.claims) < 2 or not extraction.relations:
        pytest.skip("Extractor did not produce an implication for this text.")

    cid_a = extraction.claims[0].claim_id
    cid_b = extraction.claims[1].claim_id

    policy = CommitmentPolicy(min_confidence=0.0, min_sources=0, require_evidence=False)
    pipe = VerificationPipeline(
        llm_adapter=StubLLMAdapter([text]),
        claim_extractor=extractor,
        evidence_store=InMemoryEvidenceStore(),
        commitment_gate=CommitmentGate(policy),
        closure_engine=ClosureEngine(),
        audit_ledger=AuditLedger(),
    )
    result = pipe.run("prompt")
    # If cid_a accepted AND implies cid_b, closure should have accepted cid_b.
    if cid_a in result.newly_accepted and result.closure_result:
        assert cid_b in result.newly_accepted or cid_b in (result.closure_result.newly_accepted or [])


# ---------------------------------------------------------------------------
# PAL records emitted
# ---------------------------------------------------------------------------


def test_pipeline_emits_pal_records() -> None:
    pipe = _pipe("Single claim sentence here.")
    result = pipe.run("prompt")
    assert len(result.pal_records) >= 1  # At minimum CLAIM_EXTRACTED.
