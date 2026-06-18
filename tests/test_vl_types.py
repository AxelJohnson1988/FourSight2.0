"""Tests for gpam.vl_llm.types — canonical JSON, IDs, Claim, BeliefState."""

from __future__ import annotations

import pytest

from gpam.vl_llm.types import (
    BeliefState,
    Claim,
    ClaimRelation,
    ClaimStatus,
    EvidenceItem,
    Justification,
    RelationType,
    artifact_hash_for,
    canonical_json,
    claim_id_for,
    evidence_id_for,
    sha256_cj,
)


# ---------------------------------------------------------------------------
# canonical_json / sha256_cj (Invariant I6)
# ---------------------------------------------------------------------------


def test_canonical_json_sorts_keys() -> None:
    result = canonical_json({"z": 1, "a": 2})
    assert result == '{"a":2,"z":1}'


def test_canonical_json_compact_separators() -> None:
    result = canonical_json({"k": "v"})
    assert " " not in result


def test_canonical_json_is_deterministic() -> None:
    obj = {"b": [3, 1, 2], "a": {"x": 0}}
    assert canonical_json(obj) == canonical_json(obj)


def test_sha256_cj_returns_64_hex_chars() -> None:
    h = sha256_cj({"x": 1})
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_sha256_cj_is_deterministic() -> None:
    assert sha256_cj({"key": "value"}) == sha256_cj({"key": "value"})


def test_sha256_cj_differs_on_different_inputs() -> None:
    assert sha256_cj({"a": 1}) != sha256_cj({"a": 2})


# ---------------------------------------------------------------------------
# Claim IDs
# ---------------------------------------------------------------------------


def test_claim_id_for_is_16_chars() -> None:
    cid = claim_id_for("Some text.", {"domain": "legal"})
    assert len(cid) == 16


def test_claim_id_for_is_deterministic() -> None:
    assert (
        claim_id_for("Same text.", {"domain": "X"})
        == claim_id_for("Same text.", {"domain": "X"})
    )


def test_claim_id_differs_on_different_text() -> None:
    assert claim_id_for("Text A", {}) != claim_id_for("Text B", {})


def test_claim_id_differs_on_different_scope() -> None:
    assert (
        claim_id_for("Same text.", {"domain": "A"})
        != claim_id_for("Same text.", {"domain": "B"})
    )


# ---------------------------------------------------------------------------
# Evidence IDs + artifact hashing
# ---------------------------------------------------------------------------


def test_evidence_id_for_is_16_chars() -> None:
    eid = evidence_id_for("https://example.com", "abc123")
    assert len(eid) == 16


def test_artifact_hash_for_str() -> None:
    h = artifact_hash_for("hello world")
    assert len(h) == 64


def test_artifact_hash_for_bytes() -> None:
    h = artifact_hash_for(b"hello world")
    assert len(h) == 64


def test_artifact_hash_str_bytes_equal() -> None:
    assert artifact_hash_for("hello") == artifact_hash_for("hello".encode("utf-8"))


# ---------------------------------------------------------------------------
# Claim
# ---------------------------------------------------------------------------


def test_claim_default_status_is_draft() -> None:
    c = Claim(claim_id="abc", text="T", scope={})
    assert c.status == ClaimStatus.DRAFT


def test_claim_is_frozen() -> None:
    c = Claim(claim_id="abc", text="T", scope={})
    with pytest.raises((AttributeError, TypeError)):
        c.text = "X"  # type: ignore[misc]


def test_claim_with_predicate_form() -> None:
    c = Claim(claim_id="abc", text="T", scope={}, predicate_form="P(a, b)")
    assert c.predicate_form == "P(a, b)"


# ---------------------------------------------------------------------------
# Justification.confidence
# ---------------------------------------------------------------------------


def test_justification_confidence_scales_with_evidence_count() -> None:
    j1 = Justification(
        claim_id="x", evidence_ids=["e1"], method="tool", base_confidence=1.0
    )
    j3 = Justification(
        claim_id="x",
        evidence_ids=["e1", "e2", "e3"],
        method="tool",
        base_confidence=1.0,
    )
    # More evidence → higher confidence (Laplace scaling: n/(n+1)).
    assert j3.confidence > j1.confidence
    # n=1 → 0.5; n=3 → 0.75
    assert abs(j1.confidence - 0.5) < 1e-6
    assert abs(j3.confidence - 0.75) < 1e-6


def test_justification_confidence_capped_below_base() -> None:
    j = Justification(
        claim_id="x", evidence_ids=["e1"], method="vmg", base_confidence=0.8
    )
    assert j.confidence <= j.base_confidence


def test_justification_confidence_with_no_evidence() -> None:
    j = Justification(
        claim_id="x", evidence_ids=[], method="vmg", base_confidence=0.9
    )
    # n=0 → 0.0 (no evidence means no epistemic weight)
    assert j.confidence == 0.0


# ---------------------------------------------------------------------------
# BeliefState
# ---------------------------------------------------------------------------


def _make_claim(text: str = "Test claim", cid: str = "abc") -> Claim:
    return Claim(claim_id=cid, text=text, scope={"domain": "test"})


def test_belief_state_accepted_initially_empty() -> None:
    bs = BeliefState()
    assert len(bs.accepted) == 0


def test_belief_state_accept_promotes_to_accepted() -> None:
    bs = BeliefState()
    c = _make_claim()
    bs.claims[c.claim_id] = c
    bs.accept(c.claim_id)
    assert c.claim_id in bs.accepted


def test_belief_state_demote_sets_undecided() -> None:
    bs = BeliefState()
    c = _make_claim()
    bs.claims[c.claim_id] = c
    bs.accept(c.claim_id)
    bs.demote(c.claim_id)
    assert bs.claims[c.claim_id].status == ClaimStatus.UNDECIDED


def test_belief_state_accept_unknown_id_is_noop() -> None:
    bs = BeliefState()
    bs.accept("nonexistent")  # Must not raise.


def test_belief_state_implies_edges() -> None:
    bs = BeliefState()
    rel = ClaimRelation(RelationType.IMPLIES, "a", "b")
    bs.relations.append(rel)
    assert bs.implies_edges() == [rel]


def test_belief_state_contradicts_edges() -> None:
    bs = BeliefState()
    rel = ClaimRelation(RelationType.CONTRADICTS, "a", "b")
    bs.relations.append(rel)
    assert bs.contradicts_edges() == [rel]
