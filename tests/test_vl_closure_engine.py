"""Tests for gpam.vl_llm.closure_engine (LCE, Invariant I4)."""

from __future__ import annotations

import pytest

from gpam.vl_llm.closure_engine import ClosureEngine
from gpam.vl_llm.types import ClaimRelation, RelationType


def _implies(a: str, b: str) -> ClaimRelation:
    return ClaimRelation(RelationType.IMPLIES, a, b)


def _contradicts(a: str, b: str) -> ClaimRelation:
    return ClaimRelation(RelationType.CONTRADICTS, a, b)


# ---------------------------------------------------------------------------
# Basic closure
# ---------------------------------------------------------------------------


def test_close_direct_implication() -> None:
    engine = ClosureEngine()
    result = engine.close(
        accepted=frozenset({"A"}),
        relations=[_implies("A", "B")],
    )
    assert "B" in result.newly_accepted
    assert len(result.proof_steps) == 1
    assert result.proof_steps[0].from_claim == "A"
    assert result.proof_steps[0].to_claim == "B"


def test_close_transitive_chain() -> None:
    engine = ClosureEngine()
    result = engine.close(
        accepted=frozenset({"A"}),
        relations=[_implies("A", "B"), _implies("B", "C")],
    )
    assert "B" in result.newly_accepted
    assert "C" in result.newly_accepted


def test_close_does_not_re_accept_already_accepted() -> None:
    engine = ClosureEngine()
    result = engine.close(
        accepted=frozenset({"A", "B"}),
        relations=[_implies("A", "B")],
    )
    # B already accepted — must not appear in newly_accepted.
    assert "B" not in result.newly_accepted


def test_close_empty_accepted_produces_no_new() -> None:
    engine = ClosureEngine()
    result = engine.close(
        accepted=frozenset(),
        relations=[_implies("A", "B")],
    )
    assert result.newly_accepted == []


def test_close_contradicts_edges_not_followed() -> None:
    engine = ClosureEngine()
    result = engine.close(
        accepted=frozenset({"A"}),
        relations=[_contradicts("A", "B")],
    )
    assert "B" not in result.newly_accepted


def test_close_no_relations_produces_nothing() -> None:
    engine = ClosureEngine()
    result = engine.close(accepted=frozenset({"A"}), relations=[])
    assert result.newly_accepted == []


# ---------------------------------------------------------------------------
# Depth limit (Invariant I4 — closure disabled / truncated)
# ---------------------------------------------------------------------------


def test_close_respects_max_depth() -> None:
    engine = ClosureEngine(max_depth=1)
    # A→B→C: at depth 1, B is derived; C requires depth 2 → truncated.
    result = engine.close(
        accepted=frozenset({"A"}),
        relations=[_implies("A", "B"), _implies("B", "C")],
    )
    assert "B" in result.newly_accepted
    assert "C" not in result.newly_accepted
    assert result.truncated is True


def test_close_respects_max_new_accepts() -> None:
    engine = ClosureEngine(max_new_accepts=2)
    # A→B, A→C, A→D: limit is 2.
    relations = [_implies("A", x) for x in ["B", "C", "D"]]
    result = engine.close(accepted=frozenset({"A"}), relations=relations)
    assert len(result.newly_accepted) <= 2
    assert result.truncated is True


# ---------------------------------------------------------------------------
# Cycle safety
# ---------------------------------------------------------------------------


def test_close_handles_cycle_safely() -> None:
    engine = ClosureEngine()
    # A→B→A: cycle — should terminate without infinite loop.
    result = engine.close(
        accepted=frozenset({"A"}),
        relations=[_implies("A", "B"), _implies("B", "A")],
    )
    assert "B" in result.newly_accepted
    # A is already accepted — must not appear in newly_accepted.
    assert "A" not in result.newly_accepted
    assert result.truncated is False


def test_close_self_loop_is_safe() -> None:
    engine = ClosureEngine()
    result = engine.close(
        accepted=frozenset({"A"}),
        relations=[_implies("A", "A")],
    )
    assert result.newly_accepted == []


# ---------------------------------------------------------------------------
# Domain exclusion
# ---------------------------------------------------------------------------


def test_close_excludes_specified_domain() -> None:
    engine = ClosureEngine(excluded_domains={"classified"})
    result = engine.close(
        accepted=frozenset({"A"}),
        relations=[_implies("A", "B")],
        claim_scopes={"B": {"domain": "classified"}},
    )
    assert "B" not in result.newly_accepted
    assert "B" in result.skipped_domain


# ---------------------------------------------------------------------------
# Proof steps
# ---------------------------------------------------------------------------


def test_proof_step_depth_is_correct() -> None:
    engine = ClosureEngine()
    result = engine.close(
        accepted=frozenset({"A"}),
        relations=[_implies("A", "B"), _implies("B", "C")],
    )
    depths = {s.to_claim: s.depth for s in result.proof_steps}
    assert depths["B"] == 1
    assert depths["C"] == 2


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


def test_closure_engine_rejects_invalid_max_depth() -> None:
    with pytest.raises(ValueError):
        ClosureEngine(max_depth=0)


def test_closure_engine_rejects_invalid_max_new_accepts() -> None:
    with pytest.raises(ValueError):
        ClosureEngine(max_new_accepts=0)
