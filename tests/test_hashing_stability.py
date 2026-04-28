"""Tests for MemoryBlock hash stability and canonical JSON determinism."""

from __future__ import annotations

from gpam.memory_block import MemoryBlock, MemoryStatus, _canonical_json, sha256_hex


def _base_block() -> MemoryBlock:
    return MemoryBlock(
        id="MB-20260428-AAAA",
        title="Title",
        summary="Summary",
        sources=[
            "https://example.com/a",
            "https://example.org/b",
            "https://example.net/c",
        ],
        confidence_score=0.7,
        entropy_score=0.2,
        tags=["x"],
        created_at="2026-04-28T00:00:00Z",
        status=MemoryStatus.VERIFIED,
        hash="",
    )


# ---------------------------------------------------------------------------
# Hash determinism
# ---------------------------------------------------------------------------


def test_hash_is_deterministic() -> None:
    """Calling with_hash() twice on the same model returns the same hash."""
    b1 = _base_block().with_hash()
    b2 = b1.model_copy(update={"hash": ""}).with_hash()
    assert b1.hash == b2.hash


def test_hash_is_64_hex_chars() -> None:
    b = _base_block().with_hash()
    assert len(b.hash) == 64
    assert all(c in "0123456789abcdef" for c in b.hash)


def test_hash_excludes_hash_field_itself() -> None:
    """Hash must not depend on the current value of the hash field."""
    b_empty = _base_block()  # hash=""
    b_with_hash = _base_block().with_hash()
    # Both have the same fields apart from hash; their computed hashes should agree.
    assert b_empty.compute_hash() == b_with_hash.compute_hash()


def test_hash_changes_on_title_change() -> None:
    b1 = _base_block().with_hash()
    b2 = _base_block()
    b2 = b2.model_copy(update={"title": "Different Title", "hash": ""}).with_hash()
    assert b1.hash != b2.hash


def test_hash_changes_on_summary_change() -> None:
    b1 = _base_block().with_hash()
    b2 = _base_block().model_copy(update={"summary": "Changed", "hash": ""}).with_hash()
    assert b1.hash != b2.hash


def test_hash_changes_on_source_change() -> None:
    b1 = _base_block().with_hash()
    b2 = MemoryBlock(
        id=b1.id,
        title=b1.title,
        summary=b1.summary,
        sources=["https://other.com/x"],  # single different source
        confidence_score=b1.confidence_score,
        entropy_score=b1.entropy_score,
        tags=b1.tags,
        created_at=b1.created_at,
        status=b1.status,
        hash="",
    ).with_hash()
    assert b1.hash != b2.hash


def test_hash_changes_on_status_change() -> None:
    """Status is part of the hash so tampered status is detectable."""
    b1 = _base_block().model_copy(update={"status": MemoryStatus.VERIFIED}).with_hash()
    b2 = _base_block().model_copy(update={"status": MemoryStatus.REJECTED}).with_hash()
    assert b1.hash != b2.hash


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


def test_canonical_json_is_key_sorted() -> None:
    obj = {"z": 1, "a": 2, "m": 3}
    result = _canonical_json(obj)
    assert result == '{"a":2,"m":3,"z":1}'


def test_canonical_json_is_compact() -> None:
    """No spaces around colons or commas."""
    result = _canonical_json({"key": "value"})
    assert " " not in result


def test_canonical_json_deterministic_across_dict_ordering() -> None:
    d1 = {"b": 2, "a": 1}
    d2 = {"a": 1, "b": 2}
    assert _canonical_json(d1) == _canonical_json(d2)


# ---------------------------------------------------------------------------
# Round-trip serialisation
# ---------------------------------------------------------------------------


def test_model_round_trips_json() -> None:
    """Serialise to JSON, parse back, recompute hash — must match."""
    original = _base_block().with_hash()
    json_str = original.model_dump_json(indent=2)
    loaded = MemoryBlock.model_validate_json(json_str)
    assert loaded.compute_hash() == original.hash


def test_now_iso8601_utc_ends_with_z() -> None:
    ts = MemoryBlock.now_iso8601_utc()
    assert ts.endswith("Z")
    # Basic structure: YYYY-MM-DDTHH:MM:SS...Z
    assert "T" in ts
    assert len(ts) >= 20
