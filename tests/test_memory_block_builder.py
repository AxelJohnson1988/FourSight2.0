"""Tests for gpam.memory_block_builder — build_memory_block and write_memory_block_json."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from gpam.memory_block import MemoryBlock, MemoryStatus
from gpam.memory_block_builder import BuildInput, build_memory_block, write_memory_block_json


def _minimal_input(**overrides) -> BuildInput:
    defaults = dict(
        date_yyyymmdd="20260428",
        title="  Hello World  ",
        summary="  A valid summary.  ",
        sources=[
            "https://example.com/a",
            "https://example.org/b",
            "https://example.net/c",
        ],
        confidence_score=0.8,
        entropy_score=0.3,
        tags=["  legal  ", "  test  "],
    )
    defaults.update(overrides)
    return BuildInput(**defaults)


# ---------------------------------------------------------------------------
# Block structure
# ---------------------------------------------------------------------------


def test_build_produces_unverified_block() -> None:
    mb = build_memory_block(_minimal_input())
    assert mb.status == MemoryStatus.UNVERIFIED


def test_build_has_non_empty_hash() -> None:
    mb = build_memory_block(_minimal_input())
    assert len(mb.hash) == 64


def test_build_id_matches_pattern() -> None:
    mb = build_memory_block(_minimal_input())
    assert re.match(r"^MB-20260428-[A-Z0-9]{4}$", mb.id), f"Bad ID: {mb.id}"


def test_build_strips_title_whitespace() -> None:
    mb = build_memory_block(_minimal_input(title="  Trimmed  "))
    assert mb.title == "Trimmed"


def test_build_strips_summary_whitespace() -> None:
    mb = build_memory_block(_minimal_input(summary="  Trimmed summary.  "))
    assert mb.summary == "Trimmed summary."


def test_build_strips_tag_whitespace() -> None:
    mb = build_memory_block(_minimal_input(tags=["  legal  ", "  docs  "]))
    assert mb.tags == ["legal", "docs"]


def test_build_drops_blank_tags() -> None:
    mb = build_memory_block(_minimal_input(tags=["legal", "  ", "", "docs"]))
    assert "" not in mb.tags
    assert "  " not in mb.tags
    assert "legal" in mb.tags
    assert "docs" in mb.tags


def test_build_hash_matches_recomputed() -> None:
    """The stored hash must equal the independently recomputed hash."""
    mb = build_memory_block(_minimal_input())
    assert mb.hash == mb.compute_hash()


def test_build_created_at_ends_with_z() -> None:
    mb = build_memory_block(_minimal_input())
    assert mb.created_at.endswith("Z")


def test_build_uses_provided_date() -> None:
    mb = build_memory_block(_minimal_input(date_yyyymmdd="20991231"))
    assert mb.id.startswith("MB-20991231-")


def test_two_builds_same_input_get_unique_ids() -> None:
    """IDs use a cryptographic random suffix — two calls should not collide."""
    ids = {build_memory_block(_minimal_input()).id for _ in range(20)}
    # With 2-byte random suffix we expect at most a tiny collision probability.
    assert len(ids) > 1, "Expected unique IDs across 20 builds"


# ---------------------------------------------------------------------------
# Disk persistence
# ---------------------------------------------------------------------------


def test_write_creates_json_file(tmp_path: Path) -> None:
    mb = build_memory_block(_minimal_input())
    path = write_memory_block_json(out_dir=tmp_path, block=mb)
    assert path.exists()
    assert path.suffix == ".json"
    assert path.name == f"{mb.id}.json"


def test_write_json_is_valid_memory_block(tmp_path: Path) -> None:
    mb = build_memory_block(_minimal_input())
    path = write_memory_block_json(out_dir=tmp_path, block=mb)
    loaded = MemoryBlock.model_validate_json(path.read_text(encoding="utf-8"))
    assert loaded.id == mb.id
    assert loaded.hash == mb.hash
    assert loaded.status == mb.status


def test_write_creates_parent_directories(tmp_path: Path) -> None:
    out_dir = tmp_path / "deep" / "nested" / "dir"
    mb = build_memory_block(_minimal_input())
    path = write_memory_block_json(out_dir=out_dir, block=mb)
    assert path.exists()


def test_write_is_indented_json(tmp_path: Path) -> None:
    mb = build_memory_block(_minimal_input())
    path = write_memory_block_json(out_dir=tmp_path, block=mb)
    raw = path.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert isinstance(parsed, dict)
    # Indented JSON should span multiple lines
    assert "\n" in raw


def test_write_preserves_hash(tmp_path: Path) -> None:
    mb = build_memory_block(_minimal_input())
    path = write_memory_block_json(out_dir=tmp_path, block=mb)
    loaded = MemoryBlock.model_validate_json(path.read_text(encoding="utf-8"))
    assert loaded.compute_hash() == loaded.hash
