"""Tests for gpam.notebooklm_batch_runner — batching, export, and enforcement."""

from __future__ import annotations

from pathlib import Path

import pytest

from gpam.memory_block import MemoryBlock, MemoryStatus
from gpam.notebooklm_batch_runner import (
    BatchPolicy,
    create_batches,
    export_batch_markdown,
    require_verified,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _block(
    n: int,
    status: MemoryStatus = MemoryStatus.VERIFIED,
    tag: str = "legal",
) -> MemoryBlock:
    return MemoryBlock(
        id=f"MB-20260428-{n:04X}",
        title=f"Block {n}",
        summary=f"Summary for block {n}.",
        sources=[
            f"https://example{n}.com/a",
            f"https://example{n}.org/b",
            f"https://example{n}.net/c",
        ],
        confidence_score=0.9,
        entropy_score=0.5,
        tags=[tag],
        created_at="2026-04-28T00:00:00Z",
        status=status,
        hash="",
    ).with_hash()


def _verified_blocks(count: int) -> list[MemoryBlock]:
    return [_block(i) for i in range(count)]


# ---------------------------------------------------------------------------
# BatchPolicy validation
# ---------------------------------------------------------------------------


def test_batch_policy_default_is_150() -> None:
    assert BatchPolicy().batch_size == 150


def test_batch_policy_zero_raises() -> None:
    with pytest.raises(ValueError, match="batch_size"):
        BatchPolicy(batch_size=0)


def test_batch_policy_negative_raises() -> None:
    with pytest.raises(ValueError, match="batch_size"):
        BatchPolicy(batch_size=-1)


def test_batch_policy_over_150_raises() -> None:
    with pytest.raises(ValueError, match="batch_size"):
        BatchPolicy(batch_size=151)


def test_batch_policy_exactly_150_is_valid() -> None:
    policy = BatchPolicy(batch_size=150)
    assert policy.batch_size == 150


# ---------------------------------------------------------------------------
# create_batches
# ---------------------------------------------------------------------------


def test_create_batches_single_batch() -> None:
    blocks = _verified_blocks(5)
    batches = create_batches(blocks)
    assert len(batches) == 1
    assert len(batches[0]) == 5


def test_create_batches_exact_boundary() -> None:
    blocks = _verified_blocks(150)
    batches = create_batches(blocks)
    assert len(batches) == 1
    assert len(batches[0]) == 150


def test_create_batches_splits_at_boundary() -> None:
    blocks = _verified_blocks(151)
    batches = create_batches(blocks)
    assert len(batches) == 2
    assert len(batches[0]) == 150
    assert len(batches[1]) == 1


def test_create_batches_custom_policy() -> None:
    blocks = _verified_blocks(10)
    batches = create_batches(blocks, policy=BatchPolicy(batch_size=3))
    assert len(batches) == 4  # 3+3+3+1
    assert len(batches[-1]) == 1


def test_create_batches_raises_on_empty() -> None:
    with pytest.raises(ValueError, match="at least one block"):
        create_batches([])


def test_create_batches_preserves_order() -> None:
    blocks = _verified_blocks(5)
    batches = create_batches(blocks)
    assert [b.id for b in batches[0]] == [b.id for b in blocks]


# ---------------------------------------------------------------------------
# require_verified
# ---------------------------------------------------------------------------


def test_require_verified_passes_all_verified() -> None:
    blocks = _verified_blocks(3)
    result = require_verified(blocks)
    assert result == blocks


def test_require_verified_raises_on_unverified() -> None:
    blocks = [_block(0, status=MemoryStatus.UNVERIFIED)]
    with pytest.raises(ValueError, match="not VERIFIED"):
        require_verified(blocks)


def test_require_verified_raises_on_rejected() -> None:
    blocks = [_block(0, status=MemoryStatus.REJECTED)]
    with pytest.raises(ValueError, match="not VERIFIED"):
        require_verified(blocks)


def test_require_verified_raises_on_synthesized() -> None:
    blocks = [_block(0, status=MemoryStatus.SYNTHESIZED)]
    with pytest.raises(ValueError, match="not VERIFIED"):
        require_verified(blocks)


def test_require_verified_raises_on_first_bad_block() -> None:
    """Should raise on the first non-VERIFIED block, not silently skip."""
    blocks = [_block(0), _block(1, status=MemoryStatus.UNVERIFIED), _block(2)]
    with pytest.raises(ValueError, match="MB-20260428-0001"):
        require_verified(blocks)


def test_require_verified_returns_list() -> None:
    blocks = _verified_blocks(3)
    result = require_verified(iter(blocks))  # type: ignore[arg-type]
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# export_batch_markdown
# ---------------------------------------------------------------------------


def test_export_creates_file(tmp_path: Path) -> None:
    batch = _verified_blocks(3)
    out = tmp_path / "batch-001.md"
    export_batch_markdown(out_path=out, batch=batch)
    assert out.exists()


def test_export_has_yaml_frontmatter(tmp_path: Path) -> None:
    batch = _verified_blocks(3)
    out = tmp_path / "batch.md"
    export_batch_markdown(out_path=out, batch=batch)
    content = out.read_text(encoding="utf-8")
    assert content.startswith("---")
    assert "generated_by" in content
    assert "VERIFIED_INPUTS_ONLY" in content


def test_export_frontmatter_lists_all_block_ids(tmp_path: Path) -> None:
    batch = _verified_blocks(3)
    out = tmp_path / "batch.md"
    export_batch_markdown(out_path=out, batch=batch)
    content = out.read_text(encoding="utf-8")
    for block in batch:
        assert block.id in content


def test_export_contains_block_summaries(tmp_path: Path) -> None:
    batch = _verified_blocks(2)
    out = tmp_path / "batch.md"
    export_batch_markdown(out_path=out, batch=batch)
    content = out.read_text(encoding="utf-8")
    for block in batch:
        assert block.summary in content


def test_export_contains_source_urls(tmp_path: Path) -> None:
    batch = _verified_blocks(2)
    out = tmp_path / "batch.md"
    export_batch_markdown(out_path=out, batch=batch)
    content = out.read_text(encoding="utf-8")
    for block in batch:
        for src in block.sources:
            assert str(src) in content


def test_export_block_count_in_frontmatter(tmp_path: Path) -> None:
    batch = _verified_blocks(7)
    out = tmp_path / "batch.md"
    export_batch_markdown(out_path=out, batch=batch)
    content = out.read_text(encoding="utf-8")
    assert "block_count: 7" in content


def test_export_creates_parent_directories(tmp_path: Path) -> None:
    batch = _verified_blocks(2)
    out = tmp_path / "deep" / "nested" / "batch.md"
    export_batch_markdown(out_path=out, batch=batch)
    assert out.exists()


def test_export_is_deterministic(tmp_path: Path) -> None:
    """Same input → same output file content."""
    batch = _verified_blocks(5)
    out1 = tmp_path / "a.md"
    out2 = tmp_path / "b.md"
    export_batch_markdown(out_path=out1, batch=batch)
    export_batch_markdown(out_path=out2, batch=batch)
    assert out1.read_text() == out2.read_text()
