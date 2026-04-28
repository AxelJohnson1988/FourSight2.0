"""Tests for gpam.adobe_packer — tile payload generation, dedup, and export."""

from __future__ import annotations

from pathlib import Path

import pytest

from gpam.adobe_packer import AdobeSpacePacker, TilePackerPolicy, TilePayload
from gpam.memory_block import MemoryBlock, MemoryStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _block(
    n: int,
    status: MemoryStatus = MemoryStatus.VERIFIED,
    tag: str = "legal",
    summary: str | None = None,
) -> MemoryBlock:
    return MemoryBlock(
        id=f"MB-20260428-{n:04X}",
        title=f"Block {n}",
        summary=summary or f"Summary for block number {n}.",
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


# ---------------------------------------------------------------------------
# TilePackerPolicy validation
# ---------------------------------------------------------------------------


def test_policy_defaults() -> None:
    p = TilePackerPolicy()
    assert p.max_tiles == 100
    assert p.max_summary_chars == 1_500


def test_policy_max_tiles_zero_raises() -> None:
    with pytest.raises(ValueError, match="max_tiles"):
        TilePackerPolicy(max_tiles=0)


def test_policy_max_summary_chars_too_small_raises() -> None:
    with pytest.raises(ValueError, match="max_summary_chars"):
        TilePackerPolicy(max_summary_chars=5)


# ---------------------------------------------------------------------------
# AdobeSpacePacker.pack — filtering
# ---------------------------------------------------------------------------


def test_pack_raises_on_empty_input() -> None:
    packer = AdobeSpacePacker()
    with pytest.raises(ValueError, match="at least one block"):
        packer.pack([])


def test_pack_filters_out_unverified() -> None:
    blocks = [
        _block(0, status=MemoryStatus.VERIFIED),
        _block(1, status=MemoryStatus.UNVERIFIED),
        _block(2, status=MemoryStatus.REJECTED),
    ]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks)
    assert len(payload.tiles) == 1
    assert payload.skipped_non_verified == 2


def test_pack_all_non_verified_produces_empty_tiles() -> None:
    blocks = [_block(0, status=MemoryStatus.UNVERIFIED)]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks)
    assert len(payload.tiles) == 0
    assert payload.skipped_non_verified == 1


# ---------------------------------------------------------------------------
# AdobeSpacePacker.pack — deduplication
# ---------------------------------------------------------------------------


def test_pack_deduplicates_by_hash() -> None:
    """Two blocks with the same content hash → only one tile."""
    b1 = _block(0)
    # Build a duplicate by copying b1 (same content, same hash)
    b2 = b1.model_copy()
    packer = AdobeSpacePacker()
    payload = packer.pack([b1, b2])
    assert len(payload.tiles) == 1
    assert payload.skipped_duplicates == 1


def test_pack_distinct_blocks_not_deduped() -> None:
    blocks = [_block(i) for i in range(5)]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks)
    assert len(payload.tiles) == 5
    assert payload.skipped_duplicates == 0


# ---------------------------------------------------------------------------
# AdobeSpacePacker.pack — tile cap
# ---------------------------------------------------------------------------


def test_pack_respects_max_tiles_cap() -> None:
    blocks = [_block(i) for i in range(10)]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks, policy=TilePackerPolicy(max_tiles=5))
    assert len(payload.tiles) == 5
    assert payload.skipped_overflow == 5


def test_pack_overflow_counter_accurate() -> None:
    blocks = [_block(i) for i in range(7)]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks, policy=TilePackerPolicy(max_tiles=3))
    assert payload.skipped_overflow == 4


# ---------------------------------------------------------------------------
# AdobeSpacePacker.pack — summary truncation
# ---------------------------------------------------------------------------


def test_pack_truncates_long_summary() -> None:
    long_summary = "x" * 3000
    block = _block(0, summary=long_summary)
    packer = AdobeSpacePacker()
    policy = TilePackerPolicy(max_summary_chars=100)
    payload = packer.pack([block], policy=policy)
    assert len(payload.tiles[0].summary) == 100
    assert payload.tiles[0].summary.endswith("…")


def test_pack_does_not_truncate_short_summary() -> None:
    block = _block(0, summary="Short summary.")
    packer = AdobeSpacePacker()
    payload = packer.pack([block])
    assert payload.tiles[0].summary == "Short summary."


# ---------------------------------------------------------------------------
# AdobeSpacePacker.pack — grouping and ordering
# ---------------------------------------------------------------------------


def test_pack_groups_by_tag() -> None:
    blocks = [
        _block(0, tag="legal"),
        _block(1, tag="medical"),
        _block(2, tag="legal"),
    ]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks)
    tags = [t.tag for t in payload.tiles]
    # legal blocks should be adjacent
    legal_indices = [i for i, tag in enumerate(tags) if tag == "legal"]
    assert legal_indices == list(range(legal_indices[0], legal_indices[-1] + 1))


def test_pack_untagged_block_gets_uncategorized_tag() -> None:
    block = MemoryBlock(
        id="MB-20260428-FFFF",
        title="No Tag Block",
        summary="Summary.",
        sources=["https://a.com", "https://b.com", "https://c.com"],
        confidence_score=0.9,
        entropy_score=0.5,
        tags=[],  # no tags
        created_at="2026-04-28T00:00:00Z",
        status=MemoryStatus.VERIFIED,
        hash="",
    ).with_hash()
    packer = AdobeSpacePacker()
    payload = packer.pack([block])
    assert payload.tiles[0].tag == "uncategorized"


def test_pack_is_deterministic() -> None:
    """Same input → same tile order (sort is stable)."""
    blocks = [_block(i) for i in range(10)]
    packer = AdobeSpacePacker()
    p1 = packer.pack(blocks)
    p2 = packer.pack(blocks)
    assert [t.block_id for t in p1.tiles] == [t.block_id for t in p2.tiles]


# ---------------------------------------------------------------------------
# export_tile_payload
# ---------------------------------------------------------------------------


def test_export_creates_file(tmp_path: Path) -> None:
    blocks = [_block(i) for i in range(3)]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks)
    out = tmp_path / "tile-payload.md"
    packer.export_tile_payload(payload, out_path=out)
    assert out.exists()


def test_export_has_yaml_frontmatter(tmp_path: Path) -> None:
    blocks = [_block(0)]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks)
    out = tmp_path / "payload.md"
    packer.export_tile_payload(payload, out_path=out)
    content = out.read_text(encoding="utf-8")
    assert content.startswith("---")
    assert "generated_by" in content
    assert "Git-only" in content


def test_export_frontmatter_has_payload_sha256(tmp_path: Path) -> None:
    blocks = [_block(0)]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks)
    out = tmp_path / "payload.md"
    packer.export_tile_payload(payload, out_path=out)
    content = out.read_text(encoding="utf-8")
    assert "payload_sha256:" in content


def test_export_contains_human_interlock_note(tmp_path: Path) -> None:
    """Adobe Spaces has no write authority — the export must say so."""
    blocks = [_block(0)]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks)
    out = tmp_path / "payload.md"
    packer.export_tile_payload(payload, out_path=out)
    content = out.read_text(encoding="utf-8")
    assert "Human interlock required" in content


def test_export_default_path_includes_date(tmp_path: Path, monkeypatch) -> None:
    """When out_path is omitted, path includes the date_label."""
    import os
    monkeypatch.chdir(tmp_path)
    blocks = [_block(0)]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks)
    out = packer.export_tile_payload(payload, date_label="2026-04-28")
    assert "2026-04-28" in str(out)
    assert out.exists()


def test_export_contains_all_tile_ids(tmp_path: Path) -> None:
    blocks = [_block(i) for i in range(4)]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks)
    out = tmp_path / "payload.md"
    packer.export_tile_payload(payload, out_path=out)
    content = out.read_text(encoding="utf-8")
    for tile in payload.tiles:
        assert tile.block_id in content


def test_export_payload_sha256_is_deterministic(tmp_path: Path) -> None:
    """Same tiles → same payload_sha256 in the frontmatter."""
    blocks = [_block(0), _block(1)]
    packer = AdobeSpacePacker()
    payload = packer.pack(blocks)
    out1 = tmp_path / "a.md"
    out2 = tmp_path / "b.md"
    packer.export_tile_payload(payload, out_path=out1)
    packer.export_tile_payload(payload, out_path=out2)
    # Extract payload_sha256 from both files
    def get_hash(path: Path) -> str:
        for line in path.read_text().splitlines():
            if line.startswith("payload_sha256:"):
                return line.split(":", 1)[1].strip()
        return ""
    assert get_hash(out1) == get_hash(out2)
