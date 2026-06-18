"""Adobe Spaces tile payload generator — VERIFIED-only, deduped by hash.

Architecture boundary
---------------------
Adobe Spaces is a Non-Sovereign Processing System (NSPS).  It has **no write
authority** over the GPAM ledger.  This module enforces that boundary:

1. Filter: only ``VERIFIED`` blocks enter.
2. Dedupe: blocks are deduplicated by their canonical ``hash`` field.
3. Group: tiles are arranged by primary tag so related blocks tile adjacently.
4. Cap: output is bounded by ``TilePackerPolicy.max_tiles``.
5. Export: writes a deterministic Markdown file committed to Git at
   ``exports/adobe-spaces/<date>/tile-payload.md`` — *not* directly to Adobe.
6. Human interlock: the human manually imports the payload into Adobe Spaces.

Adobe becomes a *compression view*, not the storage of record.  Adobe can
always be rebuilt from Git; Git cannot be rebuilt from Adobe.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from gpam.memory_block import MemoryBlock, MemoryStatus

_DEFAULT_MAX_TILES = 100
_DEFAULT_MAX_SUMMARY_CHARS = 1_500  # chars per tile; keeps tiles scannable


@dataclass(frozen=True)
class TilePackerPolicy:
    """Configuration for :class:`AdobeSpacePacker`.

    Attributes
    ----------
    max_tiles:
        Hard ceiling on the number of tiles produced (default: 100).
    max_summary_chars:
        Maximum characters of ``summary`` text included per tile (default: 1500).
        Longer summaries are truncated with a ``…`` suffix.
    """

    max_tiles: int = _DEFAULT_MAX_TILES
    max_summary_chars: int = _DEFAULT_MAX_SUMMARY_CHARS

    def __post_init__(self) -> None:
        if self.max_tiles < 1:
            raise ValueError(f"max_tiles must be >= 1, got {self.max_tiles}")
        if self.max_summary_chars < 10:
            raise ValueError(
                f"max_summary_chars must be >= 10, got {self.max_summary_chars}"
            )


@dataclass(frozen=True)
class Tile:
    """A single tile in the Adobe Spaces payload.

    Attributes
    ----------
    block_id:
        Source ``MemoryBlock.id``.
    title:
        Block title.
    summary:
        Potentially-truncated block summary.
    tag:
        Primary tag used for spatial grouping (``"uncategorized"`` if none).
    block_hash:
        SHA-256 of the canonical block content — used for deduplication.
    """

    block_id: str
    title: str
    summary: str
    tag: str
    block_hash: str


@dataclass(frozen=True)
class TilePayload:
    """Output of :meth:`AdobeSpacePacker.pack`.

    Attributes
    ----------
    tiles:
        Deduplicated, tag-grouped tiles within ``policy.max_tiles``.
    skipped_non_verified:
        Number of blocks dropped because ``status != VERIFIED``.
    skipped_duplicates:
        Number of blocks dropped as hash-duplicates.
    skipped_overflow:
        Number of blocks dropped because the tile cap was reached.
    policy:
        The policy used to generate this payload.
    """

    tiles: List[Tile]
    skipped_non_verified: int
    skipped_duplicates: int
    skipped_overflow: int
    policy: TilePackerPolicy


class AdobeSpacePacker:
    """Deduplicates and packs VERIFIED MemoryBlocks into a Git-committed tile payload.

    Examples
    --------
    >>> from gpam.memory_block import MemoryBlock, MemoryStatus
    >>> mb = MemoryBlock(
    ...     id="MB-20260428-AAAA", title="T", summary="S",
    ...     sources=["https://a.com", "https://b.com", "https://c.com"],
    ...     confidence_score=0.9, entropy_score=0.5, tags=["legal"],
    ...     created_at="2026-04-28T00:00:00Z",
    ...     status=MemoryStatus.VERIFIED, hash="",
    ... ).with_hash()
    >>> packer = AdobeSpacePacker()
    >>> payload = packer.pack([mb])
    >>> payload.tiles[0].tag
    'legal'
    """

    def pack(
        self,
        blocks: List[MemoryBlock],
        policy: TilePackerPolicy = TilePackerPolicy(),
    ) -> TilePayload:
        """Produce a :class:`TilePayload` from *blocks*.

        Parameters
        ----------
        blocks:
            Input blocks of any status.  Non-VERIFIED blocks are counted in
            ``skipped_non_verified`` and silently excluded.
        policy:
            Packing constraints.

        Returns
        -------
        TilePayload
            Deduplicated, grouped tiles within policy limits.

        Raises
        ------
        ValueError
            If *blocks* is empty.
        """
        if not blocks:
            raise ValueError("pack() requires at least one block")

        skipped_non_verified = 0
        skipped_duplicates = 0
        skipped_overflow = 0

        seen_hashes: set[str] = set()
        tiles: List[Tile] = []

        # Group verified, deduped blocks by primary tag (stable insertion order)
        for block in blocks:
            if block.status != MemoryStatus.VERIFIED:
                skipped_non_verified += 1
                continue

            if block.hash in seen_hashes:
                skipped_duplicates += 1
                continue

            if len(tiles) >= policy.max_tiles:
                skipped_overflow += 1
                continue

            seen_hashes.add(block.hash)

            summary = block.summary
            if len(summary) > policy.max_summary_chars:
                summary = summary[: policy.max_summary_chars - 1] + "…"

            tag = block.tags[0] if block.tags else "uncategorized"
            tiles.append(
                Tile(
                    block_id=block.id,
                    title=block.title,
                    summary=summary,
                    tag=tag,
                    block_hash=block.hash,
                )
            )

        # Sort by tag → title for deterministic, domain-coherent spatial layout
        tiles.sort(key=lambda t: (t.tag, t.title))

        return TilePayload(
            tiles=tiles,
            skipped_non_verified=skipped_non_verified,
            skipped_duplicates=skipped_duplicates,
            skipped_overflow=skipped_overflow,
            policy=policy,
        )

    def export_tile_payload(
        self,
        payload: TilePayload,
        *,
        out_path: Optional[Path] = None,
        date_label: Optional[str] = None,
    ) -> Path:
        """Write the tile payload as Markdown and return the path.

        The file is written to *out_path* if given, otherwise to:
            ``exports/adobe-spaces/<date_label>/tile-payload.md``

        where *date_label* defaults to today's UTC date (``YYYY-MM-DD``).

        Parameters
        ----------
        payload:
            The :class:`TilePayload` to serialise.
        out_path:
            Explicit output path.  Parent directories are created as needed.
        date_label:
            Date string used to construct the default output path when *out_path*
            is not given.

        Returns
        -------
        Path
            Absolute path of the written file.

        Notes
        -----
        Commit this file to Git before opening Adobe Spaces.  Adobe has no
        write authority; Git is the storage of record.
        """
        if out_path is None:
            label = date_label or datetime.now(timezone.utc).strftime("%Y-%m-%d")
            out_path = Path("exports") / "adobe-spaces" / label / "tile-payload.md"

        out_path.parent.mkdir(parents=True, exist_ok=True)

        payload_hash = _payload_hash(payload)
        lines: List[str] = [
            "---",
            'generated_by: "gpam-adobe-packer"',
            'authority: "Git-only — Adobe Spaces has no write authority"',
            f"tile_count: {len(payload.tiles)}",
            f"skipped_non_verified: {payload.skipped_non_verified}",
            f"skipped_duplicates: {payload.skipped_duplicates}",
            f"skipped_overflow: {payload.skipped_overflow}",
            f"max_tiles_policy: {payload.policy.max_tiles}",
            f"payload_sha256: {payload_hash}",
            f"generated_at: {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}",
            "---",
            "",
            "# Adobe Spaces Tile Payload",
            "",
            "> **Human interlock required.**  Import this file manually into Adobe Spaces.",
            "> Do not automate Adobe credentials or session handling.",
            "> If Adobe diverges from Git, Git wins.",
            "",
        ]

        # Group tiles by tag for spatial rendering
        current_tag: Optional[str] = None
        for tile in payload.tiles:
            if tile.tag != current_tag:
                current_tag = tile.tag
                lines += [f"## {tile.tag}", ""]

            lines += [
                f"### {tile.block_id} — {tile.title}",
                "",
                tile.summary,
                "",
                f"*hash: `{tile.block_hash[:16]}…`*",
                "",
            ]

        out_path.write_text("\n".join(lines), encoding="utf-8")
        return out_path


def _payload_hash(payload: TilePayload) -> str:
    """Return a deterministic SHA-256 of the tile payload content."""
    canonical = json.dumps(
        [
            {"block_id": t.block_id, "block_hash": t.block_hash}
            for t in payload.tiles
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
