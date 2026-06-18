"""Build MemoryBlocks from verified inputs and write them to disk as canonical JSON.

Key dependencies:
    pathlib      (stdlib)
    pydantic     (via MemoryBlock)
    secrets      (stdlib, cryptographically random ID suffix)

Design decisions
----------------
* IDs use ``secrets.token_hex`` for the 4-character suffix so that two blocks
  built in the same second still get unique IDs.
* The builder always produces ``status=UNVERIFIED``; status changes are the
  responsibility of :func:`~gpam.verified_memory_gate.verified_memory_gate`.
* ``write_memory_block_json`` is idempotent: if the file already exists it is
  overwritten, preserving the stored hash.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import List

from gpam.memory_block import MemoryBlock, MemoryStatus


def _id_suffix() -> str:
    """Return a 4-character uppercase hex string (2 random bytes)."""
    return secrets.token_hex(2).upper()


@dataclass(frozen=True)
class BuildInput:
    """Input data for :func:`build_memory_block`.

    Attributes
    ----------
    date_yyyymmdd:
        Date component of the block ID, e.g. ``"20260428"``.
    title:
        Short human-readable label.
    summary:
        Condensed factual content.
    sources:
        List of URL strings.
    confidence_score:
        Caller-supplied confidence in [0.0, 1.0].
    entropy_score:
        Domain diversity score in [0.0, 1.0].  Computed by the caller or by
        :class:`~gpam.verification_engine.VerificationEngine`.
    tags:
        Domain/topic labels.
    """

    date_yyyymmdd: str
    title: str
    summary: str
    sources: List[str]
    confidence_score: float
    entropy_score: float
    tags: List[str]


def build_memory_block(inp: BuildInput) -> MemoryBlock:
    """Create a new :class:`~gpam.memory_block.MemoryBlock` from *inp*.

    The block is assigned ``status=UNVERIFIED`` and a deterministic hash.
    The caller is responsible for running the VMG before promoting the block.

    Parameters
    ----------
    inp:
        Structured build input.

    Returns
    -------
    MemoryBlock
        A fully hashed, ``UNVERIFIED`` block ready to be written to disk.

    Examples
    --------
    >>> bi = BuildInput(
    ...     date_yyyymmdd="20260428",
    ...     title="  Hello  ",
    ...     summary="World",
    ...     sources=["https://example.com"],
    ...     confidence_score=0.8,
    ...     entropy_score=0.3,
    ...     tags=["test"],
    ... )
    >>> mb = build_memory_block(bi)
    >>> mb.title
    'Hello'
    >>> mb.status
    <MemoryStatus.UNVERIFIED: 'UNVERIFIED'>
    """
    block = MemoryBlock(
        id=f"MB-{inp.date_yyyymmdd}-{_id_suffix()}",
        title=inp.title.strip(),
        summary=inp.summary.strip(),
        sources=inp.sources,  # type: ignore[arg-type]  # pydantic coerces str → HttpUrl
        confidence_score=float(inp.confidence_score),
        entropy_score=float(inp.entropy_score),
        tags=[t.strip() for t in inp.tags if t.strip()],
        created_at=MemoryBlock.now_iso8601_utc(),
        status=MemoryStatus.UNVERIFIED,
        hash="",
    ).with_hash()
    return block


def write_memory_block_json(*, out_dir: Path, block: MemoryBlock) -> Path:
    """Serialise *block* as indented JSON and write to *out_dir*/<id>.json.

    Parameters
    ----------
    out_dir:
        Directory to write into.  Created (including parents) if absent.
    block:
        The block to serialise.

    Returns
    -------
    Path
        Absolute path of the written file.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{block.id}.json"
    path.write_text(block.model_dump_json(indent=2, by_alias=False), encoding="utf-8")
    return path
