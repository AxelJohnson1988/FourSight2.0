"""NotebookLM batch exporter + Git reintegration artifact generator.

Phase 1 does NOT call NotebookLM APIs.
Output is a deterministic Markdown bundle to be committed to Git.

Design decisions
----------------
* :func:`require_verified` raises immediately on the first non-VERIFIED block
  rather than silently skipping, forcing the caller to fix the pipeline.
* Batch Markdown files include YAML front-matter so they can be parsed by
  downstream tools (Warden, GitHub Actions) without re-reading the body.
* The 150-block ceiling matches NotebookLM's documented context limit.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

from gpam.memory_block import MemoryBlock, MemoryStatus

_DEFAULT_BATCH_SIZE = 150


@dataclass(frozen=True)
class BatchPolicy:
    """Batching configuration for :func:`create_batches`.

    Attributes
    ----------
    batch_size:
        Maximum blocks per NotebookLM session.  Must be in [1, 150].
    """

    batch_size: int = _DEFAULT_BATCH_SIZE

    def __post_init__(self) -> None:
        if not (1 <= self.batch_size <= _DEFAULT_BATCH_SIZE):
            raise ValueError(
                f"batch_size must be between 1 and {_DEFAULT_BATCH_SIZE}, "
                f"got {self.batch_size}"
            )


def require_verified(blocks: Iterable[MemoryBlock]) -> List[MemoryBlock]:
    """Return *blocks* as a list, raising if any block is not ``VERIFIED``.

    Parameters
    ----------
    blocks:
        Iterable of :class:`~gpam.memory_block.MemoryBlock`.

    Returns
    -------
    List[MemoryBlock]
        All blocks, unchanged, if every block has ``status=VERIFIED``.

    Raises
    ------
    ValueError
        On the first block whose ``status`` is not ``VERIFIED``.
    """
    out: List[MemoryBlock] = []
    for b in blocks:
        if b.status != MemoryStatus.VERIFIED:
            raise ValueError(
                f"Block {b.id} is not VERIFIED (status={b.status.value}). "
                "Only VERIFIED blocks may be sent to NotebookLM."
            )
        out.append(b)
    return out


def create_batches(
    blocks: List[MemoryBlock],
    policy: BatchPolicy = BatchPolicy(),
) -> List[List[MemoryBlock]]:
    """Split *blocks* into batches of at most ``policy.batch_size``.

    Parameters
    ----------
    blocks:
        Pre-verified blocks to batch.  All must have ``status=VERIFIED``
        (enforced by the caller via :func:`require_verified`).
    policy:
        Batching configuration.

    Returns
    -------
    List[List[MemoryBlock]]
        One or more batches.  The last batch may be smaller than
        ``policy.batch_size``.

    Raises
    ------
    ValueError
        If *blocks* is empty.
    """
    if not blocks:
        raise ValueError("create_batches() requires at least one block")
    size = policy.batch_size
    return [blocks[i : i + size] for i in range(0, len(blocks), size)]


def export_batch_markdown(*, out_path: Path, batch: List[MemoryBlock]) -> Path:
    """Write *batch* as a Markdown file with YAML front-matter to *out_path*.

    The front-matter lists all block IDs so outputs can be traced back to their
    source blocks when committed to Git.

    Parameters
    ----------
    out_path:
        Destination file path.  Parent directories are created if absent.
    batch:
        List of VERIFIED blocks to export.

    Returns
    -------
    Path
        The written file path (same as *out_path*).
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = [
        "---",
        'generated_by: "gpam-notebooklm-export"',
        "verification_status: VERIFIED_INPUTS_ONLY",
        f"block_count: {len(batch)}",
        "source_blocks:",
    ]
    for b in batch:
        lines.append(f"  - {b.id}")
    lines += ["---", "", "# NotebookLM Input Batch", ""]

    for b in batch:
        lines += [
            f"## {b.id} — {b.title}",
            "",
            b.summary,
            "",
            "Sources:",
        ]
        for u in b.sources:
            lines.append(f"- {u}")
        lines += ["", "---", ""]

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path
