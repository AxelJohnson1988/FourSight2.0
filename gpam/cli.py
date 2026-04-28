"""GPAM Phase 1 CLI — build, verify, and export memory blocks.

Subcommands
-----------
build
    Create a new UNVERIFIED MemoryBlock JSON from structured input.
verify
    Run the Verified Memory Gate against a saved block JSON.
export-notebooklm
    Batch VERIFIED blocks from a directory into Markdown files for Git commit.

All outputs are local files.  Nothing is uploaded automatically.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from gpam.memory_block import MemoryBlock, MemoryStatus
from gpam.memory_block_builder import BuildInput, build_memory_block, write_memory_block_json
from gpam.notebooklm_batch_runner import BatchPolicy, create_batches, export_batch_markdown, require_verified
from gpam.verified_memory_gate import VmgPolicy, verified_memory_gate


def _cmd_build(args: argparse.Namespace) -> None:
    mb = build_memory_block(
        BuildInput(
            date_yyyymmdd=args.date,
            title=args.title,
            summary=args.summary,
            sources=args.source,
            confidence_score=args.confidence,
            entropy_score=args.entropy,
            tags=args.tag or [],
        )
    )
    path = write_memory_block_json(out_dir=Path(args.out_dir), block=mb)
    print(path)


def _cmd_verify(args: argparse.Namespace) -> None:
    raw = Path(args.block_json).read_text(encoding="utf-8")
    mb = MemoryBlock.model_validate_json(raw)

    policy = VmgPolicy()
    res = verified_memory_gate(block=mb, similarity_score=args.similarity, policy=policy)

    updated = mb.model_copy(update={"status": res.status}).with_hash()
    Path(args.block_json).write_text(
        updated.model_dump_json(indent=2, by_alias=False), encoding="utf-8"
    )

    output = {"status": res.status.value, "reason_codes": res.reason_codes}
    print(json.dumps(output))
    if res.status != MemoryStatus.VERIFIED:
        sys.exit(1)


def _cmd_export_notebooklm(args: argparse.Namespace) -> None:
    blocks_dir = Path(args.blocks_dir)
    blocks = []
    for f in sorted(blocks_dir.glob("MB-*.json")):
        blocks.append(MemoryBlock.model_validate_json(f.read_text(encoding="utf-8")))

    try:
        verified = require_verified(blocks)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    if not verified:
        print("ERROR: no VERIFIED blocks found in directory", file=sys.stderr)
        sys.exit(1)

    policy = BatchPolicy(batch_size=args.batch_size)
    batches = create_batches(verified, policy=policy)
    out_dir = Path(args.out_dir)

    for i, batch in enumerate(batches, start=1):
        export_batch_markdown(out_path=out_dir / f"batch-{i:03d}.md", batch=batch)

    print(f"exported {len(batches)} batch(es) → {out_dir}")


def main() -> None:  # noqa: C901
    parser = argparse.ArgumentParser(
        prog="gpam",
        description="GPAM Phase 1 CLI — sovereign memory block pipeline",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # ── build ──────────────────────────────────────────────────────────
    b = sub.add_parser("build", help="Create a new UNVERIFIED MemoryBlock JSON")
    b.add_argument("--date", required=True, metavar="YYYYMMDD",
                   help="Date component of the block ID, e.g. 20260428")
    b.add_argument("--title", required=True)
    b.add_argument("--summary", required=True)
    b.add_argument("--source", action="append", required=True, dest="source",
                   metavar="URL", help="Source URL (repeat for multiple)")
    b.add_argument("--confidence", type=float, required=True, metavar="FLOAT",
                   help="Confidence score in [0.0, 1.0]")
    b.add_argument("--entropy", type=float, required=True, metavar="FLOAT",
                   help="Domain entropy score in [0.0, 1.0]")
    b.add_argument("--tag", action="append", default=[], dest="tag",
                   metavar="TAG", help="Topic tag (repeat for multiple)")
    b.add_argument("--out-dir", default="memory_blocks", metavar="DIR")

    # ── verify ─────────────────────────────────────────────────────────
    v = sub.add_parser("verify", help="Run the Verified Memory Gate on a block JSON")
    v.add_argument("--block-json", required=True, metavar="PATH",
                   help="Path to the MemoryBlock JSON file to evaluate")
    v.add_argument("--similarity", type=float, required=True, metavar="FLOAT",
                   help="Pre-computed semantic similarity score in [0.0, 1.0]")

    # ── export-notebooklm ──────────────────────────────────────────────
    e = sub.add_parser(
        "export-notebooklm",
        help="Batch VERIFIED blocks into Markdown files for Git commit",
    )
    e.add_argument("--blocks-dir", required=True, metavar="DIR",
                   help="Directory containing MB-*.json block files")
    e.add_argument("--out-dir", default="exports/notebooklm", metavar="DIR")
    e.add_argument("--batch-size", type=int, default=150, metavar="N",
                   help="Max blocks per NotebookLM session (1–150)")

    args = parser.parse_args()

    if args.cmd == "build":
        _cmd_build(args)
    elif args.cmd == "verify":
        _cmd_verify(args)
    elif args.cmd == "export-notebooklm":
        _cmd_export_notebooklm(args)


if __name__ == "__main__":
    main()
