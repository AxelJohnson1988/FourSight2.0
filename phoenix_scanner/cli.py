"""Command-line interface for the Phoenix Scanner toolkit."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sub-command implementations
# ---------------------------------------------------------------------------


def cmd_crawl(args: argparse.Namespace) -> int:
    from phoenix_scanner.config import Config
    from phoenix_scanner.crawler import crawl, write_manifest

    cfg = Config(
        root_dir=Path(args.root),
        include_globs=args.include or [],
        exclude_globs=args.exclude or ["**/.git/**"],
        extensions=args.ext or [],
        max_file_size=args.max_size,
        text_only=args.text_only,
        checkpoint_file=Path(args.checkpoint) if args.checkpoint else None,
        checkpoint_db_path=Path(args.checkpoint_db) if args.checkpoint_db else None,
        manifest_path=Path(args.output),
    )

    logger.info("Crawling %s …", cfg.root_dir)
    entries = crawl(cfg, max_workers=args.workers)
    write_manifest(entries, cfg.manifest_path)
    print(
        json.dumps(
            {"status": "ok", "entries": len(entries), "manifest": str(cfg.manifest_path)}
        )
    )
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from phoenix_scanner.config import Config
    from phoenix_scanner.crawler import read_manifest
    from phoenix_scanner.registry import PatternRegistry
    from phoenix_scanner.scanner import scan, write_findings

    cfg = Config(
        chunk_size=args.chunk_size,
        max_bytes_per_file=args.max_bytes,
        redact_matches=args.redact,
        use_gpu=args.gpu,
        extra_keywords=args.keyword or [],
        findings_path=Path(args.output),
        sandboxed=args.sandboxed,
    )

    registry: PatternRegistry | None = None
    if args.patterns_dir:
        registry = PatternRegistry()
        registry.load_from_dir(Path(args.patterns_dir))
        logger.info("Loaded %d pattern(s) from %s", len(registry), args.patterns_dir)

    logger.info("Reading manifest %s …", args.manifest)
    entries = read_manifest(Path(args.manifest))
    logger.info("Scanning %d files …", len(entries))
    findings = scan(entries, cfg, pattern_registry=registry)
    write_findings(findings, cfg.findings_path)
    print(
        json.dumps(
            {
                "status": "ok",
                "findings": len(findings),
                "output": str(cfg.findings_path),
            }
        )
    )
    return 0


def cmd_crawl_scan(args: argparse.Namespace) -> int:
    from phoenix_scanner.config import Config
    from phoenix_scanner.crawler import crawl, write_manifest
    from phoenix_scanner.registry import PatternRegistry
    from phoenix_scanner.scanner import scan, write_findings

    manifest_path = Path(args.manifest_path)
    cfg = Config(
        root_dir=Path(args.root),
        include_globs=args.include or [],
        exclude_globs=args.exclude or ["**/.git/**"],
        extensions=args.ext or [],
        max_file_size=args.max_size,
        text_only=args.text_only,
        manifest_path=manifest_path,
        checkpoint_db_path=Path(args.checkpoint_db) if args.checkpoint_db else None,
        chunk_size=args.chunk_size,
        max_bytes_per_file=args.max_bytes,
        redact_matches=args.redact,
        use_gpu=args.gpu,
        extra_keywords=args.keyword or [],
        findings_path=Path(args.findings_path),
        sandboxed=args.sandboxed,
    )

    registry: PatternRegistry | None = None
    if args.patterns_dir:
        registry = PatternRegistry()
        registry.load_from_dir(Path(args.patterns_dir))
        logger.info("Loaded %d pattern(s) from %s", len(registry), args.patterns_dir)

    logger.info("Crawling %s …", cfg.root_dir)
    entries = crawl(cfg, max_workers=args.workers)
    write_manifest(entries, cfg.manifest_path)

    logger.info("Scanning %d files …", len(entries))
    findings = scan(entries, cfg, pattern_registry=registry)
    write_findings(findings, cfg.findings_path)

    print(
        json.dumps(
            {
                "status": "ok",
                "entries": len(entries),
                "findings": len(findings),
                "manifest": str(cfg.manifest_path),
                "output": str(cfg.findings_path),
            }
        )
    )
    return 0


def cmd_anchor(args: argparse.Namespace) -> int:
    from phoenix_scanner.anchoring import anchor
    from phoenix_scanner.config import Config

    cfg = Config()
    result = anchor(
        text=args.text or "",
        file_path=Path(args.file) if args.file else None,
        config=cfg,
    )
    print(json.dumps(result, indent=2))
    return 0


def cmd_key_ceremony(args: argparse.Namespace) -> int:
    from phoenix_scanner.keys import OverwriteBlockedError, perform_key_ceremony

    try:
        priv_path, pub_path = perform_key_ceremony(
            base_name=args.name,
            directory=Path(args.directory),
            overwrite=args.overwrite,
        )
        print(
            json.dumps(
                {
                    "status": "ok",
                    "private_key_file": str(priv_path),
                    "public_key_file": str(pub_path),
                    "warning": (
                        "Move the private key to offline storage immediately. "
                        "Never commit it to version control."
                    ),
                }
            )
        )
        return 0
    except OverwriteBlockedError as exc:
        print(json.dumps({"status": "error", "message": str(exc)}))
        return 1


def cmd_pipeline(args: argparse.Namespace) -> int:
    from phoenix_scanner.pipeline import run_pipeline

    results = run_pipeline(Path(args.file))
    print(json.dumps(results, indent=2))
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phoenix-scanner",
        description="Phoenix Scanner – modular cryptographic scanning toolkit",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── crawl ──────────────────────────────────────────────────────────────
    p_crawl = sub.add_parser("crawl", help="Enumerate files and write a manifest")
    p_crawl.add_argument("root", help="Root directory to crawl")
    p_crawl.add_argument("-o", "--output", default="manifest.jsonl", help="Manifest output path")
    p_crawl.add_argument("--include", nargs="*", help="Include glob patterns")
    p_crawl.add_argument("--exclude", nargs="*", help="Exclude glob patterns")
    p_crawl.add_argument("--ext", nargs="*", help="File extension filter (e.g. .py .txt)")
    p_crawl.add_argument("--max-size", type=int, default=10 * 1024 * 1024, help="Max file size (bytes)")
    p_crawl.add_argument("--text-only", action="store_true", help="Only include text-ish files")
    p_crawl.add_argument("--checkpoint", help="Checkpoint file path for resumable crawls")
    p_crawl.add_argument(
        "--checkpoint-db",
        help="SQLite checkpoint DB path (Phase 4; preferred over --checkpoint)",
    )
    p_crawl.add_argument("--workers", type=int, default=4, help="Number of worker processes")

    # ── scan ───────────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Scan files listed in a manifest")
    p_scan.add_argument("manifest", help="Path to manifest JSONL")
    p_scan.add_argument("-o", "--output", default="findings.jsonl", help="Findings output path")
    p_scan.add_argument("--chunk-size", type=int, default=256 * 1024, help="Read chunk size (bytes)")
    p_scan.add_argument("--max-bytes", type=int, default=5 * 1024 * 1024, help="Max bytes per file")
    p_scan.add_argument("--redact", action="store_true", help="Redact match text in output")
    p_scan.add_argument("--gpu", action="store_true", help="Use GPU acceleration if available")
    p_scan.add_argument("--keyword", nargs="*", help="Extra keywords to search for")
    p_scan.add_argument(
        "--patterns-dir",
        help="Directory of .py plugin files to load into PatternRegistry (Phase 1)",
    )
    p_scan.add_argument(
        "--sandboxed",
        action="store_true",
        help="Scan each file in an isolated worker process with resource limits (Phase 2)",
    )

    # ── crawl-scan ─────────────────────────────────────────────────────────
    p_cs = sub.add_parser("crawl-scan", help="Crawl then scan in one step")
    p_cs.add_argument("root", help="Root directory to crawl")
    p_cs.add_argument("--manifest-path", default="manifest.jsonl")
    p_cs.add_argument("--findings-path", default="findings.jsonl")
    p_cs.add_argument("--include", nargs="*")
    p_cs.add_argument("--exclude", nargs="*")
    p_cs.add_argument("--ext", nargs="*")
    p_cs.add_argument("--max-size", type=int, default=10 * 1024 * 1024)
    p_cs.add_argument("--text-only", action="store_true")
    p_cs.add_argument("--workers", type=int, default=4)
    p_cs.add_argument("--chunk-size", type=int, default=256 * 1024)
    p_cs.add_argument("--max-bytes", type=int, default=5 * 1024 * 1024)
    p_cs.add_argument("--redact", action="store_true")
    p_cs.add_argument("--gpu", action="store_true")
    p_cs.add_argument("--keyword", nargs="*")
    p_cs.add_argument(
        "--patterns-dir",
        help="Directory of .py plugin files to load into PatternRegistry (Phase 1)",
    )
    p_cs.add_argument(
        "--sandboxed",
        action="store_true",
        help="Scan each file in an isolated worker process with resource limits (Phase 2)",
    )
    p_cs.add_argument(
        "--checkpoint-db",
        help="SQLite checkpoint DB path (Phase 4)",
    )

    # ── anchor ─────────────────────────────────────────────────────────────
    p_anchor = sub.add_parser("anchor", help="Hash text/file and generate OP_RETURN payload")
    p_anchor.add_argument("--text", help="Text payload to hash")
    p_anchor.add_argument("--file", help="File path to hash")

    # ── pipeline ───────────────────────────────────────────────────────────
    p_pipe = sub.add_parser(
        "pipeline",
        help="Run a declarative YAML pipeline definition (Phase 3; requires pyyaml)",
    )
    p_pipe.add_argument(
        "--file",
        default="phoenix_pipeline.yaml",
        help="Path to the pipeline YAML file (default: phoenix_pipeline.yaml)",
    )

    # ── key-ceremony ───────────────────────────────────────────────────────
    p_key = sub.add_parser("key-ceremony", help="Generate an Ed25519 keypair")
    p_key.add_argument("--name", default="signing_key", help="Base name for key files")
    p_key.add_argument("--directory", default=".", help="Output directory")
    p_key.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting existing key files (dangerous!)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "crawl": cmd_crawl,
        "scan": cmd_scan,
        "crawl-scan": cmd_crawl_scan,
        "anchor": cmd_anchor,
        "key-ceremony": cmd_key_ceremony,
        "pipeline": cmd_pipeline,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
