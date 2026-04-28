"""Configuration dataclass for the Phoenix Scanner toolkit."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """Central configuration object.  All values have safe defaults."""

    # Crawler
    root_dir: Path = field(default_factory=lambda: Path("."))
    include_globs: list[str] = field(default_factory=list)
    exclude_globs: list[str] = field(default_factory=lambda: ["**/.git/**"])
    extensions: list[str] = field(default_factory=list)
    max_file_size: int = 10 * 1024 * 1024  # 10 MB
    text_only: bool = False
    checkpoint_file: Path | None = None
    # Phase 4: SQLite checkpoint replaces the plain-text checkpoint file when set.
    checkpoint_db_path: Path | None = None
    manifest_path: Path = field(default_factory=lambda: Path("manifest.jsonl"))

    # Scanner
    chunk_size: int = 256 * 1024  # 256 KB
    max_bytes_per_file: int = 5 * 1024 * 1024  # 5 MB
    redact_matches: bool = False
    use_gpu: bool = False  # opt-in; falls back to CPU if unavailable
    extra_keywords: list[str] = field(default_factory=list)
    # Phase 1: directory of .py plugin files loaded into PatternRegistry at runtime.
    patterns_dir: Path | None = None
    # Phase 2: run each file scan in an isolated worker process.
    sandboxed: bool = False

    # Ledger
    findings_path: Path = field(default_factory=lambda: Path("findings.jsonl"))
    summary_path: Path = field(default_factory=lambda: Path("summary.json"))

    # Anchoring
    op_return_prefix: str = "414c454501"  # "ALEE\x01"

    @classmethod
    def from_env(cls) -> "Config":
        """Build a Config from environment variables with sensible fallbacks."""
        return cls(
            root_dir=Path(os.getenv("PHOENIX_ROOT_DIR", ".")),
            max_file_size=int(os.getenv("PHOENIX_MAX_FILE_SIZE", str(10 * 1024 * 1024))),
            chunk_size=int(os.getenv("PHOENIX_CHUNK_SIZE", str(256 * 1024))),
            max_bytes_per_file=int(
                os.getenv("PHOENIX_MAX_BYTES_PER_FILE", str(5 * 1024 * 1024))
            ),
            use_gpu=os.getenv("PHOENIX_USE_GPU", "0") == "1",
            redact_matches=os.getenv("PHOENIX_REDACT", "0") == "1",
        )
