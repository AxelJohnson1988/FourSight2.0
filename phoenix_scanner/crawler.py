"""Drive crawler / indexer – multi-process, resumable, JSONL manifest output."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Generator, Iterable

from phoenix_scanner.config import Config

logger = logging.getLogger(__name__)

_TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".txt", ".md", ".rst", ".log", ".csv", ".tsv", ".json", ".jsonl",
        ".xml", ".html", ".htm", ".yaml", ".yml", ".toml", ".ini", ".cfg",
        ".py", ".js", ".ts", ".sh", ".bash", ".c", ".cpp", ".h", ".java",
        ".go", ".rs", ".rb", ".php", ".sql",
    }
)


@dataclass
class ManifestEntry:
    """One row in the crawler manifest."""

    path: str
    size: int
    mtime: float
    path_hash: str  # SHA-256 of the absolute path string


def _hash_path(path_str: str) -> str:
    return hashlib.sha256(path_str.encode()).hexdigest()


def _matches_any(name: str, globs: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name, g) for g in globs)


def _should_include(
    entry: os.DirEntry[str],
    *,
    include_globs: list[str],
    exclude_globs: list[str],
    extensions: list[str],
    max_file_size: int,
    text_only: bool,
) -> bool:
    name = entry.name
    path = entry.path

    # Exclude check (glob against full path and name)
    for pat in exclude_globs:
        if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(name, pat):
            return False

    # Include check (if list non-empty, must match at least one)
    if include_globs and not _matches_any(name, include_globs):
        return False

    # Extension filter
    if extensions:
        _, ext = os.path.splitext(name)
        if ext.lower() not in {e.lower() for e in extensions}:
            return False

    try:
        stat = entry.stat()
    except OSError:
        return False

    if stat.st_size > max_file_size:
        return False

    if text_only:
        _, ext = os.path.splitext(name)
        if ext.lower() not in _TEXT_EXTENSIONS:
            return False

    return True


def _scan_directory(
    dir_path: str,
    include_globs: list[str],
    exclude_globs: list[str],
    extensions: list[str],
    max_file_size: int,
    text_only: bool,
) -> list[dict]:
    """Worker function: scan one directory and return ManifestEntry dicts."""
    results: list[dict] = []
    try:
        with os.scandir(dir_path) as it:
            for entry in it:
                if entry.is_file(follow_symlinks=False):
                    if _should_include(
                        entry,
                        include_globs=include_globs,
                        exclude_globs=exclude_globs,
                        extensions=extensions,
                        max_file_size=max_file_size,
                        text_only=text_only,
                    ):
                        try:
                            stat = entry.stat()
                            results.append(
                                asdict(
                                    ManifestEntry(
                                        path=os.path.abspath(entry.path),
                                        size=stat.st_size,
                                        mtime=stat.st_mtime,
                                        path_hash=_hash_path(
                                            os.path.abspath(entry.path)
                                        ),
                                    )
                                )
                            )
                        except OSError:
                            pass
    except PermissionError:
        pass
    return results


def _enumerate_dirs(root: Path, exclude_globs: list[str]) -> Generator[str, None, None]:
    """BFS over directories, honouring exclude globs."""
    queue: list[str] = [str(root.resolve())]
    while queue:
        current = queue.pop()
        yield current
        try:
            with os.scandir(current) as it:
                for entry in sorted(it, key=lambda e: e.name):
                    if entry.is_dir(follow_symlinks=False):
                        skip = any(
                            fnmatch.fnmatch(entry.path, pat)
                            or fnmatch.fnmatch(entry.name, pat)
                            for pat in exclude_globs
                        )
                        if not skip:
                            queue.append(entry.path)
        except PermissionError:
            pass


def crawl(config: Config, *, max_workers: int = 4) -> list[ManifestEntry]:
    """Crawl *config.root_dir* and return a sorted list of ManifestEntry objects.

    Supports resuming via *config.checkpoint_file*: directories already
    written to the checkpoint are skipped.
    """
    already_done: set[str] = set()
    if config.checkpoint_file and config.checkpoint_file.exists():
        with open(config.checkpoint_file) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    already_done.add(line)

    dirs = [
        d
        for d in _enumerate_dirs(config.root_dir, config.exclude_globs)
        if d not in already_done
    ]

    entries: list[ManifestEntry] = []

    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _scan_directory,
                d,
                config.include_globs,
                config.exclude_globs,
                config.extensions,
                config.max_file_size,
                config.text_only,
            ): d
            for d in dirs
        }
        for future in as_completed(futures):
            d = futures[future]
            try:
                rows = future.result()
                for row in rows:
                    entries.append(ManifestEntry(**row))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Directory %s failed: %s", d, exc)

            # Update checkpoint
            if config.checkpoint_file:
                with open(config.checkpoint_file, "a") as fh:
                    fh.write(d + "\n")

    entries.sort(key=lambda e: e.path)
    return entries


def write_manifest(entries: list[ManifestEntry], path: Path) -> None:
    """Write manifest entries to a newline-delimited JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(asdict(entry)) + "\n")
    logger.info("Wrote %d entries to %s", len(entries), path)


def read_manifest(path: Path) -> list[ManifestEntry]:
    """Read manifest entries from a JSONL file."""
    entries: list[ManifestEntry] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(ManifestEntry(**json.loads(line)))
    return entries
