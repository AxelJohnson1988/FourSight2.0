"""Tests for phoenix_scanner.checkpoint (Phase 4 — SQLite CheckpointDB)."""

from __future__ import annotations

from pathlib import Path

import pytest

from phoenix_scanner.checkpoint import CheckpointDB
from phoenix_scanner.config import Config
from phoenix_scanner.crawler import crawl


# ---------------------------------------------------------------------------
# Basic state transitions
# ---------------------------------------------------------------------------


def test_mark_done_and_is_done(tmp_path: Path):
    with CheckpointDB(tmp_path / "cp.db") as db:
        assert not db.is_done("/foo/bar")
        db.mark_done("/foo/bar")
        assert db.is_done("/foo/bar")


def test_mark_done_not_done_for_other_dirs(tmp_path: Path):
    with CheckpointDB(tmp_path / "cp.db") as db:
        db.mark_done("/foo/bar")
        assert not db.is_done("/foo/baz")
        assert not db.is_done("/other")


def test_mark_pending_resets_done(tmp_path: Path):
    with CheckpointDB(tmp_path / "cp.db") as db:
        db.mark_done("/dir")
        db.mark_pending("/dir")
        assert not db.is_done("/dir")


def test_mark_failed_stores_error(tmp_path: Path):
    with CheckpointDB(tmp_path / "cp.db") as db:
        db.mark_failed("/bad/dir", "PermissionError")
        failed = db.failed_dirs()
        assert any(d == "/bad/dir" and "PermissionError" in (e or "") for d, e in failed)


def test_mark_failed_not_reported_as_done(tmp_path: Path):
    with CheckpointDB(tmp_path / "cp.db") as db:
        db.mark_failed("/bad/dir", "error")
        assert not db.is_done("/bad/dir")


# ---------------------------------------------------------------------------
# Bulk query helpers
# ---------------------------------------------------------------------------


def test_done_dirs_returns_only_done(tmp_path: Path):
    with CheckpointDB(tmp_path / "cp.db") as db:
        db.mark_done("/a")
        db.mark_done("/b")
        db.mark_failed("/c", "err")
        db.mark_pending("/d")
        done = db.done_dirs()
        assert done == {"/a", "/b"}


def test_pending_dirs_returns_only_pending(tmp_path: Path):
    with CheckpointDB(tmp_path / "cp.db") as db:
        db.mark_pending("/x")
        db.mark_done("/y")
        pending = db.pending_dirs()
        assert "/x" in pending
        assert "/y" not in pending


def test_failed_dirs_empty_when_none(tmp_path: Path):
    with CheckpointDB(tmp_path / "cp.db") as db:
        assert db.failed_dirs() == []


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_mark_done_twice_is_idempotent(tmp_path: Path):
    with CheckpointDB(tmp_path / "cp.db") as db:
        db.mark_done("/dir")
        db.mark_done("/dir")  # must not raise
        assert db.is_done("/dir")


def test_mark_failed_then_done_is_done(tmp_path: Path):
    with CheckpointDB(tmp_path / "cp.db") as db:
        db.mark_failed("/dir", "err")
        db.mark_done("/dir")
        assert db.is_done("/dir")
        assert not any(d == "/dir" for d, _ in db.failed_dirs())


# ---------------------------------------------------------------------------
# Persistence across sessions
# ---------------------------------------------------------------------------


def test_persists_across_sessions(tmp_path: Path):
    db_path = tmp_path / "cp.db"
    with CheckpointDB(db_path) as db:
        db.mark_done("/persist/me")

    # Re-open fresh connection
    with CheckpointDB(db_path) as db2:
        assert db2.is_done("/persist/me")


# ---------------------------------------------------------------------------
# Integration with crawl()
# ---------------------------------------------------------------------------


def test_crawl_with_sqlite_checkpoint_skips_done_dirs(tmp_path: Path):
    """Second crawl with the same CheckpointDB skips already-done directories."""
    (tmp_path / "a.txt").write_text("hello")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.txt").write_text("world")

    db_path = tmp_path / "crawl_cp.db"
    cfg = Config(root_dir=tmp_path, max_file_size=100)

    # First crawl: populates the DB
    entries1 = crawl(cfg, max_workers=1, checkpoint_db=CheckpointDB(db_path))
    assert len(entries1) >= 2

    # Second crawl: all directories already marked done → no entries
    entries2 = crawl(cfg, max_workers=1, checkpoint_db=CheckpointDB(db_path))
    assert len(entries2) == 0


def test_crawl_with_checkpoint_db_path_in_config(tmp_path: Path):
    """Config.checkpoint_db_path triggers automatic CheckpointDB creation."""
    (tmp_path / "x.txt").write_text("data")
    db_path = tmp_path / "auto_cp.db"
    cfg = Config(root_dir=tmp_path, max_file_size=100, checkpoint_db_path=db_path)

    entries = crawl(cfg, max_workers=1)
    assert len(entries) >= 1
    assert db_path.exists()

    # Second run with same config skips done dirs
    entries2 = crawl(cfg, max_workers=1)
    assert len(entries2) == 0
