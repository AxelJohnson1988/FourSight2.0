"""Tests for phoenix_scanner.crawler."""

import json
import os
from pathlib import Path

import pytest

from phoenix_scanner.config import Config
from phoenix_scanner.crawler import (
    ManifestEntry,
    crawl,
    read_manifest,
    write_manifest,
)


@pytest.fixture()
def tmp_tree(tmp_path: Path) -> Path:
    """Create a small directory tree for crawl tests."""
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "b.py").write_text("print('hi')")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.log").write_text("log line")
    (sub / "big.bin").write_bytes(b"\x00" * 20)
    return tmp_path


def test_crawl_finds_files(tmp_tree: Path):
    cfg = Config(root_dir=tmp_tree, max_file_size=100)
    entries = crawl(cfg, max_workers=1)
    paths = {Path(e.path).name for e in entries}
    assert "a.txt" in paths
    assert "b.py" in paths
    assert "c.log" in paths
    assert "big.bin" in paths  # 20 bytes < 100


def test_crawl_respects_max_file_size(tmp_tree: Path):
    cfg = Config(root_dir=tmp_tree, max_file_size=15)
    entries = crawl(cfg, max_workers=1)
    names = {Path(e.path).name for e in entries}
    assert "big.bin" not in names


def test_crawl_text_only(tmp_tree: Path):
    cfg = Config(root_dir=tmp_tree, text_only=True, max_file_size=100)
    entries = crawl(cfg, max_workers=1)
    names = {Path(e.path).name for e in entries}
    assert "big.bin" not in names
    assert "a.txt" in names


def test_crawl_extension_filter(tmp_tree: Path):
    cfg = Config(root_dir=tmp_tree, extensions=[".py"], max_file_size=100)
    entries = crawl(cfg, max_workers=1)
    assert all(e.path.endswith(".py") for e in entries)


def test_write_and_read_manifest(tmp_tree: Path, tmp_path: Path):
    cfg = Config(root_dir=tmp_tree, max_file_size=100)
    entries = crawl(cfg, max_workers=1)
    manifest_path = tmp_path / "manifest.jsonl"
    write_manifest(entries, manifest_path)

    assert manifest_path.exists()
    reloaded = read_manifest(manifest_path)
    assert len(reloaded) == len(entries)
    assert {e.path for e in reloaded} == {e.path for e in entries}


def test_manifest_entry_has_required_fields(tmp_tree: Path):
    cfg = Config(root_dir=tmp_tree, max_file_size=100)
    entries = crawl(cfg, max_workers=1)
    for e in entries:
        assert isinstance(e.path, str)
        assert isinstance(e.size, int)
        assert isinstance(e.mtime, float)
        assert len(e.path_hash) == 64  # SHA-256 hex


def test_crawl_sorted_output(tmp_tree: Path):
    cfg = Config(root_dir=tmp_tree, max_file_size=100)
    entries = crawl(cfg, max_workers=1)
    paths = [e.path for e in entries]
    assert paths == sorted(paths)
