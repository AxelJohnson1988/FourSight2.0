"""Tests for gpam.sync.ledger — JSONL fallback and chain integrity."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from gpam.sync.ledger import (
    LedgerBackend,
    SyncEventLogResult,
    _GENESIS_HASH,
    _canonical,
    _jsonl_append,
    _jsonl_path,
    _jsonl_prev_hash,
    _sha256,
    log_sync_event,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fresh_ledger(tmp_path: Path) -> Path:
    """Return a path inside tmp_path and point the env var at it."""
    p = tmp_path / "test_ledger.jsonl"
    return p


# ---------------------------------------------------------------------------
# _canonical / _sha256
# ---------------------------------------------------------------------------


def test_canonical_is_sorted_compact_json() -> None:
    result = _canonical({"z": 1, "a": 2})
    assert result == '{"a":2,"z":1}'


def test_sha256_returns_64_hex_chars() -> None:
    h = _sha256("hello")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_sha256_is_deterministic() -> None:
    assert _sha256("test") == _sha256("test")


# ---------------------------------------------------------------------------
# JSONL genesis
# ---------------------------------------------------------------------------


def test_prev_hash_returns_genesis_when_no_file(tmp_path: Path) -> None:
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(tmp_path / "new.jsonl")}):
        assert _jsonl_prev_hash() == _GENESIS_HASH


def test_prev_hash_returns_genesis_on_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(p)}):
        assert _jsonl_prev_hash() == _GENESIS_HASH


# ---------------------------------------------------------------------------
# JSONL append — single entry
# ---------------------------------------------------------------------------


def test_jsonl_append_creates_file(tmp_path: Path) -> None:
    p = _fresh_ledger(tmp_path)
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(p)}):
        _jsonl_append({"event_type": "test"})
    assert p.exists()


def test_jsonl_append_produces_valid_json(tmp_path: Path) -> None:
    p = _fresh_ledger(tmp_path)
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(p)}):
        _jsonl_append({"event_type": "test"})
    entry = json.loads(p.read_text(encoding="utf-8").strip())
    assert "event" in entry
    assert "timestamp" in entry
    assert "chain_hash" in entry
    assert "prev_hash" in entry


def test_jsonl_first_entry_has_genesis_prev_hash(tmp_path: Path) -> None:
    p = _fresh_ledger(tmp_path)
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(p)}):
        _jsonl_append({"event_type": "first"})
    entry = json.loads(p.read_text(encoding="utf-8").strip())
    assert entry["prev_hash"] == _GENESIS_HASH


# ---------------------------------------------------------------------------
# JSONL chain integrity
# ---------------------------------------------------------------------------


def test_jsonl_chain_links_entries(tmp_path: Path) -> None:
    p = _fresh_ledger(tmp_path)
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(p)}):
        _jsonl_append({"event_type": "first"})
        _jsonl_append({"event_type": "second"})

    lines = [json.loads(ln) for ln in p.read_text(encoding="utf-8").strip().splitlines()]
    assert lines[1]["prev_hash"] == lines[0]["chain_hash"]


def test_jsonl_chain_is_replayable(tmp_path: Path) -> None:
    """Recompute every chain_hash from prev_hash + event — all must match."""
    p = _fresh_ledger(tmp_path)
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(p)}):
        for i in range(5):
            _jsonl_append({"event_type": f"event_{i}", "seq": i})

    lines = [json.loads(ln) for ln in p.read_text(encoding="utf-8").strip().splitlines()]
    for entry in lines:
        payload = {
            "event": entry["event"],
            "timestamp": entry["timestamp"],
            "prev_hash": entry["prev_hash"],
        }
        expected = _sha256(entry["prev_hash"] + _canonical(payload))
        assert entry["chain_hash"] == expected, (
            f"Chain broken at entry: {entry['event']}"
        )


def test_jsonl_chain_detects_tamper(tmp_path: Path) -> None:
    """Mutating an entry breaks the chain hash of the following entry."""
    p = _fresh_ledger(tmp_path)
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(p)}):
        _jsonl_append({"event_type": "original"})
        _jsonl_append({"event_type": "second"})

    lines = p.read_text(encoding="utf-8").strip().splitlines()
    first = json.loads(lines[0])
    second = json.loads(lines[1])

    # Tamper: change the chain_hash of the first entry.
    first["chain_hash"] = "dead" * 16
    p.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n", encoding="utf-8")

    # The second entry's prev_hash no longer matches the tampered first entry.
    reloaded = [json.loads(ln) for ln in p.read_text(encoding="utf-8").strip().splitlines()]
    assert reloaded[1]["prev_hash"] != reloaded[0]["chain_hash"]


# ---------------------------------------------------------------------------
# log_sync_event — public API
# ---------------------------------------------------------------------------


def test_log_sync_event_returns_result(tmp_path: Path) -> None:
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(tmp_path / "l.jsonl")}):
        result = log_sync_event("test_event", key="value")
    assert isinstance(result, SyncEventLogResult)


def test_log_sync_event_uses_jsonl_when_akashic_unavailable(tmp_path: Path) -> None:
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(tmp_path / "l.jsonl")}):
        result = log_sync_event("test_event")
    assert result.backend == LedgerBackend.JSONL


def test_log_sync_event_chain_hash_is_64_hex(tmp_path: Path) -> None:
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(tmp_path / "l.jsonl")}):
        result = log_sync_event("test_event")
    assert len(result.chain_hash) == 64
    assert all(c in "0123456789abcdef" for c in result.chain_hash)


def test_log_sync_event_writes_event_type(tmp_path: Path) -> None:
    p = tmp_path / "l.jsonl"
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(p)}):
        log_sync_event("forward_sync_complete", files_routed=3)
    entry = json.loads(p.read_text(encoding="utf-8").strip())
    assert entry["event"]["event_type"] == "forward_sync_complete"
    assert entry["event"]["files_routed"] == 3


def test_log_sync_event_multiple_calls_build_chain(tmp_path: Path) -> None:
    p = tmp_path / "l.jsonl"
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(p)}):
        r1 = log_sync_event("event_a")
        r2 = log_sync_event("event_b")

    lines = [json.loads(ln) for ln in p.read_text(encoding="utf-8").strip().splitlines()]
    assert lines[1]["prev_hash"] == lines[0]["chain_hash"]
    assert r2.chain_hash == lines[1]["chain_hash"]


def test_log_sync_event_uses_akashic_when_importable(tmp_path: Path) -> None:
    """When _try_akashic succeeds, backend should be AKASHIC."""
    fake_hash = "a" * 64

    with (
        patch("gpam.sync.ledger._try_akashic", return_value=fake_hash),
        patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(tmp_path / "l.jsonl")}),
    ):
        result = log_sync_event("test_event")

    assert result.backend == LedgerBackend.AKASHIC
    assert result.chain_hash == fake_hash


def test_log_sync_event_falls_back_on_akashic_failure(tmp_path: Path) -> None:
    """When _try_akashic returns None, must fall back to JSONL without raising."""
    with (
        patch("gpam.sync.ledger._try_akashic", return_value=None),
        patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(tmp_path / "l.jsonl")}),
    ):
        result = log_sync_event("test_event")

    assert result.backend == LedgerBackend.JSONL


def test_log_sync_event_result_path_matches_jsonl_path(tmp_path: Path) -> None:
    p = tmp_path / "specific.jsonl"
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(p)}):
        result = log_sync_event("test_event")
    assert result.path == p


def test_log_sync_event_creates_parent_directories(tmp_path: Path) -> None:
    p = tmp_path / "deep" / "nested" / "ledger.jsonl"
    with patch.dict(os.environ, {"GPAM_SYNC_LEDGER_PATH": str(p)}):
        log_sync_event("test_event")
    assert p.exists()
