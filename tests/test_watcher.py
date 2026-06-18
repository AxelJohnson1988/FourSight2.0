"""Tests for phoenix_scanner.watcher (Phase 2 — ScanWatcher)."""

from __future__ import annotations

from pathlib import Path

import pytest

from phoenix_scanner.config import Config
from phoenix_scanner.crawler import ManifestEntry
from phoenix_scanner.scanner import scan
from phoenix_scanner.watcher import ScanWatcher


def _make_entry(path: str, size: int = 0) -> ManifestEntry:
    return ManifestEntry(path=path, size=size, mtime=0.0, path_hash="0" * 64)


# ---------------------------------------------------------------------------
# ScanWatcher dataclass
# ---------------------------------------------------------------------------


def test_watcher_defaults():
    w = ScanWatcher()
    assert w.max_findings_per_file == 0
    assert w.elapsed_time_budget == 0.0
    assert w.alert_callback is None


def test_watcher_alert_fires_callback():
    events = []
    w = ScanWatcher(alert_callback=lambda e, m: events.append((e, m)))
    w.alert("test-event", "hello")
    assert events == [("test-event", "hello")]


def test_watcher_alert_tolerates_broken_callback():
    """A raising callback must never abort the watcher."""

    def bad_callback(event: str, msg: str) -> None:
        raise RuntimeError("boom")

    w = ScanWatcher(alert_callback=bad_callback)
    w.alert("x", "y")  # must not raise


def test_watcher_alert_no_callback():
    """alert() without a callback must not raise."""
    w = ScanWatcher()
    w.alert("x", "y")


# ---------------------------------------------------------------------------
# ScanWatcher integrated with scan()
# ---------------------------------------------------------------------------


def test_watcher_no_limits_does_not_truncate(tmp_path: Path):
    sha = "a" * 64
    f = tmp_path / "many.txt"
    f.write_text("\n".join([sha] * 10))

    entry = _make_entry(str(f), f.stat().st_size)
    cfg = Config()
    watcher = ScanWatcher()  # no limits
    findings = scan([entry], cfg, watcher=watcher)
    sha_findings = [x for x in findings if x.match_type == "sha256_hex"]
    assert len(sha_findings) >= 10


def test_watcher_max_findings_per_file_truncates(tmp_path: Path):
    sha = "b" * 64
    f = tmp_path / "many.txt"
    f.write_text("\n".join([sha] * 20))

    alerts: list[tuple[str, str]] = []
    entry = _make_entry(str(f), f.stat().st_size)
    cfg = Config()
    watcher = ScanWatcher(
        max_findings_per_file=3,
        alert_callback=lambda e, m: alerts.append((e, m)),
    )
    findings = scan([entry], cfg, watcher=watcher)
    sha_findings = [x for x in findings if x.match_type == "sha256_hex"]
    assert len(sha_findings) <= 3
    assert any("max-findings-per-file" in a[0] for a in alerts)
    assert any("threshold-exceeded" in a[0] for a in alerts)


def test_watcher_cap_alert_includes_file_path(tmp_path: Path):
    sha = "c" * 64
    f = tmp_path / "evidence.txt"
    # Write 5 sha256 values on separate lines so each gets its own word-boundary match
    f.write_text("\n".join([sha] * 5))

    messages: list[str] = []
    entry = _make_entry(str(f), f.stat().st_size)
    cfg = Config()
    watcher = ScanWatcher(
        max_findings_per_file=1,
        alert_callback=lambda e, m: messages.append(m),
    )
    scan([entry], cfg, watcher=watcher)
    assert any(str(f) in m for m in messages)


def test_watcher_cap_applied_per_file_not_globally(tmp_path: Path):
    """Cap is per-file: two files each hitting 3 findings → at most 6 total."""
    sha = "d" * 64
    f1 = tmp_path / "a.txt"
    f2 = tmp_path / "b.txt"
    f1.write_text("\n".join([sha] * 10))
    f2.write_text("\n".join([sha] * 10))

    entries = [
        _make_entry(str(f1), f1.stat().st_size),
        _make_entry(str(f2), f2.stat().st_size),
    ]
    cfg = Config()
    watcher = ScanWatcher(max_findings_per_file=3)
    findings = scan(entries, cfg, watcher=watcher)
    sha_findings = [x for x in findings if x.match_type == "sha256_hex"]
    # Each file capped at 3 → max 6 total
    assert len(sha_findings) <= 6


# ---------------------------------------------------------------------------
# Sandboxed mode (Phase 2)
# ---------------------------------------------------------------------------


def test_sandboxed_scan_returns_findings(tmp_path: Path):
    sha = "e" * 64
    f = tmp_path / "data.txt"
    f.write_text(f"hash={sha}")

    entry = _make_entry(str(f), f.stat().st_size)
    cfg = Config()
    # sandboxed=True exercises the ProcessPoolExecutor path
    findings = scan([entry], cfg, sandboxed=True)
    assert any(x.match_type == "sha256_hex" for x in findings)


def test_sandboxed_scan_via_config(tmp_path: Path):
    sha = "f" * 64
    f = tmp_path / "data.txt"
    f.write_text(sha)

    entry = _make_entry(str(f), f.stat().st_size)
    cfg = Config(sandboxed=True)
    findings = scan([entry], cfg)
    assert any(x.match_type == "sha256_hex" for x in findings)


def test_sandboxed_scan_with_watcher(tmp_path: Path):
    sha = "1" * 64
    f = tmp_path / "big.txt"
    f.write_text("\n".join([sha] * 15))

    alerts: list[str] = []
    entry = _make_entry(str(f), f.stat().st_size)
    cfg = Config()
    watcher = ScanWatcher(
        max_findings_per_file=5,
        elapsed_time_budget=30.0,
        alert_callback=lambda e, m: alerts.append(e),
    )
    findings = scan([entry], cfg, watcher=watcher, sandboxed=True)
    sha_findings = [x for x in findings if x.match_type == "sha256_hex"]
    assert len(sha_findings) <= 5
