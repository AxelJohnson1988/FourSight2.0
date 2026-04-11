"""Tests for phoenix_scanner.scanner."""

from pathlib import Path

import pytest

from phoenix_scanner.config import Config
from phoenix_scanner.crawler import ManifestEntry
from phoenix_scanner.scanner import Finding, _scan_chunk, scan, write_findings, read_findings
from phoenix_scanner.patterns import PATTERNS


def _make_entry(path: str, size: int = 0) -> ManifestEntry:
    return ManifestEntry(path=path, size=size, mtime=0.0, path_hash="0" * 64)


def test_scan_chunk_finds_sha256():
    sha = "a" * 64
    chunk = f"hash={sha}".encode()
    findings = _scan_chunk(chunk, 0, 0, PATTERNS, False, "test.txt")
    types = {f.match_type for f in findings}
    assert "sha256_hex" in types


def test_scan_chunk_redacts_match():
    sha = "a" * 64
    chunk = f"hash={sha}".encode()
    findings = _scan_chunk(chunk, 0, 0, PATTERNS, True, "test.txt")
    sha_findings = [f for f in findings if f.match_type == "sha256_hex"]
    assert sha_findings
    assert sha_findings[0].match_text == "<REDACTED>"


def test_scan_chunk_byte_offset(tmp_path: Path):
    prefix = b"x" * 100
    sha = b"a" * 64
    chunk = prefix + b" " + sha + b" "
    findings = _scan_chunk(chunk, 0, 0, PATTERNS, False, "f.txt")
    sha_findings = [f for f in findings if f.match_type == "sha256_hex"]
    assert sha_findings
    assert sha_findings[0].byte_offset == 101


def test_scan_file_end_to_end(tmp_path: Path):
    sha = "b" * 64
    test_file = tmp_path / "test.txt"
    test_file.write_text(f"Master Proof Hash: {sha}\nsome other line\n")

    entry = _make_entry(str(test_file), test_file.stat().st_size)
    cfg = Config(chunk_size=4096, max_bytes_per_file=1024 * 1024)
    findings = scan([entry], cfg)
    types = {f.match_type for f in findings}
    assert "sha256_hex" in types
    assert "master_proof_hash" in types


def test_scan_respects_max_bytes(tmp_path: Path):
    """Scanner must not read beyond max_bytes_per_file."""
    # Put the SHA256 after the 10-byte cap
    sha = "c" * 64
    test_file = tmp_path / "long.txt"
    test_file.write_text("x" * 20 + sha)

    entry = _make_entry(str(test_file), test_file.stat().st_size)
    cfg = Config(chunk_size=10, max_bytes_per_file=10)
    findings = scan([entry], cfg)
    sha_findings = [f for f in findings if f.match_type == "sha256_hex"]
    assert sha_findings == []


def test_write_and_read_findings(tmp_path: Path):
    import time

    findings = [
        Finding(
            file_path="/tmp/x.txt",
            match_type="sha256_hex",
            match_text="a" * 64,
            byte_offset=0,
            line_number=1,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            pattern_description="SHA-256",
        )
    ]
    out = tmp_path / "findings.jsonl"
    write_findings(findings, out)
    reloaded = read_findings(out)
    assert len(reloaded) == 1
    assert reloaded[0].match_type == "sha256_hex"
