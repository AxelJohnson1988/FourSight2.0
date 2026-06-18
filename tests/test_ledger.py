"""Tests for phoenix_scanner.ledger."""

import json
import os
from pathlib import Path

import pytest

from phoenix_scanner.ledger import write_ledger


@pytest.fixture()
def findings_file(tmp_path: Path) -> Path:
    path = tmp_path / "findings.jsonl"
    rows = [
        {"match_type": "sha256_hex", "file_path": "/a.txt"},
        {"match_type": "sha256_hex", "file_path": "/b.txt"},
        {"match_type": "ipfs_cidv0", "file_path": "/c.txt"},
    ]
    with open(path, "w") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    return path


def test_ledger_creates_summary(findings_file: Path, tmp_path: Path):
    summary_path = tmp_path / "summary.json"
    summary = write_ledger(findings_file, summary_path)
    assert summary_path.exists()
    assert summary["total_findings"] == 3
    assert summary["counts_by_type"]["sha256_hex"] == 2
    assert summary["counts_by_type"]["ipfs_cidv0"] == 1


def test_ledger_includes_findings_hash(findings_file: Path, tmp_path: Path):
    summary = write_ledger(findings_file, tmp_path / "s.json")
    assert len(summary["findings_sha256"]) == 64


def test_ledger_signing_with_ephemeral_key(findings_file: Path, tmp_path: Path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private_key = Ed25519PrivateKey.generate()
    priv_hex = private_key.private_bytes_raw().hex()  # type: ignore[attr-defined]

    os.environ["PHOENIX_PRIVATE_KEY_HEX"] = priv_hex
    try:
        summary = write_ledger(findings_file, tmp_path / "signed.json")
    finally:
        del os.environ["PHOENIX_PRIVATE_KEY_HEX"]

    assert "signature" in summary
    assert len(summary["signature"]) == 128  # Ed25519 sig = 64 bytes = 128 hex


def test_ledger_missing_findings_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        write_ledger(tmp_path / "nonexistent.jsonl", tmp_path / "s.json")
