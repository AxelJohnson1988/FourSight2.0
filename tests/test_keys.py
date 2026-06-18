"""Tests for phoenix_scanner.keys."""

import os
import stat
from pathlib import Path

import pytest

from phoenix_scanner.keys import OverwriteBlockedError, load_public_key_hex, perform_key_ceremony


def test_key_ceremony_creates_files(tmp_path: Path):
    priv, pub = perform_key_ceremony("mykey", directory=tmp_path)
    assert priv.exists()
    assert pub.exists()
    assert priv.stat().st_size == 32
    assert pub.stat().st_size == 32


def test_key_ceremony_private_permissions(tmp_path: Path):
    priv, _ = perform_key_ceremony("mykey", directory=tmp_path)
    mode = priv.stat().st_mode & 0o777
    assert mode == 0o600


def test_key_ceremony_overwrite_blocked(tmp_path: Path):
    perform_key_ceremony("mykey", directory=tmp_path)
    with pytest.raises(OverwriteBlockedError):
        perform_key_ceremony("mykey", directory=tmp_path)


def test_key_ceremony_overwrite_allowed(tmp_path: Path):
    perform_key_ceremony("mykey", directory=tmp_path)
    # Should not raise
    priv2, pub2 = perform_key_ceremony("mykey", directory=tmp_path, overwrite=True)
    assert priv2.exists()


def test_load_public_key_hex(tmp_path: Path):
    _, pub = perform_key_ceremony("mykey", directory=tmp_path)
    hex_str = load_public_key_hex(pub)
    assert len(hex_str) == 64  # 32 bytes = 64 hex chars


def test_load_public_key_hex_wrong_size(tmp_path: Path):
    bad = tmp_path / "bad.pub"
    bad.write_bytes(b"tooshort")
    with pytest.raises(ValueError):
        load_public_key_hex(bad)
