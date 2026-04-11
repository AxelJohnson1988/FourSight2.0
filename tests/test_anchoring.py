"""Tests for phoenix_scanner.anchoring."""

import hashlib

import pytest

from phoenix_scanner.anchoring import anchor, build_op_return_payload, hash_bytes, hash_file
from phoenix_scanner.config import Config


def test_hash_bytes_known_value():
    result = hash_bytes(b"hello")
    assert result == hashlib.sha256(b"hello").hexdigest()


def test_hash_file(tmp_path):
    f = tmp_path / "data.txt"
    f.write_bytes(b"world")
    assert hash_file(f) == hashlib.sha256(b"world").hexdigest()


def test_build_op_return_payload_default_prefix():
    digest = "a" * 64
    payload = build_op_return_payload(digest)
    assert payload.startswith("414c454501")
    assert payload.endswith(digest)
    assert len(payload) == len("414c454501") + 64


def test_build_op_return_payload_rejects_wrong_length():
    with pytest.raises(ValueError):
        build_op_return_payload("abc")


def test_anchor_text_only():
    result = anchor(text="hello")
    assert result["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert result["byte_length"] == 5
    assert result["op_return_payload"].startswith("414c454501")


def test_anchor_file_only(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"data")
    result = anchor(file_path=f)
    assert result["sha256"] == hashlib.sha256(b"data").hexdigest()


def test_anchor_text_and_file(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"world")
    result = anchor(text="hello ", file_path=f)
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert result["sha256"] == expected


def test_anchor_empty_payload():
    result = anchor()
    assert result["sha256"] == hashlib.sha256(b"").hexdigest()
    assert result["byte_length"] == 0


def test_anchor_custom_prefix():
    cfg = Config(op_return_prefix="deadbeef")
    result = anchor(text="test", config=cfg)
    assert result["op_return_payload"].startswith("deadbeef")
