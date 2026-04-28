"""Tests for phoenix_scanner.anchoring."""

import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest

from phoenix_scanner.anchoring import (
    anchor,
    broadcast_op_return,
    build_op_return_payload,
    hash_bytes,
    hash_file,
    pin_to_ipfs,
)
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
    assert result["byte_length"] == "5"
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


def test_anchor_empty_text_no_file_raises():
    """Empty text with no file_path must raise ValueError (null-hash guard)."""
    with pytest.raises(ValueError, match="non-empty text or a file_path"):
        anchor()


def test_anchor_whitespace_only_no_file_raises():
    """Whitespace-only text with no file_path must also raise."""
    with pytest.raises(ValueError, match="non-empty text or a file_path"):
        anchor(text="   \t\n")


def test_anchor_empty_text_with_file_allowed(tmp_path):
    """Empty text is fine when a file_path is supplied."""
    f = tmp_path / "x.bin"
    f.write_bytes(b"data")
    result = anchor(text="", file_path=f)
    assert result["sha256"] == hashlib.sha256(b"data").hexdigest()


def test_anchor_custom_prefix():
    cfg = Config(op_return_prefix="deadbeef")
    result = anchor(text="test", config=cfg)
    assert result["op_return_payload"].startswith("deadbeef")


def test_anchor_no_ipfs_cid_without_gateway():
    result = anchor(text="hello")
    assert "ipfs_cid" not in result


def test_anchor_with_ipfs_gateway(tmp_path):
    """anchor() should include ipfs_cid when gateway_url is provided."""
    fake_cid = "QmFakeCID123"
    with patch("phoenix_scanner.anchoring.pin_to_ipfs", return_value=fake_cid) as mock_pin:
        result = anchor(text="hello", ipfs_gateway_url="http://127.0.0.1:5001")
    assert result["ipfs_cid"] == fake_cid
    mock_pin.assert_called_once()


# ---------------------------------------------------------------------------
# pin_to_ipfs
# ---------------------------------------------------------------------------

def test_pin_to_ipfs_success():
    fake_response_body = json.dumps({"Hash": "QmABC", "Size": "10"}).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = fake_response_body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        cid = pin_to_ipfs(b"hello", gateway_url="http://127.0.0.1:5001")

    assert cid == "QmABC"


def test_pin_to_ipfs_bad_response_raises():
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"NotHash": "x"}'
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(RuntimeError, match="Unexpected IPFS response"):
            pin_to_ipfs(b"hello", gateway_url="http://127.0.0.1:5001")


# ---------------------------------------------------------------------------
# broadcast_op_return
# ---------------------------------------------------------------------------

def test_broadcast_op_return_success():
    fake_txid = "deadbeef" * 8
    fake_body = json.dumps({"result": fake_txid, "error": None, "id": "phoenix"}).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = fake_body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        txid = broadcast_op_return(
            "aabbcc",
            node_url="http://127.0.0.1:8332",
            auth=("user", "pass"),
        )

    assert txid == fake_txid


def test_broadcast_op_return_rpc_error_raises():
    fake_body = json.dumps(
        {"result": None, "error": {"code": -25, "message": "bad tx"}, "id": "phoenix"}
    ).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = fake_body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(ValueError, match="Bitcoin RPC error"):
            broadcast_op_return(
                "aabbcc",
                node_url="http://127.0.0.1:8332",
                auth=("user", "pass"),
            )
