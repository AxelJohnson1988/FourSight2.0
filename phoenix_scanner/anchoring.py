"""Hashing and OP_RETURN payload generation."""

from __future__ import annotations

import hashlib
from pathlib import Path

from phoenix_scanner.config import Config


def hash_bytes(data: bytes) -> str:
    """Return SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    """Return SHA-256 hex digest of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_op_return_payload(digest_hex: str, *, prefix: str = "414c454501") -> str:
    """Concatenate the prefix and the SHA-256 hex to form an OP_RETURN payload.

    The default prefix ``414c454501`` is the ASCII bytes for ``ALEE`` followed
    by a version byte ``0x01``.

    Parameters
    ----------
    digest_hex:
        64-character hex string (SHA-256 output).
    prefix:
        Hex string prepended to the digest.  Defaults to the ALEE prefix.

    Returns
    -------
    str
        A hex string suitable for embedding in a Bitcoin ``OP_RETURN`` output.
        Note: Bitcoin enforces an 80-byte limit on ``OP_RETURN`` data; callers
        should validate the total length themselves if broadcasting.
    """
    if len(digest_hex) != 64:
        raise ValueError(f"digest_hex must be 64 hex chars; got {len(digest_hex)}")
    return prefix + digest_hex


def anchor(
    text: str = "",
    file_path: Path | None = None,
    *,
    config: Config | None = None,
) -> dict[str, str]:
    """Compute a SHA-256 anchor from optional *text* and/or *file_path*.

    Parameters
    ----------
    text:
        UTF-8 text payload (may be empty).
    file_path:
        Optional path to a file whose contents are appended to the text bytes.
    config:
        Config object (used for ``op_return_prefix``).

    Returns
    -------
    dict with keys:
        - ``sha256`` – hex digest
        - ``op_return_payload`` – hex OP_RETURN string
        - ``byte_length`` – total bytes hashed
    """
    if config is None:
        config = Config()

    payload = text.encode("utf-8")
    if file_path is not None:
        with open(file_path, "rb") as fh:
            payload += fh.read()

    digest = hashlib.sha256(payload).hexdigest()
    op_return = build_op_return_payload(digest, prefix=config.op_return_prefix)

    return {
        "sha256": digest,
        "op_return_payload": op_return,
        "byte_length": len(payload),
    }
