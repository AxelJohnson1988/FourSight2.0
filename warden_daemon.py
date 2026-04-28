"""
Warden Daemon v1 — Pure trusted-execution pipeline.

Architecture:
  [Gradio UI / any caller]
        ↓
  [Input Buffer / Staging]
        ↓
  [Warden Daemon — ONLY signer]  ← this module
        ↓
  [Ledger + Output]

The UI layer must never sign, never finalize hashes, and never call the
ledger directly.  It submits raw payloads (text + optional file path) to
`anchor()` and receives back a read-only record dict.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ── ALEE OP_RETURN prefix (hex) ────────────────────────────────────────────
_ALEE_PREFIX_HEX = "414c454501"  # "ALEE" + version byte 0x01


# ───────────────────────────────────────────────────────────────────────────
# 1. Canonical Payload Construction
# ───────────────────────────────────────────────────────────────────────────

def build_canonical_payload(text_input: Optional[str], file_bytes: Optional[bytes]) -> bytes:
    """
    Build a deterministic byte payload from text and/or file content.

    Framing delimiters guarantee identical hashing across environments and
    prevent silent structural drift when one component is absent.

    Args:
        text_input: Optional text string to include.
        file_bytes: Optional raw bytes of an uploaded/read file.

    Returns:
        A canonical byte sequence suitable for hashing.

    Raises:
        ValueError: If both text_input and file_bytes are empty/None.
    """
    text_part = text_input.encode("utf-8") if text_input else b""
    file_part = file_bytes if file_bytes else b""

    if not text_part and not file_part:
        raise ValueError("Empty payload: provide text, file bytes, or both.")

    return (
        b"TEXT_START\n"
        + text_part
        + b"\nTEXT_END\nFILE_START\n"
        + file_part
        + b"\nFILE_END"
    )


# ───────────────────────────────────────────────────────────────────────────
# 2. SHA-256 Hashing
# ───────────────────────────────────────────────────────────────────────────

def compute_hash(payload: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of *payload*."""
    return hashlib.sha256(payload).hexdigest()


# ───────────────────────────────────────────────────────────────────────────
# 3. Ed25519 Signing
# ───────────────────────────────────────────────────────────────────────────

def sign_hash(private_key_bytes: bytes, message_hash_hex: str) -> str:
    """
    Sign a hex-encoded SHA-256 hash with an Ed25519 private key.

    Args:
        private_key_bytes: Raw 32-byte Ed25519 private key material.
        message_hash_hex: Lowercase hex string of the hash to sign.

    Returns:
        Hex-encoded 64-byte Ed25519 signature.

    Raises:
        ValueError: If the private key is not exactly 32 bytes.
    """
    if len(private_key_bytes) != 32:
        raise ValueError(
            f"Invalid Ed25519 private key: expected 32 bytes, got {len(private_key_bytes)}."
        )
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature = private_key.sign(bytes.fromhex(message_hash_hex))
    return signature.hex()


def _load_private_key() -> Optional[bytes]:
    """
    Load the Ed25519 private key from the environment variable
    ``WARDEN_PRIVATE_KEY_HEX`` (preferred) or from the file path in
    ``WARDEN_PRIVATE_KEY_PATH``.

    Returns ``None`` when no key source is configured; callers must treat
    unsigned records accordingly.
    """
    hex_val = os.environ.get("WARDEN_PRIVATE_KEY_HEX", "").strip()
    if hex_val:
        raw = bytes.fromhex(hex_val)
        if len(raw) != 32:
            raise ValueError(
                "WARDEN_PRIVATE_KEY_HEX must decode to exactly 32 bytes."
            )
        return raw

    path_val = os.environ.get("WARDEN_PRIVATE_KEY_PATH", "").strip()
    if path_val:
        key_path = Path(path_val)
        if not key_path.exists():
            raise FileNotFoundError(f"Private key file not found: {key_path}")
        raw = key_path.read_bytes()
        if len(raw) != 32:
            raise ValueError(
                f"Key file must contain exactly 32 bytes, got {len(raw)}."
            )
        return raw

    return None


def _get_public_key_hex(private_key_bytes: bytes) -> str:
    """Derive the Ed25519 public key and return it as a hex string."""
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    pub = private_key.public_key()
    # cryptography >= 2.6 exposes raw bytes via public_bytes_raw()
    try:
        return pub.public_bytes_raw().hex()
    except AttributeError:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
        return pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


# ───────────────────────────────────────────────────────────────────────────
# 4. Hash Chaining
# ───────────────────────────────────────────────────────────────────────────

def chain_hash(current_hash: str, previous_hash: str) -> str:
    """
    Combine *previous_hash* and *current_hash* into a single chain digest.

    Tampering with any prior record breaks all subsequent chain hashes,
    providing append-only integrity across the ledger.

    Args:
        current_hash: Hex SHA-256 of the current record's payload.
        previous_hash: Hex SHA-256 chain hash of the immediately preceding record.

    Returns:
        Hex SHA-256 of ``(previous_hash + current_hash)``.
    """
    combined = (previous_hash + current_hash).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


# ───────────────────────────────────────────────────────────────────────────
# 5. Corruption / Sanity Check
# ───────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_PATTERNS: tuple[bytes, ...] = (
    b"advertisement",
    b"<script",
    b"javascript:",
    b"eval(",
    b"exec(",
)


def sanity_check(content: bytes) -> str:
    """
    Run lightweight pre-signing anomaly detection on raw payload bytes.

    Args:
        content: The canonical payload bytes before hashing.

    Returns:
        ``"OK"`` when no anomalies are detected.

    Raises:
        ValueError: When the payload is empty.
        RuntimeError: When a suspicious pattern is detected (includes the
            matched pattern in the message so callers can log it).
    """
    if len(content) == 0:
        raise ValueError("Empty payload — refusing to sign a null digest.")

    lower = content.lower()
    for pattern in _SUSPICIOUS_PATTERNS:
        if pattern in lower:
            raise RuntimeError(
                f"⚠️ Suspicious content detected: pattern '{pattern.decode()}' found. "
                "Signing aborted."
            )

    return "OK"


# ───────────────────────────────────────────────────────────────────────────
# 6. Ledger I/O
# ───────────────────────────────────────────────────────────────────────────

_GENESIS_HASH = "0" * 64  # Sentinel for the first ledger entry


def get_last_hash(ledger_path: str | Path) -> str:
    """
    Return the *chain_hash* field of the most recent ledger entry.

    Returns the genesis sentinel (64 zeros) when the ledger is absent or empty.
    """
    p = Path(ledger_path)
    if not p.exists() or p.stat().st_size == 0:
        return _GENESIS_HASH
    with p.open("r", encoding="utf-8") as fh:
        records = json.load(fh)
    if not records:
        return _GENESIS_HASH
    return records[-1]["chain_hash"]


def append_to_ledger(record: dict, ledger_path: str | Path) -> None:
    """
    Atomically append *record* to the JSON ledger file.

    The ledger is a JSON array written as a single file.  Append is
    implemented as read-modify-write; for high-throughput use cases replace
    this with an append-log or SQLite backend.
    """
    p = Path(ledger_path)
    records: list[dict] = []
    if p.exists() and p.stat().st_size > 0:
        with p.open("r", encoding="utf-8") as fh:
            records = json.load(fh)
    records.append(record)
    tmp = p.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2)
    tmp.replace(p)


# ───────────────────────────────────────────────────────────────────────────
# 7. OP_RETURN Formatting
# ───────────────────────────────────────────────────────────────────────────

def format_op_return(master_hash_hex: str) -> str:
    """Return the full Bitcoin OP_RETURN hex payload (ALEE prefix + hash)."""
    return _ALEE_PREFIX_HEX + master_hash_hex


# ───────────────────────────────────────────────────────────────────────────
# 8. Top-Level Orchestrator
# ───────────────────────────────────────────────────────────────────────────

def anchor(
    text_input: Optional[str] = None,
    file_path: Optional[str | Path] = None,
    file_bytes: Optional[bytes] = None,
    ledger_path: str | Path = "warden_ledger.json",
) -> dict:
    """
    Full Warden pipeline: build → check → hash → sign → chain → ledger.

    Exactly one of *file_path* or *file_bytes* should be supplied when
    anchoring file content; if *file_path* is given its bytes are read here
    inside the trust boundary.

    Args:
        text_input: Optional text payload.
        file_path: Optional path to a file whose content will be included.
        file_bytes: Optional pre-read file bytes (alternative to file_path).
        ledger_path: Path to the JSON ledger file (created if absent).

    Returns:
        A dict with the fields:
            - ``timestamp``      — ISO-8601 UTC timestamp
            - ``input_size``     — canonical payload size in bytes
            - ``master_hash``    — hex SHA-256 of the canonical payload
            - ``op_return``      — Bitcoin OP_RETURN hex string
            - ``previous_hash``  — chain hash of the preceding record
            - ``chain_hash``     — chain hash of this record
            - ``signature``      — Ed25519 hex signature (or ``null``)
            - ``public_key``     — Ed25519 hex public key (or ``null``)
            - ``sanity``         — ``"OK"`` or an anomaly description

    Raises:
        ValueError: On empty payload or invalid key material.
        RuntimeError: When the sanity check rejects the content.
        FileNotFoundError: When *file_path* does not exist.
    """
    # ── resolve file bytes ────────────────────────────────────────────────
    if file_path is not None and file_bytes is None:
        fp = Path(file_path)
        if not fp.exists():
            raise FileNotFoundError(f"File not found: {fp}")
        file_bytes = fp.read_bytes()

    # ── step 1: canonical payload ─────────────────────────────────────────
    payload = build_canonical_payload(text_input, file_bytes)

    # ── step 2: sanity check (before signing) ────────────────────────────
    sanity_result = sanity_check(payload)

    # ── step 3: SHA-256 ───────────────────────────────────────────────────
    master_hash = compute_hash(payload)

    # ── step 4: Ed25519 signature ─────────────────────────────────────────
    private_key_bytes = _load_private_key()
    signature_hex: Optional[str] = None
    public_key_hex: Optional[str] = None
    if private_key_bytes is not None:
        signature_hex = sign_hash(private_key_bytes, master_hash)
        public_key_hex = _get_public_key_hex(private_key_bytes)

    # ── step 5: hash chaining ─────────────────────────────────────────────
    previous_hash = get_last_hash(ledger_path)
    chained = chain_hash(master_hash, previous_hash)

    # ── step 6: assemble record ───────────────────────────────────────────
    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_size": len(payload),
        "master_hash": master_hash,
        "op_return": format_op_return(master_hash),
        "previous_hash": previous_hash,
        "chain_hash": chained,
        "signature": signature_hex,
        "public_key": public_key_hex,
        "sanity": sanity_result,
    }

    # ── step 7: append to ledger ──────────────────────────────────────────
    append_to_ledger(record, ledger_path)

    return record


# ───────────────────────────────────────────────────────────────────────────
# CLI entry-point (local / Colab use)
# ───────────────────────────────────────────────────────────────────────────

def _print_record(record: dict) -> None:
    print("\n" + "=" * 60)
    print("  WARDEN DAEMON v1 — CRYPTOGRAPHIC ANCHOR")
    print("=" * 60)
    print(f"  Timestamp   : {record['timestamp']}")
    print(f"  Input size  : {record['input_size']} bytes")
    print(f"  Master hash : {record['master_hash']}")
    print(f"  OP_RETURN   : {record['op_return']}")
    print(f"  Prev. hash  : {record['previous_hash']}")
    print(f"  Chain hash  : {record['chain_hash']}")
    print(f"  Signature   : {record['signature'] or '(no key configured)'}")
    print(f"  Public key  : {record['public_key'] or '(no key configured)'}")
    print(f"  Sanity      : {record['sanity']}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Warden Daemon v1 — hash, sign, and chain-anchor a payload."
    )
    parser.add_argument("--text", default=None, help="Text payload to anchor.")
    parser.add_argument("--file", default=None, help="Path to a file to anchor.")
    parser.add_argument(
        "--ledger",
        default="warden_ledger.json",
        help="Path to the JSON ledger file (default: warden_ledger.json).",
    )
    args = parser.parse_args()

    if not args.text and not args.file:
        parser.error("Provide at least --text or --file.")

    result = anchor(
        text_input=args.text,
        file_path=args.file,
        ledger_path=args.ledger,
    )
    _print_record(result)
