"""Evidence ledger: tamper-evident summary writer with optional Ed25519 signing."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_PRIVATE_KEY_ENV = "PHOENIX_PRIVATE_KEY_HEX"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sign_hex(message: bytes, private_key_hex: str) -> str:
    """Sign *message* with an Ed25519 private key supplied as a hex string."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    raw = bytes.fromhex(private_key_hex)
    private_key = Ed25519PrivateKey.from_private_bytes(raw)
    sig = private_key.sign(message)
    return sig.hex()


def write_ledger(
    findings_path: Path,
    summary_path: Path,
    *,
    extra_meta: dict | None = None,
) -> dict:
    """Create a summary JSON anchored to *findings_path*.

    The summary contains:
    - counts by match type
    - SHA-256 of the findings file
    - optional Ed25519 signature (key read from env var only)
    - timestamp

    Returns the summary dict.
    """
    if not findings_path.exists():
        raise FileNotFoundError(f"Findings file not found: {findings_path}")

    findings_hash = _sha256_file(findings_path)
    counts: dict[str, int] = {}

    with open(findings_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                mt = row.get("match_type", "unknown")
                counts[mt] = counts.get(mt, 0) + 1
            except json.JSONDecodeError:
                pass

    summary: dict = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "findings_file": str(findings_path),
        "findings_sha256": findings_hash,
        "total_findings": sum(counts.values()),
        "counts_by_type": counts,
    }

    if extra_meta:
        summary["meta"] = extra_meta

    # Optional signing via env var (never touch disk)
    private_key_hex = os.getenv(_PRIVATE_KEY_ENV)
    if private_key_hex:
        try:
            canonical = json.dumps(summary, sort_keys=True).encode()
            summary["signature"] = _sign_hex(canonical, private_key_hex)
            logger.info("Summary signed with Ed25519 key from env var.")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Signing failed: %s", exc)
    else:
        logger.debug("No %s env var set; summary will be unsigned.", _PRIVATE_KEY_ENV)

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    logger.info("Ledger written to %s", summary_path)
    return summary
