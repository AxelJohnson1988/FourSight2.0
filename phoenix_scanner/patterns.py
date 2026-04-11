"""Compiled regex patterns used by the scanner."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Pattern:
    """A named, compiled regex pattern."""

    name: str
    regex: re.Pattern[str]
    description: str


def _p(name: str, pattern: str, description: str, flags: int = 0) -> Pattern:
    return Pattern(name=name, regex=re.compile(pattern, flags), description=description)


# ---------------------------------------------------------------------------
# Built-in patterns
# ---------------------------------------------------------------------------

PATTERNS: list[Pattern] = [
    _p(
        "sha256_hex",
        r"\b([0-9a-fA-F]{64})\b",
        "SHA-256 hex digest (64 hex chars)",
    ),
    _p(
        "ed25519_sig_hex",
        r"\b([0-9a-fA-F]{128})\b",
        "Ed25519 signature heuristic (128 hex chars / 64 bytes)",
    ),
    _p(
        "ipfs_cidv0",
        r"\b(Qm[1-9A-HJ-NP-Za-km-z]{44,})\b",
        "IPFS CIDv0 (base58-encoded SHA-256 multihash)",
    ),
    _p(
        "ipfs_cidv1",
        r"\b(b[a-z2-7]{58,})\b",
        "IPFS CIDv1 (base32-encoded)",
    ),
    _p(
        "master_proof_hash",
        r"Master\s+Proof\s+Hash[:\s]+([0-9a-fA-F]{64})",
        "Explicit 'Master Proof Hash' label followed by a SHA-256 hex",
        re.IGNORECASE,
    ),
    _p(
        "verify_timestamp_script",
        r"verify_and_timestamp\.sh",
        "Reference to the verify_and_timestamp.sh script",
    ),
    _p(
        "op_return_payload",
        r"414c454501[0-9a-fA-F]{64}",
        "ALEE OP_RETURN payload (prefix + SHA-256)",
        re.IGNORECASE,
    ),
]


def build_keyword_pattern(keywords: list[str]) -> Pattern | None:
    """Return a combined pattern for user-supplied keywords, or None if empty."""
    if not keywords:
        return None
    escaped = [re.escape(kw) for kw in keywords]
    combined = "|".join(f"({e})" for e in escaped)
    return _p("user_keyword", combined, "User-supplied keyword match", re.IGNORECASE)
