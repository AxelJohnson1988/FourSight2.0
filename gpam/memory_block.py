"""Canonical GPAM Memory Block schema + deterministic hashing.

Key dependencies:
    pydantic >=2.0  (strict validation + JSON serialisation)
    hashlib / json  (canonical hashing — no external deps)

Design decisions
----------------
* ``hash`` covers every field *except* ``hash`` itself, so the digest can be
  recomputed from a loaded block and compared for tamper detection.
* ``id`` is included in the hash payload so the hash is specific to this
  particular block instance, not just its content.
* ``created_at`` must be UTC ISO-8601 ending with ``Z`` — lightweight check,
  keeps the model deterministic without heavy date libraries.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import List

from pydantic import BaseModel, Field, HttpUrl, StrictFloat, StrictStr, field_validator


class MemoryStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    SYNTHESIZED = "SYNTHESIZED"


def _canonical_json(obj: dict) -> str:
    """Stable, compact JSON string — deterministic across Python versions."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 encoded string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class MemoryBlock(BaseModel):
    """A single verified unit of knowledge in the GPAM Memory Promotion Pipeline.

    Parameters
    ----------
    id:
        Unique block identifier in ``MB-YYYYMMDD-XXXX`` format.
    title:
        Short human-readable label (1–200 characters).
    summary:
        Condensed factual content (1–10 000 characters).
    sources:
        One or more URL references supporting this block.
    confidence_score:
        Caller-supplied confidence in [0.0, 1.0].
    entropy_score:
        Domain diversity of sources in [0.0, 1.0].  Set by the builder from
        caller input in Phase 1; computed by :class:`VerificationEngine` in Phase 2A.
    tags:
        Domain/topic labels for thematic grouping and batch routing.
    created_at:
        UTC ISO-8601 timestamp ending with ``"Z"``.
    status:
        Lifecycle state — ``UNVERIFIED`` → ``VERIFIED`` or ``REJECTED`` → ``SYNTHESIZED``.
    hash:
        SHA-256 of the canonical JSON of all other fields.  Empty string until
        :meth:`with_hash` is called.

    Examples
    --------
    >>> mb = MemoryBlock(
    ...     id="MB-20260428-AAAA",
    ...     title="Example",
    ...     summary="A verified fact.",
    ...     sources=["https://example.com/a"],
    ...     confidence_score=0.9,
    ...     entropy_score=0.5,
    ...     tags=["legal"],
    ...     created_at="2026-04-28T00:00:00Z",
    ...     status=MemoryStatus.UNVERIFIED,
    ...     hash="",
    ... ).with_hash()
    >>> len(mb.hash)
    64
    """

    id: StrictStr = Field(..., pattern=r"^MB-\d{8}-[A-Z0-9]{4}$")
    title: StrictStr = Field(min_length=1, max_length=200)
    summary: StrictStr = Field(min_length=1, max_length=10_000)

    sources: List[HttpUrl] = Field(default_factory=list, min_length=1)
    confidence_score: StrictFloat = Field(ge=0.0, le=1.0)
    entropy_score: StrictFloat = Field(ge=0.0, le=1.0)

    tags: List[StrictStr] = Field(default_factory=list)
    created_at: StrictStr
    status: MemoryStatus

    # Empty string until with_hash() is called; excluded from its own hash.
    hash: StrictStr = Field(default="")

    @field_validator("created_at")
    @classmethod
    def _validate_iso8601_utc(cls, v: str) -> str:
        if not v.endswith("Z"):
            raise ValueError("created_at must be UTC ISO-8601 ending with 'Z'")
        return v

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def compute_hash(self) -> str:
        """Return SHA-256 of the canonical JSON of all fields except ``hash``.

        The result is a 64-character hex string.  Calling this twice on the
        same model instance returns the same value (deterministic).
        """
        payload = self.model_dump(mode="json")
        payload.pop("hash", None)
        return sha256_hex(_canonical_json(payload))

    def with_hash(self) -> "MemoryBlock":
        """Return a copy of this block with the ``hash`` field populated.

        The original block is not mutated.
        """
        return self.model_copy(update={"hash": self.compute_hash()})

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def now_iso8601_utc() -> str:
        """Return the current UTC time as an ISO-8601 string ending with ``Z``."""
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
