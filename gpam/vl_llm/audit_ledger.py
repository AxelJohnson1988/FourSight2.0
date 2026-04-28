"""Provenance & Audit Ledger (PAL) — hash-chained append-only log (§3.6, Step F).

Invariants enforced here
-------------------------
I1  — Decision record written to PAL before claim is labelled ACCEPTED.
I5  — If PAL is unavailable, system degrades to DRAFT-only mode.
I6  — All state transitions hashed over canonical JSON (§1.3).

PAL is a thin bridge over the existing GPAM sync ledger
(``gpam.sync.ledger.log_sync_event``).  If that ledger is unavailable
(import failure, disk full, …), PAL falls back to an in-memory JSONL
buffer with a ``degraded=True`` flag — outputs may then only be labelled
DRAFT (Invariant I5).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Literal, Optional

from gpam.vl_llm.types import canonical_json, sha256_cj


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Event types (§3.6)
# ---------------------------------------------------------------------------

PalEventType = Literal[
    "CLAIM_EXTRACTED",
    "EVIDENCE_ADDED",
    "COMMIT_DECISION",
    "CLOSURE_APPLIED",
    "CONTRADICTION_FOUND",
]

# ---------------------------------------------------------------------------
# Record / Result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PalRecord:
    """A single PAL entry (§3.6).

    Attributes
    ----------
    timestamp_utc:
        UTC ISO-8601 ending with ``Z``.
    event_type:
        One of the five canonical event types.
    payload_cj:
        Canonical JSON payload dict.
    payload_hash:
        sha256(CJ(payload_cj)).
    prev_hash:
        Chain hash of the preceding entry.  Empty string for the genesis entry.
    """

    timestamp_utc: str
    event_type: str
    payload_cj: dict
    payload_hash: str
    prev_hash: str = ""


@dataclass(frozen=True)
class PalAppendResult:
    """Return value of :meth:`AuditLedger.append`.

    Attributes
    ----------
    ok:
        ``True`` on success.
    record_hash:
        Hash of the appended record (chain hash from the underlying ledger).
    error:
        Non-empty only when ``ok=False``.
    degraded:
        ``True`` when the underlying GPAM ledger was unavailable and the
        record was written to the in-memory fallback only (Invariant I5).
    """

    ok: bool
    record_hash: str
    error: str = ""
    degraded: bool = False


# ---------------------------------------------------------------------------
# AuditLedger
# ---------------------------------------------------------------------------


class AuditLedger:
    """PAL implementation: bridges to ``gpam.sync.ledger`` (§3.6).

    Invariant I5 — Fail-Closed on Missing Gate
        If the underlying GPAM ledger is unavailable, ``append()`` succeeds
        but sets ``degraded=True``.  The pipeline checks this flag and
        downgrades all outputs to ``DRAFT``.

    Parameters
    ----------
    gpam_ledger_path:
        Override the GPAM JSONL ledger path (for testing).
        Passed as the ``GPAM_SYNC_LEDGER_PATH`` env var context.

    Examples
    --------
    >>> ledger = AuditLedger()
    >>> result = ledger.append("CLAIM_EXTRACTED", {"claim_id": "abc", "text": "..."})
    >>> result.ok
    True
    """

    def __init__(self, gpam_ledger_path: Optional[str] = None) -> None:
        self._path_override = gpam_ledger_path
        self._fallback: List[dict] = []  # in-memory buffer when GPAM unavailable
        self._degraded = False

    @property
    def degraded(self) -> bool:
        """``True`` if the underlying ledger is unavailable (I5)."""
        return self._degraded

    def append(
        self, event_type: PalEventType, payload: dict
    ) -> PalAppendResult:
        """Append a hash-chained record to the PAL (§3.6, Invariant I1/I6).

        Parameters
        ----------
        event_type:
            One of the five canonical event types.
        payload:
            Arbitrary event data.  Will be serialised to canonical JSON.

        Returns
        -------
        PalAppendResult
        """
        ts = _now_utc()
        payload_hash = sha256_cj(payload)

        record = {
            "timestamp_utc": ts,
            "event_type": event_type,
            "payload_cj": payload,
            "payload_hash": payload_hash,
        }

        # --- Attempt: GPAM sync ledger ---
        try:
            chain_hash = self._write_to_gpam(event_type, record)
            self._degraded = False
            return PalAppendResult(ok=True, record_hash=chain_hash, degraded=False)
        except Exception as exc:  # noqa: BLE001
            # --- Fallback: in-memory buffer (Invariant I5) ---
            self._degraded = True
            self._fallback.append(record)
            return PalAppendResult(
                ok=True,
                record_hash=payload_hash,
                error=f"GPAM unavailable — in-memory fallback: {exc}",
                degraded=True,
            )

    def fallback_records(self) -> List[dict]:
        """Return in-memory fallback records (non-empty only when degraded)."""
        return list(self._fallback)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_to_gpam(self, event_type: str, record: dict) -> str:
        """Write *record* to the GPAM sync ledger.  Returns chain_hash."""
        ctx: dict = {}
        if self._path_override:
            ctx["GPAM_SYNC_LEDGER_PATH"] = self._path_override

        if ctx:
            import os as _os

            old = {k: _os.environ.get(k) for k in ctx}
            _os.environ.update(ctx)

        try:
            from gpam.sync.ledger import log_sync_event  # noqa: PLC0415

            # Pass only extra metadata; event_type is the positional arg.
            kwargs = {k: v for k, v in record.items() if k != "event_type"}
            result = log_sync_event(event_type, **kwargs)
            return result.chain_hash
        finally:
            if ctx:
                import os as _os

                for k, v in old.items():
                    if v is None:
                        _os.environ.pop(k, None)
                    else:
                        _os.environ[k] = v
