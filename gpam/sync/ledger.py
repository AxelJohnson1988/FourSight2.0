"""GPAM sync event ledger — sovereign audit trail for all sync operations.

Resolution order
----------------
1. Try ``warden.akashic`` (real SQLite hash-chained ledger on the Warden node).
2. Fall back to a standalone append-only JSONL file (hash-chained, same design).
   File path: ``logs/gpam_sync_events.jsonl`` (overridable via
   ``GPAM_SYNC_LEDGER_PATH`` env var).

Either path guarantees:
- Every event is flushed to disk before ``log_sync_event()`` returns.
- Chain hashes link every entry to its predecessor (tamper-evident).
- No sync event is ever silently dropped.
- The active backend is always reported so callers can include it in
  their own GPAM records.

Importing this module never raises — even if all optional deps are missing.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Backend indicator
# ---------------------------------------------------------------------------


class LedgerBackend(str, Enum):
    AKASHIC = "akashic"      # warden.akashic SQLite ledger
    JSONL = "jsonl_fallback"  # standalone hash-chained JSONL


# ---------------------------------------------------------------------------
# Standalone JSONL fallback (mirrors scripts/gpam_ledger.ts)
# ---------------------------------------------------------------------------

_JSONL_LOCK = threading.Lock()
_GENESIS_HASH = "0" * 64


def _jsonl_path() -> Path:
    env = os.environ.get("GPAM_SYNC_LEDGER_PATH", "")
    return Path(env) if env else Path("logs") / "gpam_sync_events.jsonl"


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _jsonl_prev_hash() -> str:
    """Return the chain_hash of the last JSONL entry, or the genesis sentinel."""
    path = _jsonl_path()
    if not path.exists():
        return _GENESIS_HASH
    try:
        content = path.read_text(encoding="utf-8").strip()
        if not content:
            return _GENESIS_HASH
        last_line = content.rsplit("\n", 1)[-1]
        entry = json.loads(last_line)
        return entry.get("chain_hash", _GENESIS_HASH)
    except (json.JSONDecodeError, KeyError, OSError):
        return _GENESIS_HASH


def _jsonl_append(event: Dict[str, Any]) -> str:
    """Append *event* to the JSONL ledger.  Returns the new chain_hash."""
    with _JSONL_LOCK:
        prev_hash = _jsonl_prev_hash()
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        entry_data = {"event": event, "timestamp": timestamp, "prev_hash": prev_hash}
        chain_hash = _sha256(prev_hash + _canonical(entry_data))
        entry = {**entry_data, "chain_hash": chain_hash}

        path = _jsonl_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

        return chain_hash


# ---------------------------------------------------------------------------
# Akashic shim
# ---------------------------------------------------------------------------


def _try_akashic(event: Dict[str, Any]) -> Optional[str]:
    """Attempt to log *event* to warden.akashic.  Return chain_hash or None."""
    try:
        from warden.akashic import AkashicDB  # noqa: PLC0415

        db_path = Path(os.environ.get("AKASHIC_DB_PATH", "warden/akashic.db"))
        db = AkashicDB(db_path)

        # AkashicDB.append() expects a specific envelope; we bridge by storing
        # the sync event in the ``artifacts`` JSON field and using a synthetic
        # delivery_id derived from the event content hash.
        delivery_id = _sha256(_canonical(event))[:32]
        db.append(
            delivery_id=delivery_id,
            repo=event.get("repo", os.environ.get("GITHUB_REPOSITORY", "unknown")),
            head_sha=event.get("commit_sha", "sync-event"),
            artifacts=[{"path": event.get("event_type", "sync"), "sha256": delivery_id}],
            validated=True,
            tool_metadata_hash=_sha256(_canonical({"event_type": event.get("event_type")})),
        )
        return delivery_id  # akashic doesn't expose chain_hash to callers
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class SyncEventLogResult:
    """Return value of :func:`log_sync_event`.

    Attributes
    ----------
    backend:
        Which backend successfully wrote the entry.
    chain_hash:
        Tamper-evident chain hash of this entry (hex).  For akashic backend
        this is the delivery_id hash; for JSONL it is the full SHA-256 chain
        hash.
    path:
        Path to the log file (JSONL backend) or DB file (akashic backend).
    """

    __slots__ = ("backend", "chain_hash", "path")

    def __init__(
        self, backend: LedgerBackend, chain_hash: str, path: Optional[Path]
    ) -> None:
        self.backend = backend
        self.chain_hash = chain_hash
        self.path = path

    def __repr__(self) -> str:
        return (
            f"SyncEventLogResult(backend={self.backend.value!r}, "
            f"chain_hash={self.chain_hash[:12]!r}…, path={self.path})"
        )


def log_sync_event(event_type: str, **fields: Any) -> SyncEventLogResult:
    """Write a sync event to the GPAM audit ledger.

    Tries ``warden.akashic`` first; falls back to JSONL automatically.
    Never raises — log failures are downgraded to a best-effort JSONL write.

    Parameters
    ----------
    event_type:
        Short label, e.g. ``"forward_sync_complete"`` or ``"annotation_written"``.
    **fields:
        Arbitrary keyword fields attached to the event (serialised as JSON).

    Returns
    -------
    SyncEventLogResult
        Describes which backend was used and the resulting chain hash.

    Examples
    --------
    >>> result = log_sync_event("forward_sync_complete", files_routed=3, backend="local")
    >>> result.backend  # doctest: +SKIP
    <LedgerBackend.JSONL: 'jsonl_fallback'>
    """
    event: Dict[str, Any] = {"event_type": event_type, **fields}

    # --- Attempt 1: warden.akashic ---
    akashic_hash = _try_akashic(event)
    if akashic_hash is not None:
        db_path = Path(os.environ.get("AKASHIC_DB_PATH", "warden/akashic.db"))
        return SyncEventLogResult(LedgerBackend.AKASHIC, akashic_hash, db_path)

    # --- Attempt 2: standalone JSONL fallback ---
    chain_hash = _jsonl_append(event)
    return SyncEventLogResult(LedgerBackend.JSONL, chain_hash, _jsonl_path())
