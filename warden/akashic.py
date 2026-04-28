"""Akashic audit log — SQLite-backed, append-only, hash-chained.

Schema
------
akashic_log
    id                  AUTOINCREMENT primary key
    delivery_id         GitHub X-GitHub-Delivery header (unique)
    repo                full repo name  (owner/repo)
    head_sha            commit SHA that triggered the event
    timestamp           ISO-8601 UTC
    artifacts           JSON array of {"path": str, "sha256": str}
    validated           0 / 1
    tool_metadata_hash  sha256 of canonical public metadata (no secrets)
    chain_hash          sha256(prev_chain_hash || canonical_row) — tamper-evident

processed_deliveries
    delivery_id         TEXT PRIMARY KEY — idempotency store
    processed_at        ISO-8601 UTC

Design decisions
----------------
* ``tool_metadata_hash`` covers repo, head_sha, and artifacts only — no secrets.
* ``chain_hash`` links each row to its predecessor so any row deletion is
  detectable by recomputing the chain.
* The module has zero network dependencies; all I/O goes through the caller.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS akashic_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id         TEXT    NOT NULL,
    repo                TEXT    NOT NULL,
    head_sha            TEXT    NOT NULL,
    timestamp           TEXT    NOT NULL,
    artifacts           TEXT    NOT NULL,
    validated           INTEGER NOT NULL CHECK(validated IN (0, 1)),
    tool_metadata_hash  TEXT    NOT NULL,
    chain_hash          TEXT    NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_delivery_log
    ON akashic_log(delivery_id);

CREATE TABLE IF NOT EXISTS processed_deliveries (
    delivery_id  TEXT PRIMARY KEY,
    processed_at TEXT NOT NULL
);
"""

_GENESIS_HASH = "0" * 64  # sentinel for the very first chain link


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    """Stable, compact JSON bytes — deterministic across Python versions."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def compute_tool_metadata_hash(repo: str, head_sha: str, artifacts: list[dict]) -> str:
    """Return sha256 of canonical ``{repo, head_sha, artifacts}`` — no secrets.

    Parameters
    ----------
    repo:
        Full GitHub repository name, e.g. ``"AxelJohnson1988/phoenix-anchor"``.
    head_sha:
        The commit SHA that was pushed.
    artifacts:
        List of ``{"path": str, "sha256": str}`` dicts for allowlisted files.

    Returns
    -------
    str
        64-character hex digest.
    """
    payload = {"repo": repo, "head_sha": head_sha, "artifacts": artifacts}
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _compute_chain_hash(prev_hash: str, row_data: dict) -> str:
    """Hash-chain link: sha256(prev_chain_hash + canonical_row)."""
    payload = {"prev": prev_hash, "row": row_data}
    return hashlib.sha256(_canonical(payload)).hexdigest()


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------


class AkashicDB:
    """SQLite-backed Akashic audit log with idempotency guard.

    Parameters
    ----------
    db_path:
        Filesystem path for the SQLite database.  Defaults to
        ``akashic_audit.db`` in the current working directory.

    Examples
    --------
    >>> db = AkashicDB(":memory:")
    >>> db.is_processed("abc")
    False
    """

    def __init__(self, db_path: Path | str = "akashic_audit.db") -> None:
        self._db_path = str(db_path)
        self._init_db()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # Idempotency
    # ------------------------------------------------------------------

    def is_processed(self, delivery_id: str) -> bool:
        """Return *True* if *delivery_id* was already processed."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM processed_deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
        return row is not None

    def mark_processed(self, delivery_id: str) -> None:
        """Record *delivery_id* as processed (idempotent — INSERT OR IGNORE)."""
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO processed_deliveries(delivery_id, processed_at)"
                " VALUES (?,?)",
                (delivery_id, ts),
            )

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def append(
        self,
        *,
        delivery_id: str,
        repo: str,
        head_sha: str,
        artifacts: list[dict],
        validated: bool,
    ) -> dict:
        """Append one event to the audit log and return the complete record.

        Parameters
        ----------
        delivery_id:
            GitHub ``X-GitHub-Delivery`` header value.
        repo:
            Full repository name.
        head_sha:
            Commit SHA at which artifacts were fetched.
        artifacts:
            List of ``{"path": str, "sha256": str}`` for allowlisted files.
        validated:
            ``True`` if at least one allowlisted path was changed; ``False``
            for a ``deny`` event.

        Returns
        -------
        dict
            The complete audit record including ``tool_metadata_hash`` and
            ``chain_hash``.  Contains **no secrets**.
        """
        tool_metadata_hash = compute_tool_metadata_hash(repo, head_sha, artifacts)
        ts = datetime.now(timezone.utc).isoformat()

        row_data: dict = {
            "delivery_id": delivery_id,
            "repo": repo,
            "head_sha": head_sha,
            "timestamp": ts,
            "artifacts": artifacts,
            "validated": validated,
            "tool_metadata_hash": tool_metadata_hash,
        }

        with self._connect() as conn:
            prev = conn.execute(
                "SELECT chain_hash FROM akashic_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = prev["chain_hash"] if prev else _GENESIS_HASH
            chain_hash = _compute_chain_hash(prev_hash, row_data)

            conn.execute(
                """
                INSERT INTO akashic_log
                    (delivery_id, repo, head_sha, timestamp, artifacts,
                     validated, tool_metadata_hash, chain_hash)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    delivery_id,
                    repo,
                    head_sha,
                    ts,
                    json.dumps(artifacts, separators=(",", ":")),
                    1 if validated else 0,
                    tool_metadata_hash,
                    chain_hash,
                ),
            )

        return {**row_data, "chain_hash": chain_hash}

    def get_log(self) -> list[dict]:
        """Return all audit records as a list of dicts (oldest first)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM akashic_log ORDER BY id ASC"
            ).fetchall()
        result = []
        for row in rows:
            entry = dict(row)
            entry["artifacts"] = json.loads(entry["artifacts"])
            entry["validated"] = bool(entry["validated"])
            result.append(entry)
        return result

    def verify_chain(self) -> bool:
        """Recompute every chain hash and return *True* if all match.

        A mismatch means at least one row was tampered with or deleted.
        """
        # Fields excluded from the hash: the auto-assigned id (unknown at insert
        # time) and chain_hash itself (it *is* the hash we're verifying).
        _EXCLUDE = {"id", "chain_hash"}
        records = self.get_log()
        prev_hash = _GENESIS_HASH
        for record in records:
            row_data = {k: record[k] for k in record if k not in _EXCLUDE}
            expected = _compute_chain_hash(prev_hash, row_data)
            if expected != record["chain_hash"]:
                return False
            prev_hash = record["chain_hash"]
        return True
