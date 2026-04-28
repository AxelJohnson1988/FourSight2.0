"""Tamper-evident Akashic Ledger backed by SQLite.

Each ledger entry contains:

.. code-block:: json

    {
        "timestamp":           "2025-01-01T00:00:00Z",
        "input_hash":          "<sha256 of raw input>",
        "output_hash":         "<sha256 of processed output>",
        "semantic_score":      0.87,
        "warden_signature":    "<optional caller-supplied signature>",
        "previous_entry_hash": "<sha256 of previous entry dict>",
        "entry_hash":          "<sha256 of this entry dict>"
    }

The ``previous_entry_hash`` field links every entry to its predecessor,
forming a hash chain.  Any retroactive modification to a stored entry breaks
the chain and is detected by :meth:`AkashicLedger.verify_chain`.

Usage::

    from warden.akashic import AkashicLedger

    ledger = AkashicLedger("akashic.db")
    entry = ledger.append(
        input_hash="abc...",
        output_hash="def...",
        semantic_score=0.98,
    )
    assert ledger.verify_chain()
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time

_GENESIS = "0" * 64  # sentinel previous-entry hash for the very first entry


class AkashicLedger:
    """SQLite-backed hash-chained ledger.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  Pass ``":memory:"`` for an
        in-process, test-only ledger that is discarded on close.
    """

    def __init__(self, db_path: str = "akashic.db") -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ledger (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp           TEXT    NOT NULL,
                input_hash          TEXT    NOT NULL,
                output_hash         TEXT    NOT NULL,
                semantic_score      REAL    NOT NULL,
                warden_signature    TEXT    NOT NULL,
                previous_entry_hash TEXT    NOT NULL,
                entry_hash          TEXT    NOT NULL UNIQUE
            )
            """
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(
        self,
        *,
        input_hash: str,
        output_hash: str,
        semantic_score: float,
        warden_signature: str = "",
    ) -> dict:
        """Append a new entry to the ledger.

        Returns the entry as a ``dict`` including the computed
        ``entry_hash`` and ``previous_entry_hash``.
        """
        previous_entry_hash = self._latest_entry_hash()
        timestamp = _utc_iso()

        # Build the content dict first (without entry_hash)
        entry_content = {
            "timestamp": timestamp,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "semantic_score": semantic_score,
            "warden_signature": warden_signature,
            "previous_entry_hash": previous_entry_hash,
        }
        entry_hash = _hash_dict(entry_content)

        self._conn.execute(
            """
            INSERT INTO ledger
              (timestamp, input_hash, output_hash, semantic_score,
               warden_signature, previous_entry_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                input_hash,
                output_hash,
                semantic_score,
                warden_signature,
                previous_entry_hash,
                entry_hash,
            ),
        )
        self._conn.commit()

        return {**entry_content, "entry_hash": entry_hash}

    def verify_chain(self) -> bool:
        """Return ``True`` if the entire hash chain is intact.

        Iterates every row in insertion order and checks that:

        1. The stored ``previous_entry_hash`` matches the *actual* hash of the
           preceding entry.
        2. The stored ``entry_hash`` matches the SHA-256 of the row's content.
        """
        rows = self._conn.execute(
            "SELECT timestamp, input_hash, output_hash, semantic_score, "
            "warden_signature, previous_entry_hash, entry_hash "
            "FROM ledger ORDER BY id"
        ).fetchall()

        prev_hash = _GENESIS
        for row in rows:
            (
                timestamp,
                input_hash,
                output_hash,
                semantic_score,
                warden_signature,
                previous_entry_hash,
                entry_hash,
            ) = row

            if previous_entry_hash != prev_hash:
                return False

            expected = _hash_dict(
                {
                    "timestamp": timestamp,
                    "input_hash": input_hash,
                    "output_hash": output_hash,
                    "semantic_score": semantic_score,
                    "warden_signature": warden_signature,
                    "previous_entry_hash": previous_entry_hash,
                }
            )
            if expected != entry_hash:
                return False

            prev_hash = entry_hash

        return True

    def entries(self) -> list[dict]:
        """Return all ledger entries in insertion order."""
        rows = self._conn.execute(
            "SELECT timestamp, input_hash, output_hash, semantic_score, "
            "warden_signature, previous_entry_hash, entry_hash "
            "FROM ledger ORDER BY id"
        ).fetchall()
        keys = [
            "timestamp",
            "input_hash",
            "output_hash",
            "semantic_score",
            "warden_signature",
            "previous_entry_hash",
            "entry_hash",
        ]
        return [dict(zip(keys, row)) for row in rows]

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

    def __enter__(self) -> "AkashicLedger":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _latest_entry_hash(self) -> str:
        """Return the ``entry_hash`` of the most-recently inserted row."""
        row = self._conn.execute(
            "SELECT entry_hash FROM ledger ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else _GENESIS


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _utc_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _hash_dict(d: dict) -> str:
    """Return the hex SHA-256 digest of *d* serialised with sorted keys.

    Sorting keys guarantees a stable serialisation regardless of insertion
    order, which is essential for reproducible hash-chain verification.
    """
    serialised = json.dumps(d, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialised.encode()).hexdigest()
