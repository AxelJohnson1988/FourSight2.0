"""SQLite-backed checkpoint / session management for resumable crawls (Phase 4).

:class:`CheckpointDB` replaces the plain text checkpoint file with a proper
SQLite database that tracks per-directory scan progress at three granular
states: ``pending``, ``done``, and ``failed``.

Schema
------
.. code-block:: sql

    CREATE TABLE scan_state (
        path_id   INTEGER PRIMARY KEY AUTOINCREMENT,
        directory TEXT    UNIQUE NOT NULL,
        status    TEXT    CHECK(status IN ('pending', 'done', 'failed'))
                          DEFAULT 'pending',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        error_log TEXT
    );

Example
-------
::

    from pathlib import Path
    from phoenix_scanner.checkpoint import CheckpointDB

    with CheckpointDB(Path("scan.db")) as db:
        if not db.is_done("/mnt/vault/subdir"):
            # … scan the directory …
            db.mark_done("/mnt/vault/subdir")
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_state (
    path_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    directory TEXT    UNIQUE NOT NULL,
    status    TEXT    CHECK(status IN ('pending', 'done', 'failed')) DEFAULT 'pending',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    error_log TEXT
);
"""


class CheckpointDB:
    """Manages per-directory scan progress in a SQLite database.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  Created automatically if absent.
    """

    def __init__(self, db_path: Path) -> None:
        self._path = db_path
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def mark_pending(self, directory: str) -> None:
        """Insert or reset *directory* to ``'pending'``."""
        self._conn.execute(
            """
            INSERT INTO scan_state (directory, status)
            VALUES (?, 'pending')
            ON CONFLICT(directory) DO UPDATE
                SET status    = 'pending',
                    timestamp = CURRENT_TIMESTAMP,
                    error_log = NULL
            """,
            (directory,),
        )
        self._conn.commit()

    def mark_done(self, directory: str) -> None:
        """Record *directory* as successfully scanned."""
        self._conn.execute(
            """
            INSERT INTO scan_state (directory, status)
            VALUES (?, 'done')
            ON CONFLICT(directory) DO UPDATE
                SET status    = 'done',
                    timestamp = CURRENT_TIMESTAMP,
                    error_log = NULL
            """,
            (directory,),
        )
        self._conn.commit()

    def mark_failed(self, directory: str, error: str = "") -> None:
        """Record *directory* as failed, storing the *error* message."""
        self._conn.execute(
            """
            INSERT INTO scan_state (directory, status, error_log)
            VALUES (?, 'failed', ?)
            ON CONFLICT(directory) DO UPDATE
                SET status    = 'failed',
                    timestamp = CURRENT_TIMESTAMP,
                    error_log = excluded.error_log
            """,
            (directory, error),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Query operations
    # ------------------------------------------------------------------

    def is_done(self, directory: str) -> bool:
        """Return ``True`` if *directory* has status ``'done'``."""
        row = self._conn.execute(
            "SELECT status FROM scan_state WHERE directory = ?", (directory,)
        ).fetchone()
        return row is not None and row[0] == "done"

    def done_dirs(self) -> set[str]:
        """Return the set of all directories with status ``'done'``."""
        rows = self._conn.execute(
            "SELECT directory FROM scan_state WHERE status = 'done'"
        ).fetchall()
        return {row[0] for row in rows}

    def pending_dirs(self) -> list[str]:
        """Return directories with status ``'pending'``, oldest first."""
        rows = self._conn.execute(
            "SELECT directory FROM scan_state"
            " WHERE status = 'pending' ORDER BY timestamp"
        ).fetchall()
        return [row[0] for row in rows]

    def failed_dirs(self) -> list[tuple[str, str | None]]:
        """Return ``(directory, error_log)`` pairs for all failed directories."""
        rows = self._conn.execute(
            "SELECT directory, error_log FROM scan_state WHERE status = 'failed'"
        ).fetchall()
        return list(rows)

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

    def __enter__(self) -> "CheckpointDB":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
