"""Evidence Store — pluggable artifact storage with SHA-256 hashing (§3.3, Step C).

The filesystem-backed implementation stores artifacts under a configured
root directory.  Each artifact is written once and identified by its content
hash, making the store append-only and idempotent.

No network calls are made.  The store has no Notion/Git dependency — it is
a pure local truth surface.  The pipeline layer handles propagation to PAL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from gpam.vl_llm.types import (
    EvidenceItem,
    artifact_hash_for,
    evidence_id_for,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AddArtifactResult:
    """Outcome of :meth:`EvidenceStore.add_artifact`."""

    evidence_id: str
    artifact_hash: str
    already_existed: bool


# ---------------------------------------------------------------------------
# In-memory evidence store (no disk I/O — safe for tests)
# ---------------------------------------------------------------------------


class InMemoryEvidenceStore:
    """Thread-unsafe in-memory implementation for testing (§3.3).

    All state is lost on garbage collection.  Use :class:`FilesystemEvidenceStore`
    in production.
    """

    def __init__(self) -> None:
        self._items: Dict[str, EvidenceItem] = {}  # evidence_id → EvidenceItem

    def add_artifact(
        self,
        *,
        source_uri: str,
        data: str | bytes,
        retrieved_at: Optional[str] = None,
        extract: Optional[str] = None,
    ) -> AddArtifactResult:
        """Hash *data* and store the resulting :class:`EvidenceItem`.

        Idempotent: adding the same (source_uri, data) pair twice returns the
        same ``evidence_id`` without creating a duplicate.

        Parameters
        ----------
        source_uri:
            URI of the originating document.
        data:
            Raw artifact bytes or UTF-8 text.
        retrieved_at:
            UTC ISO-8601 timestamp.  Defaults to now.
        extract:
            Optional verbatim excerpt (≤ 2 000 chars).

        Returns
        -------
        AddArtifactResult
        """
        a_hash = artifact_hash_for(data)
        e_id = evidence_id_for(source_uri, a_hash)
        ts = retrieved_at or _now_utc()

        already = e_id in self._items
        if not already:
            self._items[e_id] = EvidenceItem(
                evidence_id=e_id,
                source_uri=source_uri,
                artifact_hash=a_hash,
                extract=(extract or "")[:2000],
                retrieved_at=ts,
            )

        return AddArtifactResult(
            evidence_id=e_id, artifact_hash=a_hash, already_existed=already
        )

    def cite(self, evidence_id: str) -> Optional[EvidenceItem]:
        """Return the :class:`EvidenceItem` for *evidence_id*, or ``None``."""
        return self._items.get(evidence_id)

    def list_ids(self) -> List[str]:
        """Return all stored evidence IDs."""
        return list(self._items.keys())

    def __len__(self) -> int:
        return len(self._items)


# ---------------------------------------------------------------------------
# Filesystem-backed evidence store (production)
# ---------------------------------------------------------------------------


class FilesystemEvidenceStore:
    """Filesystem-backed evidence store for production use (§3.3).

    Layout under *root_dir*::

        root_dir/
          artifacts/
            <artifact_hash>.bin      # raw bytes
          index/
            <evidence_id>.json       # EvidenceItem metadata

    The store is append-only: once written, artifacts and index entries
    are never modified.

    Parameters
    ----------
    root_dir:
        Base directory.  Created on first use.
    """

    def __init__(self, root_dir: Path) -> None:
        self._root = root_dir
        self._artifacts = root_dir / "artifacts"
        self._index = root_dir / "index"

    def _ensure_dirs(self) -> None:
        self._artifacts.mkdir(parents=True, exist_ok=True)
        self._index.mkdir(parents=True, exist_ok=True)

    def add_artifact(
        self,
        *,
        source_uri: str,
        data: str | bytes,
        retrieved_at: Optional[str] = None,
        extract: Optional[str] = None,
    ) -> AddArtifactResult:
        """Hash *data* and persist to the filesystem store.

        Idempotent: if the artifact already exists (same hash), the
        existing index entry is returned without modification.
        """
        self._ensure_dirs()

        raw = data.encode("utf-8") if isinstance(data, str) else data
        a_hash = artifact_hash_for(raw)
        e_id = evidence_id_for(source_uri, a_hash)
        ts = retrieved_at or _now_utc()

        index_path = self._index / f"{e_id}.json"
        already = index_path.exists()

        if not already:
            # Write artifact bytes (content-addressed).
            artifact_path = self._artifacts / f"{a_hash}.bin"
            if not artifact_path.exists():
                artifact_path.write_bytes(raw)

            # Write index entry.
            entry = {
                "evidence_id": e_id,
                "source_uri": source_uri,
                "artifact_hash": a_hash,
                "extract": (extract or "")[:2000],
                "retrieved_at": ts,
            }
            index_path.write_text(
                json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8"
            )

        return AddArtifactResult(
            evidence_id=e_id, artifact_hash=a_hash, already_existed=already
        )

    def cite(self, evidence_id: str) -> Optional[EvidenceItem]:
        """Return the :class:`EvidenceItem` for *evidence_id*, or ``None``."""
        index_path = self._index / f"{evidence_id}.json"
        if not index_path.exists():
            return None
        data = json.loads(index_path.read_text(encoding="utf-8"))
        return EvidenceItem(**data)

    def list_ids(self) -> List[str]:
        """Return all stored evidence IDs."""
        self._ensure_dirs()
        return [p.stem for p in self._index.glob("*.json")]

    def __len__(self) -> int:
        self._ensure_dirs()
        return sum(1 for _ in self._index.glob("*.json"))


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
