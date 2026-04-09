"""
E.A.E. Effort Tracker — The Flow Meter
=======================================
Monitors two sovereign data-streams:
  1. GitHub commits  (GPAM log proxy via the GitHub REST API)
  2. Focus sessions  (local start/stop timer — no third-party surveillance)

"If Shard 2.1 code is committed + SHA-256 verified = Points Manifested."
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests  # type: ignore
    _REQUESTS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _REQUESTS_AVAILABLE = False

from eae.config import DATA_DIR, POINT_VALUES, SESSION_FILE
from eae.vault import VaultState


# ---------------------------------------------------------------------------
# Focus Session
# ---------------------------------------------------------------------------
@dataclass
class FocusSession:
    start_ts: float = field(default_factory=time.time)
    end_ts: Optional[float] = None
    label: str = "Deep Work"

    @property
    def elapsed_minutes(self) -> float:
        end = self.end_ts if self.end_ts is not None else time.time()
        return (end - self.start_ts) / 60.0

    @property
    def is_active(self) -> bool:
        return self.end_ts is None

    def stop(self) -> float:
        """Stop the session and return elapsed minutes."""
        self.end_ts = time.time()
        return self.elapsed_minutes

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    @classmethod
    def load(cls) -> Optional["FocusSession"]:
        """Return the active session from disk, or None."""
        if not SESSION_FILE.exists():
            return None
        try:
            data = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
            session = cls(**data)
            return session if session.is_active else None
        except (json.JSONDecodeError, TypeError):
            return None

    def save(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        SESSION_FILE.write_text(
            json.dumps(self.__dict__, indent=2), encoding="utf-8"
        )

    def clear(self) -> None:
        if SESSION_FILE.exists():
            SESSION_FILE.unlink()


# ---------------------------------------------------------------------------
# GitHub Commit Tracker
# ---------------------------------------------------------------------------
class CommitTracker:
    """
    Pulls recent commits from a GitHub repo via the public REST API and
    manifests points into the vault for any new (unseen) commits.
    """

    SEEN_COMMITS_FILE: Path = DATA_DIR / "seen_commits.json"

    def __init__(self, owner: str, repo: str, token: Optional[str] = None):
        self.owner = owner
        self.repo = repo
        self.token = token
        self._seen: set[str] = self._load_seen()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load_seen(self) -> set[str]:
        if self.SEEN_COMMITS_FILE.exists():
            try:
                return set(json.loads(self.SEEN_COMMITS_FILE.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, ValueError):
                pass
        return set()

    def _save_seen(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.SEEN_COMMITS_FILE.write_text(
            json.dumps(list(self._seen), indent=2), encoding="utf-8"
        )

    def _api_headers(self) -> dict:
        headers: dict = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def fetch_new_commits(self) -> list[dict]:
        """
        Fetch commits from GitHub and return only those not yet seen.
        Returns an empty list if *requests* is unavailable or the API call fails.
        """
        if not _REQUESTS_AVAILABLE:
            return []
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/commits"
        try:
            resp = requests.get(url, headers=self._api_headers(), timeout=10)
            resp.raise_for_status()
            commits = resp.json()
        except Exception:
            return []

        new_commits = [c for c in commits if c.get("sha") not in self._seen]
        return new_commits

    def manifest_commit_points(self, vault: VaultState) -> int:
        """
        Fetch new commits, award points, and return the total points manifested.
        """
        new_commits = self.fetch_new_commits()
        total = 0
        for commit in new_commits:
            sha: str = commit.get("sha", "")
            # A commit is "verified" when GitHub reports GPG signature verification
            verified: bool = (
                commit.get("commit", {})
                .get("verification", {})
                .get("verified", False)
            )
            points = POINT_VALUES.for_commit(verified=verified)
            source = f"github:{self.owner}/{self.repo}@{sha[:7]}"
            vault.manifest_points(points, source=source)
            self._seen.add(sha)
            total += points

        if new_commits:
            self._save_seen()
        return total


# ---------------------------------------------------------------------------
# Effort Tracker (orchestrator)
# ---------------------------------------------------------------------------
class EffortTracker:
    """
    High-level interface used by the dashboard.
    Combines focus-session management and commit monitoring.
    """

    def __init__(
        self,
        vault: VaultState,
        github_owner: Optional[str] = None,
        github_repo: Optional[str] = None,
        github_token: Optional[str] = None,
    ):
        self.vault = vault
        self._commit_tracker: Optional[CommitTracker] = (
            CommitTracker(github_owner, github_repo, token=github_token)
            if github_owner and github_repo
            else None
        )
        self._active_session: Optional[FocusSession] = FocusSession.load()

    # ------------------------------------------------------------------
    # Focus sessions
    # ------------------------------------------------------------------
    def start_focus_session(self, label: str = "Deep Work") -> FocusSession:
        if self._active_session and self._active_session.is_active:
            raise RuntimeError(
                "A focus session is already active. Stop it before starting a new one."
            )
        session = FocusSession(label=label)
        session.save()
        self._active_session = session
        return session

    def stop_focus_session(self) -> Optional[int]:
        """
        Stop the current focus session and manifest points.
        Returns the points manifested, or None if no session was active.
        """
        if not self._active_session or not self._active_session.is_active:
            # Try loading from disk (e.g. if tracker was re-instantiated)
            self._active_session = FocusSession.load()
        if not self._active_session:
            return None

        minutes = self._active_session.stop()
        points = POINT_VALUES.for_focus_session(int(minutes))
        source = f"focus:{self._active_session.label}:{int(minutes)}min"
        if points > 0:
            self.vault.manifest_points(points, source=source)
        self._active_session.clear()
        self._active_session = None
        return points

    @property
    def active_session(self) -> Optional[FocusSession]:
        return self._active_session

    # ------------------------------------------------------------------
    # GitHub integration
    # ------------------------------------------------------------------
    def sync_commits(self) -> int:
        """Sync new commits and return points manifested. 0 if not configured."""
        if self._commit_tracker is None:
            return 0
        return self._commit_tracker.manifest_commit_points(self.vault)

    # ------------------------------------------------------------------
    # Pressure gauge
    # ------------------------------------------------------------------
    def pressure_level(self) -> int:
        """
        Returns a pressure level index 0-4 mapped to PRESSURE_LABELS.
        Based on vault fill ratio.
        """
        from eae.config import PRESSURE_LABELS
        ratio = self.vault.fill_ratio
        # 5 levels: [0.0, 0.2), [0.2, 0.4), [0.4, 0.6), [0.6, 0.8), [0.8, 1.0+]
        index = min(len(PRESSURE_LABELS) - 1, int(ratio * len(PRESSURE_LABELS)))
        return index
