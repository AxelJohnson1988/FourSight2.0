"""Tests for the E.A.E. Effort Tracker."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from eae.config import POINT_VALUES
from eae.tracker import CommitTracker, EffortTracker, FocusSession
from eae.vault import VaultState


# ---------------------------------------------------------------------------
# FocusSession tests
# ---------------------------------------------------------------------------
class TestFocusSession:
    def test_elapsed_minutes_increases(self) -> None:
        session = FocusSession()
        time.sleep(0.05)
        assert session.elapsed_minutes > 0

    def test_stop_returns_minutes(self) -> None:
        session = FocusSession()
        time.sleep(0.05)
        mins = session.stop()
        assert mins > 0
        assert session.is_active is False

    def test_is_active_true_when_not_stopped(self) -> None:
        session = FocusSession()
        assert session.is_active is True

    def test_is_active_false_after_stop(self) -> None:
        session = FocusSession()
        session.stop()
        assert session.is_active is False

    def test_persistence_round_trip(self, tmp_path: Path) -> None:
        session_file = tmp_path / "session.json"
        with patch("eae.tracker.SESSION_FILE", session_file), \
             patch("eae.tracker.DATA_DIR", tmp_path):
            s = FocusSession(label="Testing")
            s.save()
            loaded = FocusSession.load()
        assert loaded is not None
        assert loaded.label == "Testing"

    def test_load_returns_none_when_no_file(self, tmp_path: Path) -> None:
        session_file = tmp_path / "nonexistent.json"
        with patch("eae.tracker.SESSION_FILE", session_file):
            assert FocusSession.load() is None

    def test_load_returns_none_for_completed_session(self, tmp_path: Path) -> None:
        session_file = tmp_path / "session.json"
        with patch("eae.tracker.SESSION_FILE", session_file), \
             patch("eae.tracker.DATA_DIR", tmp_path):
            s = FocusSession()
            s.stop()
            s.save()
            loaded = FocusSession.load()
        assert loaded is None


# ---------------------------------------------------------------------------
# EffortTracker tests
# ---------------------------------------------------------------------------
class TestEffortTracker:
    def _tracker(self) -> EffortTracker:
        return EffortTracker(VaultState())

    def test_start_focus_session(self) -> None:
        vault = VaultState()
        tracker = EffortTracker(vault)
        with patch("eae.tracker.FocusSession.save"):
            session = tracker.start_focus_session(label="Coding")
        assert session.label == "Coding"
        assert tracker.active_session is not None

    def test_start_second_session_raises(self) -> None:
        vault = VaultState()
        tracker = EffortTracker(vault)
        with patch("eae.tracker.FocusSession.save"):
            tracker.start_focus_session(label="First")
            with pytest.raises(RuntimeError, match="already active"):
                tracker.start_focus_session(label="Second")

    def test_stop_session_no_session_returns_none(self) -> None:
        vault = VaultState()
        tracker = EffortTracker(vault)
        with patch("eae.tracker.FocusSession.load", return_value=None):
            result = tracker.stop_focus_session()
        assert result is None

    def test_stop_session_manifests_points_for_30min(self) -> None:
        vault = VaultState()
        tracker = EffortTracker(vault)
        # Simulate a session that ran for 35 minutes
        mock_session = FocusSession(label="30min test")
        mock_session.start_ts = time.time() - 35 * 60  # 35 min ago
        with patch("eae.tracker.FocusSession.save"), \
             patch("eae.tracker.FocusSession.clear"):
            tracker.start_focus_session(label="30min test")
            tracker._active_session = mock_session  # override with mock
            points = tracker.stop_focus_session()
        assert points == POINT_VALUES.focus_session_30min

    def test_stop_session_no_points_under_30min(self) -> None:
        vault = VaultState()
        tracker = EffortTracker(vault)
        mock_session = FocusSession(label="Short")
        mock_session.start_ts = time.time() - 10 * 60  # only 10 min ago
        with patch("eae.tracker.FocusSession.save"), \
             patch("eae.tracker.FocusSession.clear"):
            tracker.start_focus_session(label="Short")
            tracker._active_session = mock_session
            points = tracker.stop_focus_session()
        assert points == 0
        assert vault.points == 0

    def test_pressure_level_dormant_at_start(self) -> None:
        vault = VaultState()
        tracker = EffortTracker(vault)
        assert tracker.pressure_level() == 0  # DORMANT

    def test_pressure_level_pressurized_when_full(self) -> None:
        vault = VaultState()
        vault.manifest_points(vault.monthly_threshold, source="test")
        tracker = EffortTracker(vault)
        assert tracker.pressure_level() == 4  # PRESSURIZED

    def test_sync_commits_returns_zero_without_config(self) -> None:
        vault = VaultState()
        tracker = EffortTracker(vault)
        assert tracker.sync_commits() == 0


# ---------------------------------------------------------------------------
# CommitTracker tests
# ---------------------------------------------------------------------------
class TestCommitTracker:
    def test_fetch_new_commits_returns_empty_on_error(self) -> None:
        tracker = CommitTracker("owner", "repo", token=None)
        with patch("eae.tracker._REQUESTS_AVAILABLE", True), \
             patch("eae.tracker.requests") as mock_req:
            mock_req.get.side_effect = Exception("network error")
            result = tracker.fetch_new_commits()
        assert result == []

    def test_fetch_new_commits_returns_empty_without_requests(self) -> None:
        tracker = CommitTracker("owner", "repo")
        with patch("eae.tracker._REQUESTS_AVAILABLE", False):
            result = tracker.fetch_new_commits()
        assert result == []

    def test_manifest_commit_points_verified(self, tmp_path: Path) -> None:
        vault = VaultState()
        seen_file = tmp_path / "seen_commits.json"
        tracker = CommitTracker("owner", "repo")
        tracker.SEEN_COMMITS_FILE = seen_file

        fake_commits = [
            {
                "sha": "abc123",
                "commit": {"verification": {"verified": True}},
            }
        ]
        with patch.object(tracker, "fetch_new_commits", return_value=fake_commits), \
             patch("eae.tracker.DATA_DIR", tmp_path):
            pts = tracker.manifest_commit_points(vault)

        assert pts == POINT_VALUES.github_commit_verified
        assert vault.points == POINT_VALUES.github_commit_verified

    def test_manifest_commit_points_skips_seen(self, tmp_path: Path) -> None:
        vault = VaultState()
        seen_file = tmp_path / "seen_commits.json"
        tracker = CommitTracker("owner", "repo")
        tracker.SEEN_COMMITS_FILE = seen_file

        # First call
        fake_commits = [{"sha": "abc123", "commit": {"verification": {"verified": False}}}]
        with patch.object(tracker, "fetch_new_commits", return_value=fake_commits), \
             patch("eae.tracker.DATA_DIR", tmp_path):
            tracker.manifest_commit_points(vault)

        # Second call: same commit should be skipped
        with patch.object(tracker, "fetch_new_commits", return_value=[]):
            pts = tracker.manifest_commit_points(vault)

        assert pts == 0  # nothing new
