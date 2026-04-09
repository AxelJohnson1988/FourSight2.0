"""Tests for the E.A.E. config module."""

from __future__ import annotations

from eae.config import POINT_VALUES, PRESSURE_LABELS, PointValues


class TestPointValues:
    def test_for_focus_session_under_30(self) -> None:
        assert POINT_VALUES.for_focus_session(20) == 0

    def test_for_focus_session_30min(self) -> None:
        assert POINT_VALUES.for_focus_session(30) == POINT_VALUES.focus_session_30min

    def test_for_focus_session_60min(self) -> None:
        assert POINT_VALUES.for_focus_session(60) == POINT_VALUES.focus_session_60min

    def test_for_focus_session_90min(self) -> None:
        assert POINT_VALUES.for_focus_session(90) == POINT_VALUES.focus_session_90min

    def test_for_focus_session_over_90(self) -> None:
        assert POINT_VALUES.for_focus_session(120) == POINT_VALUES.focus_session_90min

    def test_for_commit_verified(self) -> None:
        assert POINT_VALUES.for_commit(verified=True) == POINT_VALUES.github_commit_verified

    def test_for_commit_unverified(self) -> None:
        assert POINT_VALUES.for_commit(verified=False) == POINT_VALUES.github_commit_unverified

    def test_verified_more_than_unverified(self) -> None:
        assert POINT_VALUES.github_commit_verified > POINT_VALUES.github_commit_unverified


class TestPressureLabels:
    def test_five_labels(self) -> None:
        assert len(PRESSURE_LABELS) == 5

    def test_first_label_dormant(self) -> None:
        assert PRESSURE_LABELS[0] == "DORMANT"

    def test_last_label_pressurized(self) -> None:
        assert PRESSURE_LABELS[-1] == "PRESSURIZED"
