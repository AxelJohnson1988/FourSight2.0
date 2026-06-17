"""Tests for the E.A.E. Allowance Vault."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

import eae.config as cfg
from eae.vault import VaultState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def fresh_vault(tmp_path: Path) -> VaultState:
    """Return a VaultState backed by a temp directory (no disk side-effects)."""
    with patch("eae.config.VAULT_FILE", tmp_path / "vault.json"), \
         patch("eae.config.DATA_DIR", tmp_path), \
         patch("eae.vault.VAULT_FILE", tmp_path / "vault.json"), \
         patch("eae.vault.DATA_DIR", tmp_path):
        v = VaultState()
    return v


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestVaultState:
    def test_initial_state(self) -> None:
        v = VaultState()
        assert v.points == 0
        assert v.fill_ratio == 0.0
        assert v.valve_open is False
        assert v.usd_equivalent == 0.0

    def test_manifest_points_increments(self) -> None:
        v = VaultState()
        v.manifest_points(50, source="test")
        assert v.points == 50
        assert len(v.manifested_sessions) == 1

    def test_manifest_points_negative_raises(self) -> None:
        v = VaultState()
        with pytest.raises(ValueError, match="sovereignty is additive"):
            v.manifest_points(-10)

    def test_fill_ratio_caps_at_one(self) -> None:
        v = VaultState()
        v.manifest_points(v.monthly_threshold * 2, source="overfill")
        assert v.fill_ratio == 1.0

    def test_valve_opens_at_threshold(self) -> None:
        v = VaultState()
        v.manifest_points(v.monthly_threshold, source="threshold_hit")
        assert v.valve_open is True

    def test_valve_closed_below_threshold(self) -> None:
        v = VaultState()
        v.manifest_points(v.monthly_threshold - 1, source="almost")
        assert v.valve_open is False

    def test_open_valve_resets_points(self) -> None:
        v = VaultState()
        v.manifest_points(v.monthly_threshold, source="full")
        result = v.open_valve()
        assert result == v.allowance_usd
        assert v.points == 0  # reset for next cycle
        assert len(v.extractions) == 1

    def test_open_valve_below_threshold_returns_none(self) -> None:
        v = VaultState()
        v.manifest_points(10, source="partial")
        assert v.open_valve() is None
        assert v.points == 10  # unchanged

    def test_usd_equivalent(self) -> None:
        v = VaultState()
        v.manifest_points(100, source="partial")
        assert v.usd_equivalent == 100.0

    def test_usd_equivalent_capped(self) -> None:
        v = VaultState()
        v.manifest_points(1000, source="huge")
        assert v.usd_equivalent == v.allowance_usd

    def test_reset_clears_points(self) -> None:
        v = VaultState()
        v.manifest_points(50, source="some_work")
        v.reset()
        assert v.points == 0
        assert len(v.manifested_sessions) == 0

    def test_persistence_round_trip(self, tmp_path: Path) -> None:
        vault_file = tmp_path / "vault.json"
        with patch("eae.vault.VAULT_FILE", vault_file), \
             patch("eae.vault.DATA_DIR", tmp_path):
            v = VaultState()
            v.manifest_points(42, source="persist_test")
            v.save()

            v2 = VaultState.load()
        assert v2.points == 42

    def test_persistence_corrupt_file_returns_fresh(self, tmp_path: Path) -> None:
        vault_file = tmp_path / "vault.json"
        vault_file.write_text("NOT_JSON", encoding="utf-8")
        with patch("eae.vault.VAULT_FILE", vault_file):
            v = VaultState.load()
        assert v.points == 0
