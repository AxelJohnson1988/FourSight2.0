"""Tests for the E.A.E. Integrity Warden."""

from __future__ import annotations

import pytest

from eae.warden import IntegrityWarden, WardenResult


class TestIntegrityWarden:
    def setup_method(self) -> None:
        self.warden = IntegrityWarden()

    # ------------------------------------------------------------------
    # Clean text
    # ------------------------------------------------------------------
    def test_clean_text_passes_through(self) -> None:
        result = self.warden.scan("Manifest your points and open the valve.")
        assert result.is_clean
        assert not result.was_modified

    # ------------------------------------------------------------------
    # Sovereign substitutions
    # ------------------------------------------------------------------
    def test_apply_for_replaced(self) -> None:
        result = self.warden.scan("Apply for credit to get started.")
        assert result.was_modified
        assert "manifest" in result.cleansed.lower()
        assert "apply for" not in result.cleansed.lower()

    def test_submit_form_replaced(self) -> None:
        result = self.warden.scan("Please submit a form to proceed.")
        assert result.was_modified
        assert "commit logic" in result.cleansed.lower()

    def test_request_withdrawal_replaced(self) -> None:
        result = self.warden.scan("Request withdrawal of funds.")
        assert result.was_modified
        assert "open valve" in result.cleansed.lower()

    def test_approval_replaced(self) -> None:
        result = self.warden.scan("Waiting for approval.")
        assert result.was_modified
        assert "threshold confirmation" in result.cleansed.lower()

    def test_account_balance_replaced(self) -> None:
        result = self.warden.scan("Check your account balance here.")
        assert result.was_modified
        assert "vault level" in result.cleansed.lower()

    def test_withdrawal_replaced(self) -> None:
        result = self.warden.scan("Your withdrawal has been processed.")
        assert result.was_modified
        assert "extraction" in result.cleansed.lower()

    def test_case_insensitive(self) -> None:
        result = self.warden.scan("APPLY FOR a loan NOW.")
        assert result.was_modified

    # ------------------------------------------------------------------
    # Purge triggers
    # ------------------------------------------------------------------
    def test_ssn_triggers_purge(self) -> None:
        result = self.warden.scan("Enter your SSN to continue.")
        assert result.purge_required
        assert not result.is_clean

    def test_credit_score_triggers_purge(self) -> None:
        result = self.warden.scan("We need your credit score.")
        assert result.purge_required

    def test_bank_account_triggers_purge(self) -> None:
        result = self.warden.scan("Link your bank account here.")
        assert result.purge_required

    # ------------------------------------------------------------------
    # enforce() helper
    # ------------------------------------------------------------------
    def test_enforce_returns_cleansed(self) -> None:
        clean = self.warden.enforce("Submit a form and get approval.")
        assert "commit logic" in clean.lower()

    def test_enforce_raises_on_purge_trigger(self) -> None:
        with pytest.raises(ValueError, match=r"\[WARDEN\]"):
            self.warden.enforce("Enter your SSN to proceed.")

    # ------------------------------------------------------------------
    # WardenResult properties
    # ------------------------------------------------------------------
    def test_result_was_modified_false_when_no_change(self) -> None:
        result = self.warden.scan("Open the valve.")
        assert not result.was_modified

    def test_result_flags_populated(self) -> None:
        result = self.warden.scan("Apply for credit.")
        assert len(result.flags) > 0
