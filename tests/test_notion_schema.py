"""Tests for gpam.sync.notion_schema — idempotent Notion database provisioning."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from gpam.sync.notion_schema import (
    DatabaseProvisionResult,
    ensure_adr_registry,
    ensure_module_tracker,
    lookup_legal_evidence_registry,
    provision_all_databases,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_search(db_id: str | None):
    """Return a patch for _search_databases that returns *db_id*."""
    return patch("gpam.sync.notion_schema._search_databases", return_value=db_id)


def _mock_create(db_id: str, url: str = "https://notion.so/db-url"):
    """Return a patch for _create_database that returns (*db_id*, *url*)."""
    return patch(
        "gpam.sync.notion_schema._create_database", return_value=(db_id, url)
    )


# ---------------------------------------------------------------------------
# DatabaseProvisionResult
# ---------------------------------------------------------------------------


def test_result_is_frozen() -> None:
    r = DatabaseProvisionResult(
        database_id="abc", created=True, name="Test", url="https://notion.so/x"
    )
    with pytest.raises((AttributeError, TypeError)):
        r.database_id = "other"  # type: ignore[misc]


def test_result_error_defaults_none() -> None:
    r = DatabaseProvisionResult(
        database_id="x", created=False, name="X", url=""
    )
    assert r.error is None


# ---------------------------------------------------------------------------
# ensure_adr_registry — error paths (no token / no parent)
# ---------------------------------------------------------------------------


def test_adr_registry_fails_without_token(monkeypatch) -> None:
    monkeypatch.delenv("NOTION_API_KEY", raising=False)
    monkeypatch.delenv("NOTION_PARENT_PAGE_ID", raising=False)
    result = ensure_adr_registry()
    assert result.error is not None
    assert "NOTION_API_KEY" in result.error


def test_adr_registry_fails_without_parent_when_not_existing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTION_API_KEY", "secret")
    monkeypatch.setenv("GPAM_SYNC_LEDGER_PATH", str(tmp_path / "l.jsonl"))
    monkeypatch.delenv("NOTION_PARENT_PAGE_ID", raising=False)

    with _mock_search(None):  # not found → would need to create
        result = ensure_adr_registry()

    assert result.error is not None
    assert "NOTION_PARENT_PAGE_ID" in result.error


# ---------------------------------------------------------------------------
# ensure_adr_registry — idempotency (already exists)
# ---------------------------------------------------------------------------


def test_adr_registry_idempotent_when_existing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTION_API_KEY", "secret")
    monkeypatch.setenv("GPAM_SYNC_LEDGER_PATH", str(tmp_path / "l.jsonl"))

    with _mock_search("existing-db-id"), _mock_create("should-not-be-called") as create_mock:
        result = ensure_adr_registry()

    create_mock.assert_not_called()
    assert result.database_id == "existing-db-id"
    assert result.created is False


# ---------------------------------------------------------------------------
# ensure_adr_registry — creation path
# ---------------------------------------------------------------------------


def test_adr_registry_creates_when_not_existing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTION_API_KEY", "secret")
    monkeypatch.setenv("NOTION_PARENT_PAGE_ID", "parent-page-id")
    monkeypatch.setenv("GPAM_SYNC_LEDGER_PATH", str(tmp_path / "l.jsonl"))

    with _mock_search(None), _mock_create("new-adr-db-id"):
        result = ensure_adr_registry()

    assert result.database_id == "new-adr-db-id"
    assert result.created is True
    assert result.error is None


def test_adr_registry_creation_failure_returns_error(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTION_API_KEY", "secret")
    monkeypatch.setenv("NOTION_PARENT_PAGE_ID", "parent-page-id")
    monkeypatch.setenv("GPAM_SYNC_LEDGER_PATH", str(tmp_path / "l.jsonl"))

    with _mock_search(None), patch(
        "gpam.sync.notion_schema._create_database",
        side_effect=ConnectionError("Notion unreachable"),
    ):
        result = ensure_adr_registry()

    assert result.error is not None
    assert "Notion unreachable" in result.error


# ---------------------------------------------------------------------------
# ensure_module_tracker — same patterns
# ---------------------------------------------------------------------------


def test_module_tracker_fails_without_token(monkeypatch) -> None:
    monkeypatch.delenv("NOTION_API_KEY", raising=False)
    result = ensure_module_tracker()
    assert result.error is not None


def test_module_tracker_idempotent_when_existing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTION_API_KEY", "secret")
    monkeypatch.setenv("GPAM_SYNC_LEDGER_PATH", str(tmp_path / "l.jsonl"))

    with _mock_search("mt-existing-id"), _mock_create("x") as create_mock:
        result = ensure_module_tracker()

    create_mock.assert_not_called()
    assert result.database_id == "mt-existing-id"
    assert result.created is False


def test_module_tracker_creates_when_not_existing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTION_API_KEY", "secret")
    monkeypatch.setenv("NOTION_PARENT_PAGE_ID", "parent-page-id")
    monkeypatch.setenv("GPAM_SYNC_LEDGER_PATH", str(tmp_path / "l.jsonl"))

    with _mock_search(None), _mock_create("new-mt-db-id"):
        result = ensure_module_tracker()

    assert result.database_id == "new-mt-db-id"
    assert result.created is True


# ---------------------------------------------------------------------------
# lookup_legal_evidence_registry
# ---------------------------------------------------------------------------


def test_legal_lookup_fails_without_token(monkeypatch) -> None:
    monkeypatch.delenv("NOTION_API_KEY", raising=False)
    result = lookup_legal_evidence_registry()
    assert result.error is not None
    assert "NOTION_API_KEY" in result.error


def test_legal_lookup_finds_existing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTION_API_KEY", "secret")
    monkeypatch.setenv("GPAM_SYNC_LEDGER_PATH", str(tmp_path / "l.jsonl"))

    with _mock_search("legal-db-id"):
        result = lookup_legal_evidence_registry()

    assert result.database_id == "legal-db-id"
    assert result.created is False
    assert result.error is None


def test_legal_lookup_returns_error_when_not_found(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTION_API_KEY", "secret")
    monkeypatch.setenv("GPAM_SYNC_LEDGER_PATH", str(tmp_path / "l.jsonl"))

    with _mock_search(None):
        result = lookup_legal_evidence_registry()

    assert result.error is not None
    assert "NOTION_LEGAL_DB_ID" in result.error


# ---------------------------------------------------------------------------
# provision_all_databases
# ---------------------------------------------------------------------------


def test_provision_all_returns_three_keys(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTION_API_KEY", "secret")
    monkeypatch.setenv("NOTION_PARENT_PAGE_ID", "parent-id")
    monkeypatch.setenv("GPAM_SYNC_LEDGER_PATH", str(tmp_path / "l.jsonl"))

    with _mock_search("found-id"), _mock_create("created-id"):
        results = provision_all_databases()

    assert set(results.keys()) == {"adr", "module_tracker", "legal"}


def test_provision_all_adr_idempotent_when_existing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NOTION_API_KEY", "secret")
    monkeypatch.setenv("NOTION_PARENT_PAGE_ID", "parent-id")
    monkeypatch.setenv("GPAM_SYNC_LEDGER_PATH", str(tmp_path / "l.jsonl"))

    with _mock_search("adr-existing"):
        results = provision_all_databases()

    assert results["adr"].database_id == "adr-existing"
    assert results["adr"].created is False


def test_provision_all_partial_failure_does_not_raise(monkeypatch, tmp_path) -> None:
    """If one database fails, the others should still succeed."""
    monkeypatch.setenv("NOTION_API_KEY", "secret")
    monkeypatch.setenv("NOTION_PARENT_PAGE_ID", "parent-id")
    monkeypatch.setenv("GPAM_SYNC_LEDGER_PATH", str(tmp_path / "l.jsonl"))

    def selective_search(token, name):
        # ADR: not found; others: found
        return None if name == "ADR Registry" else "found-id"

    with (
        patch("gpam.sync.notion_schema._search_databases", side_effect=selective_search),
        patch(
            "gpam.sync.notion_schema._create_database",
            side_effect=RuntimeError("API rate limit"),
        ),
    ):
        results = provision_all_databases()

    # ADR failed (creation raised)
    assert results["adr"].error is not None
    # Legal succeeded (found)
    assert results["legal"].database_id == "found-id"
