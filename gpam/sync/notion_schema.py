"""Notion database schema creation — ADR Registry and Module Tracker.

Context (from confirmed answers)
---------------------------------
- Legal Evidence Registry: **already exists** in Notion as a page/database.
  Accessed by setting ``NOTION_LEGAL_DB_ID`` env var.
- ADR Registry: does **not yet exist** → :func:`create_adr_registry` creates it.
- Module Tracker: does **not yet exist** → :func:`create_module_tracker` creates it.

All creation functions:
- Are idempotent (check for an existing database by name before creating).
- Require ``NOTION_API_KEY`` and ``NOTION_PARENT_PAGE_ID`` env vars.
- Return the Notion database ID which should then be stored as a GitHub
  Actions secret / Warden node env var for subsequent sync runs.
- Log every creation event to the GPAM sync ledger.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from gpam.sync.ledger import log_sync_event

_NOTION_VERSION = "2022-06-28"
_BASE_URL = "https://api.notion.com/v1"


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DatabaseProvisionResult:
    """Outcome of a :func:`ensure_*` call.

    Attributes
    ----------
    database_id:
        Notion database ID (use as ``NOTION_*_DB_ID`` secret).
    created:
        ``True`` if the database was newly created; ``False`` if it already
        existed and was returned as-is.
    name:
        Human-readable database name.
    url:
        Notion URL for the database.
    error:
        Non-``None`` if the operation failed.
    """

    database_id: str
    created: bool
    name: str
    url: str
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Notion API helpers
# ---------------------------------------------------------------------------


def _headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Notion-Version": _NOTION_VERSION,
        "Content-Type": "application/json",
    }


def _search_databases(token: str, name: str) -> Optional[str]:
    """Return the ID of a Notion database whose title matches *name*, or ``None``."""
    import requests

    resp = requests.post(
        f"{_BASE_URL}/search",
        json={"query": name, "filter": {"property": "object", "value": "database"}},
        headers=_headers(token),
        timeout=15,
    )
    try:
        resp.raise_for_status()
    except Exception:
        return None

    for result in resp.json().get("results", []):
        title_parts = result.get("title", [])
        title = "".join(p.get("plain_text", "") for p in title_parts).strip()
        if title == name:
            return result["id"]
    return None


def _create_database(
    token: str,
    parent_page_id: str,
    title: str,
    properties: Dict[str, Any],
    icon_emoji: str = "📋",
) -> tuple[str, str]:
    """Create a Notion database and return ``(database_id, url)``."""
    import requests

    payload = {
        "parent": {"type": "page_id", "page_id": parent_page_id},
        "title": [{"type": "text", "text": {"content": title}}],
        "icon": {"type": "emoji", "emoji": icon_emoji},
        "properties": properties,
    }

    resp = requests.post(
        f"{_BASE_URL}/databases",
        json=payload,
        headers=_headers(token),
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["id"], data.get("url", "")


# ---------------------------------------------------------------------------
# ADR Registry
# ---------------------------------------------------------------------------

_ADR_PROPERTIES: Dict[str, Any] = {
    # title is required and implicit as the Name field
    "Name": {"title": {}},
    "Status": {
        "select": {
            "options": [
                {"name": "Draft", "color": "yellow"},
                {"name": "Accepted", "color": "green"},
                {"name": "Deprecated", "color": "gray"},
                {"name": "Superseded", "color": "orange"},
            ]
        }
    },
    "DecisionDate": {"date": {}},
    "FilePath": {"rich_text": {}},
    "CommitSHA": {"rich_text": {}},
    "Tags": {"multi_select": {"options": []}},
    "SyncedAt": {"date": {}},
}


def ensure_adr_registry(
    *,
    notion_token: Optional[str] = None,
    parent_page_id: Optional[str] = None,
) -> DatabaseProvisionResult:
    """Return (or create) the ADR Registry database in Notion.

    Parameters
    ----------
    notion_token:
        Notion integration token.  Defaults to ``NOTION_API_KEY`` env var.
    parent_page_id:
        Notion page ID under which the database is created.  Defaults to
        ``NOTION_PARENT_PAGE_ID`` env var.

    Returns
    -------
    DatabaseProvisionResult
        Set ``NOTION_ADR_DB_ID = result.database_id`` as a secret after first run.
    """
    token = notion_token or os.environ.get("NOTION_API_KEY", "")
    parent = parent_page_id or os.environ.get("NOTION_PARENT_PAGE_ID", "")

    if not token:
        return DatabaseProvisionResult(
            database_id="", created=False, name="ADR Registry", url="",
            error="NOTION_API_KEY is not set.",
        )

    db_name = "ADR Registry"

    # Idempotency: check if it already exists.
    existing_id = _search_databases(token, db_name)
    if existing_id:
        log_sync_event(
            "notion_db_found", database_name=db_name, database_id=existing_id
        )
        return DatabaseProvisionResult(
            database_id=existing_id, created=False, name=db_name, url=""
        )

    if not parent:
        return DatabaseProvisionResult(
            database_id="", created=False, name=db_name, url="",
            error=(
                "NOTION_PARENT_PAGE_ID is not set. "
                "Set it to the Notion page ID where the ADR Registry should live."
            ),
        )

    try:
        db_id, url = _create_database(
            token, parent, db_name, _ADR_PROPERTIES, icon_emoji="📐"
        )
        log_sync_event(
            "notion_db_created", database_name=db_name, database_id=db_id
        )
        return DatabaseProvisionResult(
            database_id=db_id, created=True, name=db_name, url=url
        )
    except Exception as exc:  # noqa: BLE001
        return DatabaseProvisionResult(
            database_id="", created=False, name=db_name, url="", error=str(exc)
        )


# ---------------------------------------------------------------------------
# Module Tracker
# ---------------------------------------------------------------------------

_MODULE_TRACKER_PROPERTIES: Dict[str, Any] = {
    "Name": {"title": {}},
    "Module": {"rich_text": {}},
    "Status": {
        "select": {
            "options": [
                {"name": "Active", "color": "green"},
                {"name": "Experimental", "color": "blue"},
                {"name": "Deprecated", "color": "gray"},
            ]
        }
    },
    "FilePath": {"rich_text": {}},
    "CommitSHA": {"rich_text": {}},
    "SyncedAt": {"date": {}},
    "Tags": {"multi_select": {"options": []}},
}


def ensure_module_tracker(
    *,
    notion_token: Optional[str] = None,
    parent_page_id: Optional[str] = None,
) -> DatabaseProvisionResult:
    """Return (or create) the Module Tracker database in Notion.

    Parameters
    ----------
    notion_token:
        Notion integration token.  Defaults to ``NOTION_API_KEY`` env var.
    parent_page_id:
        Notion page ID under which the database is created.  Defaults to
        ``NOTION_PARENT_PAGE_ID`` env var.

    Returns
    -------
    DatabaseProvisionResult
        Set ``NOTION_MODULE_TRACKER_DB_ID = result.database_id`` as a secret after first run.
    """
    token = notion_token or os.environ.get("NOTION_API_KEY", "")
    parent = parent_page_id or os.environ.get("NOTION_PARENT_PAGE_ID", "")

    if not token:
        return DatabaseProvisionResult(
            database_id="", created=False, name="Module Tracker", url="",
            error="NOTION_API_KEY is not set.",
        )

    db_name = "Module Tracker"

    existing_id = _search_databases(token, db_name)
    if existing_id:
        log_sync_event(
            "notion_db_found", database_name=db_name, database_id=existing_id
        )
        return DatabaseProvisionResult(
            database_id=existing_id, created=False, name=db_name, url=""
        )

    if not parent:
        return DatabaseProvisionResult(
            database_id="", created=False, name=db_name, url="",
            error=(
                "NOTION_PARENT_PAGE_ID is not set. "
                "Set it to the Notion page ID where the Module Tracker should live."
            ),
        )

    try:
        db_id, url = _create_database(
            token, parent, db_name, _MODULE_TRACKER_PROPERTIES, icon_emoji="🗂️"
        )
        log_sync_event(
            "notion_db_created", database_name=db_name, database_id=db_id
        )
        return DatabaseProvisionResult(
            database_id=db_id, created=True, name=db_name, url=url
        )
    except Exception as exc:  # noqa: BLE001
        return DatabaseProvisionResult(
            database_id="", created=False, name=db_name, url="", error=str(exc)
        )


# ---------------------------------------------------------------------------
# Legal Evidence Registry (already exists — lookup only)
# ---------------------------------------------------------------------------


def lookup_legal_evidence_registry(
    *, notion_token: Optional[str] = None
) -> DatabaseProvisionResult:
    """Find the existing Legal Evidence Registry database in Notion.

    The legal evidence registry exists as a page/database in the workspace.
    This function searches by name and returns its ID.  If not found, it
    returns an error result with instructions.

    Parameters
    ----------
    notion_token:
        Notion integration token.  Defaults to ``NOTION_API_KEY`` env var.

    Returns
    -------
    DatabaseProvisionResult
        Set ``NOTION_LEGAL_DB_ID = result.database_id`` as a secret.
    """
    token = notion_token or os.environ.get("NOTION_API_KEY", "")

    if not token:
        return DatabaseProvisionResult(
            database_id="", created=False, name="Legal Evidence Registry", url="",
            error="NOTION_API_KEY is not set.",
        )

    # Try the known names for the existing legal database.
    for candidate_name in ("Legal Evidence Registry", "Legal Timeline"):
        db_id = _search_databases(token, candidate_name)
        if db_id:
            log_sync_event(
                "notion_db_found",
                database_name=candidate_name,
                database_id=db_id,
                note="existing legal registry — no creation needed",
            )
            return DatabaseProvisionResult(
                database_id=db_id, created=False, name=candidate_name, url=""
            )

    return DatabaseProvisionResult(
        database_id="", created=False, name="Legal Evidence Registry", url="",
        error=(
            "Legal Evidence Registry not found by name search. "
            "Open the database in Notion and set "
            "NOTION_LEGAL_DB_ID to the ID from the URL "
            "(the 32-char hex string before the '?v=' query parameter)."
        ),
    )


# ---------------------------------------------------------------------------
# Provision all databases (one-time setup)
# ---------------------------------------------------------------------------


def provision_all_databases(
    *,
    notion_token: Optional[str] = None,
    parent_page_id: Optional[str] = None,
) -> Dict[str, DatabaseProvisionResult]:
    """Provision (or find) all three sync databases.

    Run this once during initial setup.  After running, store the returned
    database IDs as GitHub Actions secrets / Warden node env vars:

        NOTION_ADR_DB_ID
        NOTION_MODULE_TRACKER_DB_ID
        NOTION_LEGAL_DB_ID

    Parameters
    ----------
    notion_token:
        Notion integration token.
    parent_page_id:
        Notion page ID for newly created databases.

    Returns
    -------
    dict[str, DatabaseProvisionResult]
        Keys: ``"adr"``, ``"module_tracker"``, ``"legal"``.
    """
    kwargs = {"notion_token": notion_token, "parent_page_id": parent_page_id}
    results = {
        "adr": ensure_adr_registry(**kwargs),
        "module_tracker": ensure_module_tracker(**kwargs),
        "legal": lookup_legal_evidence_registry(notion_token=notion_token),
    }

    log_sync_event(
        "notion_provision_complete",
        adr_id=results["adr"].database_id,
        module_tracker_id=results["module_tracker"].database_id,
        legal_id=results["legal"].database_id,
        errors={k: v.error for k, v in results.items() if v.error},
    )

    return results
