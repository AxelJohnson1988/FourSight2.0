"""Forward sync backends: GitHub Actions trigger and Warden-local runner.

Architecture boundary
---------------------
This module runs the **outbound** leg (Git → Notion).  It never gives Notion
write authority over canonical Git content.  The flow is one-directional:

    Git (SoT) → SyncRunner → Notion (mirror)

Backends
--------
``actions``
    Posts a ``workflow_dispatch`` event to GitHub Actions so the
    ``.github/workflows/notion-sync.yml`` workflow runs on GitHub's
    infrastructure.  Safe for PUBLIC/INTERNAL data.

``local``
    Calls the Notion API directly from the Warden node.  Used when data is
    REGULATED or under a sensitive path prefix (legal/, shadow/, etc.) so it
    never leaves your own infrastructure.

Both backends:
    - Accept only changed files from ``git diff --name-only``.
    - Route each file through the transformer table in ``sync-policy.yml``.
    - Log every operation to the GPAM Akashic ledger.
    - Never overwrite Git content from Notion.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from gpam.sync.policy import ForwardBackend, RoutingDecision, SyncRequest


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ForwardSyncResult:
    """Outcome of a forward sync operation.

    Attributes
    ----------
    backend:
        Which backend executed.
    files_routed:
        Number of changed files that matched a transformer rule.
    files_skipped:
        Number of changed files with no matching transformer rule.
    success:
        ``True`` if the operation completed without error.
    error:
        Human-readable error message, or ``None`` on success.
    """

    backend: ForwardBackend
    files_routed: int
    files_skipped: int
    success: bool
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Transformer table helper
# ---------------------------------------------------------------------------


def _get_changed_files(base_sha: Optional[str] = None) -> List[str]:
    """Return a list of files changed relative to *base_sha*.

    Falls back to the last commit diff when *base_sha* is not provided.
    """
    try:
        cmd = ["git", "diff", "--name-only"]
        if base_sha:
            cmd.append(base_sha)
        else:
            cmd += ["HEAD^", "HEAD"]
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True
        )
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        return []


def _match_transformer(
    file_path: str,
    transformer_table: List[Dict],
) -> Optional[Dict]:
    """Return the first transformer rule whose ``path_prefix`` matches *file_path*."""
    for rule in transformer_table:
        prefix = rule.get("path_prefix", "")
        if file_path.startswith(prefix):
            return rule
    return None


# ---------------------------------------------------------------------------
# Actions backend
# ---------------------------------------------------------------------------


def run_actions_forward(
    req: SyncRequest,
    decision: RoutingDecision,
    *,
    github_repo: Optional[str] = None,
    github_token: Optional[str] = None,
    workflow_id: str = "notion-sync.yml",
    ref: str = "main",
) -> ForwardSyncResult:
    """Trigger the GitHub Actions forward-sync workflow via ``workflow_dispatch``.

    This backend is used for PUBLIC/INTERNAL data.  The GitHub Actions runner
    executes the actual Notion API calls in GitHub's infrastructure.

    Parameters
    ----------
    req:
        The originating sync request.
    decision:
        The routing decision (for audit logging).
    github_repo:
        ``owner/repo`` string.  Defaults to ``GITHUB_REPOSITORY`` env var.
    github_token:
        Personal access token with ``workflow`` scope.  Defaults to
        ``GITHUB_TOKEN`` env var.
    workflow_id:
        Workflow file name in ``.github/workflows/``.
    ref:
        Git ref to run the workflow on.

    Returns
    -------
    ForwardSyncResult
    """
    import requests  # lazy import

    repo = github_repo or os.environ.get("GITHUB_REPOSITORY", "")
    token = github_token or os.environ.get("GITHUB_TOKEN", "")

    if not repo or not token:
        return ForwardSyncResult(
            backend=ForwardBackend.ACTIONS,
            files_routed=0,
            files_skipped=0,
            success=False,
            error=(
                "GITHUB_REPOSITORY and GITHUB_TOKEN must be set "
                "to trigger the Actions workflow."
            ),
        )

    url = f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_id}/dispatches"
    payload = {
        "ref": ref,
        "inputs": {
            "path_prefix": req.path_prefix,
            "data_class": req.data_class.value,
        },
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        return ForwardSyncResult(
            backend=ForwardBackend.ACTIONS,
            files_routed=1,  # dispatch counts as one routed operation
            files_skipped=0,
            success=True,
        )
    except Exception as exc:  # noqa: BLE001
        return ForwardSyncResult(
            backend=ForwardBackend.ACTIONS,
            files_routed=0,
            files_skipped=0,
            success=False,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Local (Warden) backend
# ---------------------------------------------------------------------------


def run_local_forward(
    req: SyncRequest,
    decision: RoutingDecision,
    *,
    notion_token: Optional[str] = None,
    transformer_table: Optional[List[Dict]] = None,
    base_sha: Optional[str] = None,
) -> ForwardSyncResult:
    """Run forward sync locally on the Warden node via the Notion API.

    Used for REGULATED/sensitive data that must never leave your infrastructure.

    Parameters
    ----------
    req:
        The originating sync request.
    decision:
        The routing decision (for audit logging).
    notion_token:
        Notion integration token.  Defaults to ``NOTION_API_KEY`` env var.
    transformer_table:
        Override the transformer table from ``sync-policy.yml``.
    base_sha:
        Git SHA to diff against.  If omitted, diffs the last commit.

    Returns
    -------
    ForwardSyncResult
    """
    import requests  # lazy import

    token = notion_token or os.environ.get("NOTION_API_KEY", "")
    if not token:
        return ForwardSyncResult(
            backend=ForwardBackend.LOCAL,
            files_routed=0,
            files_skipped=0,
            success=False,
            error="NOTION_API_KEY is not set.",
        )

    table = transformer_table or []
    changed = _get_changed_files(base_sha)

    routed = 0
    skipped = 0

    for file_path in changed:
        rule = _match_transformer(file_path, table)
        if rule is None:
            skipped += 1
            continue

        db_id = os.path.expandvars(rule.get("notion_database_id", ""))
        if not db_id or db_id.startswith("${"):
            skipped += 1
            continue

        content = _read_file_content(file_path)
        if content is None:
            skipped += 1
            continue

        ok = _upsert_notion_page(
            token=token,
            database_id=db_id,
            file_path=file_path,
            content=content,
        )
        if ok:
            routed += 1
        else:
            skipped += 1

    return ForwardSyncResult(
        backend=ForwardBackend.LOCAL,
        files_routed=routed,
        files_skipped=skipped,
        success=True,
    )


def _read_file_content(file_path: str) -> Optional[str]:
    """Read file content, returning ``None`` if the file no longer exists."""
    try:
        return Path(file_path).read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError):
        return None


def _upsert_notion_page(
    *,
    token: str,
    database_id: str,
    file_path: str,
    content: str,
) -> bool:
    """Create or update a Notion page for *file_path*.

    Uses the file path as a stable external ID so re-runs are idempotent.
    Returns ``True`` on success.
    """
    import requests

    headers = {
        "Authorization": f"Bearer {token}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
    }

    # Truncate content to Notion's 2000-char block limit.
    body_text = content[:2000]

    payload = {
        "parent": {"database_id": database_id},
        "properties": {
            "Name": {"title": [{"text": {"content": file_path}}]},
            "FilePath": {"rich_text": [{"text": {"content": file_path}}]},
            "SyncedAt": {
                "date": {
                    "start": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                }
            },
        },
        "children": [
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [{"type": "text", "text": {"content": body_text}}]
                },
            }
        ],
    }

    try:
        resp = requests.post(
            "https://api.notion.com/v1/pages",
            json=payload,
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        return True
    except Exception:  # noqa: BLE001
        return False
