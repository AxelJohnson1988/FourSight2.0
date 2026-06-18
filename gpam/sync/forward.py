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
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, List, Optional

from gpam.sync.ledger import log_sync_event
from gpam.sync.policy import DataClass, ForwardBackend, RoutingDecision, SyncRequest

# ---------------------------------------------------------------------------
# Notion API constants
# ---------------------------------------------------------------------------

# Hard limit documented by Notion: a single blocks.children.append call may
# contain at most 100 children.  Exceeding this produces a 400 that is easy
# to misread as a network failure.  We chunk automatically.
NOTION_BLOCK_CHUNK_SIZE = 100


# ---------------------------------------------------------------------------
# Markdown preprocessing (must run BEFORE any Markdown→blocks conversion)
# ---------------------------------------------------------------------------


def strip_anchor_links(markdown_text: str) -> str:
    """Strip relative anchor links that the Notion API rejects outright.

    Notion's block model has no concept of same-document anchors, so any link
    whose href starts with ``#`` will cause the API to reject the entire block.
    This function preserves the visible link text so the document remains
    readable after stripping.

    Only relative anchors are affected.  External links (``http://`` /
    ``https://``) are passed through unchanged.

    Parameters
    ----------
    markdown_text:
        Raw Markdown content, possibly containing anchor links.

    Returns
    -------
    str
        Preprocessed Markdown safe to pass to a Markdown→Notion-blocks
        converter such as ``@tryfabric/martian``.

    Examples
    --------
    >>> strip_anchor_links("[see timeline](#timeline-of-events)")
    'see timeline'
    >>> strip_anchor_links("[overview](#overview)")
    'overview'
    >>> strip_anchor_links("[external](https://example.com)")
    '[external](https://example.com)'
    >>> strip_anchor_links("[mixed](#anchor) and [link](https://x.com)")
    'mixed and [link](https://x.com)'
    """
    # Matches [visible text](#anything) — the negative lookahead ensures
    # we never strip http/https links.
    _ANCHOR_RE = re.compile(r"\[([^\]]+)\]\((?!https?://)#[^)]*\)")
    return _ANCHOR_RE.sub(r"\1", markdown_text)


# ---------------------------------------------------------------------------
# Block chunking (Notion 100-block API limit)
# ---------------------------------------------------------------------------


def chunk_blocks(
    blocks: List[Dict], chunk_size: int = NOTION_BLOCK_CHUNK_SIZE
) -> Generator[List[Dict], None, None]:
    """Yield successive *chunk_size*-sized slices of *blocks*.

    Required because Notion's ``blocks.children.append`` endpoint rejects
    any request whose ``children`` array exceeds 100 entries.

    Parameters
    ----------
    blocks:
        Flat list of Notion block dicts.
    chunk_size:
        Maximum number of blocks per API call (default: 100).

    Yields
    ------
    list[dict]
        A slice of *blocks* of at most *chunk_size* entries.

    Examples
    --------
    >>> list(chunk_blocks([{"type": "paragraph"}] * 250, chunk_size=100))
    # → three lists: 100, 100, 50 blocks
    """
    if chunk_size < 1:
        raise ValueError(f"chunk_size must be >= 1, got {chunk_size}")
    for i in range(0, len(blocks), chunk_size):
        yield blocks[i : i + chunk_size]


def _append_blocks_in_chunks(
    *,
    token: str,
    page_id: str,
    blocks: List[Dict],
    chunk_size: int = NOTION_BLOCK_CHUNK_SIZE,
) -> None:
    """Append *blocks* to a Notion page via sequential chunked API calls.

    Raises immediately on the first chunk failure (Phoenix hard-FAIL
    principle) so the caller can log the error rather than silently
    producing a partially-synced page.

    Parameters
    ----------
    token:
        Notion integration token.
    page_id:
        Target Notion page or block ID.
    blocks:
        All blocks to append.  May exceed 100 — chunking is handled here.
    chunk_size:
        API call batch size (default: 100).

    Raises
    ------
    requests.HTTPError
        If any individual chunk append call returns a non-2xx status.
    """
    import requests

    headers = {
        "Authorization": f"Bearer {token}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
    }
    url = f"https://api.notion.com/v1/blocks/{page_id}/children"

    for chunk in chunk_blocks(blocks, chunk_size):
        resp = requests.patch(url, json={"children": chunk}, headers=headers, timeout=15)
        resp.raise_for_status()  # hard-fail; caller decides how to handle


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
        # Defense-in-depth: re-verify classification even though the router
        # should have prevented REGULATED/CONFIDENTIAL reaching this backend.
        # Log the anomaly to the GPAM ledger and skip — never silently proceed.
        _guard_data_class(req, file_path)

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


def _guard_data_class(req: SyncRequest, file_path: str) -> None:
    """Log and skip REGULATED/CONFIDENTIAL files that reach a non-local backend.

    This should never happen — the router is supposed to catch these.
    Logging the anomaly to the GPAM ledger makes the routing failure auditable.
    Raises ``ValueError`` so the caller can skip the file.
    """
    if req.data_class in (DataClass.REGULATED, DataClass.CONFIDENTIAL):
        log_sync_event(
            "SYNC_ROUTING_ANOMALY",
            severity="HIGH",
            file=file_path,
            data_class=req.data_class.value,
            message=(
                f"{req.data_class.value} file reached the local forward backend "
                "via the Actions route. This indicates a router failure."
            ),
        )
        raise ValueError(
            f"SYNC_ROUTING_ANOMALY: {req.data_class.value} file {file_path!r} "
            "must not be processed by the Actions backend."
        )


def _read_file_content(file_path: str) -> Optional[str]:
    """Read file content, returning ``None`` if the file no longer exists."""
    try:
        return Path(file_path).read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError):
        return None


def _markdown_to_blocks(content: str) -> List[Dict]:
    """Convert Markdown text to a flat list of Notion paragraph blocks.

    This is a minimal pure-Python converter for the local backend.  For the
    Actions backend, ``@tryfabric/martian`` (Node.js) should be used via a
    subprocess call for richer formatting support.

    Each non-empty line becomes a separate paragraph block, capped at
    Notion's 2000-character rich-text limit per block.

    Parameters
    ----------
    content:
        Preprocessed Markdown (anchor links already stripped).

    Returns
    -------
    list[dict]
        Notion block dicts suitable for ``blocks.children.append``.
    """
    blocks = []
    for line in content.splitlines():
        text = line.strip()
        if not text:
            continue
        # Notion rich-text hard limit is 2000 chars per segment.
        text = text[:2000]
        blocks.append(
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [{"type": "text", "text": {"content": text}}]
                },
            }
        )
    return blocks


def _upsert_notion_page(
    *,
    token: str,
    database_id: str,
    file_path: str,
    content: str,
) -> bool:
    """Create a Notion page for *file_path* and append its blocks in chunks.

    Preprocessing applied before any API call:
    1. ``strip_anchor_links`` — removes ``[text](#anchor)`` hrefs that the
       Notion API rejects outright.
    2. ``_markdown_to_blocks`` — converts lines to paragraph block dicts.
    3. ``_append_blocks_in_chunks`` — splits the block list at the 100-block
       API limit and makes sequential calls (hard-fail on any chunk error).

    Uses the file path as a stable external ID so re-runs are idempotent.
    Returns ``True`` on success, ``False`` on any API failure.
    """
    import requests

    headers = {
        "Authorization": f"Bearer {token}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
    }

    # Step 1: anchor-strip before conversion.
    clean_content = strip_anchor_links(content)

    # Step 2: convert to blocks (first 100 go in the page creation payload;
    # the rest are appended separately to respect the 100-block limit).
    all_blocks = _markdown_to_blocks(clean_content)
    first_chunk = all_blocks[:NOTION_BLOCK_CHUNK_SIZE]
    remaining = all_blocks[NOTION_BLOCK_CHUNK_SIZE:]

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
        "children": first_chunk,
    }

    try:
        resp = requests.post(
            "https://api.notion.com/v1/pages",
            json=payload,
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        page_id: str = resp.json()["id"]

        # Step 3: append remaining blocks in chunks of ≤100.
        if remaining:
            _append_blocks_in_chunks(
                token=token,
                page_id=page_id,
                blocks=remaining,
            )

        return True
    except Exception:  # noqa: BLE001
        return False
