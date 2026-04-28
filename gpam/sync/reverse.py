"""Reverse sync backends: polling and Cloudflare webhook receiver stub.

Architecture boundary
---------------------
Notion can only **annotate** canonical Git files — it can never overwrite them.
Annotations live in a dedicated ``annotations/`` directory and are committed
with a restricted token that has write access ONLY to that directory.

Backends
--------
``polling``
    Warden reaches OUT to Notion on a schedule (cron/systemd timer).
    - Fetches all Notion pages modified since the last poll timestamp.
    - For each changed page, writes an annotation file:
        ``annotations/<source_path>/<notion_page_id>/<timestamp>.md``
    - Commits via Git.
    - Zero inbound exposure — entirely outbound traffic.

``webhook_cloudflare``
    Notion pushes IN via Cloudflare Tunnel + Access.
    - Requires ``INBOUND_EXPOSURE_ALLOWED=true`` env var AND
      ``SyncRequest.inbound_exposure_allowed=True``.
    - Verifies the Notion webhook signature before processing.
    - Returns a stub that starts a Flask receiver; Cloudflare Tunnel
      must be configured separately.
    - If either opt-in is absent, ``SyncRouter`` falls back to polling.

Sovereignty invariants
----------------------
- Annotation commits use a token with write access ONLY to ``annotations/``.
- Canonical source files are never touched by the reverse path.
- Every annotation file carries frontmatter identifying its Notion origin.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from gpam.sync.policy import ReverseBackend, RoutingDecision, SyncRequest

_ANNOTATION_DIR = Path("annotations")
_POLL_STATE_FILE = Path(".gpam-poll-state.json")


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReverseSyncResult:
    """Outcome of a reverse sync operation.

    Attributes
    ----------
    backend:
        Which backend executed.
    annotations_written:
        Number of new annotation files committed.
    success:
        ``True`` if the operation completed without error.
    error:
        Human-readable error message, or ``None`` on success.
    """

    backend: ReverseBackend
    annotations_written: int
    success: bool
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Annotation file writer (shared by both backends)
# ---------------------------------------------------------------------------


def _write_annotation(
    *,
    notion_page_id: str,
    source_path: str,
    comment: str,
    author: str,
    notion_url: str,
) -> Path:
    """Write an annotation Markdown file and return its path.

    The file is placed at:
        ``annotations/<source_path>/<notion_page_id>/<timestamp>.md``

    This path is deterministic within a second — re-runs within the same
    second are idempotent (the file is overwritten, not duplicated).
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_source = source_path.replace("/", "_").strip("_")
    out_dir = _ANNOTATION_DIR / safe_source / notion_page_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{timestamp}.md"

    lines = [
        "---",
        f"notion_page_id: {notion_page_id}",
        f"source_path: {source_path}",
        f"annotated_by: {author}",
        f"notion_url: {notion_url}",
        f"timestamp: {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}",
        'authority: "annotation-only — canonical file is unchanged"',
        "---",
        "",
        comment,
        "",
    ]
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def _git_commit_annotation(path: Path, message: str) -> bool:
    """Stage and commit a single annotation file.  Returns ``True`` on success."""
    try:
        subprocess.run(["git", "add", str(path)], check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", message],
            check=True,
            capture_output=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


# ---------------------------------------------------------------------------
# Polling backend
# ---------------------------------------------------------------------------


def run_polling_reverse(
    req: SyncRequest,
    decision: RoutingDecision,
    *,
    notion_token: Optional[str] = None,
    poll_interval_minutes: int = 10,
) -> ReverseSyncResult:
    """Poll Notion for pages changed since the last run and write annotations.

    This backend makes entirely **outbound** requests — zero inbound exposure.
    The last-poll timestamp is persisted in ``.gpam-poll-state.json`` so
    successive runs only process new changes.

    Parameters
    ----------
    req:
        The originating sync request.
    decision:
        The routing decision (for audit logging).
    notion_token:
        Notion integration token.  Defaults to ``NOTION_API_KEY`` env var.
    poll_interval_minutes:
        Unused by this function (set in the systemd timer / cron schedule),
        kept for signature symmetry with the daemon wrapper.

    Returns
    -------
    ReverseSyncResult
    """
    import requests

    token = notion_token or os.environ.get("NOTION_API_KEY", "")
    if not token:
        return ReverseSyncResult(
            backend=ReverseBackend.POLLING,
            annotations_written=0,
            success=False,
            error="NOTION_API_KEY is not set.",
        )

    last_poll = _load_poll_state()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    headers = {
        "Authorization": f"Bearer {token}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
    }

    # Search for pages updated since last poll.
    search_payload: Dict = {
        "filter": {"property": "object", "value": "page"},
        "sort": {"direction": "descending", "timestamp": "last_edited_time"},
    }

    written = 0
    try:
        resp = requests.post(
            "https://api.notion.com/v1/search",
            json=search_payload,
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        pages = resp.json().get("results", [])

        for page in pages:
            last_edited = page.get("last_edited_time", "")
            if last_poll and last_edited <= last_poll:
                continue  # already processed

            page_id = page.get("id", "")
            url = page.get("url", "")
            # Extract title from page properties.
            props = page.get("properties", {})
            title = _extract_title(props)

            annotation_path = _write_annotation(
                notion_page_id=page_id,
                source_path=req.path_prefix or "root",
                comment=f"Notion page updated: {title}\nLast edited: {last_edited}",
                author="notion-poller",
                notion_url=url,
            )
            committed = _git_commit_annotation(
                annotation_path,
                f"annotation: Notion update {page_id[:8]} at {last_edited}",
            )
            if committed:
                written += 1

    except Exception as exc:  # noqa: BLE001
        return ReverseSyncResult(
            backend=ReverseBackend.POLLING,
            annotations_written=written,
            success=False,
            error=str(exc),
        )

    _save_poll_state(now)
    return ReverseSyncResult(
        backend=ReverseBackend.POLLING,
        annotations_written=written,
        success=True,
    )


def _extract_title(properties: Dict) -> str:
    """Best-effort title extraction from a Notion page properties dict."""
    for key in ("Name", "Title", "title"):
        prop = properties.get(key, {})
        title_list = prop.get("title", [])
        if title_list:
            return "".join(
                t.get("plain_text", "") for t in title_list
            ).strip()
    return "(untitled)"


def _load_poll_state() -> Optional[str]:
    """Return the last-poll ISO timestamp, or ``None`` if no state exists."""
    if not _POLL_STATE_FILE.exists():
        return None
    try:
        state = json.loads(_POLL_STATE_FILE.read_text(encoding="utf-8"))
        return state.get("last_poll")
    except (json.JSONDecodeError, KeyError):
        return None


def _save_poll_state(timestamp: str) -> None:
    """Persist *timestamp* as the last-poll marker."""
    _POLL_STATE_FILE.write_text(
        json.dumps({"last_poll": timestamp}, indent=2), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Webhook receiver stub (disabled by default)
# ---------------------------------------------------------------------------


def run_webhook_receiver(
    req: SyncRequest,
    decision: RoutingDecision,
    *,
    notion_webhook_secret: Optional[str] = None,
    host: str = "127.0.0.1",  # localhost only — Cloudflare Tunnel terminates externally
    port: int = 8765,
) -> ReverseSyncResult:
    """Start a Flask webhook receiver for Notion → Git annotations.

    ⚠️  This backend is **disabled by default**.  It is only reachable when:
        1. ``SyncRouter`` selected it (requires double opt-in — see policy.py).
        2. A Cloudflare Tunnel is configured to forward to ``host:port``.
        3. Cloudflare Access is configured to restrict inbound traffic to
           Notion's webhook IP range.

    The receiver binds to localhost only.  Cloudflare Tunnel handles the
    public-facing TLS and identity gating.  Never bind to ``0.0.0.0`` directly.

    Parameters
    ----------
    req:
        The originating sync request.
    decision:
        The routing decision.
    notion_webhook_secret:
        Notion webhook verification secret.  Defaults to
        ``NOTION_WEBHOOK_SECRET`` env var.
    host:
        Bind address (default: ``127.0.0.1`` — localhost only).
    port:
        Bind port (default: ``8765``).

    Returns
    -------
    ReverseSyncResult
        Returns immediately with a failure result if the exposure guard is not
        satisfied; otherwise starts the Flask receiver (blocking).
    """
    # Re-check exposure guard even though SyncRouter already verified it —
    # defence in depth: the backend guards itself independently.
    env_flag = os.environ.get("INBOUND_EXPOSURE_ALLOWED", "false").lower().strip()
    if env_flag != "true" or not req.inbound_exposure_allowed:
        return ReverseSyncResult(
            backend=ReverseBackend.WEBHOOK_CLOUDFLARE,
            annotations_written=0,
            success=False,
            error=(
                "Webhook receiver refused to start: INBOUND_EXPOSURE_ALLOWED "
                "must be 'true' in the environment AND inbound_exposure_allowed "
                "must be True in the SyncRequest. Falling back to polling."
            ),
        )

    secret = notion_webhook_secret or os.environ.get("NOTION_WEBHOOK_SECRET", "")

    try:
        from flask import Flask, abort, request as flask_request

        app = Flask("gpam-webhook-receiver")

        @app.route("/notion-webhook", methods=["POST"])
        def notion_webhook():
            # Verify Notion signature.
            sig_header = flask_request.headers.get("X-Notion-Signature", "")
            if secret:
                body = flask_request.get_data()
                expected = hmac.new(
                    secret.encode("utf-8"), body, hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(f"sha256={expected}", sig_header):
                    abort(401)

            payload = flask_request.get_json(force=True) or {}
            page_id = payload.get("entity", {}).get("id", "unknown")
            url = payload.get("entity", {}).get("url", "")
            comment = f"Notion webhook event: {payload.get('type', 'update')}"

            annotation_path = _write_annotation(
                notion_page_id=page_id,
                source_path=req.path_prefix or "root",
                comment=comment,
                author="notion-webhook",
                notion_url=url,
            )
            _git_commit_annotation(
                annotation_path,
                f"annotation: Notion webhook {page_id[:8]}",
            )
            return {"status": "ok"}, 200

        # Bind to localhost only — Cloudflare Tunnel terminates externally.
        app.run(host=host, port=port, debug=False)

        return ReverseSyncResult(
            backend=ReverseBackend.WEBHOOK_CLOUDFLARE,
            annotations_written=0,  # receiver is persistent; count is per-request
            success=True,
        )

    except ImportError:
        return ReverseSyncResult(
            backend=ReverseBackend.WEBHOOK_CLOUDFLARE,
            annotations_written=0,
            success=False,
            error="Flask is not installed. Run: pip install flask",
        )
