"""Warden Flask webhook server — Phoenix Anchor Validation Pipeline.

Environment variables
---------------------
GITHUB_WEBHOOK_SECRET
    HMAC-SHA256 secret shared with the GitHub webhook configuration.
    **Required** for production; an empty string disables signature checking
    (never do this in production).
GITHUB_TOKEN
    Optional personal-access token for fetching content from private anchor
    repositories.  Never logged.
AKASHIC_DB_PATH
    Filesystem path for the SQLite audit database.
    Defaults to ``akashic_audit.db`` in the current working directory.
PHOENIX_ANCHOR_REPO
    Expected full repository name, e.g. ``AxelJohnson1988/phoenix-anchor``.
    Defaults to the canonical anchor repo.

Allowlist (which paths count as anchorable)
-------------------------------------------
Exact matches : ``anchor-log.md``, ``proof.txt``
Prefix matches: ``artifacts/``, ``inbox/``

Any commit that touches only non-allowlisted paths produces a ``decision=deny``
Akashic event — it is logged but not considered valid.

Webhook replay prevention
-------------------------
The ``X-GitHub-Delivery`` header is stored in SQLite on first receipt.
Duplicate deliveries return HTTP 200 with ``{"status": "duplicate"}`` without
re-processing or re-logging.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

import requests
from flask import Flask, Response, abort, jsonify, request

from .akashic import AkashicDB

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_ANCHOR_REPO = "AxelJohnson1988/phoenix-anchor"
_ALLOWLIST_EXACT: frozenset[str] = frozenset({"anchor-log.md", "proof.txt"})
_ALLOWLIST_PREFIXES: tuple[str, ...] = ("artifacts/", "inbox/")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _verify_signature(payload: bytes, sig_header: str, secret: bytes) -> None:
    """Abort with 403 if *sig_header* does not match the HMAC-SHA256 of *payload*.

    Parameters
    ----------
    payload:
        Raw request body bytes.
    sig_header:
        Value of the ``X-Hub-Signature-256`` HTTP header.
    secret:
        HMAC secret bytes (``GITHUB_WEBHOOK_SECRET``).

    Raises
    ------
    werkzeug.exceptions.Forbidden (HTTP 403)
        On any signature mismatch or malformed header.
    """
    if not secret:
        # Secret not configured — refuse all requests in this path rather than
        # silently allowing unsigned webhooks.
        abort(403, description="GITHUB_WEBHOOK_SECRET not configured")
    if not sig_header.startswith("sha256="):
        abort(403, description="Missing or malformed X-Hub-Signature-256")
    expected = "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig_header):
        abort(403, description="Signature mismatch")


def _is_allowlisted(path: str) -> bool:
    """Return *True* if *path* is on the anchor repo allowlist."""
    if path in _ALLOWLIST_EXACT:
        return True
    return any(path.startswith(prefix) for prefix in _ALLOWLIST_PREFIXES)


def _fetch_file_sha256(
    repo: str, path: str, ref: str, token: str = ""
) -> str | None:
    """Fetch raw file content from the GitHub Contents API and return sha256.

    Parameters
    ----------
    repo:
        Full repository name.
    path:
        File path within the repo.
    ref:
        Commit SHA or branch/tag name.
    token:
        Optional GitHub PAT.  Never logged.

    Returns
    -------
    str or None
        Hex sha256 digest of the raw file bytes, or *None* on fetch failure.
    """
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    headers: dict[str, str] = {"Accept": "application/vnd.github.v3.raw"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.get(url, headers=headers, params={"ref": ref}, timeout=15)
    except requests.RequestException:
        return None
    if resp.status_code == 200:
        return hashlib.sha256(resp.content).hexdigest()
    return None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_app(
    *,
    webhook_secret: bytes | None = None,
    anchor_repo: str | None = None,
    github_token: str | None = None,
    db_path: str | None = None,
) -> Flask:
    """Create and return the configured Flask application.

    All parameters fall back to environment variables when *None*.

    Parameters
    ----------
    webhook_secret:
        Raw HMAC secret bytes.  Defaults to ``GITHUB_WEBHOOK_SECRET`` env var.
    anchor_repo:
        Expected full repository name.  Defaults to ``PHOENIX_ANCHOR_REPO``
        env var, then ``"AxelJohnson1988/phoenix-anchor"``.
    github_token:
        GitHub PAT for private-repo access.  Defaults to ``GITHUB_TOKEN``.
    db_path:
        SQLite database path.  Defaults to ``AKASHIC_DB_PATH`` env var, then
        ``"akashic_audit.db"``.
    """
    _secret: bytes = (
        webhook_secret
        if webhook_secret is not None
        else os.environ.get("GITHUB_WEBHOOK_SECRET", "").encode()
    )
    _repo: str = (
        anchor_repo
        if anchor_repo is not None
        else os.environ.get("PHOENIX_ANCHOR_REPO", _DEFAULT_ANCHOR_REPO)
    )
    _token: str = (
        github_token
        if github_token is not None
        else os.environ.get("GITHUB_TOKEN", "")
    )
    _db_path: str = (
        db_path
        if db_path is not None
        else os.environ.get("AKASHIC_DB_PATH", "akashic_audit.db")
    )

    db = AkashicDB(_db_path)
    app = Flask(__name__)

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.route("/health", methods=["GET"])
    def health() -> tuple[Response, int]:
        return jsonify({"status": "ok"}), 200

    @app.route("/webhook/github/push", methods=["POST"])
    def github_push() -> tuple[Response, int]:
        # 1 — HMAC verification
        sig_header = request.headers.get("X-Hub-Signature-256", "")
        _verify_signature(request.data, sig_header, _secret)

        # 2 — Replay / idempotency guard
        delivery_id = request.headers.get("X-GitHub-Delivery", "")
        if db.is_processed(delivery_id):
            return jsonify({"status": "duplicate", "delivery_id": delivery_id}), 200

        # Mark early so concurrent duplicates also hit the guard
        db.mark_processed(delivery_id)

        # 3 — Parse and filter payload
        payload: dict[str, Any] = request.get_json(force=True) or {}
        ref: str = payload.get("ref", "")
        if ref != "refs/heads/main":
            return jsonify({"status": "skipped", "reason": "not_main_branch"}), 200

        repo_full: str = payload.get("repository", {}).get("full_name", "")
        if repo_full != _repo:
            return jsonify({"status": "skipped", "reason": "wrong_repository"}), 200

        commits: list[dict] = payload.get("commits", [])
        if not commits:
            return jsonify({"status": "skipped", "reason": "no_commits"}), 200

        head_commit: dict = commits[-1]
        head_sha: str = head_commit.get("id", "")

        changed_paths: set[str] = set(
            head_commit.get("added", []) + head_commit.get("modified", [])
        )

        # 4 — Allowlist filter
        anchorable: list[str] = sorted(
            p for p in changed_paths if _is_allowlisted(p)
        )
        validated: bool = bool(anchorable)

        # 5 — Fetch artifact sha256 from GitHub Contents API
        artifacts: list[dict] = []
        for path in anchorable:
            sha = _fetch_file_sha256(repo_full, path, head_sha, token=_token)
            artifacts.append({"path": path, "sha256": sha or ""})

        # 6 — Append Akashic record
        record = db.append(
            delivery_id=delivery_id,
            repo=repo_full,
            head_sha=head_sha,
            artifacts=artifacts,
            validated=validated,
        )

        decision = "allow" if validated else "deny"
        return (
            jsonify(
                {
                    "status": "ok",
                    "decision": decision,
                    "tool_metadata_hash": record["tool_metadata_hash"],
                    "validated": validated,
                    "artifacts": artifacts,
                }
            ),
            200,
        )

    return app


# ---------------------------------------------------------------------------
# Module-level default app (for ``flask run`` / gunicorn entrypoints)
# ---------------------------------------------------------------------------

app = create_app()
