"""Tests for the Warden webhook server and Akashic audit log.

All GitHub API calls are mocked — these tests never touch the network or a
real Bitcoin/IPFS node.

Test matrix
-----------
Akashic (unit)
    test_akashic_append_and_retrieve
    test_akashic_idempotency_store
    test_akashic_chain_verify_passes
    test_akashic_chain_verify_fails_on_tamper
    test_tool_metadata_hash_deterministic
    test_tool_metadata_hash_no_secrets

Server — HMAC / auth
    test_missing_signature_returns_403
    test_bad_signature_returns_403
    test_valid_signature_accepted

Server — delivery filtering
    test_wrong_branch_skipped
    test_wrong_repo_skipped
    test_no_commits_skipped

Server — allowlist logic
    test_allowlisted_exact_anchor_log_allow
    test_allowlisted_exact_proof_txt_allow
    test_allowlisted_prefix_artifacts_allow
    test_allowlisted_prefix_inbox_allow
    test_non_allowlisted_path_deny
    test_mixed_paths_only_allowlisted_fetched

Server — idempotency / replay protection
    test_duplicate_delivery_returns_duplicate_status
    test_duplicate_delivery_not_relogged

Server — artifact hashing
    test_artifact_sha256_recorded_in_response
    test_github_api_failure_records_empty_sha

Server — response fields
    test_response_contains_tool_metadata_hash
    test_tool_metadata_hash_in_response_is_deterministic
    test_response_contains_no_secrets

Server — health endpoint
    test_health_endpoint
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
from unittest.mock import MagicMock, patch

import pytest

from warden.akashic import AkashicDB, compute_tool_metadata_hash
from warden.server import create_app, _is_allowlisted

# ---------------------------------------------------------------------------
# Constants & helpers
# ---------------------------------------------------------------------------

_TEST_SECRET = b"test-warden-secret-xyzzy"
_ANCHOR_REPO = "AxelJohnson1988/phoenix-anchor"
_HEAD_SHA = "abc123def456" * 3 + "abcd"  # 40 hex chars


def _sign(payload: bytes, secret: bytes = _TEST_SECRET) -> str:
    """Compute the X-Hub-Signature-256 header value for a payload."""
    digest = _hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _push_payload(
    *,
    repo: str = _ANCHOR_REPO,
    ref: str = "refs/heads/main",
    head_sha: str = _HEAD_SHA,
    added: list[str] | None = None,
    modified: list[str] | None = None,
) -> bytes:
    """Build a minimal GitHub push webhook payload."""
    data = {
        "ref": ref,
        "repository": {"full_name": repo},
        "commits": [
            {
                "id": head_sha,
                "timestamp": "2024-01-01T00:00:00Z",
                "added": added or [],
                "modified": modified or [],
                "removed": [],
            }
        ],
    }
    return json.dumps(data).encode()


def _headers(payload: bytes, *, delivery_id: str = "delivery-001") -> dict:
    return {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": _sign(payload),
        "X-GitHub-Delivery": delivery_id,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path):
    return AkashicDB(tmp_path / "test_akashic.db")


@pytest.fixture()
def client(tmp_path):
    """Flask test client with an isolated in-memory-adjacent SQLite DB."""
    app = create_app(
        webhook_secret=_TEST_SECRET,
        anchor_repo=_ANCHOR_REPO,
        github_token="",
        db_path=str(tmp_path / "warden_test.db"),
    )
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Akashic unit tests
# ---------------------------------------------------------------------------


class TestAkashicDB:
    def test_append_and_retrieve(self, db):
        record = db.append(
            delivery_id="d1",
            repo=_ANCHOR_REPO,
            head_sha=_HEAD_SHA,
            artifacts=[{"path": "anchor-log.md", "sha256": "aabb"}],
            validated=True,
        )
        assert record["validated"] is True
        assert record["repo"] == _ANCHOR_REPO
        assert "tool_metadata_hash" in record
        assert "chain_hash" in record

        log = db.get_log()
        assert len(log) == 1
        assert log[0]["delivery_id"] == "d1"

    def test_idempotency_store(self, db):
        assert not db.is_processed("d99")
        db.mark_processed("d99")
        assert db.is_processed("d99")
        # Duplicate mark_processed must not raise
        db.mark_processed("d99")
        assert db.is_processed("d99")

    def test_chain_verify_passes(self, db):
        db.append(
            delivery_id="c1",
            repo=_ANCHOR_REPO,
            head_sha=_HEAD_SHA,
            artifacts=[],
            validated=False,
        )
        db.append(
            delivery_id="c2",
            repo=_ANCHOR_REPO,
            head_sha=_HEAD_SHA,
            artifacts=[{"path": "proof.txt", "sha256": "cc"}],
            validated=True,
        )
        assert db.verify_chain() is True

    def test_chain_verify_fails_on_tamper(self, db):
        db.append(
            delivery_id="t1",
            repo=_ANCHOR_REPO,
            head_sha=_HEAD_SHA,
            artifacts=[],
            validated=False,
        )
        # Directly mutate a row to simulate tampering
        import sqlite3

        con = sqlite3.connect(str(db._db_path))
        con.execute("UPDATE akashic_log SET head_sha = 'tampered' WHERE id = 1")
        con.commit()
        con.close()
        assert db.verify_chain() is False

    def test_tool_metadata_hash_deterministic(self, db):
        h1 = compute_tool_metadata_hash(
            _ANCHOR_REPO, _HEAD_SHA, [{"path": "anchor-log.md", "sha256": "ff"}]
        )
        h2 = compute_tool_metadata_hash(
            _ANCHOR_REPO, _HEAD_SHA, [{"path": "anchor-log.md", "sha256": "ff"}]
        )
        assert h1 == h2
        assert len(h1) == 64  # sha256 hex

    def test_tool_metadata_hash_no_secrets(self):
        """Ensure the hash only uses public data — no tokens or private keys."""
        h = compute_tool_metadata_hash("owner/repo", "sha", [])
        # Recompute manually — if the function adds secrets this will diverge
        canonical = json.dumps(
            {"repo": "owner/repo", "head_sha": "sha", "artifacts": []},
            sort_keys=True,
            separators=(",", ":"),
        )
        expected = hashlib.sha256(canonical.encode()).hexdigest()
        assert h == expected


# ---------------------------------------------------------------------------
# Allowlist unit tests
# ---------------------------------------------------------------------------


class TestAllowlist:
    @pytest.mark.parametrize(
        "path,expected",
        [
            ("anchor-log.md", True),
            ("proof.txt", True),
            ("artifacts/finding_01.md", True),
            ("artifacts/sub/deep.json", True),
            ("inbox/capture.txt", True),
            ("inbox/", True),
            ("README.md", False),
            ("src/main.py", False),
            ("anchor-log.md.bak", False),
            ("proof.txt~", False),
            (".github/workflows/ci.yml", False),
        ],
    )
    def test_is_allowlisted(self, path, expected):
        assert _is_allowlisted(path) is expected


# ---------------------------------------------------------------------------
# Server — HMAC / auth tests
# ---------------------------------------------------------------------------


class TestHMAC:
    def test_missing_signature_returns_403(self, client):
        payload = _push_payload()
        resp = client.post(
            "/webhook/github/push",
            data=payload,
            content_type="application/json",
            headers={"X-GitHub-Delivery": "d-nosig"},
        )
        assert resp.status_code == 403

    def test_bad_signature_returns_403(self, client):
        payload = _push_payload()
        resp = client.post(
            "/webhook/github/push",
            data=payload,
            content_type="application/json",
            headers={
                "X-Hub-Signature-256": "sha256=deadbeef" * 8,
                "X-GitHub-Delivery": "d-badsig",
            },
        )
        assert resp.status_code == 403

    def test_wrong_secret_returns_403(self, client):
        payload = _push_payload()
        bad_sig = _sign(payload, secret=b"wrong-secret")
        resp = client.post(
            "/webhook/github/push",
            data=payload,
            content_type="application/json",
            headers={"X-Hub-Signature-256": bad_sig, "X-GitHub-Delivery": "d-wrng"},
        )
        assert resp.status_code == 403

    def test_valid_signature_accepted(self, client):
        payload = _push_payload(added=["anchor-log.md"])
        with patch("warden.server._fetch_file_sha256", return_value="aabb"):
            resp = client.post(
                "/webhook/github/push",
                data=payload,
                headers=_headers(payload),
            )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Server — delivery filtering
# ---------------------------------------------------------------------------


class TestDeliveryFiltering:
    def test_wrong_branch_skipped(self, client):
        payload = _push_payload(ref="refs/heads/feature-x", added=["anchor-log.md"])
        resp = client.post(
            "/webhook/github/push",
            data=payload,
            headers=_headers(payload, delivery_id="d-branch"),
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["status"] == "skipped"
        assert body["reason"] == "not_main_branch"

    def test_wrong_repo_skipped(self, client):
        payload = _push_payload(
            repo="someone-else/other-repo", added=["anchor-log.md"]
        )
        resp = client.post(
            "/webhook/github/push",
            data=payload,
            headers=_headers(payload, delivery_id="d-repo"),
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["status"] == "skipped"
        assert body["reason"] == "wrong_repository"

    def test_no_commits_skipped(self, client):
        data = {
            "ref": "refs/heads/main",
            "repository": {"full_name": _ANCHOR_REPO},
            "commits": [],
        }
        payload = json.dumps(data).encode()
        resp = client.post(
            "/webhook/github/push",
            data=payload,
            headers=_headers(payload, delivery_id="d-nocommits"),
        )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "skipped"


# ---------------------------------------------------------------------------
# Server — allowlist logic
# ---------------------------------------------------------------------------


class TestAllowlistLogic:
    def _post(self, client, added=None, modified=None, delivery_id="d-allow"):
        payload = _push_payload(added=added, modified=modified)
        with patch("warden.server._fetch_file_sha256", return_value="cafebabe"):
            return client.post(
                "/webhook/github/push",
                data=payload,
                headers=_headers(payload, delivery_id=delivery_id),
            )

    def test_anchor_log_allow(self, client):
        resp = self._post(client, added=["anchor-log.md"], delivery_id="d-al")
        body = resp.get_json()
        assert body["decision"] == "allow"
        assert body["validated"] is True

    def test_proof_txt_allow(self, client):
        resp = self._post(client, modified=["proof.txt"], delivery_id="d-pt")
        body = resp.get_json()
        assert body["decision"] == "allow"

    def test_artifacts_prefix_allow(self, client):
        resp = self._post(
            client, added=["artifacts/finding_01.md"], delivery_id="d-art"
        )
        body = resp.get_json()
        assert body["decision"] == "allow"

    def test_inbox_prefix_allow(self, client):
        resp = self._post(client, added=["inbox/capture.txt"], delivery_id="d-inb")
        body = resp.get_json()
        assert body["decision"] == "allow"

    def test_non_allowlisted_deny(self, client):
        resp = self._post(client, modified=["README.md"], delivery_id="d-deny")
        body = resp.get_json()
        assert body["decision"] == "deny"
        assert body["validated"] is False
        assert body["artifacts"] == []

    def test_mixed_paths_only_allowlisted_fetched(self, client):
        """Non-allowlisted paths in the same commit must not be fetched."""
        payload = _push_payload(
            added=["artifacts/ok.md", "src/evil.py"],
            modified=["README.md"],
        )
        fetch_mock = MagicMock(return_value="deadbeef")
        with patch("warden.server._fetch_file_sha256", fetch_mock):
            resp = client.post(
                "/webhook/github/push",
                data=payload,
                headers=_headers(payload, delivery_id="d-mix"),
            )

        body = resp.get_json()
        assert body["decision"] == "allow"
        fetched_paths = [call.args[1] for call in fetch_mock.call_args_list]
        assert "artifacts/ok.md" in fetched_paths
        assert "src/evil.py" not in fetched_paths
        assert "README.md" not in fetched_paths


# ---------------------------------------------------------------------------
# Server — idempotency / replay protection
# ---------------------------------------------------------------------------


class TestReplayProtection:
    def test_duplicate_delivery_returns_duplicate_status(self, client):
        payload = _push_payload(added=["anchor-log.md"])
        with patch("warden.server._fetch_file_sha256", return_value="aa"):
            resp1 = client.post(
                "/webhook/github/push",
                data=payload,
                headers=_headers(payload, delivery_id="d-dup"),
            )
            resp2 = client.post(
                "/webhook/github/push",
                data=payload,
                headers=_headers(payload, delivery_id="d-dup"),
            )

        assert resp1.status_code == 200
        assert resp1.get_json()["status"] == "ok"
        assert resp2.status_code == 200
        assert resp2.get_json()["status"] == "duplicate"

    def test_duplicate_delivery_not_relogged(self, tmp_path):
        """The Akashic log must contain exactly one entry per delivery_id."""
        db_path = str(tmp_path / "dup_test.db")
        app = create_app(
            webhook_secret=_TEST_SECRET,
            anchor_repo=_ANCHOR_REPO,
            db_path=db_path,
        )
        app.config["TESTING"] = True
        with app.test_client() as c:
            payload = _push_payload(added=["proof.txt"])
            with patch("warden.server._fetch_file_sha256", return_value="bb"):
                c.post(
                    "/webhook/github/push",
                    data=payload,
                    headers=_headers(payload, delivery_id="d-once"),
                )
                c.post(
                    "/webhook/github/push",
                    data=payload,
                    headers=_headers(payload, delivery_id="d-once"),
                )

        log = AkashicDB(db_path).get_log()
        assert len(log) == 1, "duplicate delivery must not create a second audit record"


# ---------------------------------------------------------------------------
# Server — artifact hashing
# ---------------------------------------------------------------------------


class TestArtifactHashing:
    def test_artifact_sha256_recorded_in_response(self, client):
        expected_sha = "cafecafe" * 8  # 64-char hex
        payload = _push_payload(added=["artifacts/evidence.md"])
        with patch("warden.server._fetch_file_sha256", return_value=expected_sha):
            resp = client.post(
                "/webhook/github/push",
                data=payload,
                headers=_headers(payload, delivery_id="d-sha"),
            )
        body = resp.get_json()
        assert body["artifacts"][0]["sha256"] == expected_sha
        assert body["artifacts"][0]["path"] == "artifacts/evidence.md"

    def test_github_api_failure_records_empty_sha(self, client):
        """If the GitHub API is unreachable the artifact sha256 is '' not an error."""
        payload = _push_payload(added=["anchor-log.md"])
        with patch("warden.server._fetch_file_sha256", return_value=None):
            resp = client.post(
                "/webhook/github/push",
                data=payload,
                headers=_headers(payload, delivery_id="d-fail"),
            )
        body = resp.get_json()
        assert body["status"] == "ok"
        assert body["artifacts"][0]["sha256"] == ""


# ---------------------------------------------------------------------------
# Server — response-field contracts
# ---------------------------------------------------------------------------


class TestResponseFields:
    def test_response_contains_tool_metadata_hash(self, client):
        payload = _push_payload(added=["anchor-log.md"])
        with patch("warden.server._fetch_file_sha256", return_value="dd"):
            resp = client.post(
                "/webhook/github/push",
                data=payload,
                headers=_headers(payload, delivery_id="d-meta"),
            )
        body = resp.get_json()
        assert "tool_metadata_hash" in body
        assert len(body["tool_metadata_hash"]) == 64  # sha256 hex

    def test_tool_metadata_hash_deterministic(self, tmp_path):
        """Two identical pushes (different deliveries) must yield the same hash."""
        app = create_app(
            webhook_secret=_TEST_SECRET,
            anchor_repo=_ANCHOR_REPO,
            db_path=str(tmp_path / "det_test.db"),
        )
        app.config["TESTING"] = True
        with app.test_client() as c:
            payload = _push_payload(added=["anchor-log.md"])
            with patch("warden.server._fetch_file_sha256", return_value="ee"):
                r1 = c.post(
                    "/webhook/github/push",
                    data=payload,
                    headers=_headers(payload, delivery_id="d-det1"),
                )
                r2 = c.post(
                    "/webhook/github/push",
                    data=payload,
                    headers=_headers(payload, delivery_id="d-det2"),
                )

        assert r1.get_json()["tool_metadata_hash"] == r2.get_json()["tool_metadata_hash"]

    def test_response_contains_no_secrets(self, client):
        """The JSON response must not echo any token or the HMAC secret."""
        payload = _push_payload(added=["proof.txt"])
        with patch("warden.server._fetch_file_sha256", return_value="ff"):
            resp = client.post(
                "/webhook/github/push",
                data=payload,
                headers=_headers(payload, delivery_id="d-sec"),
            )
        body = resp.get_data(as_text=True)
        # The test secret must never appear in the response
        assert _TEST_SECRET.decode() not in body
        assert "Authorization" not in body
        assert "token" not in body.lower() and "github_token" not in body.lower()


# ---------------------------------------------------------------------------
# Server — health
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.get_json() == {"status": "ok"}
