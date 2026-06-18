"""Hashing, OP_RETURN payload generation, IPFS pinning, and Bitcoin broadcast."""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from phoenix_scanner.config import Config


def hash_bytes(data: bytes) -> str:
    """Return SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    """Return SHA-256 hex digest of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_op_return_payload(digest_hex: str, *, prefix: str = "414c454501") -> str:
    """Concatenate the prefix and the SHA-256 hex to form an OP_RETURN payload.

    The default prefix ``414c454501`` is the ASCII bytes for ``ALEE`` followed
    by a version byte ``0x01``.

    Parameters
    ----------
    digest_hex:
        64-character hex string (SHA-256 output).
    prefix:
        Hex string prepended to the digest.  Defaults to the ALEE prefix.

    Returns
    -------
    str
        A hex string suitable for embedding in a Bitcoin ``OP_RETURN`` output.
        Note: Bitcoin enforces an 80-byte limit on ``OP_RETURN`` data; callers
        should validate the total length themselves if broadcasting.
    """
    if len(digest_hex) != 64:
        raise ValueError(f"digest_hex must be 64 hex chars; got {len(digest_hex)}")
    return prefix + digest_hex


def pin_to_ipfs(data: bytes, *, gateway_url: str) -> str:
    """POST *data* to an IPFS HTTP API and return the CID string.

    Parameters
    ----------
    data:
        Raw bytes to pin.
    gateway_url:
        Base URL of the IPFS HTTP API (e.g. ``http://127.0.0.1:5001``).
        The endpoint ``/api/v0/add`` will be appended automatically.

    Returns
    -------
    str
        The CID (Content Identifier) returned by the IPFS node.

    Raises
    ------
    RuntimeError
        If the IPFS API returns a non-200 status or an unexpected response body.
    """
    url = gateway_url.rstrip("/") + "/api/v0/add"
    # Minimal multipart/form-data encoding — avoids adding a third-party dep.
    boundary = "----PhoenixIPFSBoundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="payload"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"IPFS API error {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"IPFS connection failed: {exc.reason}") from exc

    try:
        info: dict[str, Any] = json.loads(raw)
        return info["Hash"]
    except (json.JSONDecodeError, KeyError) as exc:
        raise RuntimeError(f"Unexpected IPFS response: {raw!r}") from exc


def broadcast_op_return(
    payload_hex: str,
    *,
    node_url: str,
    auth: tuple[str, str],
) -> str:
    """Submit a pre-built OP_RETURN payload to a Bitcoin node and return the TXID.

    This function calls the ``sendrawtransaction`` JSON-RPC method.  **It
    never constructs a full transaction** — the caller must supply an already-
    signed raw transaction hex that embeds the OP_RETURN output.  The
    ``payload_hex`` argument here is the raw-transaction hex (not just the
    OP_RETURN data field).

    Parameters
    ----------
    payload_hex:
        Hex-encoded signed raw Bitcoin transaction containing the OP_RETURN.
    node_url:
        URL of the Bitcoin node's JSON-RPC endpoint
        (e.g. ``http://127.0.0.1:8332``).
    auth:
        ``(username, password)`` tuple for HTTP Basic Auth.

    Returns
    -------
    str
        The transaction ID (TXID) returned by the node.

    Raises
    ------
    ValueError
        If the node returns a JSON-RPC error.
    RuntimeError
        On network or HTTP-level failures.

    Notes
    -----
    This function requires **explicit caller opt-in** (passing ``node_url`` and
    ``auth``).  It is never called automatically by the scanner pipeline.
    Bitcoin mainnet transactions are irreversible — review the raw transaction
    carefully before broadcasting.
    """
    import base64

    body = json.dumps(
        {
            "jsonrpc": "1.0",
            "id": "phoenix",
            "method": "sendrawtransaction",
            "params": [payload_hex],
        }
    ).encode("utf-8")

    credentials = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req = urllib.request.Request(
        node_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {credentials}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Bitcoin node HTTP error {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Bitcoin node connection failed: {exc.reason}") from exc

    try:
        response: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Unexpected Bitcoin node response: {raw!r}") from exc

    if response.get("error") is not None:
        raise ValueError(f"Bitcoin RPC error: {response['error']}")

    return str(response["result"])


def anchor(
    text: str = "",
    file_path: Path | None = None,
    *,
    config: Config | None = None,
    ipfs_gateway_url: str | None = None,
) -> dict[str, str]:
    """Compute a SHA-256 anchor from *text* and/or *file_path*.

    Parameters
    ----------
    text:
        UTF-8 text payload.  Must be non-empty when *file_path* is ``None``.
    file_path:
        Optional path to a file whose contents are appended to the text bytes.
    config:
        Config object (used for ``op_return_prefix``).
    ipfs_gateway_url:
        When provided, the payload bytes are pinned to IPFS and the returned
        dict gains an ``ipfs_cid`` key.  Existing callers that omit this
        argument are unaffected.

    Returns
    -------
    dict with keys:
        - ``sha256`` – hex digest
        - ``op_return_payload`` – hex OP_RETURN string
        - ``byte_length`` – total bytes hashed
        - ``ipfs_cid`` – CID string (only present when *ipfs_gateway_url* is set)

    Raises
    ------
    ValueError
        If both *text* is empty/whitespace and *file_path* is ``None``.
    """
    if not text.strip() and file_path is None:
        raise ValueError(
            "anchor() requires non-empty text or a file_path; "
            "refusing to hash zero bytes (would produce the e3b0c44… null digest)."
        )

    if config is None:
        config = Config()

    payload = text.encode("utf-8")
    if file_path is not None:
        with open(file_path, "rb") as fh:
            payload += fh.read()

    digest = hashlib.sha256(payload).hexdigest()
    op_return = build_op_return_payload(digest, prefix=config.op_return_prefix)

    result: dict[str, str] = {
        "sha256": digest,
        "op_return_payload": op_return,
        "byte_length": str(len(payload)),
    }

    if ipfs_gateway_url is not None:
        result["ipfs_cid"] = pin_to_ipfs(payload, gateway_url=ipfs_gateway_url)

    return result
