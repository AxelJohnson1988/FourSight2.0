"""Warden — Phoenix Anchor Validation Pipeline.

Exposes a Flask webhook endpoint that:
* verifies GitHub push payloads with HMAC-SHA256
* enforces an allowlist of anchorable paths
* fetches artifact content hashes from the GitHub Contents API
* appends tamper-evident, hash-chained events to an Akashic SQLite audit log
* guards against webhook replay via a processed-deliveries table
"""

from .akashic import AkashicDB
from .server import create_app

__all__ = ["create_app", "AkashicDB"]
