"""FourSight 2.0 — Warden integrity and drift-detection engine.

Public API::

    from warden import Warden, WardenResult

    with Warden() as warden:
        result = warden.process("original text", "processed text")
        print(result.drift.status)   # safe / warning / block
        print(result.blocked)        # bool

Submodules
----------
- :mod:`warden.integrity` — SHA-256 file and byte-level hashing
- :mod:`warden.drift`     — cosine-similarity semantic drift detection
- :mod:`warden.akashic`   — SQLite hash-chained tamper-evident ledger
- :mod:`warden.capture`   — corruption capture bundles (diff + metadata)
- :mod:`warden.warden`    — Warden class (dual-channel validation)
"""

from warden.warden import Warden, WardenResult

__all__ = ["Warden", "WardenResult"]
