"""Core Warden class — dual-channel validation, drift detection, and logging.

The Warden is the single authoritative actor that:

1. Hashes Channel A (raw input) and Channel B (processed output).
2. Measures semantic drift between the two channels.
3. Appends a tamper-evident, hash-chained entry to the Akashic Ledger.
4. When drift exceeds the WARNING threshold, saves a corruption capture bundle
   containing the raw input, processed output, unified diff, and metadata.

Usage::

    from warden.warden import Warden

    with Warden(db_path=":memory:", capture_dir="/tmp/captures") as warden:
        result = warden.process("original text", "processed text")
        print(result.drift.status)          # DriftStatus.SAFE / WARNING / BLOCK
        print(result.ledger_entry)          # full hash-chained entry dict
        print(result.capture_path)          # Path or None
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from warden.akashic import AkashicLedger
from warden.capture import CorruptionCapture
from warden.drift import DriftResult, DriftStatus, evaluate_drift
from warden.integrity import compute_sha256_bytes


@dataclass
class WardenResult:
    """Result returned by :meth:`Warden.process`."""

    input_hash: str
    """SHA-256 hex digest of the raw input (Channel A)."""

    output_hash: str
    """SHA-256 hex digest of the processed output (Channel B)."""

    drift: DriftResult
    """Semantic drift evaluation result."""

    ledger_entry: dict
    """The hash-chained entry appended to the Akashic Ledger."""

    capture_path: Optional[Path] = None
    """Directory of the corruption capture bundle, or ``None`` if SAFE."""

    @property
    def blocked(self) -> bool:
        """``True`` when drift status is :attr:`~warden.drift.DriftStatus.BLOCK`."""
        return self.drift.is_blocked()


class Warden:
    """Dual-channel Warden — the sole authority for validating pipeline state.

    Parameters
    ----------
    db_path:
        Path to the SQLite ledger database.  Pass ``":memory:"`` for
        an ephemeral, in-process ledger (useful in tests).
    capture_dir:
        Directory where corruption capture bundles are written.
    safe_threshold:
        Cosine-similarity score above which content is SAFE (default 0.95).
    warn_threshold:
        Score at or above which a WARNING is issued; below this → BLOCK
        (default 0.80).
    """

    def __init__(
        self,
        db_path: str = "akashic.db",
        capture_dir: str = "corruption_captures",
        safe_threshold: float = 0.95,
        warn_threshold: float = 0.80,
    ) -> None:
        self._ledger = AkashicLedger(db_path)
        self._capture = CorruptionCapture(capture_dir)
        self._safe_threshold = safe_threshold
        self._warn_threshold = warn_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(
        self,
        raw_input: str,
        processed_output: str,
        *,
        warden_signature: str = "",
        event_id: str = "",
    ) -> WardenResult:
        """Validate both channels and return a :class:`WardenResult`.

        Steps
        -----
        1. Hash Channel A (raw input) and Channel B (processed output).
        2. Compute semantic drift between the two channels.
        3. Append a tamper-evident entry to the Akashic Ledger.
        4. If drift ≥ WARNING, write a corruption capture bundle.

        Parameters
        ----------
        raw_input:
            Pre-normalisation text (Channel A).
        processed_output:
            Post-normalisation text (Channel B).
        warden_signature:
            Optional caller-supplied signature stored verbatim in the ledger.
        event_id:
            Optional identifier used to label the capture bundle directory.
        """
        # Step 1 — Dual-channel hashing
        input_hash = compute_sha256_bytes(raw_input.encode())
        output_hash = compute_sha256_bytes(processed_output.encode())

        # Step 2 — Semantic drift
        drift = evaluate_drift(
            raw_input,
            processed_output,
            safe_threshold=self._safe_threshold,
            warn_threshold=self._warn_threshold,
        )

        # Step 3 — Tamper-evident ledger entry
        entry = self._ledger.append(
            input_hash=input_hash,
            output_hash=output_hash,
            semantic_score=drift.score,
            warden_signature=warden_signature,
        )

        # Step 4 — Corruption capture for WARNING and BLOCK events
        capture_path: Optional[Path] = None
        if drift.status != DriftStatus.SAFE:
            capture_path = self._capture.capture(
                raw_input,
                processed_output,
                drift_score=drift.score,
                event_id=event_id,
            )

        return WardenResult(
            input_hash=input_hash,
            output_hash=output_hash,
            drift=drift,
            ledger_entry=entry,
            capture_path=capture_path,
        )

    def verify_ledger(self) -> bool:
        """Return ``True`` if the entire Akashic Ledger hash chain is intact."""
        return self._ledger.verify_chain()

    def close(self) -> None:
        """Close the underlying ledger database connection."""
        self._ledger.close()

    def __enter__(self) -> "Warden":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
