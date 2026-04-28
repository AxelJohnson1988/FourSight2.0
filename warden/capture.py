"""Corruption Capture Mode.

When semantic drift crosses the WARNING or BLOCK threshold the Warden
automatically saves a *capture bundle* — a directory containing:

- ``raw_input.txt``      — the pre-normalisation text (Channel A)
- ``processed_output.txt`` — the post-normalisation text (Channel B)
- ``diff.patch``         — unified diff between the two
- ``metadata.json``      — process metadata (PID, timestamp, drift score)

Each bundle is written to a configurable output directory and named by
UTC timestamp so bundles are sortable and never overwritten.

Usage::

    from warden.capture import CorruptionCapture

    cc = CorruptionCapture(output_dir="corruption_captures")
    bundle_path = cc.capture(
        raw_input="original text",
        processed_output="altered text",
        drift_score=0.72,
        event_id="evt_001",
    )
    print(f"Bundle saved to: {bundle_path}")
"""

from __future__ import annotations

import difflib
import json
import os
import time
from pathlib import Path


class CorruptionCapture:
    """Saves artefacts whenever drift triggers a WARNING or BLOCK event.

    Parameters
    ----------
    output_dir:
        Directory where capture bundles are written.  Created automatically
        if it does not already exist.
    """

    def __init__(self, output_dir: str = "corruption_captures") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def capture(
        self,
        raw_input: str,
        processed_output: str,
        *,
        drift_score: float,
        event_id: str = "",
    ) -> Path:
        """Write a capture bundle and return its directory path.

        Parameters
        ----------
        raw_input:
            The pre-normalisation text (Channel A).
        processed_output:
            The post-normalisation text (Channel B).
        drift_score:
            The cosine-similarity score that triggered capture.
        event_id:
            Optional caller-supplied identifier appended to the bundle name.
        """
        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        name = f"{ts}_{event_id}" if event_id else ts
        bundle_dir = self.output_dir / name
        bundle_dir.mkdir(parents=True, exist_ok=True)

        # Channel A — raw input
        (bundle_dir / "raw_input.txt").write_text(raw_input, encoding="utf-8")

        # Channel B — processed output
        (bundle_dir / "processed_output.txt").write_text(
            processed_output, encoding="utf-8"
        )

        # Unified diff between the two channels
        diff = _unified_diff(raw_input, processed_output)
        (bundle_dir / "diff.patch").write_text(diff, encoding="utf-8")

        # Process metadata
        metadata = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pid": os.getpid(),
            "drift_score": drift_score,
            "event_id": event_id,
            "raw_input_bytes": len(raw_input.encode()),
            "processed_output_bytes": len(processed_output.encode()),
        }
        (bundle_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )

        return bundle_dir


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _unified_diff(text_a: str, text_b: str) -> str:
    """Return a unified diff string comparing *text_a* with *text_b*."""
    lines_a = text_a.splitlines(keepends=True)
    lines_b = text_b.splitlines(keepends=True)
    diff = difflib.unified_diff(
        lines_a,
        lines_b,
        fromfile="raw_input",
        tofile="processed_output",
    )
    return "".join(diff)
