"""ScanWatcher — per-file observer hook for FourSight 2.0 (Phase 2).

A :class:`ScanWatcher` is an optional observer that can be passed to
:func:`phoenix_scanner.scanner.scan`.  It enforces two independent budgets:

* **max_findings_per_file** – caps the number of findings retained for any
  single file.  When exceeded the file's findings are truncated and an alert
  is fired.
* **elapsed_time_budget** – wall-clock seconds allowed per file.  In
  *sandboxed* mode this is enforced by abandoning the worker future; in
  inline mode it acts as a post-hoc warning only.

Alerts are delivered to an optional ``alert_callback`` callable with the
signature ``(event: str, message: str) -> None``.  Known event strings:

``"max-findings-per-file"``
    Findings cap exceeded; list was truncated.
``"elapsed-time-budget"``
    Worker timed out; findings for this file are empty.
``"threshold-exceeded"``
    Generic threshold violation (fired alongside the specific event).

Example
-------
::

    from phoenix_scanner.watcher import ScanWatcher

    alerts = []
    watcher = ScanWatcher(
        max_findings_per_file=500,
        elapsed_time_budget=5.0,
        alert_callback=lambda event, msg: alerts.append((event, msg)),
    )
    findings = scan(entries, config, watcher=watcher)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)


@dataclass
class ScanWatcher:
    """Observer that enforces per-file scanning budgets.

    Parameters
    ----------
    max_findings_per_file:
        Maximum findings retained for a single file.  ``0`` disables the cap.
    elapsed_time_budget:
        Wall-clock seconds per file before a timeout is declared.
        ``0.0`` disables the budget.
    alert_callback:
        Optional callable invoked as ``alert_callback(event, message)``
        whenever a threshold is breached.  Exceptions raised inside the
        callback are suppressed so they never abort the scan.
    """

    max_findings_per_file: int = 0
    elapsed_time_budget: float = 0.0
    alert_callback: Callable[[str, str], None] | None = field(default=None, repr=False)

    def alert(self, event: str, message: str) -> None:
        """Fire the alert callback (if registered) and log at WARNING level."""
        logger.warning("ScanWatcher [%s]: %s", event, message)
        if self.alert_callback is not None:
            try:
                self.alert_callback(event, message)
            except Exception:  # noqa: BLE001
                pass  # Never let a broken callback abort the scan
