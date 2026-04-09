"""
E.A.E. Configuration — Socratic Point Values & Sovereign Settings
=================================================================
Language convention:
  - "Apply for credit"    →  "Manifest Points"
  - "Submit Form"         →  "Commit Logic"
  - "Request Withdrawal"  →  "Open Valve"
"""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATA_DIR: Path = Path.home() / ".eae"
VAULT_FILE: Path = DATA_DIR / "vault.json"
SESSION_FILE: Path = DATA_DIR / "session.json"

# ---------------------------------------------------------------------------
# Monthly allowance (the Reservoir)
# ---------------------------------------------------------------------------
MONTHLY_ALLOWANCE_USD: float = 200.0          # Fixed sovereign allowance
POINTS_PER_DOLLAR: int = 1                    # 1 point = $1
MONTHLY_THRESHOLD: int = int(MONTHLY_ALLOWANCE_USD * POINTS_PER_DOLLAR)  # 200

# Gauge pressure labels (Dormant → Pressurized)
PRESSURE_LABELS: list[str] = [
    "DORMANT",
    "WARMING",
    "ACTIVE",
    "FLOWING",
    "PRESSURIZED",
]

# ---------------------------------------------------------------------------
# Socratic Point Values  (creation-focused, no debt language)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PointValues:
    github_commit_verified: int = 10   # Commit + SHA-256 verified
    github_commit_unverified: int = 5  # Commit without GPG signature
    focus_session_30min: int = 5       # 30-minute deep-work session
    focus_session_60min: int = 12      # 60-minute deep-work session
    focus_session_90min: int = 20      # 90-minute deep-work session
    code_review_completed: int = 15    # Pull-request review finished
    documentation_committed: int = 8   # Docs committed to repo
    bug_fix_committed: int = 12        # Bug-fix commit (label/keyword)
    test_suite_green: int = 10         # Full test suite passes

    def for_focus_session(self, minutes: int) -> int:
        """Return points for a focus session of *minutes* length."""
        if minutes >= 90:
            return self.focus_session_90min
        if minutes >= 60:
            return self.focus_session_60min
        if minutes >= 30:
            return self.focus_session_30min
        return 0  # Sessions under 30 minutes don't manifest points

    def for_commit(self, *, verified: bool = False) -> int:
        """Return points for a GitHub commit."""
        return self.github_commit_verified if verified else self.github_commit_unverified


POINT_VALUES = PointValues()
