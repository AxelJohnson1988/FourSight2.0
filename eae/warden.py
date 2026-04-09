"""
E.A.E. Integrity Warden
========================
The Warden Daemon ensures the internal UI stays Clean, Socratic, and Truthful.
It is forbidden from using "Financial Simulation" language and will flag or
replace any predatory patterns it detects in text intended for display.

Predatory patterns (Big Finance / scam-funnel):
  - "apply for credit / loan / funding"
  - "submit form / application"
  - "request withdrawal / payment"
  - "approval" language
  - "account balance / overdraft / interest rate"
  - Anything that frames the user as a *supplicant* rather than a *sovereign*

Sovereign replacements are defined in SOVEREIGN_SUBSTITUTIONS.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Predatory-pattern → Sovereign-pattern substitutions
# ---------------------------------------------------------------------------
SOVEREIGN_SUBSTITUTIONS: list[tuple[re.Pattern, str]] = [
    # Apply / application
    (re.compile(r"\bapply\s+for\b", re.IGNORECASE), "manifest"),
    (re.compile(r"\bapplication\b", re.IGNORECASE), "commitment"),
    (re.compile(r"\bapplicant\b", re.IGNORECASE), "architect"),
    # Credit / debt / loan language
    (re.compile(r"\bcredit\b", re.IGNORECASE), "point reserve"),
    (re.compile(r"\bloan\b", re.IGNORECASE), "advance"),
    (re.compile(r"\bdebt\b", re.IGNORECASE), "deficit"),
    (re.compile(r"\binterest\s+rate\b", re.IGNORECASE), "manifested ratio"),
    (re.compile(r"\boverdraft\b", re.IGNORECASE), "reserve shortfall"),
    # Approval / permission
    (re.compile(r"\bapproval\b", re.IGNORECASE), "threshold confirmation"),
    (re.compile(r"\bapproved\b", re.IGNORECASE), "threshold met"),
    (re.compile(r"\bdenied\b", re.IGNORECASE), "threshold not yet reached"),
    (re.compile(r"\bpending\s+review\b", re.IGNORECASE), "in flow"),
    # Submission
    (re.compile(r"\bsubmit\s+(a\s+)?form\b", re.IGNORECASE), "commit logic"),
    (re.compile(r"\bsubmission\b", re.IGNORECASE), "commitment"),
    # Withdrawal / payment request
    (re.compile(r"\brequest\s+withdrawal\b", re.IGNORECASE), "open valve"),
    (re.compile(r"\bwithdrawal\b", re.IGNORECASE), "extraction"),
    (re.compile(r"\bwithdraw\b", re.IGNORECASE), "extract"),
    # Account language
    (re.compile(r"\baccount\s+balance\b", re.IGNORECASE), "vault level"),
    (re.compile(r"\baccount\b", re.IGNORECASE), "vault"),
]

# Patterns that trigger a "Visual Purge" alert (not just replacement)
PURGE_TRIGGERS: list[re.Pattern] = [
    re.compile(r"\bSSN\b|\bsocial\s+security\b", re.IGNORECASE),
    re.compile(r"\bcredit\s+score\b", re.IGNORECASE),
    re.compile(r"\bbank\s+(account|statement|routing)\b", re.IGNORECASE),
    re.compile(r"\bscam\b", re.IGNORECASE),
    re.compile(r"\bpayday\s+loan\b", re.IGNORECASE),
    re.compile(r"\bpredatory\b", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Warden result
# ---------------------------------------------------------------------------
@dataclass
class WardenResult:
    original: str
    cleansed: str
    flags: list[str] = field(default_factory=list)
    purge_required: bool = False

    @property
    def was_modified(self) -> bool:
        return self.original != self.cleansed

    @property
    def is_clean(self) -> bool:
        return not self.purge_required and not self.flags


# ---------------------------------------------------------------------------
# Warden
# ---------------------------------------------------------------------------
class IntegrityWarden:
    """
    Scans text (UI strings, log messages, etc.) and enforces sovereign language.
    """

    def scan(self, text: str) -> WardenResult:
        """
        Scan *text* for predatory patterns.

        Returns a WardenResult with:
          - cleansed text (substitutions applied)
          - flags (list of pattern names detected)
          - purge_required flag (if a hard-purge trigger is found)
        """
        flags: list[str] = []
        purge_required = False

        # Check for hard-purge triggers first
        for pattern in PURGE_TRIGGERS:
            if pattern.search(text):
                flags.append(f"PURGE_TRIGGER:{pattern.pattern}")
                purge_required = True

        # Apply sovereign substitutions
        cleansed = text
        for pattern, replacement in SOVEREIGN_SUBSTITUTIONS:
            new_text, n_subs = re.subn(pattern, replacement, cleansed)
            if n_subs > 0:
                flags.append(f"SUBSTITUTED:{pattern.pattern}→{replacement}")
                cleansed = new_text

        return WardenResult(
            original=text,
            cleansed=cleansed,
            flags=flags,
            purge_required=purge_required,
        )

    def enforce(self, text: str) -> str:
        """
        Convenience method: scan and return the cleansed text.
        Raises ValueError if a purge trigger is detected.
        """
        result = self.scan(text)
        if result.purge_required:
            raise ValueError(
                f"[WARDEN] Visual Purge triggered — predatory content detected: "
                f"{result.flags}"
            )
        return result.cleansed
