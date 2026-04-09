"""
E.A.E. Vault — The Allowance Reservoir
=======================================
Cold-storage logic: points accumulate; the [EXTRACT] valve opens only once
the monthly threshold is crossed.

Language is intentionally sovereign:
  "Manifest Points" not "apply for credit"
  "Open Valve"       not "request withdrawal"
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from eae.config import (
    DATA_DIR,
    MONTHLY_THRESHOLD,
    MONTHLY_ALLOWANCE_USD,
    POINTS_PER_DOLLAR,
    VAULT_FILE,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class VaultState:
    points: int = 0
    monthly_threshold: int = MONTHLY_THRESHOLD
    allowance_usd: float = MONTHLY_ALLOWANCE_USD
    manifested_sessions: list[dict] = field(default_factory=list)  # audit log
    extractions: list[dict] = field(default_factory=list)          # extraction log

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    @classmethod
    def load(cls) -> "VaultState":
        """Load vault state from disk, or create a fresh state."""
        if VAULT_FILE.exists():
            try:
                data = json.loads(VAULT_FILE.read_text(encoding="utf-8"))
                return cls(**data)
            except (json.JSONDecodeError, TypeError):
                pass
        return cls()

    def save(self) -> None:
        """Persist vault state to disk."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        VAULT_FILE.write_text(
            json.dumps(self.__dict__, indent=2), encoding="utf-8"
        )

    # ------------------------------------------------------------------
    # Domain logic
    # ------------------------------------------------------------------
    @property
    def valve_open(self) -> bool:
        """The [EXTRACT] valve is physically interactable once threshold is met."""
        return self.points >= self.monthly_threshold

    @property
    def fill_ratio(self) -> float:
        """0.0 → 1.0 representing how full the Vault Cartridge is."""
        return min(1.0, self.points / self.monthly_threshold)

    @property
    def usd_equivalent(self) -> float:
        """Dollar value of current points (capped at allowance)."""
        return min(self.allowance_usd, self.points / POINTS_PER_DOLLAR)

    def manifest_points(self, amount: int, source: str = "unspecified") -> int:
        """Add *amount* points to the vault and return the new total."""
        if amount < 0:
            raise ValueError("Points must be non-negative — sovereignty is additive.")
        self.points += amount
        self.manifested_sessions.append(
            {"ts": int(time.time()), "source": source, "points": amount}
        )
        self.save()
        return self.points

    def open_valve(self) -> Optional[float]:
        """
        Attempt to open the [EXTRACT] valve.

        Returns the allowance amount if the threshold is met, None otherwise.
        The valve is a one-way gate per cycle: extracting resets the counter.
        """
        if not self.valve_open:
            return None
        extracted = self.allowance_usd
        self.extractions.append(
            {"ts": int(time.time()), "usd": extracted, "points_spent": self.points}
        )
        self.points = 0  # Reset for the next cycle
        self.save()
        return extracted

    def reset(self) -> None:
        """Hard reset — wipes all points (used by Integrity Warden tests)."""
        self.points = 0
        self.manifested_sessions.clear()
        self.save()
