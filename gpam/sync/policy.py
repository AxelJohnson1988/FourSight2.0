"""Deterministic sync routing policy — SyncRequest, SyncRouter, exposure guard.

Key design decisions
--------------------
* Rules are evaluated **in order** — first match wins.
* ``webhook_cloudflare`` is **doubly guarded**:
    1. The ``SyncRequest.inbound_exposure_allowed`` flag must be ``True``.
    2. The ``INBOUND_EXPOSURE_ALLOWED`` environment variable must be ``"true"``.
  If either guard fails, the router falls back to ``polling`` and logs the
  override so the decision is always auditable.
* REGULATED data and sensitive path prefixes short-circuit to ``local`` before
  any other forward rule is evaluated.
* The router is stateless and pure — all routing inputs are explicit.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DataClass(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    REGULATED = "REGULATED"


class LatencySla(str, Enum):
    REALTIME = "realtime"
    BATCH = "batch"


class ForwardBackend(str, Enum):
    ACTIONS = "actions"
    LOCAL = "local"


class ReverseBackend(str, Enum):
    POLLING = "polling"
    WEBHOOK_CLOUDFLARE = "webhook_cloudflare"


# ---------------------------------------------------------------------------
# Request + Decision types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SyncRequest:
    """All routing inputs — must be explicit, never guessed.

    Parameters
    ----------
    path_prefix:
        File path prefix of the content being synced, e.g. ``"docs/adr/"``.
    data_class:
        Sensitivity classification of the content.
    latency_sla:
        ``REALTIME`` if annotation delay is unacceptable; ``BATCH`` otherwise.
    inbound_exposure_allowed:
        Set ``True`` only when you have consciously accepted inbound network
        exposure (required alongside ``INBOUND_EXPOSURE_ALLOWED=true`` env var
        before ``webhook_cloudflare`` can be selected).
    """

    path_prefix: str
    data_class: DataClass = DataClass.INTERNAL
    latency_sla: LatencySla = LatencySla.BATCH
    inbound_exposure_allowed: bool = False


@dataclass(frozen=True)
class RoutingDecision:
    """Result of a routing evaluation.

    Attributes
    ----------
    forward:
        Selected forward backend.
    reverse:
        Selected reverse backend.
    forward_rule_matched:
        Description of the rule that determined the forward backend
        (``"default"`` when no rule matched).
    reverse_rule_matched:
        Same for reverse.
    exposure_guard_overrode_webhook:
        ``True`` when ``webhook_cloudflare`` was blocked by the exposure guard
        and ``polling`` was substituted.  Always auditable.
    """

    forward: ForwardBackend
    reverse: ReverseBackend
    forward_rule_matched: str = "default"
    reverse_rule_matched: str = "default"
    exposure_guard_overrode_webhook: bool = False


# ---------------------------------------------------------------------------
# Policy loader
# ---------------------------------------------------------------------------


def load_policy(path: Path = Path("sync-policy.yml")) -> Dict[str, Any]:
    """Load and return the raw policy dict from *path*.

    Parameters
    ----------
    path:
        Path to the YAML policy file.  Defaults to ``sync-policy.yml`` in the
        current working directory.

    Raises
    ------
    FileNotFoundError
        If the policy file does not exist.
    ValueError
        If the YAML cannot be parsed.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Sync policy file not found: {path}. "
            "Create sync-policy.yml or pass an explicit path."
        )
    try:
        with path.open(encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse sync policy {path}: {exc}") from exc


# ---------------------------------------------------------------------------
# SyncRouter
# ---------------------------------------------------------------------------


class SyncRouter:
    """Deterministic policy router for forward and reverse sync backends.

    Parameters
    ----------
    policy:
        Raw policy dict from :func:`load_policy`.

    Examples
    --------
    >>> from gpam.sync.policy import SyncRouter, SyncRequest, DataClass, LatencySla
    >>> router = SyncRouter({"forward": {"default": "actions"}, "reverse": {"default": "polling"}})
    >>> req = SyncRequest(path_prefix="docs/adr/")
    >>> decision = router.route(req)
    >>> decision.forward
    <ForwardBackend.ACTIONS: 'actions'>
    >>> decision.reverse
    <ReverseBackend.POLLING: 'polling'>
    """

    def __init__(self, policy: Dict[str, Any]) -> None:
        self._forward_default = ForwardBackend(
            policy.get("forward", {}).get("default", "actions")
        )
        self._forward_rules: List[Dict[str, Any]] = (
            policy.get("forward", {}).get("rules", [])
        )
        self._reverse_default = ReverseBackend(
            policy.get("reverse", {}).get("default", "polling")
        )
        self._reverse_rules: List[Dict[str, Any]] = (
            policy.get("reverse", {}).get("rules", [])
        )
        self._sensitive_prefixes: List[str] = (
            policy.get("routing", {}).get("sensitive_path_prefixes", [])
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def route(self, req: SyncRequest) -> RoutingDecision:
        """Evaluate *req* against the policy and return a :class:`RoutingDecision`.

        This method is pure — it does not start any process or make any network
        call.  Side-effects live in the backend runners.
        """
        forward, fwd_label = self._route_forward(req)
        reverse, rev_label, guard_overrode = self._route_reverse(req)
        return RoutingDecision(
            forward=forward,
            reverse=reverse,
            forward_rule_matched=fwd_label,
            reverse_rule_matched=rev_label,
            exposure_guard_overrode_webhook=guard_overrode,
        )

    # ------------------------------------------------------------------
    # Forward routing
    # ------------------------------------------------------------------

    def _route_forward(self, req: SyncRequest) -> tuple[ForwardBackend, str]:
        # Hard guard 1: REGULATED data is always local.
        if req.data_class == DataClass.REGULATED:
            return ForwardBackend.LOCAL, "hard-guard:data_class=REGULATED"

        # Hard guard 2: sensitive path prefixes are always local.
        for prefix in self._sensitive_prefixes:
            if req.path_prefix.startswith(prefix):
                return ForwardBackend.LOCAL, f"hard-guard:sensitive_path_prefix={prefix}"

        # Evaluate rules in order (first match wins).
        for rule in self._forward_rules:
            if self._matches(rule, req):
                route = ForwardBackend(rule["route"])
                return route, f"rule:{rule}"

        return self._forward_default, "default"

    # ------------------------------------------------------------------
    # Reverse routing
    # ------------------------------------------------------------------

    def _route_reverse(
        self, req: SyncRequest
    ) -> tuple[ReverseBackend, str, bool]:
        """Return (backend, label, exposure_guard_overrode)."""
        for rule in self._reverse_rules:
            if self._matches(rule, req):
                candidate = ReverseBackend(rule["route"])
                if candidate == ReverseBackend.WEBHOOK_CLOUDFLARE:
                    if self._webhook_exposure_allowed(req):
                        return candidate, f"rule:{rule}", False
                    # Guard blocked it — fall back to polling and mark override.
                    return ReverseBackend.POLLING, f"rule:{rule}:guard_fallback", True
                return candidate, f"rule:{rule}", False

        return self._reverse_default, "default", False

    # ------------------------------------------------------------------
    # Rule matching
    # ------------------------------------------------------------------

    @staticmethod
    def _matches(rule: Dict[str, Any], req: SyncRequest) -> bool:
        """Return ``True`` iff every key in ``rule["match"]`` matches *req* (AND logic)."""
        match = rule.get("match", {})
        for key, expected in match.items():
            if key == "path_prefix":
                if not req.path_prefix.startswith(str(expected)):
                    return False
            elif key == "data_class":
                if req.data_class.value != str(expected):
                    return False
            elif key == "latency_sla":
                if req.latency_sla.value != str(expected):
                    return False
            elif key == "inbound_exposure_allowed":
                if req.inbound_exposure_allowed != bool(expected):
                    return False
        return True

    # ------------------------------------------------------------------
    # Exposure guard
    # ------------------------------------------------------------------

    @staticmethod
    def _webhook_exposure_allowed(req: SyncRequest) -> bool:
        """Return ``True`` only if BOTH opt-ins are present.

        Conditions:
        1. ``SyncRequest.inbound_exposure_allowed`` is ``True``.
        2. Environment variable ``INBOUND_EXPOSURE_ALLOWED`` equals ``"true"``.

        If either is absent, the guard blocks ``webhook_cloudflare`` and the
        router falls back to ``polling``.  This prevents accidental inbound
        public endpoints.
        """
        if not req.inbound_exposure_allowed:
            return False
        env_flag = os.environ.get("INBOUND_EXPOSURE_ALLOWED", "false").lower().strip()
        return env_flag == "true"
