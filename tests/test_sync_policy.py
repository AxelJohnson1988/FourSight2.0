"""Tests for gpam.sync.policy — SyncRouter deterministic routing and exposure guard."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from gpam.sync.policy import (
    DataClass,
    ForwardBackend,
    LatencySla,
    ReverseBackend,
    RoutingDecision,
    SyncRequest,
    SyncRouter,
    load_policy,
)


# ---------------------------------------------------------------------------
# Minimal policy fixtures
# ---------------------------------------------------------------------------


FULL_POLICY = {
    "forward": {
        "default": "actions",
        "rules": [
            {"match": {"path_prefix": "legal/"}, "route": "local"},
            {"match": {"path_prefix": "shadow/"}, "route": "local"},
            {"match": {"data_class": "REGULATED"}, "route": "local"},
        ],
    },
    "reverse": {
        "default": "polling",
        "rules": [
            {
                "match": {"latency_sla": "realtime", "inbound_exposure_allowed": True},
                "route": "webhook_cloudflare",
            }
        ],
    },
    "routing": {
        "sensitive_path_prefixes": ["legal/", "shadow/", "medical/"],
    },
}

EMPTY_POLICY: dict = {}


# ---------------------------------------------------------------------------
# Forward routing
# ---------------------------------------------------------------------------


def test_forward_default_is_actions() -> None:
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(path_prefix="docs/adr/")
    decision = router.route(req)
    assert decision.forward == ForwardBackend.ACTIONS
    assert decision.forward_rule_matched == "default"


def test_forward_legal_prefix_routes_local_via_rule() -> None:
    """legal/ is in both hard-guard prefixes and explicit rules."""
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(path_prefix="legal/some-file.md")
    decision = router.route(req)
    assert decision.forward == ForwardBackend.LOCAL


def test_forward_shadow_prefix_routes_local() -> None:
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(path_prefix="shadow/case.md")
    decision = router.route(req)
    assert decision.forward == ForwardBackend.LOCAL


def test_forward_medical_prefix_routes_local_via_hard_guard() -> None:
    """medical/ is in sensitive_path_prefixes but not in rules — hard guard fires."""
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(path_prefix="medical/records.md")
    decision = router.route(req)
    assert decision.forward == ForwardBackend.LOCAL
    assert "hard-guard" in decision.forward_rule_matched


def test_forward_regulated_data_class_routes_local() -> None:
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(path_prefix="docs/secret.md", data_class=DataClass.REGULATED)
    decision = router.route(req)
    assert decision.forward == ForwardBackend.LOCAL
    assert "REGULATED" in decision.forward_rule_matched


def test_forward_regulated_hard_guard_fires_before_rules() -> None:
    """REGULATED is checked before path-prefix rules."""
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(path_prefix="docs/public.md", data_class=DataClass.REGULATED)
    decision = router.route(req)
    # Hard guard fires — matched label should indicate the REGULATED guard.
    assert decision.forward == ForwardBackend.LOCAL
    assert "REGULATED" in decision.forward_rule_matched


def test_forward_public_data_uses_default() -> None:
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(path_prefix="docs/", data_class=DataClass.PUBLIC)
    decision = router.route(req)
    assert decision.forward == ForwardBackend.ACTIONS


def test_forward_gpam_prefix_uses_actions() -> None:
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(path_prefix="gpam/memory_blocks/")
    decision = router.route(req)
    assert decision.forward == ForwardBackend.ACTIONS


def test_forward_custom_default_local() -> None:
    policy = {"forward": {"default": "local"}, "reverse": {"default": "polling"}}
    router = SyncRouter(policy)
    req = SyncRequest(path_prefix="docs/")
    decision = router.route(req)
    assert decision.forward == ForwardBackend.LOCAL


# ---------------------------------------------------------------------------
# Reverse routing
# ---------------------------------------------------------------------------


def test_reverse_default_is_polling() -> None:
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(path_prefix="docs/")
    decision = router.route(req)
    assert decision.reverse == ReverseBackend.POLLING
    assert decision.reverse_rule_matched == "default"


def test_reverse_batch_sla_is_polling() -> None:
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(
        path_prefix="docs/",
        latency_sla=LatencySla.BATCH,
        inbound_exposure_allowed=True,
    )
    decision = router.route(req)
    # latency_sla must be realtime AND exposure allowed — batch alone → polling.
    assert decision.reverse == ReverseBackend.POLLING


def test_reverse_realtime_without_exposure_flag_is_polling() -> None:
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(
        path_prefix="docs/",
        latency_sla=LatencySla.REALTIME,
        inbound_exposure_allowed=False,
    )
    decision = router.route(req)
    # inbound_exposure_allowed is False — cannot match the webhook rule.
    assert decision.reverse == ReverseBackend.POLLING


# ---------------------------------------------------------------------------
# Exposure guard
# ---------------------------------------------------------------------------


def test_exposure_guard_blocks_webhook_without_env_var() -> None:
    """Rule matches but env var is absent → guard overrides to polling."""
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(
        path_prefix="docs/",
        latency_sla=LatencySla.REALTIME,
        inbound_exposure_allowed=True,
    )
    # INBOUND_EXPOSURE_ALLOWED not set — guard must block.
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("INBOUND_EXPOSURE_ALLOWED", None)
        decision = router.route(req)

    assert decision.reverse == ReverseBackend.POLLING
    assert decision.exposure_guard_overrode_webhook is True


def test_exposure_guard_allows_webhook_with_both_opt_ins() -> None:
    """Both request flag AND env var present → webhook is selected."""
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(
        path_prefix="docs/",
        latency_sla=LatencySla.REALTIME,
        inbound_exposure_allowed=True,
    )
    with patch.dict(os.environ, {"INBOUND_EXPOSURE_ALLOWED": "true"}):
        decision = router.route(req)

    assert decision.reverse == ReverseBackend.WEBHOOK_CLOUDFLARE
    assert decision.exposure_guard_overrode_webhook is False


def test_exposure_guard_blocks_on_env_var_false() -> None:
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(
        path_prefix="docs/",
        latency_sla=LatencySla.REALTIME,
        inbound_exposure_allowed=True,
    )
    with patch.dict(os.environ, {"INBOUND_EXPOSURE_ALLOWED": "false"}):
        decision = router.route(req)

    assert decision.reverse == ReverseBackend.POLLING
    assert decision.exposure_guard_overrode_webhook is True


def test_exposure_guard_is_case_insensitive() -> None:
    """Env var 'TRUE' or 'True' should be accepted."""
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(
        path_prefix="docs/",
        latency_sla=LatencySla.REALTIME,
        inbound_exposure_allowed=True,
    )
    for value in ("TRUE", "True", "true"):
        with patch.dict(os.environ, {"INBOUND_EXPOSURE_ALLOWED": value}):
            decision = router.route(req)
        assert decision.reverse == ReverseBackend.WEBHOOK_CLOUDFLARE, (
            f"Expected WEBHOOK for env value={value!r}"
        )


# ---------------------------------------------------------------------------
# RoutingDecision invariants
# ---------------------------------------------------------------------------


def test_routing_decision_is_frozen() -> None:
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(path_prefix="docs/")
    decision = router.route(req)
    with pytest.raises((AttributeError, TypeError)):
        decision.forward = ForwardBackend.LOCAL  # type: ignore[misc]


def test_routing_decision_has_all_fields() -> None:
    router = SyncRouter(FULL_POLICY)
    req = SyncRequest(path_prefix="gpam/")
    decision = router.route(req)
    assert isinstance(decision, RoutingDecision)
    assert decision.forward in ForwardBackend
    assert decision.reverse in ReverseBackend
    assert isinstance(decision.forward_rule_matched, str)
    assert isinstance(decision.reverse_rule_matched, str)
    assert isinstance(decision.exposure_guard_overrode_webhook, bool)


# ---------------------------------------------------------------------------
# load_policy
# ---------------------------------------------------------------------------


def test_load_policy_reads_yaml(tmp_path) -> None:
    policy_file = tmp_path / "sync-policy.yml"
    policy_file.write_text(
        "forward:\n  default: local\nreverse:\n  default: polling\n",
        encoding="utf-8",
    )
    policy = load_policy(policy_file)
    assert policy["forward"]["default"] == "local"


def test_load_policy_raises_on_missing_file(tmp_path) -> None:
    with pytest.raises(FileNotFoundError, match="sync-policy.yml"):
        load_policy(tmp_path / "nonexistent.yml")


def test_load_policy_raises_on_invalid_yaml(tmp_path) -> None:
    bad_file = tmp_path / "bad.yml"
    bad_file.write_text("forward: [\nunclosed", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to parse"):
        load_policy(bad_file)


def test_load_policy_empty_file_returns_empty_dict(tmp_path) -> None:
    empty_file = tmp_path / "empty.yml"
    empty_file.write_text("", encoding="utf-8")
    result = load_policy(empty_file)
    assert result == {}


# ---------------------------------------------------------------------------
# SyncRouter with empty policy (graceful defaults)
# ---------------------------------------------------------------------------


def test_router_with_empty_policy_uses_defaults() -> None:
    router = SyncRouter(EMPTY_POLICY)
    req = SyncRequest(path_prefix="docs/")
    decision = router.route(req)
    assert decision.forward == ForwardBackend.ACTIONS
    assert decision.reverse == ReverseBackend.POLLING


# ---------------------------------------------------------------------------
# Rule order (first match wins)
# ---------------------------------------------------------------------------


def test_first_matching_rule_wins() -> None:
    policy = {
        "forward": {
            "default": "actions",
            "rules": [
                {"match": {"path_prefix": "docs/"}, "route": "local"},
                {"match": {"path_prefix": "docs/"}, "route": "actions"},  # unreachable
            ],
        },
        "reverse": {"default": "polling"},
    }
    router = SyncRouter(policy)
    req = SyncRequest(path_prefix="docs/adr/")
    decision = router.route(req)
    assert decision.forward == ForwardBackend.LOCAL


# ---------------------------------------------------------------------------
# SyncRequest defaults
# ---------------------------------------------------------------------------


def test_sync_request_defaults() -> None:
    req = SyncRequest(path_prefix="docs/")
    assert req.data_class == DataClass.INTERNAL
    assert req.latency_sla == LatencySla.BATCH
    assert req.inbound_exposure_allowed is False
