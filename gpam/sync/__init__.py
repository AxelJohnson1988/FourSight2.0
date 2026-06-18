"""Policy-routed execution plane for Git↔Notion synchronisation.

This package implements a single stable interface (``SyncRequest``) with
multiple backends selected deterministically by ``SyncRouter``.

Forward path (Git → Notion)
---------------------------
- ``actions``: GitHub Actions workflow, triggered automatically on push.
- ``local``: Warden node script via cron/systemd — used for sensitive data that
  must never leave your own infrastructure.

Reverse path (Notion → Git annotations)
----------------------------------------
- ``polling``: Warden reaches OUT to Notion on a schedule. Zero inbound exposure.
- ``webhook_cloudflare``: Notion pushes IN via Cloudflare Tunnel + Access.
  Requires explicit double opt-in (env var + request flag).

Sovereignty invariants
----------------------
- Notion can only **annotate** — it can never overwrite canonical Git files.
- Webhook is never selected silently. If both opt-ins are not present, the
  router always falls back to ``polling``.
- Data classified ``REGULATED`` or under a sensitive path prefix always routes
  to ``local``, regardless of other rules.
"""

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

__all__ = [
    "DataClass",
    "ForwardBackend",
    "LatencySla",
    "ReverseBackend",
    "RoutingDecision",
    "SyncRequest",
    "SyncRouter",
    "load_policy",
]
