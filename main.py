#!/usr/bin/env python3
"""
E.A.E. — Sovereign Earned Allowance Engine
===========================================
Jarvis-style CLI.  You do not apply for your life — you manifest it.

Usage
-----
  python main.py status                 Show the live dashboard
  python main.py start [LABEL]          Start a focus session
  python main.py stop                   Stop active session and manifest points
  python main.py manifest <pts> <src>   Manually manifest points
  python main.py sync                   Sync GitHub commits (requires config)
  python main.py extract                Open the [EXTRACT] valve
  python main.py reset                  Hard-reset the vault (wipes all points)
  python main.py config                 Show current configuration
"""

from __future__ import annotations

import os
import sys

from eae.config import (
    MONTHLY_ALLOWANCE_USD,
    MONTHLY_THRESHOLD,
    POINT_VALUES,
    PRESSURE_LABELS,
)
from eae.dashboard import render_dashboard
from eae.tracker import EffortTracker
from eae.vault import VaultState
from eae.warden import IntegrityWarden


def _build_tracker() -> EffortTracker:
    vault = VaultState.load()
    owner = os.environ.get("EAE_GITHUB_OWNER")
    repo = os.environ.get("EAE_GITHUB_REPO")
    token = os.environ.get("EAE_GITHUB_TOKEN")
    return EffortTracker(vault, github_owner=owner, github_repo=repo, github_token=token)


def cmd_status(args: list[str]) -> int:
    tracker = _build_tracker()
    render_dashboard(tracker)
    return 0


def cmd_start(args: list[str]) -> int:
    label = " ".join(args) if args else "Deep Work"
    tracker = _build_tracker()
    try:
        session = tracker.start_focus_session(label=label)
        print(f"\n  ⏱  Focus session started: '{session.label}'")
        print("  Run  python main.py stop  when you're done.\n")
    except RuntimeError as exc:
        print(f"\n  [WARDEN] {exc}\n", file=sys.stderr)
        return 1
    return 0


def cmd_stop(args: list[str]) -> int:
    tracker = _build_tracker()
    points = tracker.stop_focus_session()
    if points is None:
        print("\n  No active focus session found.\n", file=sys.stderr)
        return 1
    if points == 0:
        print("\n  Session stopped. Session was under 30 minutes — no points manifested yet.")
        print("  Tip: Sustain 30+ minutes of deep work to manifest points.\n")
    else:
        print(f"\n  ✅ Points manifested: +{points}")
        print(f"  Vault level: {tracker.vault.points}/{MONTHLY_THRESHOLD}\n")
    render_dashboard(tracker)
    return 0


def cmd_manifest(args: list[str]) -> int:
    if len(args) < 1:
        print("Usage: python main.py manifest <points> [source]", file=sys.stderr)
        return 1
    try:
        points = int(args[0])
    except ValueError:
        print("Points must be an integer.", file=sys.stderr)
        return 1
    source = " ".join(args[1:]) if len(args) > 1 else "manual"
    warden = IntegrityWarden()
    source = warden.enforce(source)   # ensure sovereign language
    tracker = _build_tracker()
    total = tracker.vault.manifest_points(points, source=source)
    print(f"\n  ✅ +{points} pts manifested from '{source}'")
    print(f"  Vault level: {total}/{MONTHLY_THRESHOLD}\n")
    render_dashboard(tracker)
    return 0


def cmd_sync(args: list[str]) -> int:
    tracker = _build_tracker()
    if tracker._commit_tracker is None:
        print(
            "\n  GitHub sync not configured.\n"
            "  Set EAE_GITHUB_OWNER, EAE_GITHUB_REPO (and optionally EAE_GITHUB_TOKEN).\n",
            file=sys.stderr,
        )
        return 1
    pts = tracker.sync_commits()
    if pts:
        print(f"\n  ✅ Synced commits — +{pts} pts manifested\n")
    else:
        print("\n  No new commits found.\n")
    render_dashboard(tracker)
    return 0


def cmd_extract(args: list[str]) -> int:
    tracker = _build_tracker()
    result = tracker.vault.open_valve()
    if result is None:
        remaining = tracker.vault.monthly_threshold - tracker.vault.points
        print(
            f"\n  [VAULT] Valve is sealed. {remaining} more points required to open.\n",
            file=sys.stderr,
        )
        return 1
    print(f"\n  ✅ VALVE OPENED — ${result:.2f} allowance extracted.\n")
    print("  The Vault Cartridge resets for the next cycle.\n")
    render_dashboard(tracker)
    return 0


def cmd_reset(args: list[str]) -> int:
    confirm = input("\n  Hard-reset will wipe ALL vault points. Type RESET to confirm: ")
    if confirm.strip() != "RESET":
        print("  Aborted.\n")
        return 0
    tracker = _build_tracker()
    tracker.vault.reset()
    print("  Vault reset. Starting from zero.\n")
    return 0


def cmd_config(args: list[str]) -> int:
    print("\n  E.A.E. Configuration")
    print("  " + "─" * 40)
    print(f"  Monthly Allowance : ${MONTHLY_ALLOWANCE_USD:.2f}")
    print(f"  Points Threshold  : {MONTHLY_THRESHOLD} pts")
    print()
    print("  Socratic Point Values")
    print(f"    GitHub Commit (verified)   : {POINT_VALUES.github_commit_verified} pts")
    print(f"    GitHub Commit (unverified) : {POINT_VALUES.github_commit_unverified} pts")
    print(f"    Focus Session 30 min       : {POINT_VALUES.focus_session_30min} pts")
    print(f"    Focus Session 60 min       : {POINT_VALUES.focus_session_60min} pts")
    print(f"    Focus Session 90 min       : {POINT_VALUES.focus_session_90min} pts")
    print(f"    Code Review Completed      : {POINT_VALUES.code_review_completed} pts")
    print(f"    Documentation Committed    : {POINT_VALUES.documentation_committed} pts")
    print(f"    Bug Fix Committed          : {POINT_VALUES.bug_fix_committed} pts")
    print(f"    Test Suite Green           : {POINT_VALUES.test_suite_green} pts")
    print()
    print("  Pressure Labels:", " → ".join(PRESSURE_LABELS))
    print()
    github_owner = os.environ.get("EAE_GITHUB_OWNER", "[not set]")
    github_repo = os.environ.get("EAE_GITHUB_REPO", "[not set]")
    print(f"  GitHub Owner : {github_owner}")
    print(f"  GitHub Repo  : {github_repo}")
    print()
    return 0


COMMANDS = {
    "status": cmd_status,
    "start": cmd_start,
    "stop": cmd_stop,
    "manifest": cmd_manifest,
    "sync": cmd_sync,
    "extract": cmd_extract,
    "reset": cmd_reset,
    "config": cmd_config,
}


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        return cmd_status([])
    cmd = args[0].lower()
    if cmd not in COMMANDS:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        print(f"Available: {', '.join(COMMANDS)}", file=sys.stderr)
        return 1
    return COMMANDS[cmd](args[1:])


if __name__ == "__main__":
    sys.exit(main())
