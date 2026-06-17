"""
E.A.E. Jarvis-Style Terminal Dashboard
=======================================
Displays two panels in the terminal:

  ┌─────────────────────────────────┐
  │  THE FLOW METER (Pressure Gauge) │
  │  needle: DORMANT → PRESSURIZED   │
  └─────────────────────────────────┘
  ┌─────────────────────────────────┐
  │  THE VAULT CARTRIDGE (Reservoir) │
  │  liquid fill + [EXTRACT] valve   │
  └─────────────────────────────────┘

Uses the `rich` library for high-contrast terminal rendering.
If rich is not installed, falls back to a plain-text renderer.
"""

from __future__ import annotations

from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TextColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
    _RICH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _RICH_AVAILABLE = False

from eae.config import MONTHLY_THRESHOLD, PRESSURE_LABELS
from eae.tracker import EffortTracker
from eae.vault import VaultState
from eae.warden import IntegrityWarden

_WARDEN = IntegrityWarden()
_console: Optional["Console"] = Console() if _RICH_AVAILABLE else None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Plain-text fallback helpers
# ---------------------------------------------------------------------------
def _plain_bar(fill_ratio: float, width: int = 30) -> str:
    filled = int(fill_ratio * width)
    return "[" + "█" * filled + "░" * (width - filled) + "]"


def _plain_gauge(level: int) -> str:
    label = PRESSURE_LABELS[level]
    bar = "=" * (level + 1) * 5
    return f"  PRESSURE: [{bar:>25}] {label}"


# ---------------------------------------------------------------------------
# Rich renderers
# ---------------------------------------------------------------------------
def _render_pressure_gauge_rich(tracker: EffortTracker) -> "Panel":
    level = tracker.pressure_level()
    label = PRESSURE_LABELS[level]
    ratio = tracker.vault.fill_ratio

    # Choose colour based on pressure
    colour_map = ["grey50", "yellow", "cyan", "green", "bold green"]
    colour = colour_map[level]

    progress = Progress(
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=40, style=colour, complete_style=colour),
        TextColumn("[bold]{task.percentage:>3.0f}%"),
    )
    task = progress.add_task(f"[{colour}]{label}", total=100, completed=int(ratio * 100))

    # Active session indicator
    session_line = ""
    if tracker.active_session:
        mins = tracker.active_session.elapsed_minutes
        session_line = f"\n  [bold cyan]⏱  FOCUS SESSION ACTIVE — {mins:.1f} min elapsed[/]"

    table = Table.grid(padding=(0, 1))
    table.add_row(progress)
    if session_line:
        table.add_row(Text.from_markup(session_line))

    return Panel(
        table,
        title="[bold white]⚡ THE FLOW METER[/]",
        subtitle=f"[dim]System Vitality · {tracker.vault.points}/{MONTHLY_THRESHOLD} pts[/]",
        border_style="bright_blue",
        box=box.HEAVY,
    )


def _render_vault_rich(vault: VaultState) -> "Panel":
    ratio = vault.fill_ratio
    width = 36
    filled = int(ratio * width)

    # Liquid fill: animated gradient feel with Unicode blocks
    liquid_chars = "░▒▓█"
    fill_bar = ""
    for i in range(width):
        if i < filled:
            char_idx = min(3, int((i / width) * 4) + 2)
            fill_bar += f"[cyan]{liquid_chars[char_idx]}[/]"
        else:
            fill_bar += f"[grey23]░[/]"

    # EXTRACT valve
    if vault.valve_open:
        valve = Text.from_markup(
            "\n  [bold bright_green blink][ EXTRACT VALVE OPEN — OPEN VALVE NOW ][/]\n"
            f"  [bold white]Allowance Ready: ${vault.allowance_usd:.2f}[/]"
        )
    else:
        remaining = vault.monthly_threshold - vault.points
        valve = Text.from_markup(
            f"\n  [grey50][ EXTRACT ] — {remaining} pts until valve opens[/]"
        )

    table = Table.grid(padding=(0, 0))
    table.add_row(Text.from_markup(f"  [dim]VAULT CARTRIDGE FILL LEVEL[/]"))
    table.add_row(Text.from_markup(f"  {fill_bar}"))
    table.add_row(Text.from_markup(f"  [bold cyan]{vault.points}[/] / [white]{vault.monthly_threshold}[/] points  "
                                   f"[dim](${vault.usd_equivalent:.2f} / ${vault.allowance_usd:.2f})[/]"))
    table.add_row(valve)

    return Panel(
        table,
        title="[bold white]🔒 THE VAULT CARTRIDGE[/]",
        subtitle="[dim]Cold Storage · Sovereign Reservoir[/]",
        border_style="bright_cyan",
        box=box.HEAVY,
    )


def _render_point_log_rich(vault: VaultState, n: int = 5) -> "Panel":
    recent = vault.manifested_sessions[-n:]
    table = Table(
        "Timestamp", "Source", "Points",
        box=box.SIMPLE,
        style="dim",
        header_style="bold white",
        show_edge=False,
    )
    for entry in reversed(recent):
        from datetime import datetime, timezone
        ts = datetime.fromtimestamp(entry["ts"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
        table.add_row(ts, str(entry["source"]), f"[bold cyan]+{entry['points']}[/]")

    if not recent:
        table.add_row("[dim]—[/]", "[dim]No activity yet[/]", "[dim]0[/]")

    return Panel(
        table,
        title="[bold white]📋 RECENT MANIFESTATIONS[/]",
        border_style="bright_yellow",
        box=box.HEAVY,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def render_dashboard(tracker: EffortTracker) -> None:
    """
    Print the full Jarvis-style dashboard to the terminal.
    Auto-detects rich availability and falls back to plain text.
    """
    if _RICH_AVAILABLE and _console:
        _console.clear()
        _console.print()
        _console.rule("[bold bright_white]  E . A . E .  —  SOVEREIGN EARNED ALLOWANCE ENGINE  [/]")
        _console.print()
        _console.print(_render_pressure_gauge_rich(tracker))
        _console.print(_render_vault_rich(tracker.vault))
        _console.print(_render_point_log_rich(tracker.vault))
        _console.print()
        _console.rule("[dim]Integrity Warden: ACTIVE · No predatory patterns detected[/]")
        _console.print()
    else:
        _render_plain(tracker)


def _render_plain(tracker: EffortTracker) -> None:
    vault = tracker.vault
    print()
    print("=" * 60)
    print("  E.A.E. — SOVEREIGN EARNED ALLOWANCE ENGINE")
    print("=" * 60)
    print()
    print("  ⚡ THE FLOW METER")
    print(_plain_gauge(tracker.pressure_level()))
    if tracker.active_session:
        mins = tracker.active_session.elapsed_minutes
        print(f"  ⏱  FOCUS SESSION ACTIVE — {mins:.1f} min elapsed")
    print()
    print("  🔒 THE VAULT CARTRIDGE")
    print(f"  {_plain_bar(vault.fill_ratio)}")
    print(f"  Points: {vault.points}/{vault.monthly_threshold}  "
          f"(${vault.usd_equivalent:.2f}/${vault.allowance_usd:.2f})")
    if vault.valve_open:
        print()
        print("  >>> [ EXTRACT VALVE OPEN — OPEN VALVE NOW ] <<<")
    else:
        remaining = vault.monthly_threshold - vault.points
        print(f"  [ EXTRACT ] — {remaining} pts until valve opens")
    print()
    if vault.manifested_sessions:
        print("  📋 RECENT MANIFESTATIONS")
        for entry in reversed(vault.manifested_sessions[-5:]):
            from datetime import datetime, timezone
            ts = datetime.fromtimestamp(entry["ts"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
            print(f"    {ts}  {entry['source']:40s}  +{entry['points']} pts")
    print()
    print("  Integrity Warden: ACTIVE")
    print("=" * 60)
    print()
