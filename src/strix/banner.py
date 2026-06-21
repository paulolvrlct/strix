from __future__ import annotations

import sys
import time

from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

# Hacker-movie phosphor palette.
ACCENT = "#00ff41"  # matrix green
DIM = "#1f8b3a"
ALERT = "#ff003c"

# Static fallback banner (ansi_shadow rendering of "STRIX"). See Annex A of the brief.
BANNER = r"""   ███████╗████████╗██████╗ ██╗██╗  ██╗
   ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
   ███████╗   ██║   ██████╔╝██║ ╚███╔╝
   ╚════██║   ██║   ██╔══██╗██║ ██╔██╗
   ███████║   ██║   ██║  ██║██║██╔╝ ██╗
   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝"""

TAGLINE = "// intrusion recon framework · they watch in the dark"

_BOOT = [
    "[ SYSTEM ONLINE ]  user: root  node: strix  clearance: ROOT",
    "> establishing covert channel ............ OK",
    "> loading recon modules .................. OK",
    "> arming OSINT payloads .................. OK",
]


def _ascii_art(app_name: str) -> str:
    """Render the app name with pyfiglet; fall back to the static banner on failure."""
    try:
        import pyfiglet

        return pyfiglet.figlet_format(app_name, font="ansi_shadow").rstrip("\n")
    except Exception:
        return BANNER


def render_banner(
    app_name: str = "STRIX", version: str = "0.1.0", *, use_figlet: bool = False
) -> Panel:
    """Build a Rich panel with the green ASCII banner, boot sequence and version."""
    art = _ascii_art(app_name) if use_figlet else BANNER
    lines: list[Text] = [
        Text(art, style=f"bold {ACCENT}"),
        Text(f"  {TAGLINE}", style=f"italic {DIM}"),
        Text(""),
    ]
    lines += [Text(f"  {line}", style=DIM) for line in _BOOT]
    lines.append(Text(f"  >> {app_name} v{version} ready. type a number to deploy.", style=ACCENT))
    return Panel(
        Group(*lines),
        title=f"[bold {ACCENT}]:: {app_name} C2 ::[/]",
        subtitle=f"[{ALERT}]● LIVE[/]",
        border_style=ACCENT,
        expand=False,
        padding=(0, 2),
    )


_BOOT_SEQUENCE = [
    "initializing kernel",
    "mounting recon modules",
    "arming OSINT payloads",
    "establishing covert channel",
    "routing through proxy mesh",
    "spoofing fingerprint",
]


def play_boot(console: Console, *, delay: float = 0.13) -> None:
    """Movie-style boot sequence: reveal lines one by one with a slight delay.

    No-op when stdout is not a TTY (pipes / CI), so it never disturbs scripts.
    """
    if not sys.stdout.isatty():
        return
    for line in _BOOT_SEQUENCE:
        dots = "." * max(3, 32 - len(line))
        console.print(f"[{DIM}]> {line}{dots}[/]", end="")
        time.sleep(delay)
        console.print(f" [bold {ACCENT}]✓ OK[/]")
    console.print(f"[bold {ACCENT}]> ACCESS GRANTED[/] [{DIM}]:: launching console ::[/]\n")
    time.sleep(0.2)
