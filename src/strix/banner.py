from __future__ import annotations

from rich.console import Group
from rich.panel import Panel
from rich.text import Text

ACCENT = "#22d3ee"

# Static fallback banner (ansi_shadow rendering of "STRIX"). See Annex A of the brief.
BANNER = r"""   ███████╗████████╗██████╗ ██╗██╗  ██╗
   ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
   ███████╗   ██║   ██████╔╝██║ ╚███╔╝
   ╚════██║   ██║   ██╔══██╗██║ ██╔██╗
   ███████║   ██║   ██║  ██║██║██╔╝ ██╗
   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝"""

TAGLINE = "OSINT Orchestrator · they watch in the dark"


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
    """Build a Rich panel with the cyan ASCII banner, tagline and version."""
    art = _ascii_art(app_name) if use_figlet else BANNER
    body = Group(
        Text(art, style=f"bold {ACCENT}"),
        Text(f"  {TAGLINE}", style="dim italic"),
        Text(f"  v{version}", style=ACCENT),
    )
    return Panel(body, border_style=ACCENT, expand=False, padding=(0, 2))
