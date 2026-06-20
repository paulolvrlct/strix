#!/usr/bin/env python3
"""Generate docs/demo.png — a terminal-style screenshot of STRIX output.

Renders the banner, a sample module table and the summary panel with a recording
Rich console, then rasterizes to PNG. Preferred path is a headless Chrome
screenshot of Rich's HTML export (block glyphs tile solidly); falls back to
cairosvg on the SVG export when no Chrome-family browser is available.

Usage:
    python scripts/generate_demo.py
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.terminal_theme import SVG_EXPORT_THEME

from strix.banner import render_banner
from strix.models import Finding, ModuleResult, Report, Severity, TargetType

_SEV_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "orange3",
    Severity.HIGH: "bold red",
}

_MONO = "Menlo,'DejaVu Sans Mono',monospace"

_CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
]


def _sample_report() -> Report:
    started = datetime(2026, 6, 20, 12, 0, 0, tzinfo=timezone.utc)
    findings = [
        Finding(title="Open port", value="53", source="shodan-internetdb"),
        Finding(title="Open port", value="443", source="shodan-internetdb"),
        Finding(title="Hostname", value="one.one.one.one", source="shodan-internetdb"),
        Finding(
            title="Known CVE",
            value="CVE-2023-50387",
            source="shodan-internetdb",
            url="https://nvd.nist.gov/vuln/detail/CVE-2023-50387",
            severity=Severity.HIGH,
        ),
        Finding(title="Country", value="Australia", source="ip-api"),
        Finding(title="ISP", value="Cloudflare, Inc", source="ip-api"),
        Finding(title="ASN", value="AS13335 Cloudflare, Inc.", source="ip-api"),
        Finding(title="Coordinates", value="-27.4766, 153.0166", source="ip-api"),
    ]
    module = ModuleResult(
        module="ip",
        target="1.1.1.1",
        target_type=TargetType.IP,
        started_at=started,
        finished_at=started + timedelta(milliseconds=240),
        findings=findings,
    )
    return Report(target="1.1.1.1", target_type=TargetType.IP, modules=[module])


def _render(console: Console, report: Report) -> None:
    console.print(render_banner("STRIX", "0.1.0"))
    console.print()
    for module in report.modules:
        table = Table(
            title=f"{module.module}  ({module.duration_s:.1f}s)",
            header_style="bold #22d3ee",
        )
        table.add_column("Title")
        table.add_column("Value", overflow="fold")
        table.add_column("Source")
        table.add_column("Severity")
        for f in module.findings:
            style = _SEV_STYLE.get(f.severity, "white")
            table.add_row(f.title, f.value, f.source, f"[{style}]{f.severity.value}[/]")
        console.print(table)

    body = (
        f"[bold]Target[/]: {report.target}\n"
        f"[bold]Type[/]: {report.target_type.value}\n"
        f"[bold]Findings[/]: {report.total_findings}\n"
        f"[bold]Failed modules[/]: none\n"
        f"[bold]Duration[/]: 0.2s\n"
        f"[bold]Report[/]: output/1.1.1.1_20260620_120000"
    )
    console.print(Panel(body, title="Summary", border_style="#22d3ee"))


def _find_chrome() -> str | None:
    for candidate in _CHROME_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return shutil.which("google-chrome") or shutil.which("chromium")


def _png_via_chrome(chrome: str, html_path: Path, png_path: Path) -> None:
    subprocess.run(
        [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--force-device-scale-factor=2",
            "--window-size=720,700",
            f"--screenshot={png_path}",
            html_path.resolve().as_uri(),
        ],
        check=True,
        capture_output=True,
    )


def _png_via_cairosvg(svg: str, png_path: Path) -> None:
    import cairosvg

    cairosvg.svg2png(bytestring=svg.encode("utf-8"), write_to=str(png_path), output_width=1000)


def main() -> None:
    docs = Path(__file__).resolve().parents[1] / "docs"
    docs.mkdir(exist_ok=True)
    html_path = docs / "_demo.html"
    svg_path = docs / "demo.svg"
    png_path = docs / "demo.png"

    console = Console(record=True, width=84)
    _render(console, _sample_report())

    # HTML export (screenshotted by Chrome) and SVG export (cairosvg fallback).
    html = console.export_html(theme=SVG_EXPORT_THEME, inline_styles=True).replace(
        "font-family:Fira Code,monospace", f"font-family:{_MONO}"
    )
    html_path.write_text(html, encoding="utf-8")

    console.save_svg(str(svg_path), title="strix scan 1.1.1.1")
    svg = svg_path.read_text(encoding="utf-8").replace("Fira Code, monospace", _MONO)
    svg_path.write_text(svg, encoding="utf-8")

    chrome = _find_chrome()
    if chrome:
        _png_via_chrome(chrome, html_path, png_path)
        print(f"wrote {png_path} (via headless Chrome)")
    else:
        _png_via_cairosvg(svg, png_path)
        print(f"wrote {png_path} (via cairosvg)")


if __name__ == "__main__":
    main()
