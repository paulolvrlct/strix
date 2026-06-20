from __future__ import annotations

import asyncio
import sys

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from strix.banner import render_banner
from strix.config import settings
from strix.logging import setup_logging
from strix.models import ModuleResult, Report, Severity, TargetType
from strix.orchestrator import run_modules, select_modules
from strix.registry import discover_modules
from strix.report.engine import write_report
from strix.target import detect_target_type

app = typer.Typer(
    add_completion=False,
    help="STRIX — passive OSINT orchestrator with unified reporting.",
)
console = Console()

LEGAL_TEXT = (
    "STRIX is for authorized security research, CTF, and education only. "
    "You are responsible for complying with applicable laws and platform ToS."
)

_SEV_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "orange3",
    Severity.HIGH: "bold red",
}

# ----- shared options -----------------------------------------------------------------
_OutputOpt = typer.Option(None, "--output", "-o", help="Output directory (default ./output).")
_FormatOpt = typer.Option(
    None, "--format", "-f", help="Comma-separated subset of json,md,html (default: all)."
)
_QuietOpt = typer.Option(False, "--quiet", "-q", help="Minimal output (useful in pipes/CI).")
_ConcOpt = typer.Option(None, "--max-concurrency", help="Concurrency limit (default from config).")
_AuthOpt = typer.Option(False, "--i-am-authorized", help="Acknowledge the legal warning.")


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    no_banner: bool = typer.Option(False, "--no-banner", help="Hide the ASCII banner."),
) -> None:
    """Global options. With no command, launch the interactive menu."""
    setup_logging(settings.log_level)
    if ctx.invoked_subcommand is None:
        interactive_menu()
        raise typer.Exit()


@app.command()
def version() -> None:
    """Print the STRIX version and exit."""
    console.print(f"[bold #22d3ee]{settings.app_name}[/] v{settings.version}")


@app.command()
def modules() -> None:
    """List available modules with their target types and API-key requirement."""
    mods = discover_modules()
    if not mods:
        console.print("[yellow]No modules registered yet.[/]")
        return
    table = Table(title="STRIX modules", header_style="bold #22d3ee")
    table.add_column("Module")
    table.add_column("Target types")
    table.add_column("API key")
    table.add_column("Description")
    for m in mods:
        table.add_row(
            m.name,
            ", ".join(t.value for t in m.target_types),
            "yes" if m.requires_api_key else "no",
            m.description,
        )
    console.print(table)


# ----- helpers ------------------------------------------------------------------------
def _require_authorization(authorized: bool) -> None:
    if settings.acknowledged_authorization or authorized:
        return
    console.print(Panel(LEGAL_TEXT, title="Authorization required", border_style="red"))
    console.print(
        "Re-run with [bold]--i-am-authorized[/] or set "
        "[bold]acknowledged_authorization: true[/] in config.yaml."
    )
    raise typer.Exit(code=2)


def _parse_formats(fmt: str | None) -> list[str]:
    if not fmt:
        return list(settings.default_formats)
    return [part.strip().lower() for part in fmt.split(",") if part.strip()]


def _resolve_type(target: str, type_: str) -> TargetType:
    if type_ == "auto":
        return detect_target_type(target)
    try:
        return TargetType(type_)
    except ValueError:
        console.print(f"[red]Unknown target type '{type_}'.[/]")
        raise typer.Exit(code=2) from None


def _run_with_progress(
    target: str,
    ttype: TargetType,
    mods: list,
    max_concurrency: int | None,
    quiet: bool,
) -> Report:
    if quiet:
        return asyncio.run(run_modules(target, ttype, mods, max_concurrency=max_concurrency))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task_ids = {m.name: progress.add_task(f"{m.name}…", total=1) for m in mods}

        def on_done(result: ModuleResult) -> None:
            mark = "[green]✓[/]" if not result.error else "[red]✗[/]"
            progress.update(
                task_ids[result.module], completed=1, description=f"{result.module} {mark}"
            )

        return asyncio.run(
            run_modules(target, ttype, mods, max_concurrency=max_concurrency, on_done=on_done)
        )


def _render_results(report: Report) -> None:
    for module in report.modules:
        if module.error:
            console.print(
                Panel(f"[red]{module.error}[/]", title=f"{module.module} ✗", border_style="red")
            )
            continue
        if not module.findings:
            console.print(f"[dim]{module.module}: no findings[/]")
            continue
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


def _summary(report: Report, dest) -> None:
    failed = ", ".join(report.failed_modules) or "none"
    total_duration = sum(m.duration_s for m in report.modules)
    body = (
        f"[bold]Target[/]: {report.target}\n"
        f"[bold]Type[/]: {report.target_type.value}\n"
        f"[bold]Findings[/]: {report.total_findings}\n"
        f"[bold]Failed modules[/]: {failed}\n"
        f"[bold]Duration[/]: {total_duration:.1f}s\n"
        f"[bold]Report[/]: {dest}"
    )
    console.print(Panel(body, title="Summary", border_style="#22d3ee"))


def _execute(
    target: str,
    ttype: TargetType,
    output: str | None,
    fmt: str | None,
    quiet: bool,
    max_concurrency: int | None,
    authorized: bool,
) -> None:
    _require_authorization(authorized)
    mods = select_modules(ttype)
    if not mods:
        console.print(f"[yellow]No modules available for target type '{ttype.value}'.[/]")
        raise typer.Exit(code=1)

    formats = _parse_formats(fmt)
    output_dir = output or settings.default_output_dir

    report = _run_with_progress(target, ttype, mods, max_concurrency, quiet)

    if not quiet:
        _render_results(report)

    dest = write_report(report, output_dir, formats)

    if quiet:
        console.print(
            f"{dest}  ({report.total_findings} findings, {len(report.failed_modules)} failed)"
        )
    else:
        _summary(report, dest)


# ----- scan commands ------------------------------------------------------------------
@app.command()
def username(
    target: str,
    output: str = _OutputOpt,
    fmt: str = _FormatOpt,
    quiet: bool = _QuietOpt,
    max_concurrency: int = _ConcOpt,
    authorized: bool = _AuthOpt,
) -> None:
    """Run username modules (Maigret)."""
    _execute(target, TargetType.USERNAME, output, fmt, quiet, max_concurrency, authorized)


@app.command()
def email(
    target: str,
    output: str = _OutputOpt,
    fmt: str = _FormatOpt,
    quiet: bool = _QuietOpt,
    max_concurrency: int = _ConcOpt,
    authorized: bool = _AuthOpt,
) -> None:
    """Run email modules (Holehe)."""
    _execute(target, TargetType.EMAIL, output, fmt, quiet, max_concurrency, authorized)


@app.command()
def domain(
    target: str,
    output: str = _OutputOpt,
    fmt: str = _FormatOpt,
    quiet: bool = _QuietOpt,
    max_concurrency: int = _ConcOpt,
    authorized: bool = _AuthOpt,
) -> None:
    """Run domain modules (crt.sh, DNS, WHOIS)."""
    _execute(target, TargetType.DOMAIN, output, fmt, quiet, max_concurrency, authorized)


@app.command()
def ip(
    target: str,
    output: str = _OutputOpt,
    fmt: str = _FormatOpt,
    quiet: bool = _QuietOpt,
    max_concurrency: int = _ConcOpt,
    authorized: bool = _AuthOpt,
) -> None:
    """Run IP modules (Shodan InternetDB, ip-api)."""
    _execute(target, TargetType.IP, output, fmt, quiet, max_concurrency, authorized)


@app.command()
def phone(
    target: str,
    output: str = _OutputOpt,
    fmt: str = _FormatOpt,
    quiet: bool = _QuietOpt,
    max_concurrency: int = _ConcOpt,
    authorized: bool = _AuthOpt,
) -> None:
    """Run phone modules (phonenumbers, offline)."""
    _execute(target, TargetType.PHONE, output, fmt, quiet, max_concurrency, authorized)


@app.command()
def image(
    target: str,
    output: str = _OutputOpt,
    fmt: str = _FormatOpt,
    quiet: bool = _QuietOpt,
    max_concurrency: int = _ConcOpt,
    authorized: bool = _AuthOpt,
) -> None:
    """Run image modules (ExifTool): metadata and GPS from a local file or URL."""
    _execute(target, TargetType.IMAGE, output, fmt, quiet, max_concurrency, authorized)


@app.command()
def scan(
    target: str,
    type_: str = typer.Option(
        "auto", "--type", help="auto|username|email|domain|ip|phone|image (default auto)."
    ),
    output: str = _OutputOpt,
    fmt: str = _FormatOpt,
    quiet: bool = _QuietOpt,
    max_concurrency: int = _ConcOpt,
    authorized: bool = _AuthOpt,
) -> None:
    """Auto-detect the target type and run every compatible module."""
    ttype = _resolve_type(target, type_)
    _execute(target, ttype, output, fmt, quiet, max_concurrency, authorized)


# ----- interactive menu ---------------------------------------------------------------
# (key, label, target type or None for auto-detect)
_MENU: list[tuple[str, str, TargetType | None]] = [
    ("1", "Username (Maigret)", TargetType.USERNAME),
    ("2", "Email (Holehe)", TargetType.EMAIL),
    ("3", "Domain (crt.sh / DNS / WHOIS)", TargetType.DOMAIN),
    ("4", "IP (Shodan InternetDB / ip-api)", TargetType.IP),
    ("5", "Phone (phonenumbers)", TargetType.PHONE),
    ("6", "Image (ExifTool metadata + GPS)", TargetType.IMAGE),
    ("7", "Auto-detect target type", None),
]


def _interactive_authorize() -> bool:
    """Show the legal notice once per session and require acknowledgement."""
    if settings.acknowledged_authorization:
        return True
    console.print(Panel(LEGAL_TEXT, title="Authorization required", border_style="red"))
    try:
        return Confirm.ask("Do you confirm authorized, lawful use?", default=False)
    except (EOFError, KeyboardInterrupt):
        return False


def _print_menu() -> None:
    table = Table(title="STRIX — choose a scan", header_style="bold #22d3ee", show_header=False)
    table.add_column("#", style="bold #22d3ee", justify="right")
    table.add_column("Action")
    for key, label, _ in _MENU:
        table.add_row(key, label)
    table.add_row("m", "List modules")
    table.add_row("0", "Quit")
    console.print(table)


def interactive_menu() -> None:
    """Run the numbered, navigable menu loop until the user quits."""
    if not _interactive_authorize():
        console.print("[yellow]Authorization not granted. Exiting.[/]")
        return

    while True:
        console.print()
        _print_menu()
        try:
            choice = Prompt.ask("Select").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\nBye.")
            return

        if choice in ("0", "q", "quit", "exit"):
            console.print("Bye.")
            return
        if choice == "m":
            modules()
            continue

        match = next((m for m in _MENU if m[0] == choice), None)
        if match is None:
            console.print("[yellow]Invalid choice.[/]")
            continue

        _, label, ttype = match
        try:
            target = Prompt.ask(f"Target for [bold]{label}[/]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\nBye.")
            return
        if not target:
            console.print("[yellow]Empty target, skipped.[/]")
            continue

        resolved = ttype or _resolve_type(target, "auto")
        try:
            # Authorized at the session level, so each scan runs without re-prompting.
            _execute(target, resolved, None, None, False, None, True)
        except typer.Exit:
            # e.g. no module available for that type — keep the menu running.
            pass


@app.command()
def menu() -> None:
    """Launch the interactive numbered menu (a navigable multitool)."""
    interactive_menu()


def run() -> None:
    """Console-script entry point: render the banner (unless suppressed), then dispatch."""
    argv = sys.argv[1:]
    suppress = any(a in ("--no-banner", "--quiet", "-q") for a in argv)
    if not suppress:
        console.print(render_banner(settings.app_name, settings.version))
    app()


if __name__ == "__main__":
    run()
