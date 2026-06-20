from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from strix.models import Report

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "j2"]),
)


def render_html(report: Report) -> str:
    """Render the self-contained branded HTML report."""
    template = _env.get_template("report.html.j2")
    return template.render(report=report)
