from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path

from strix.models import Report
from strix.report.markdown import render_markdown

log = logging.getLogger("strix.report")

_VALID_FORMATS = {"json", "md", "html"}


def slugify(value: str) -> str:
    """Make a filesystem-safe slug from a target string."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip().lower()).strip("_")
    return slug or "target"


def write_report(
    report: Report,
    output_dir: str | Path,
    formats: list[str],
) -> Path:
    """Write the report to ``output_dir/<slug>_<timestamp>/`` in the requested formats.

    Returns the path to the created report directory. JSON is the source of truth.
    """
    chosen = [f for f in formats if f in _VALID_FORMATS]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = Path(output_dir) / f"{slugify(report.target)}_{timestamp}"
    dest.mkdir(parents=True, exist_ok=True)

    if "json" in chosen:
        (dest / "report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")

    if "md" in chosen:
        (dest / "report.md").write_text(render_markdown(report), encoding="utf-8")

    if "html" in chosen:
        try:
            from strix.report.html import render_html

            (dest / "report.html").write_text(render_html(report), encoding="utf-8")
        except Exception as exc:  # HTML renderer arrives in Phase 2
            log.warning("HTML report skipped: %s", exc)

    return dest
