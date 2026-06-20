from __future__ import annotations

from strix.models import Report, Severity

_SEV_LABEL = {
    Severity.INFO: "ℹ️ info",
    Severity.LOW: "🔵 low",
    Severity.MEDIUM: "🟠 medium",
    Severity.HIGH: "🔴 high",
}


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Report) -> str:
    """Render a GitHub-readable Markdown report."""
    lines: list[str] = []
    lines.append(f"# STRIX report — {report.target}")
    lines.append("")
    lines.append(f"- **Target type**: {report.target_type.value}")
    lines.append(f"- **Generated at**: {report.generated_at.isoformat()}")
    lines.append(f"- **Total findings**: {report.total_findings}")
    failed = ", ".join(report.failed_modules) or "none"
    lines.append(f"- **Failed modules**: {failed}")
    lines.append("")

    for module in report.modules:
        lines.append(f"## Module: {module.module}")
        lines.append("")
        lines.append(f"_Duration: {module.duration_s:.2f}s_")
        lines.append("")
        if module.error:
            lines.append(f"> ⚠️ Error: {module.error}")
            lines.append("")
            continue
        if not module.findings:
            lines.append("_No findings._")
            lines.append("")
            continue
        lines.append("| Title | Value | Source | Severity |")
        lines.append("|---|---|---|---|")
        for f in module.findings:
            value = f.value
            if f.url:
                value = f"[{_md_escape(value)}]({f.url})"
            else:
                value = _md_escape(value)
            sev = _SEV_LABEL.get(f.severity, f.severity.value)
            lines.append(f"| {_md_escape(f.title)} | {value} | {_md_escape(f.source)} | {sev} |")
        lines.append("")

    return "\n".join(lines)
