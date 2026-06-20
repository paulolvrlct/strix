from __future__ import annotations

import logging

from rich.logging import RichHandler

# Secret values registered at runtime so they can be scrubbed from log records.
_SECRETS: list[str] = []


def register_secret(value: str | None) -> None:
    """Register a secret value (e.g. an API key) to be redacted from all logs."""
    if value and value not in _SECRETS:
        _SECRETS.append(value)


class _RedactFilter(logging.Filter):
    """Replace any registered secret appearing in a log message with ``***``."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = message
        for secret in _SECRETS:
            if secret and secret in redacted:
                redacted = redacted.replace(secret, "***")
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def setup_logging(level: str = "INFO") -> None:
    """Configure root logging with Rich output and secret redaction."""
    handler = RichHandler(rich_tracebacks=True, show_path=False, markup=False)
    handler.addFilter(_RedactFilter())
    logging.basicConfig(
        level=level.upper(),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[handler],
        force=True,
    )
