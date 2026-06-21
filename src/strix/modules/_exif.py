from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx

from strix.models import Finding, ModuleResult, Severity, TargetType
from strix.modules.base import BaseModule

# Curated EXIF/metadata tags with the severity STRIX assigns to each.
# GPS tags are privacy-sensitive (location leak) -> MEDIUM.
# Owner/serial/author tags are PII -> LOW. Everything else is INFO.
CURATED: list[tuple[str, Severity]] = [
    ("Make", Severity.INFO),
    ("Model", Severity.INFO),
    ("LensModel", Severity.INFO),
    ("Software", Severity.INFO),
    ("HostComputer", Severity.INFO),
    ("DateTimeOriginal", Severity.INFO),
    ("CreateDate", Severity.INFO),
    ("ModifyDate", Severity.INFO),
    ("ImageDescription", Severity.INFO),
    ("UserComment", Severity.INFO),
    ("Producer", Severity.INFO),
    ("Creator", Severity.LOW),
    ("Author", Severity.LOW),
    ("Artist", Severity.LOW),
    ("Copyright", Severity.LOW),
    ("OwnerName", Severity.LOW),
    ("SerialNumber", Severity.LOW),
    ("InternalSerialNumber", Severity.LOW),
    ("GPSPosition", Severity.MEDIUM),
    ("GPSLatitude", Severity.MEDIUM),
    ("GPSLongitude", Severity.MEDIUM),
    ("GPSAltitude", Severity.MEDIUM),
    ("GPSDateTime", Severity.MEDIUM),
]


def parse_exif(data: object, out: list[Finding]) -> None:
    """Map ExifTool's ``-json`` output (a list with one dict) to Findings."""
    if not isinstance(data, list) or not data:
        return
    meta = data[0]
    if not isinstance(meta, dict):
        return

    seen: set[str] = set()
    for tag, severity in CURATED:
        value = meta.get(tag)
        if value not in (None, ""):
            out.append(Finding(title=tag, value=str(value), source="exiftool", severity=severity))
            seen.add(tag)

    # Surface any remaining GPS* tag we did not curate explicitly.
    for tag, value in meta.items():
        if tag.startswith("GPS") and tag not in seen and value not in (None, ""):
            out.append(
                Finding(title=tag, value=str(value), source="exiftool", severity=Severity.MEDIUM)
            )


async def _materialize(target: str) -> tuple[Path | None, tempfile.TemporaryDirectory | None]:
    """Resolve a target to a local file path, downloading it first if it is a URL."""
    if target.startswith(("http://", "https://")):
        tmp = tempfile.TemporaryDirectory()
        try:
            name = Path(urlparse(target).path).name or "download"
            dest = Path(tmp.name) / name
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
                r = await c.get(target)
            if r.status_code != 200:
                tmp.cleanup()
                return None, None
            dest.write_bytes(r.content)
            return dest, tmp
        except Exception:
            tmp.cleanup()
            return None, None

    local = Path(target).expanduser()
    if local.is_file():
        return local, None
    return None, None


async def run_exiftool(
    module: BaseModule, target: str, ttype: TargetType, started: datetime
) -> ModuleResult:
    """Shared ExifTool runner used by the image and file modules."""
    findings: list[Finding] = []

    exe = shutil.which("exiftool")
    if not exe:
        return module._result(target, ttype, started, findings, error="exiftool not installed")

    tmpdir: tempfile.TemporaryDirectory | None = None
    try:
        path, tmpdir = await _materialize(target)
        if path is None:
            return module._result(
                target, ttype, started, findings, error="file not found or could not be fetched"
            )
        cmd = [exe, "-json", "-charset", "filename=utf8", str(path)]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        except asyncio.TimeoutError:
            proc.kill()
            return module._result(target, ttype, started, findings, error="exiftool timed out")
        data = json.loads(stdout.decode("utf-8", "replace") or "[]")
        parse_exif(data, findings)
    except Exception as exc:
        return module._result(target, ttype, started, findings, error=str(exc))
    finally:
        if tmpdir is not None:
            tmpdir.cleanup()

    return module._result(target, ttype, started, findings)
