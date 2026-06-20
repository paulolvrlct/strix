from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from strix.models import Finding, ModuleResult, Severity, TargetType
from strix.modules.base import BaseModule

# Curated EXIF/metadata tags with the severity STRIX assigns to each.
# GPS tags are privacy-sensitive (location leak) -> MEDIUM.
# Owner/serial/author tags are PII -> LOW. Everything else is INFO.
_CURATED: list[tuple[str, Severity]] = [
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


class ImageModule(BaseModule):
    name = "image"
    description = "Image metadata and GPS extraction (ExifTool)"
    target_types = [TargetType.IMAGE]
    requires_api_key = False
    rate_limit = 0.0  # local subprocess; only the optional URL fetch touches the network

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []

        exe = shutil.which("exiftool")
        if not exe:
            return self._result(
                target, TargetType.IMAGE, started, findings, error="exiftool not installed"
            )

        tmpdir: tempfile.TemporaryDirectory | None = None
        try:
            path, tmpdir = await self._materialize(target)
            if path is None:
                return self._result(
                    target,
                    TargetType.IMAGE,
                    started,
                    findings,
                    error="image not found or could not be fetched",
                )
            cmd = [exe, "-json", "-charset", "filename=utf8", str(path)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.TimeoutError:
                proc.kill()
                return self._result(
                    target, TargetType.IMAGE, started, findings, error="exiftool timed out"
                )
            data = json.loads(stdout.decode("utf-8", "replace") or "[]")
            self._parse(data, findings)
        except Exception as exc:
            return self._result(target, TargetType.IMAGE, started, findings, error=str(exc))
        finally:
            if tmpdir is not None:
                tmpdir.cleanup()

        return self._result(target, TargetType.IMAGE, started, findings)

    async def _materialize(
        self, target: str
    ) -> tuple[Path | None, tempfile.TemporaryDirectory | None]:
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

    def _parse(self, data: object, out: list[Finding]) -> None:
        """Map ExifTool's ``-json`` output (a list with one dict) to Findings."""
        if not isinstance(data, list) or not data:
            return
        meta = data[0]
        if not isinstance(meta, dict):
            return

        seen: set[str] = set()
        for tag, severity in _CURATED:
            value = meta.get(tag)
            if value not in (None, ""):
                out.append(
                    Finding(title=tag, value=str(value), source="exiftool", severity=severity)
                )
                seen.add(tag)

        # Surface any remaining GPS* tag we did not curate explicitly.
        for tag, value in meta.items():
            if tag.startswith("GPS") and tag not in seen and value not in (None, ""):
                out.append(
                    Finding(
                        title=tag, value=str(value), source="exiftool", severity=Severity.MEDIUM
                    )
                )
