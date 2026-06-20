from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from strix.models import Finding, ModuleResult, Severity, TargetType
from strix.modules.base import BaseModule


class UsernameModule(BaseModule):
    name = "username"
    description = "Account enumeration across sites (Maigret)"
    target_types = [TargetType.USERNAME]
    requires_api_key = False
    rate_limit = 1.0

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []

        exe = shutil.which("maigret")
        if not exe:
            return self._result(
                target, TargetType.USERNAME, started, findings, error="maigret not installed"
            )

        try:
            with tempfile.TemporaryDirectory() as tmp:
                cmd = [
                    exe,
                    target,
                    "--json",
                    "simple",
                    "--no-progressbar",
                    "--timeout",
                    "10",
                    "--folderoutput",
                    tmp,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    await asyncio.wait_for(proc.communicate(), timeout=240)
                except asyncio.TimeoutError:
                    proc.kill()
                    return self._result(
                        target, TargetType.USERNAME, started, findings, error="maigret timed out"
                    )
                self._parse(Path(tmp), findings)
        except Exception as exc:
            return self._result(target, TargetType.USERNAME, started, findings, error=str(exc))

        return self._result(target, TargetType.USERNAME, started, findings)

    def _parse(self, folder: Path, out: list[Finding]) -> None:
        """Parse Maigret's JSON output (shape varies across versions; be defensive)."""
        for path in folder.glob("*.json"):
            try:
                data = json.loads(path.read_text())
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            for site, info in data.items():
                if not isinstance(info, dict):
                    continue
                status = info.get("status")
                claimed = False
                if isinstance(status, dict):
                    claimed = str(status.get("status", "")).lower() == "claimed"
                elif isinstance(status, str):
                    claimed = status.lower() == "claimed"
                if not claimed:
                    continue
                url = info.get("url_user") or info.get("url")
                out.append(
                    Finding(
                        title="Account found",
                        value=str(site),
                        source="maigret",
                        url=url,
                        severity=Severity.INFO,
                    )
                )
            return  # first parseable JSON wins
