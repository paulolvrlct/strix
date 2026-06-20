from __future__ import annotations

import asyncio
import shutil
from datetime import datetime, timezone

from strix.models import Finding, ModuleResult, Severity, TargetType
from strix.modules.base import BaseModule


class EmailModule(BaseModule):
    name = "email"
    description = "Service registration check for an email (Holehe)"
    target_types = [TargetType.EMAIL]
    requires_api_key = False
    rate_limit = 1.0

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []

        exe = shutil.which("holehe")
        if not exe:
            return self._result(
                target, TargetType.EMAIL, started, findings, error="holehe not installed"
            )

        try:
            cmd = [exe, target, "--only-used", "--no-color"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=240)
            except asyncio.TimeoutError:
                proc.kill()
                return self._result(
                    target, TargetType.EMAIL, started, findings, error="holehe timed out"
                )
            self._parse(stdout.decode("utf-8", "replace"), findings)
        except Exception as exc:
            return self._result(target, TargetType.EMAIL, started, findings, error=str(exc))

        return self._result(target, TargetType.EMAIL, started, findings)

    def _parse(self, stdout: str, out: list[Finding]) -> None:
        """Each line like ``[+] service.com`` marks an account registered on that service."""
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("[+]"):
                continue
            service = line[3:].strip()
            if not service:
                continue
            out.append(
                Finding(
                    title="Registered on service",
                    value=service,
                    source="holehe",
                    severity=Severity.LOW,
                )
            )
