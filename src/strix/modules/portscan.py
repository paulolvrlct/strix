from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from strix.models import Finding, ModuleResult, Severity, TargetType
from strix.modules.base import BaseModule

# Common service ports probed by default.
_DEFAULT_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}


class PortScanModule(BaseModule):
    name = "portscan"
    description = "TCP connect port scan (ACTIVE — authorized targets only)"
    target_types = [TargetType.IP, TargetType.DOMAIN]
    requires_api_key = False
    active = True
    rate_limit = 0.0

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        ttype = TargetType.DOMAIN if any(c.isalpha() for c in target) else TargetType.IP
        try:
            sem = asyncio.Semaphore(100)

            async def _probe(port: int) -> int | None:
                async with sem:
                    try:
                        fut = asyncio.open_connection(target, port)
                        _, writer = await asyncio.wait_for(fut, timeout=1.5)
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                        return port
                    except Exception:
                        return None

            results = await asyncio.gather(*(_probe(p) for p in _DEFAULT_PORTS))
            for port in sorted(p for p in results if p is not None):
                findings.append(
                    Finding(
                        title="Open port",
                        value=str(port),
                        source="portscan",
                        severity=Severity.LOW,
                        metadata={"service": _DEFAULT_PORTS.get(port, "")},
                    )
                )
        except Exception as exc:  # never propagate
            return self._result(target, ttype, started, findings, error=str(exc))
        return self._result(target, ttype, started, findings)
