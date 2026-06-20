from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from strix.http import get_with_backoff
from strix.models import Finding, ModuleResult, Severity, TargetType
from strix.modules.base import BaseModule


class IPModule(BaseModule):
    name = "ip"
    description = "Open ports, known CVEs (Shodan InternetDB), geolocation/ASN (ip-api)"
    target_types = [TargetType.IP]
    requires_api_key = False
    rate_limit = 1.0

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        try:
            await asyncio.gather(
                self._internetdb(target, findings),
                self._ipapi(target, findings),
            )
        except Exception as exc:  # never propagate
            return self._result(target, TargetType.IP, started, findings, error=str(exc))
        return self._result(target, TargetType.IP, started, findings)

    async def _internetdb(self, ip: str, out: list[Finding]) -> None:
        """Shodan InternetDB: already-indexed public data, not an active scan."""
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            async with httpx.AsyncClient(timeout=20) as c:
                r = await get_with_backoff(c, url)
            if r.status_code != 200:
                return
            data = r.json()
            for port in data.get("ports", []):
                out.append(
                    Finding(
                        title="Open port",
                        value=str(port),
                        source="shodan-internetdb",
                        severity=Severity.INFO,
                    )
                )
            for host in data.get("hostnames", []):
                out.append(
                    Finding(
                        title="Hostname",
                        value=str(host),
                        source="shodan-internetdb",
                        severity=Severity.INFO,
                    )
                )
            for tag in data.get("tags", []):
                out.append(
                    Finding(
                        title="Tag",
                        value=str(tag),
                        source="shodan-internetdb",
                        severity=Severity.INFO,
                    )
                )
            for cpe in data.get("cpes", []):
                out.append(
                    Finding(
                        title="CPE",
                        value=str(cpe),
                        source="shodan-internetdb",
                        severity=Severity.INFO,
                    )
                )
            for cve in data.get("vulns", []):
                out.append(
                    Finding(
                        title="Known CVE",
                        value=str(cve),
                        source="shodan-internetdb",
                        url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                        severity=Severity.HIGH,
                    )
                )
        except Exception:
            return

    async def _ipapi(self, ip: str, out: list[Finding]) -> None:
        url = f"http://ip-api.com/json/{ip}"
        try:
            async with httpx.AsyncClient(timeout=20) as c:
                r = await get_with_backoff(c, url)
            if r.status_code != 200:
                return
            data = r.json()
            if data.get("status") != "success":
                return
            mapping = [
                ("Country", "country"),
                ("Region", "regionName"),
                ("City", "city"),
                ("ISP", "isp"),
                ("Organization", "org"),
                ("ASN", "as"),
            ]
            for title, key in mapping:
                value = data.get(key)
                if value:
                    out.append(
                        Finding(
                            title=title, value=str(value), source="ip-api", severity=Severity.INFO
                        )
                    )
            lat, lon = data.get("lat"), data.get("lon")
            if lat is not None and lon is not None:
                out.append(
                    Finding(
                        title="Coordinates",
                        value=f"{lat}, {lon}",
                        source="ip-api",
                        severity=Severity.INFO,
                    )
                )
        except Exception:
            return
