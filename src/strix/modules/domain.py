from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import dns.resolver
import httpx
import whois  # python-whois

from strix.http import get_with_backoff
from strix.models import Finding, ModuleResult, Severity, TargetType
from strix.modules.base import BaseModule


class DomainModule(BaseModule):
    name = "domain"
    description = "Subdomains (crt.sh), DNS records, WHOIS"
    target_types = [TargetType.DOMAIN]
    requires_api_key = False
    rate_limit = 1.0

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        try:
            await asyncio.gather(
                self._crtsh(target, findings),
                self._dns(target, findings),
            )
            await asyncio.to_thread(self._whois, target, findings)  # python-whois is sync
        except Exception as exc:  # never propagate
            return self._result(target, TargetType.DOMAIN, started, findings, error=str(exc))
        return self._result(target, TargetType.DOMAIN, started, findings)

    async def _crtsh(self, domain: str, out: list[Finding]) -> None:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=20) as c:
                r = await get_with_backoff(c, url)
            if r.status_code != 200:
                return
            seen: set[str] = set()
            for row in r.json():
                for name in row.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name and name not in seen and name.endswith(domain):
                        seen.add(name)
            for sub in sorted(seen):
                out.append(
                    Finding(title="Subdomain", value=sub, source="crt.sh", severity=Severity.INFO)
                )
        except Exception:
            return

    async def _dns(self, domain: str, out: list[Finding]) -> None:
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, domain, rtype)
                for a in answers:
                    out.append(
                        Finding(
                            title=f"DNS {rtype}",
                            value=str(a).strip('"'),
                            source="dns",
                            severity=Severity.INFO,
                        )
                    )
            except Exception:
                continue

    def _whois(self, domain: str, out: list[Finding]) -> None:
        try:
            w = whois.whois(domain)
            if w.registrar:
                out.append(
                    Finding(
                        title="Registrar",
                        value=str(w.registrar),
                        source="whois",
                        severity=Severity.INFO,
                    )
                )
            if w.creation_date:
                out.append(
                    Finding(
                        title="Creation date",
                        value=str(w.creation_date),
                        source="whois",
                        severity=Severity.INFO,
                    )
                )
        except Exception:
            pass
