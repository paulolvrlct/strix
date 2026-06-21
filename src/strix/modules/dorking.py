from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import quote_plus

from strix.models import Finding, ModuleResult, Severity, TargetType
from strix.modules.base import BaseModule

_ENGINES = {
    "google": "https://www.google.com/search?q=",
    "bing": "https://www.bing.com/search?q=",
    "duckduckgo": "https://duckduckgo.com/?q=",
}

# (label, query template). {t} is replaced by the target. Passive: only builds URLs.
_DORKS: list[tuple[str, str]] = [
    ("Indexed pages", "site:{t}"),
    ("Exact mentions", '"{t}"'),
    ("PDF documents", '"{t}" filetype:pdf'),
    ("Config/log/sql leaks", '"{t}" (filetype:env | filetype:log | filetype:sql)'),
    ("Open directories", 'intitle:"index of" "{t}"'),
    ("Admin / login pages", '"{t}" (inurl:admin | inurl:login)'),
    ("Pastebin leaks", '"{t}" site:pastebin.com'),
    ("Code on GitHub", '"{t}" site:github.com'),
    ("Credentials patterns", '"{t}" (intext:password | intext:apikey | intext:secret)'),
]


class DorkingModule(BaseModule):
    name = "dorking"
    description = "Search-engine dork URLs (Google/Bing/DuckDuckGo) — passive"
    target_types = [TargetType.DOMAIN, TargetType.USERNAME, TargetType.EMAIL, TargetType.IP]
    requires_api_key = False
    rate_limit = 0.0  # offline: only builds ready-to-click search URLs

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        for label, template in _DORKS:
            query = template.format(t=target)
            encoded = quote_plus(query)
            findings.append(
                Finding(
                    title=label,
                    value=query,
                    source="dorking",
                    url=_ENGINES["google"] + encoded,
                    severity=Severity.INFO,
                    metadata={
                        "bing": _ENGINES["bing"] + encoded,
                        "duckduckgo": _ENGINES["duckduckgo"] + encoded,
                    },
                )
            )
        return self._result(target, TargetType.DOMAIN, started, findings)
