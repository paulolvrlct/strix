from __future__ import annotations

import pytest

from strix.models import TargetType
from strix.modules.domain import DomainModule

_CRTSH_ROWS = [
    {"name_value": "a.example.com\n*.example.com"},
    {"name_value": "b.example.com"},
    {"name_value": "other.org"},  # must be filtered out (wrong suffix)
]


class _FakeResponse:
    status_code = 200

    def json(self):
        return _CRTSH_ROWS


class _FakeClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url):
        return _FakeResponse()


def _raise(*args, **kwargs):
    raise RuntimeError("network disabled in tests")


@pytest.fixture(autouse=True)
def _patch_network(monkeypatch):
    # crt.sh -> fake; DNS and WHOIS -> raise so only crt.sh findings remain.
    monkeypatch.setattr("strix.modules.domain.httpx.AsyncClient", _FakeClient)
    monkeypatch.setattr("strix.modules.domain.dns.resolver.resolve", _raise)
    monkeypatch.setattr("strix.modules.domain.whois.whois", _raise)


async def test_domain_maps_crtsh_subdomains():
    result = await DomainModule().run("example.com")

    assert result.error is None
    assert result.target_type is TargetType.DOMAIN

    subdomains = {f.value for f in result.findings if f.source == "crt.sh"}
    assert "a.example.com" in subdomains
    assert "b.example.com" in subdomains
    assert "other.org" not in subdomains  # filtered by suffix
    # Wildcard "*.example.com" is normalized to the apex.
    assert "example.com" in subdomains


async def test_domain_never_raises_on_failure(monkeypatch):
    monkeypatch.setattr("strix.modules.domain.httpx.AsyncClient", _raise)
    result = await DomainModule().run("example.com")
    # Even if everything fails, run() returns a ModuleResult instead of raising.
    assert result.module == "domain"
    assert isinstance(result.findings, list)
