from __future__ import annotations

import pytest

from strix.modules.wallet import WalletModule

_BTC_PAYLOAD = {
    "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "chain_stats": {
        "funded_txo_sum": 6_000_000_000,
        "spent_txo_sum": 1_000_000_000,
        "tx_count": 42,
    },
}


class _FakeResponse:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload

    def __call__(self, *args, **kwargs):  # AsyncClient(...) constructor
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url):
        return _FakeResponse(self._payload)


@pytest.fixture
def _patch_btc(monkeypatch):
    monkeypatch.setattr("strix.modules.wallet.httpx.AsyncClient", _FakeClient(_BTC_PAYLOAD))


async def test_bitcoin_balance_mapping(_patch_btc):
    result = await WalletModule().run("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

    assert result.error is None
    by_title = {f.title: f.value for f in result.findings}
    assert by_title["Chain"] == "Bitcoin"
    # (6.0 - 1.0) BTC = 50.0 BTC
    assert by_title["Balance (BTC)"] == "50.00000000"
    assert by_title["Transactions"] == "42"


async def test_wallet_never_raises(monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr("strix.modules.wallet.httpx.AsyncClient", _boom)
    result = await WalletModule().run("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert result.module == "wallet"
    assert isinstance(result.findings, list)
