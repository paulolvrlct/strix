from __future__ import annotations

import re
from datetime import datetime, timezone

import httpx

from strix.http import get_with_backoff
from strix.models import Finding, ModuleResult, Severity, TargetType
from strix.modules.base import BaseModule

_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class WalletModule(BaseModule):
    name = "wallet"
    description = "Crypto wallet balance & activity (BTC/ETH, public chain APIs, no key)"
    target_types = [TargetType.WALLET]
    requires_api_key = False
    rate_limit = 1.0

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        try:
            if _ETH_RE.match(target):
                await self._ethereum(target, findings)
            else:
                await self._bitcoin(target, findings)
        except Exception as exc:  # never propagate
            return self._result(target, TargetType.WALLET, started, findings, error=str(exc))
        return self._result(target, TargetType.WALLET, started, findings)

    async def _bitcoin(self, address: str, out: list[Finding]) -> None:
        url = f"https://blockstream.info/api/address/{address}"
        async with httpx.AsyncClient(timeout=20) as c:
            r = await get_with_backoff(c, url)
        if r.status_code != 200:
            return
        data = r.json()
        chain = data.get("chain_stats", {})
        funded = chain.get("funded_txo_sum", 0)
        spent = chain.get("spent_txo_sum", 0)
        balance_btc = (funded - spent) / 1e8
        tx_count = chain.get("tx_count", 0)
        explorer = f"https://blockstream.info/address/{address}"
        out.append(
            Finding(title="Chain", value="Bitcoin", source="blockstream", severity=Severity.INFO)
        )
        out.append(
            Finding(
                title="Balance (BTC)",
                value=f"{balance_btc:.8f}",
                source="blockstream",
                url=explorer,
                severity=Severity.INFO,
            )
        )
        out.append(
            Finding(
                title="Transactions",
                value=str(tx_count),
                source="blockstream",
                severity=Severity.INFO,
            )
        )

    async def _ethereum(self, address: str, out: list[Finding]) -> None:
        url = f"https://api.blockchair.com/ethereum/dashboards/address/{address}"
        async with httpx.AsyncClient(timeout=20) as c:
            r = await get_with_backoff(c, url)
        if r.status_code != 200:
            return
        payload = r.json()
        data = payload.get("data") or {}
        record = data.get(address) or data.get(address.lower())
        if not record:
            return
        addr_info = record.get("address", {})
        balance_wei = float(addr_info.get("balance", 0) or 0)
        balance_eth = balance_wei / 1e18
        tx_count = addr_info.get("transaction_count", 0)
        explorer = f"https://etherscan.io/address/{address}"
        out.append(
            Finding(title="Chain", value="Ethereum", source="blockchair", severity=Severity.INFO)
        )
        out.append(
            Finding(
                title="Balance (ETH)",
                value=f"{balance_eth:.6f}",
                source="blockchair",
                url=explorer,
                severity=Severity.INFO,
            )
        )
        out.append(
            Finding(
                title="Transactions",
                value=str(tx_count),
                source="blockchair",
                severity=Severity.INFO,
            )
        )
