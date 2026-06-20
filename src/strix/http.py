from __future__ import annotations

import asyncio

import httpx


async def get_with_backoff(
    client: httpx.AsyncClient,
    url: str,
    *,
    retries: int = 2,
    base_delay: float = 1.5,
    max_delay: float = 10.0,
) -> httpx.Response:
    """GET ``url`` with simple backoff on HTTP 429 (respecting ``Retry-After``).

    Keeps STRIX polite toward the public services it queries (see brief §2).
    """
    attempt = 0
    while True:
        response = await client.get(url)
        if response.status_code == 429 and attempt < retries:
            retry_after = response.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after else base_delay * (attempt + 1)
            except ValueError:
                delay = base_delay * (attempt + 1)
            await asyncio.sleep(min(delay, max_delay))
            attempt += 1
            continue
        return response
