from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from strix.config import settings
from strix.models import ModuleResult, Report, TargetType
from strix.modules.base import BaseModule
from strix.registry import modules_for

log = logging.getLogger("strix.orchestrator")

# Maps a module-declared API key requirement to the candidate settings fields.
_API_KEY_FIELDS = ("shodan_api_key", "virustotal_api_key", "ipinfo_token")


def _has_any_api_key() -> bool:
    return any(getattr(settings, field, None) for field in _API_KEY_FIELDS)


def select_modules(target_type: TargetType) -> list[BaseModule]:
    """Return modules compatible with the target type, skipping key-gated ones with no key."""
    selected: list[BaseModule] = []
    for module in modules_for(target_type):
        if module.requires_api_key and not _has_any_api_key():
            log.info("Skipping module %s: requires an API key, none provided", module.name)
            continue
        selected.append(module)
    return selected


async def run_modules(
    target: str,
    target_type: TargetType,
    modules: list[BaseModule],
    *,
    max_concurrency: int | None = None,
    on_done: Callable[[ModuleResult], None] | None = None,
) -> Report:
    """Run the given modules concurrently (bounded by a semaphore) and aggregate a Report.

    A single failing module never breaks the run: BaseModule.run captures its own errors.
    """
    limit = max_concurrency or settings.max_concurrency
    sem = asyncio.Semaphore(max(1, limit))

    async def _run_one(module: BaseModule) -> ModuleResult:
        async with sem:
            result = await module.run(target)
            if on_done is not None:
                on_done(result)
            return result

    results: list[ModuleResult] = []
    if modules:
        results = list(await asyncio.gather(*(_run_one(m) for m in modules)))
    return Report(target=target, target_type=target_type, modules=results)


async def run_scan(
    target: str,
    target_type: TargetType,
    *,
    max_concurrency: int | None = None,
    on_done: Callable[[ModuleResult], None] | None = None,
) -> Report:
    """Convenience wrapper: select compatible modules and run them."""
    modules = select_modules(target_type)
    return await run_modules(
        target,
        target_type,
        modules,
        max_concurrency=max_concurrency,
        on_done=on_done,
    )
