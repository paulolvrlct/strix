from __future__ import annotations

from datetime import datetime, timezone

from strix.models import Finding, ModuleResult, Severity, TargetType
from strix.modules.base import BaseModule
from strix.orchestrator import run_modules


class _OkModule(BaseModule):
    name = "ok"
    target_types = [TargetType.DOMAIN]

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        findings = [Finding(title="x", value="y", source="ok", severity=Severity.INFO)]
        return self._result(target, TargetType.DOMAIN, started, findings)


class _FailingModule(BaseModule):
    name = "boom"
    target_types = [TargetType.DOMAIN]

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        # Simulate a module that handled its own error (per the BaseModule contract).
        return self._result(target, TargetType.DOMAIN, started, [], error="kaboom")


async def test_failing_module_does_not_break_report():
    report = await run_modules(
        "example.com",
        TargetType.DOMAIN,
        [_OkModule(), _FailingModule()],
    )
    assert report.total_findings == 1
    assert report.failed_modules == ["boom"]
    assert len(report.modules) == 2


async def test_on_done_callback_is_invoked():
    seen: list[str] = []
    await run_modules(
        "example.com",
        TargetType.DOMAIN,
        [_OkModule()],
        on_done=lambda r: seen.append(r.module),
    )
    assert seen == ["ok"]
