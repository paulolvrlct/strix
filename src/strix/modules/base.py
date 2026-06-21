from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone

from strix.models import Finding, ModuleResult, TargetType


class BaseModule(ABC):
    # Metadata (override in each concrete module).
    name: str = "base"
    description: str = ""
    target_types: list[TargetType] = []  # supported target types
    requires_api_key: bool = False
    rate_limit: float = 1.0  # minimum seconds between two network requests
    active: bool = False  # True for modules that touch the target (e.g. port scan)

    def supports(self, target_type: TargetType) -> bool:
        return target_type in self.target_types

    @abstractmethod
    async def run(self, target: str) -> ModuleResult:
        """Run the collection and return a ModuleResult.

        MUST NEVER raise: capture exceptions and fill ModuleResult.error.
        Always set started_at / finished_at.
        """
        ...

    def _result(
        self,
        target: str,
        ttype: TargetType,
        started: datetime,
        findings: list[Finding],
        error: str | None = None,
    ) -> ModuleResult:
        """Helper for subclasses to build a ModuleResult with a consistent finish time."""
        return ModuleResult(
            module=self.name,
            target=target,
            target_type=ttype,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            error=error,
        )
