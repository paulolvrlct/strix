from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class TargetType(str, Enum):
    USERNAME = "username"
    EMAIL = "email"
    DOMAIN = "domain"
    IP = "ip"
    PHONE = "phone"
    IMAGE = "image"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    """An atomic observation reported by a module."""

    title: str  # e.g. "Account found"
    value: str  # e.g. "github.com/paulx"
    source: str  # module/tool name, e.g. "maigret"
    url: str | None = None
    severity: Severity = Severity.INFO
    metadata: dict = Field(default_factory=dict)


class ModuleResult(BaseModel):
    module: str
    target: str
    target_type: TargetType
    started_at: datetime
    finished_at: datetime
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None  # populated if the module failed

    @property
    def duration_s(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


class Report(BaseModel):
    target: str
    target_type: TargetType
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    modules: list[ModuleResult] = Field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(len(m.findings) for m in self.modules)

    @property
    def failed_modules(self) -> list[str]:
        return [m.module for m in self.modules if m.error]
