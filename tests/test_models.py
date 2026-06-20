from __future__ import annotations

from datetime import datetime, timedelta, timezone

from strix.models import Finding, ModuleResult, Report, Severity, TargetType


def _module_result(module: str, *, findings=None, error=None) -> ModuleResult:
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(seconds=2)
    return ModuleResult(
        module=module,
        target="example.com",
        target_type=TargetType.DOMAIN,
        started_at=start,
        finished_at=end,
        findings=findings or [],
        error=error,
    )


def test_duration_s():
    result = _module_result("domain")
    assert result.duration_s == 2.0


def test_total_findings_and_failed_modules():
    finding = Finding(title="Subdomain", value="a.example.com", source="crt.sh")
    report = Report(
        target="example.com",
        target_type=TargetType.DOMAIN,
        modules=[
            _module_result("domain", findings=[finding, finding]),
            _module_result("broken", error="boom"),
        ],
    )
    assert report.total_findings == 2
    assert report.failed_modules == ["broken"]


def test_finding_defaults():
    finding = Finding(title="t", value="v", source="s")
    assert finding.severity is Severity.INFO
    assert finding.url is None
    assert finding.metadata == {}


def test_report_roundtrip_serialization():
    finding = Finding(
        title="Known CVE",
        value="CVE-2021-1234",
        source="shodan-internetdb",
        severity=Severity.HIGH,
    )
    report = Report(
        target="1.1.1.1",
        target_type=TargetType.IP,
        modules=[_module_result("ip", findings=[finding])],
    )
    dumped = report.model_dump_json()
    restored = Report.model_validate_json(dumped)
    assert restored.target == "1.1.1.1"
    assert restored.total_findings == 1
    assert restored.modules[0].findings[0].severity is Severity.HIGH
