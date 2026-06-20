from __future__ import annotations

from datetime import datetime, timezone

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder
from phonenumbers import timezone as pn_timezone

from strix.models import Finding, ModuleResult, Severity, TargetType
from strix.modules.base import BaseModule

_LINE_TYPES = {
    PhoneNumberType.FIXED_LINE: "fixed line",
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
    PhoneNumberType.TOLL_FREE: "toll free",
    PhoneNumberType.PREMIUM_RATE: "premium rate",
    PhoneNumberType.SHARED_COST: "shared cost",
    PhoneNumberType.VOIP: "voip",
    PhoneNumberType.PERSONAL_NUMBER: "personal number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "uan",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}


class PhoneModule(BaseModule):
    name = "phone"
    description = "Offline phone metadata (validity, region, carrier, timezone, line type)"
    target_types = [TargetType.PHONE]
    requires_api_key = False
    rate_limit = 0.0  # fully offline, no network

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        try:
            number = phonenumbers.parse(target, None)
        except Exception as exc:
            return self._result(target, TargetType.PHONE, started, findings, error=str(exc))

        try:
            valid = phonenumbers.is_valid_number(number)
            findings.append(
                Finding(
                    title="Valid", value=str(valid), source="phonenumbers", severity=Severity.INFO
                )
            )
            findings.append(
                Finding(
                    title="Country code",
                    value=f"+{number.country_code}",
                    source="phonenumbers",
                    severity=Severity.INFO,
                )
            )
            findings.append(
                Finding(
                    title="E.164",
                    value=phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
                    source="phonenumbers",
                    severity=Severity.INFO,
                )
            )

            region = geocoder.description_for_number(number, "en")
            if region:
                findings.append(
                    Finding(
                        title="Region", value=region, source="phonenumbers", severity=Severity.INFO
                    )
                )

            carrier_name = carrier.name_for_number(number, "en")
            if carrier_name:
                findings.append(
                    Finding(
                        title="Carrier",
                        value=carrier_name,
                        source="phonenumbers",
                        severity=Severity.INFO,
                    )
                )

            for tz in pn_timezone.time_zones_for_number(number):
                findings.append(
                    Finding(
                        title="Timezone", value=tz, source="phonenumbers", severity=Severity.INFO
                    )
                )

            line_type = _LINE_TYPES.get(phonenumbers.number_type(number), "unknown")
            findings.append(
                Finding(
                    title="Line type",
                    value=line_type,
                    source="phonenumbers",
                    severity=Severity.INFO,
                )
            )
        except Exception as exc:
            return self._result(target, TargetType.PHONE, started, findings, error=str(exc))

        return self._result(target, TargetType.PHONE, started, findings)
