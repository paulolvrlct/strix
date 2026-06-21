from __future__ import annotations

from datetime import datetime, timezone

from strix.models import Finding, ModuleResult, TargetType
from strix.modules._exif import parse_exif, run_exiftool
from strix.modules.base import BaseModule


class ImageModule(BaseModule):
    name = "image"
    description = "Image metadata and GPS extraction (ExifTool)"
    target_types = [TargetType.IMAGE]
    requires_api_key = False
    rate_limit = 0.0  # local subprocess; only the optional URL fetch touches the network

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        return await run_exiftool(self, target, TargetType.IMAGE, started)

    def _parse(self, data: object, out: list[Finding]) -> None:
        """Kept for backward compatibility / unit tests; delegates to the shared parser."""
        parse_exif(data, out)
