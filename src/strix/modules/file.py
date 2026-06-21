from __future__ import annotations

from datetime import datetime, timezone

from strix.models import ModuleResult, TargetType
from strix.modules._exif import run_exiftool
from strix.modules.base import BaseModule


class FileModule(BaseModule):
    name = "file"
    description = "Document/media/archive metadata (ExifTool: PDF, Office, audio, video...)"
    target_types = [TargetType.FILE]
    requires_api_key = False
    rate_limit = 0.0  # local subprocess; only the optional URL fetch touches the network

    async def run(self, target: str) -> ModuleResult:
        started = datetime.now(timezone.utc)
        return await run_exiftool(self, target, TargetType.FILE, started)
