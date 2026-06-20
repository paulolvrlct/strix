from __future__ import annotations

from strix.models import Severity
from strix.modules.image import ImageModule

# Shape of one element of `exiftool -json <file>` output.
_EXIFTOOL_JSON = [
    {
        "SourceFile": "photo.jpg",
        "Make": "Apple",
        "Model": "iPhone 14 Pro",
        "Software": "16.5",
        "DateTimeOriginal": "2023:06:15 14:30:00",
        "Artist": "Jane Doe",
        "SerialNumber": "ABC123",
        "GPSLatitude": "48 deg 51' 30.00\" N",
        "GPSLongitude": "2 deg 21' 3.00\" E",
        "GPSPosition": "48 deg 51' 30.00\" N, 2 deg 21' 3.00\" E",
        "GPSDateStamp": "2023:06:15",  # uncurated GPS* tag -> still surfaced
        "ColorSpace": "sRGB",  # not curated, not GPS -> ignored
    }
]


def _findings_by_title(findings):
    return {f.title: f for f in findings}


def test_parse_maps_severities():
    out = []
    ImageModule()._parse(_EXIFTOOL_JSON, out)
    by_title = _findings_by_title(out)

    # INFO-level technical metadata.
    assert by_title["Make"].value == "Apple"
    assert by_title["Make"].severity is Severity.INFO
    assert by_title["Make"].source == "exiftool"

    # PII -> LOW.
    assert by_title["Artist"].severity is Severity.LOW
    assert by_title["SerialNumber"].severity is Severity.LOW

    # GPS -> MEDIUM (privacy-sensitive location leak).
    assert by_title["GPSPosition"].severity is Severity.MEDIUM
    assert by_title["GPSLatitude"].severity is Severity.MEDIUM

    # Uncurated GPS* tag is still surfaced at MEDIUM.
    assert by_title["GPSDateStamp"].severity is Severity.MEDIUM

    # Non-interesting tag is dropped.
    assert "ColorSpace" not in by_title


def test_parse_handles_empty_or_malformed():
    out = []
    ImageModule()._parse([], out)
    ImageModule()._parse("not a list", out)
    ImageModule()._parse([{}], out)
    assert out == []
