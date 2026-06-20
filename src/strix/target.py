from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from strix.models import TargetType

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\s().\-]{5,}$")

_IMAGE_EXTS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".tif",
    ".tiff",
    ".webp",
    ".heic",
    ".heif",
    ".bmp",
    ".cr2",
    ".nef",
    ".arw",
    ".dng",
    ".raw",
}


def _looks_like_image(value: str) -> bool:
    """True for a local image path or an http(s) URL pointing at an image file."""
    path_part = value.split("?", 1)[0].rstrip("/")
    suffix = Path(path_part).suffix.lower()
    if suffix in _IMAGE_EXTS:
        return True
    expanded = Path(value).expanduser()
    return expanded.is_file() and expanded.suffix.lower() in _IMAGE_EXTS


def detect_target_type(target: str) -> TargetType:
    """Best-effort auto-detection of a target's type.

    Order: IP -> email -> image -> phone -> domain -> username (fallback).
    """
    value = target.strip()

    # IP address (v4 or v6).
    try:
        ipaddress.ip_address(value)
        return TargetType.IP
    except ValueError:
        pass

    if _EMAIL_RE.match(value):
        return TargetType.EMAIL

    # Image file or URL (checked before domain: "photo.jpg" also matches the FQDN regex).
    if _looks_like_image(value):
        return TargetType.IMAGE

    # Phone: no letters, mostly digits, optional leading "+".
    if _PHONE_RE.match(value) and not any(c.isalpha() for c in value):
        if sum(c.isdigit() for c in value) >= 7:
            return TargetType.PHONE

    if _DOMAIN_RE.match(value):
        return TargetType.DOMAIN

    return TargetType.USERNAME
