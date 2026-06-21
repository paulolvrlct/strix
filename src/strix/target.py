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

# Crypto wallets: Ethereum (0x + 40 hex) and Bitcoin (legacy base58 or bech32).
_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BTC_RE = re.compile(r"^(bc1[ac-hj-np-z02-9]{11,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})$")

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


# Non-image files ExifTool can still read metadata from (documents, media, archives...).
_FILE_EXTS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".odt",
    ".rtf",
    ".txt",
    ".csv",
    ".mp3",
    ".wav",
    ".flac",
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".m4a",
    ".epub",
}


def _suffix_of(value: str) -> str:
    path_part = value.split("?", 1)[0].rstrip("/")
    return Path(path_part).suffix.lower()


def _looks_like_image(value: str) -> bool:
    """True for a local image path or an http(s) URL pointing at an image file."""
    if _suffix_of(value) in _IMAGE_EXTS:
        return True
    expanded = Path(value).expanduser()
    return expanded.is_file() and expanded.suffix.lower() in _IMAGE_EXTS


def _looks_like_file(value: str) -> bool:
    """True for a non-image local file/URL whose metadata ExifTool can read."""
    if _suffix_of(value) in _FILE_EXTS:
        return True
    expanded = Path(value).expanduser()
    return expanded.is_file() and expanded.suffix.lower() in _FILE_EXTS


def _looks_like_wallet(value: str) -> bool:
    return bool(_ETH_RE.match(value) or _BTC_RE.match(value))


def detect_target_type(target: str) -> TargetType:
    """Best-effort auto-detection of a target's type.

    Order: IP -> email -> wallet -> image -> file -> phone -> domain -> username.
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

    # Crypto wallet address (checked before domain/username; distinctive formats).
    if _looks_like_wallet(value):
        return TargetType.WALLET

    # Image / file by extension or existing path (before domain: "photo.jpg" matches FQDN too).
    if _looks_like_image(value):
        return TargetType.IMAGE
    if _looks_like_file(value):
        return TargetType.FILE

    # Phone: no letters, mostly digits, optional leading "+".
    if _PHONE_RE.match(value) and not any(c.isalpha() for c in value):
        if sum(c.isdigit() for c in value) >= 7:
            return TargetType.PHONE

    if _DOMAIN_RE.match(value):
        return TargetType.DOMAIN

    return TargetType.USERNAME
