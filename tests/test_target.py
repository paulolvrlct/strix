from __future__ import annotations

import pytest

from strix.models import TargetType
from strix.target import detect_target_type


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", TargetType.IP),
        ("1.1.1.1", TargetType.IP),
        ("2606:4700:4700::1111", TargetType.IP),
        ("user@example.com", TargetType.EMAIL),
        ("first.last@sub.example.co.uk", TargetType.EMAIL),
        ("example.com", TargetType.DOMAIN),
        ("sub.example.co.uk", TargetType.DOMAIN),
        ("+33612345678", TargetType.PHONE),
        ("+1 (415) 555-2671", TargetType.PHONE),
        ("photo.jpg", TargetType.IMAGE),
        ("IMG_1234.JPG", TargetType.IMAGE),
        ("/tmp/holiday.png", TargetType.IMAGE),
        ("https://example.com/pics/beach.heic", TargetType.IMAGE),
        ("report.pdf", TargetType.FILE),
        ("/tmp/data.xlsx", TargetType.FILE),
        ("song.mp3", TargetType.FILE),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", TargetType.WALLET),
        ("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", TargetType.WALLET),
        ("paulx", TargetType.USERNAME),
        ("john_doe", TargetType.USERNAME),
    ],
)
def test_detect_target_type(value, expected):
    assert detect_target_type(value) == expected


def test_invalid_email_is_not_email():
    # No TLD / malformed -> should not be classified as email.
    assert detect_target_type("not-an-email@") != TargetType.EMAIL


def test_whitespace_is_stripped():
    assert detect_target_type("  example.com  ") == TargetType.DOMAIN
