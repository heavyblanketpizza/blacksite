"""Authenticator-app codes (RFC 6238 TOTP) and one-time recovery codes.

Codes need only a clock, so they work with no network. A code is accepted for the
current 30-second step and one step either side; a step already used is refused, so a
code seen over someone's shoulder cannot be replayed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
import struct
from urllib.parse import quote, urlencode

STEP, DIGITS = 30, 6
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_SEPARATORS = re.compile(r"[\s-]+")


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def new_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    text = secret.strip().replace(" ", "").upper()
    return base64.b32decode(text + "=" * (-len(text) % 8))


def step_of(now: float) -> int:
    return int(now // STEP)


def code_at(secret: str, step: int) -> str:
    return hotp(_key(secret), step)


def verify(secret: str, code: str, now: float, last_step: int | None) -> int | None:
    """The step the code belongs to, or None. Steps at or before ``last_step`` are refused."""
    code = _SEPARATORS.sub("", code or "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    try:
        key = _key(secret)
    except (binascii.Error, ValueError):
        return None
    current = step_of(now)
    for step in (current, current - 1, current + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(hotp(key, step), code):
            return step
    return None


def provisioning_uri(secret: str, username: str, issuer: str = "Blacksite") -> str:
    query = urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": STEP})
    return f"otpauth://totp/{quote(issuer)}:{quote(username)}?{query}"


def qr_data_uri(uri: str) -> str:
    """A QR code as an SVG data URI; always dark on white so every phone camera reads it."""
    import segno

    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#161616", light="#ffffff")


def new_recovery_codes(count: int = 10) -> list[str]:
    codes: set[str] = set()
    while len(codes) < count:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        codes.add(f"{raw[:5]}-{raw[5:]}")
    return sorted(codes)


def normalize_code(code: str) -> str:
    return _SEPARATORS.sub("", code or "").lower()
