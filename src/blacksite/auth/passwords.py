"""Password hashing with scrypt from the standard library, and the password rules.

The stored form names its own parameters, ``scrypt$<n>$<r>$<p>$<salt>$<hash>``, so the
cost can be raised later and old hashes still verify (and are rehashed at next login).
Passwords are NFKC-normalized first, so the same Korean or accented text typed on two
keyboards hashes the same.
"""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import hmac
import os
import re
import secrets
import unicodedata
from pathlib import Path

# OWASP's scrypt baseline: 128 MiB and about a quarter second on a laptop. Tests lower N.
N, R, P = 2**17, 8, 1
SALT_BYTES, HASH_BYTES = 16, 32
MIN_LENGTH, MAX_LENGTH = 12, 256
_TEMP_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_TRAILING = re.compile(r"[\W\d_]+$")


class PasswordPolicyError(ValueError):
    """The new password breaks a rule; the message says which."""


def _normalize(password: str) -> bytes:
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(_normalize(password), salt=salt, n=n, r=r, p=p, dklen=HASH_BYTES,
                          maxmem=256 * n * r * p + (1 << 20))


def hash_password(password: str) -> str:
    salt = os.urandom(SALT_BYTES)
    digest = _scrypt(password, salt, N, R, P)
    return f"scrypt${N}${R}${P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def _parse(stored: str) -> tuple[int, int, int, bytes, bytes] | None:
    parts = stored.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return None
    try:
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = base64.b64decode(parts[4], validate=True)
        digest = base64.b64decode(parts[5], validate=True)
    except (ValueError, binascii.Error):
        return None
    if n < 2 or n & (n - 1) or not 0 < r <= 64 or not 0 < p <= 16 or not salt or not digest:
        return None
    return n, r, p, salt, digest


def verify_password(password: str, stored: str) -> bool:
    parsed = _parse(stored or "")
    if parsed is None:
        return False
    n, r, p, salt, digest = parsed
    try:
        candidate = _scrypt(password, salt, n, r, p)
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(candidate, digest)


def needs_rehash(stored: str) -> bool:
    parsed = _parse(stored or "")
    return parsed is None or parsed[:3] != (N, R, P)


@functools.lru_cache(maxsize=4)
def _dummy_hash(n: int) -> str:
    return hash_password(secrets.token_hex(16))


def dummy_verify(password: str) -> None:
    """Spend the same time as a real check, so a missing account cannot be told apart by timing."""
    verify_password(password, _dummy_hash(N))


@functools.lru_cache(maxsize=1)
def _common_words() -> frozenset[str]:
    path = Path(__file__).with_name("common-words.txt")
    return frozenset(line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines()
                     if line.strip() and not line.startswith("#"))


def check_policy(password: str, username: str) -> None:
    text = unicodedata.normalize("NFKC", password)
    if len(text) < MIN_LENGTH:
        raise PasswordPolicyError(f"Use at least {MIN_LENGTH} characters.")
    if len(text) > MAX_LENGTH:
        raise PasswordPolicyError(f"Use at most {MAX_LENGTH} characters.")
    lowered = text.lower()
    name = username.strip().lower()
    if len(name) >= 3 and name in lowered:
        raise PasswordPolicyError("Do not include your username.")
    if len(set(lowered)) < 5:
        raise PasswordPolicyError("Use more different characters.")
    base = _TRAILING.sub("", lowered)
    if base in _common_words() or lowered in _common_words():
        raise PasswordPolicyError("This password is too common. Try a few unrelated words.")


def temporary_password() -> str:
    """Four groups of four easy-to-read characters, e.g. k7Qm-x2Rt-9bLw-Hc4p."""
    while True:
        candidate = "-".join("".join(secrets.choice(_TEMP_ALPHABET) for _ in range(4)) for _ in range(4))
        try:
            check_policy(candidate, "")
        except PasswordPolicyError:
            continue
        return candidate
