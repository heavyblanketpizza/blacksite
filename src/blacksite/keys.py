"""Secrets that protect accounts and the audit ledger, kept in one owner-only directory.

``master.key`` holds 32 random bytes from which each purpose derives its own key with
HKDF, so a key used to hash user agents can never check a ledger record. The Ed25519
signing key signs ledger checkpoints and guide provenance; its public half can be handed
out to verify those signatures on another machine.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MASTER_FILE = "master.key"
SIGNING_FILE = "signing.key"
PUBLIC_FILE = "signing.pub"


def canonical(value: Any) -> bytes:
    """The one byte encoding that hashes and signatures cover: sorted keys, no spaces, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def group(hex_text: str) -> str:
    """A fingerprint people can read aloud and write down: 7F3A-91C2-0B5E-D4A8."""
    text = hex_text[:16].upper()
    return "-".join(text[index:index + 4] for index in range(0, len(text), 4))


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            os.chmod(path, stat.S_IRWXU)
    return path


def private_file(path: Path) -> None:
    if os.name != "nt":
        with contextlib.suppress(OSError):
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Not an Ed25519 public key")
    return key


def public_key_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sha256_hex(raw)[:16]


def verify_signature(public: Ed25519PublicKey, data: bytes, signature: str) -> bool:
    try:
        public.verify(base64.b64decode(signature, validate=True), data)
    except (InvalidSignature, binascii.Error, ValueError):
        return False
    return True


class Keys:
    def __init__(self, directory: Path) -> None:
        self.directory = private_dir(Path(directory))
        self.master = _create_or_read(self.directory / MASTER_FILE, lambda: os.urandom(32))
        pem = _create_or_read(self.directory / SIGNING_FILE, _new_signing_key)
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{self.directory / SIGNING_FILE} is not an Ed25519 key")
        self._signing = key
        self.public = key.public_key()
        public_path = self.directory / PUBLIC_FILE
        if not public_path.is_file():
            public_path.write_bytes(self.public_pem())
        self.key_id = public_key_id(self.public)
        self.fingerprint = group(self.key_id)

    def derive(self, purpose: str) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"blacksite:" + purpose.encode()).derive(self.master)

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self._signing.sign(data)).decode("ascii")

    def public_pem(self) -> bytes:
        return self.public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _new_signing_key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _create_or_read(path: Path, make: Any) -> bytes:
    """Create a secret file owner-only, or read it if it exists (another process may win the race)."""
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        for _ in range(100):  # the creating process may not have written it yet
            data = path.read_bytes()
            if data:
                return data
            time.sleep(0.02)
        raise ValueError(f"{path} is empty; restore it from a backup or remove the keys directory") from None
    data = make()
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    private_file(path)
    return data
