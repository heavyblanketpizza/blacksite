import os
import stat
from pathlib import Path

import pytest

from blacksite.config import load_settings
from blacksite.keys import Keys, canonical, group, load_public_key, verify_signature


def test_keys_persist_and_derive(tmp_path: Path) -> None:
    first = Keys(tmp_path / "keys")
    second = Keys(tmp_path / "keys")
    assert first.derive("ledger") == second.derive("ledger") != first.derive("totp")
    assert len(first.derive("ledger")) == 32
    assert first.key_id == second.key_id and len(first.key_id) == 16
    assert first.fingerprint == group(first.key_id) and len(first.fingerprint) == 19


def test_signature_round_trip(tmp_path: Path) -> None:
    keys = Keys(tmp_path / "keys")
    signature = keys.sign(b"payload")
    public = load_public_key(keys.public_pem())
    assert verify_signature(public, b"payload", signature)
    assert not verify_signature(public, b"payload!", signature)
    assert not verify_signature(public, b"payload", "not base64 at all")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_key_files_are_private(tmp_path: Path) -> None:
    Keys(tmp_path / "keys")
    assert stat.S_IMODE((tmp_path / "keys").stat().st_mode) == 0o700
    for name in ("master.key", "signing.key"):
        assert stat.S_IMODE((tmp_path / "keys" / name).stat().st_mode) == 0o600


def test_canonical_is_stable() -> None:
    assert canonical({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode()


def test_group_formats_a_fingerprint() -> None:
    assert group("7f3a91c20b5ed4a8ffff") == "7F3A-91C2-0B5E-D4A8"


def test_settings_have_auth_and_audit(tmp_path: Path) -> None:
    settings = load_settings(overrides=["auth.idle_minutes=5"], environ={}, cwd=tmp_path)
    assert settings.auth.idle_minutes == 5 and settings.auth.session_hours == 12
    assert settings.auth.store_path == tmp_path / "var/access.sqlite"
    assert settings.auth.keys_dir == tmp_path / "var/keys"
    assert settings.audit.store_path == tmp_path / "var/audit.sqlite" and settings.audit.checkpoint_every == 100
