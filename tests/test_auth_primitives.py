import pytest

from blacksite.auth import passwords, totp


def test_scrypt_round_trip_and_upgrade(monkeypatch) -> None:
    stored = passwords.hash_password("correct horse battery")
    assert stored.startswith(f"scrypt${passwords.N}$")
    assert passwords.verify_password("correct horse battery", stored)
    assert not passwords.verify_password("correct horse batterY", stored)
    assert not passwords.verify_password("x", "garbage") and not passwords.verify_password("x", "scrypt$1$2$3$@@$@@")
    assert not passwords.needs_rehash(stored)
    monkeypatch.setattr(passwords, "N", passwords.N * 2)
    assert passwords.needs_rehash(stored)
    assert passwords.verify_password("correct horse battery", stored)  # old parameters still verify


def test_same_password_hashes_differently() -> None:
    assert passwords.hash_password("river-stone-lamp-42") != passwords.hash_password("river-stone-lamp-42")


def test_dummy_verify_runs_without_a_stored_hash() -> None:
    passwords.dummy_verify("anything at all")


@pytest.mark.parametrize("password", [
    "short-1",                 # too short
    "x" * 257,                 # too long
    "aaaaaaaaaaaaaa",          # too few distinct characters
    "abababababab12",          # too few distinct characters
    "password2024!",           # common word with digits
    "Qwertyuiop123",           # keyboard run
    "alice-is-great-99",       # contains the username
])
def test_policy_rejects(password: str) -> None:
    with pytest.raises(passwords.PasswordPolicyError):
        passwords.check_policy(password, "alice")


def test_policy_accepts_good_passwords_and_temporary_ones() -> None:
    passwords.check_policy("river-stone-lamp-42", "alice")
    passwords.check_policy("비밀번호는 길고 특별해요", "alice")
    for _ in range(20):
        temporary = passwords.temporary_password()
        assert len(temporary) == 19
        passwords.check_policy(temporary, "alice")


def test_rfc6238_vectors() -> None:
    key = b"12345678901234567890"
    vectors = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
               (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]
    for seconds, expected in vectors:
        assert totp.hotp(key, seconds // 30, digits=8) == expected


def test_verify_allows_one_step_of_drift_and_refuses_replay() -> None:
    secret = totp.new_secret()
    now = 1_800_000_000.0
    step = totp.step_of(now)
    assert totp.verify(secret, totp.code_at(secret, step), now, None) == step
    assert totp.verify(secret, totp.code_at(secret, step - 1), now, None) == step - 1
    assert totp.verify(secret, totp.code_at(secret, step + 1), now, None) == step + 1
    assert totp.verify(secret, totp.code_at(secret, step - 2), now, None) is None
    assert totp.verify(secret, totp.code_at(secret, step), now, last_step=step) is None
    assert totp.verify(secret, " " + totp.code_at(secret, step)[:3] + " " + totp.code_at(secret, step)[3:], now, None) == step
    assert totp.verify(secret, "abcdef", now, None) is None and totp.verify(secret, "", now, None) is None


def test_recovery_codes_and_qr() -> None:
    codes = totp.new_recovery_codes()
    assert len(set(codes)) == 10
    assert all(len(code) == 11 and code[5] == "-" and len(totp.normalize_code(code)) == 10 for code in codes)
    assert totp.normalize_code(" ABCDE-fghij ") == "abcdefghij"
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "alice")
    assert uri.startswith("otpauth://totp/Blacksite:alice?") and "secret=JBSWY3DPEHPK3PXP" in uri
    assert totp.qr_data_uri(uri).startswith("data:image/svg+xml")
