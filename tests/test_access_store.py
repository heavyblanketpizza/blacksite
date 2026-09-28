import os
import stat
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from blacksite.auth import totp
from blacksite.auth.passwords import PasswordPolicyError
from blacksite.auth.store import AccessStore, AuthError, LoginFailed
from blacksite.config import AuthSettings

GOOD = "river-stone-lamp-42"


def member(access, name="carol", role="member"):
    user, _ = access.create_user(name, name.title(), role, "cli:test", password=GOOD, must_change=False)
    return user


def enroll(access, clock, user_id) -> tuple[str, list[str]]:
    secret = access.totp_setup(user_id)
    codes = access.totp_enroll(user_id, totp.code_at(secret, totp.step_of(clock())))
    return secret, codes


def test_login_stages_and_token_rotation(access, clock) -> None:
    user, temporary = access.create_user("Alice", "앨리스", "admin", "cli:test")
    assert access.find(" alice ").id == user.id and access.find("ALICE").id == user.id
    assert access.user(user.id).display_name == "앨리스" and user.must_change
    authed = access.authenticate(" Alice ", temporary)
    session, token = access.start_session(authed, "UA")
    assert session.stage == "password_change" and len(token) >= 43
    assert access.lookup(token)[0].id == session.id
    access.change_password(user.id, GOOD, keep_session=session.id)
    session2, token2 = access.advance(session.id)
    assert session2.stage == "totp_enroll" and token2 != token and session2.csrf != session.csrf
    assert access.lookup(token) is None
    secret, codes = enroll(access, clock, user.id)
    assert len(codes) == 10 and access.user(user.id).totp_enabled
    session3, token3 = access.advance(session2.id)
    assert session3.stage == "full" and access.lookup(token3)[1].id == user.id


def test_next_login_asks_for_the_code(access, clock) -> None:
    user = member(access, "dave", "admin")
    secret, _ = enroll(access, clock, user.id)
    session, token = access.start_session(access.authenticate("dave", GOOD), "UA")
    assert session.stage == "totp"
    clock.advance(60)
    assert access.totp_check(user.id, totp.code_at(secret, totp.step_of(clock())))
    assert not access.totp_check(user.id, totp.code_at(secret, totp.step_of(clock())))  # replay
    assert access.advance(session.id)[0].stage == "full"


def test_members_without_totp_go_straight_in(access) -> None:
    user = member(access)
    session, _ = access.start_session(access.authenticate("carol", GOOD), "UA")
    assert session.stage == "full" and access.session(session.id).user_id == user.id


def test_wrong_password_and_unknown_user_fail_the_same_way(access) -> None:
    member(access)
    with pytest.raises(LoginFailed) as wrong:
        access.authenticate("carol", "nope-nope-nope")
    with pytest.raises(LoginFailed) as unknown:
        access.authenticate("nobody", "nope-nope-nope")
    assert str(wrong.value) == str(unknown.value) == "Wrong username or password."
    assert wrong.value.user_id is not None and unknown.value.user_id is None
    assert unknown.value.hashed_name == access.pseudonym("nobody") and len(unknown.value.hashed_name) == 16


def test_lockout_backoff_and_recovery(access, clock) -> None:
    user = member(access, "bob")
    for _ in range(5):
        with pytest.raises(LoginFailed):
            access.authenticate("bob", "nope-nope-nope")
    with pytest.raises(LoginFailed) as caught:
        access.authenticate("bob", GOOD)  # correct password, but locked
    assert caught.value.locked
    clock.advance(16 * 60)
    assert access.authenticate("bob", GOOD).id == user.id
    for _ in range(5):
        with pytest.raises(LoginFailed):
            access.authenticate("bob", "nope-nope-nope")
    clock.advance(16 * 60)  # the second lockout lasts twice as long
    with pytest.raises(LoginFailed):
        access.authenticate("bob", GOOD)
    clock.advance(16 * 60)
    assert access.authenticate("bob", GOOD).id == user.id


def test_many_failures_across_accounts_throttle(access) -> None:
    assert not access.throttled()
    for index in range(21):
        with pytest.raises(LoginFailed):
            access.authenticate(f"ghost{index}", "nope-nope-nope")
    assert access.throttled()


def test_idle_expiry_after_the_laptop_sleeps(access, clock) -> None:
    user = member(access)
    session, token = access.start_session(user, "UA")
    clock.advance(29 * 60)
    assert access.lookup(token) is not None
    access.touch(session.id)
    clock.advance(29 * 60)
    assert access.lookup(token) is not None  # touched, so still inside the idle window
    clock.advance(2 * 3600)  # asleep
    assert access.lookup(token) is None and access.session(session.id).end_reason == "idle"


def test_absolute_expiry(access, clock) -> None:
    user = member(access)
    session, token = access.start_session(user, "UA")
    for _ in range(26):
        clock.advance(28 * 60)
        access.touch(session.id)
    assert access.lookup(token) is None and access.session(session.id).end_reason == "expired"


def test_suspension_ends_sessions_and_blocks_login(access) -> None:
    member(access, "root", "admin")
    user = member(access)
    session, token = access.start_session(user, "UA")
    ended = access.set_status(user.id, "suspended")
    assert ended == [session.id] and access.lookup(token) is None
    with pytest.raises(LoginFailed):
        access.authenticate("carol", GOOD)
    access.set_status(user.id, "active")
    assert access.authenticate("carol", GOOD).id == user.id


def test_last_admin_is_protected(access) -> None:
    admin = member(access, "root", "admin")
    with pytest.raises(AuthError):
        access.set_status(admin.id, "suspended")
    with pytest.raises(AuthError):
        access.set_role(admin.id, "member")
    second = member(access, "root2", "admin")
    access.set_role(admin.id, "member")
    assert access.active_admins() == 1 and access.user(second.id).role == "admin"


def test_password_change_rules_and_other_sessions_end(access) -> None:
    user = member(access)
    keep, keep_token = access.start_session(user, "UA")
    other, other_token = access.start_session(user, "UA2")
    with pytest.raises(PasswordPolicyError):
        access.change_password(user.id, "short", keep_session=keep.id)
    ended = access.change_password(user.id, "a-brand-new-passphrase", keep_session=keep.id)
    assert ended == [other.id] and access.lookup(other_token) is None and access.lookup(keep_token) is not None
    assert access.check_password(user.id, "a-brand-new-passphrase") and not access.check_password(user.id, GOOD)
    with pytest.raises(AuthError):
        access.change_password(user.id, "a-brand-new-passphrase", keep_session=keep.id)  # same as before


def test_admin_reset_password_forces_a_change(access) -> None:
    user = member(access)
    _, token = access.start_session(user, "UA")
    temporary, ended = access.reset_password(user.id)
    assert ended and access.lookup(token) is None and access.user(user.id).must_change
    assert access.start_session(access.authenticate("carol", temporary), "UA")[0].stage == "password_change"


def test_recovery_codes_are_single_use(access, clock) -> None:
    user = member(access, "erin", "admin")
    _, codes = enroll(access, clock, user.id)
    assert access.use_recovery(user.id, codes[0].upper()) == 9
    assert access.use_recovery(user.id, codes[0]) is None
    assert access.use_recovery(user.id, "zzzzz-zzzzz") is None


def test_reset_totp_requires_enrollment_again(access, clock) -> None:
    user = member(access, "fay", "admin")
    enroll(access, clock, user.id)
    access.reset_totp(user.id)
    assert not access.user(user.id).totp_enabled
    assert access.start_session(access.authenticate("fay", GOOD), "UA")[0].stage == "totp_enroll"


def test_totp_enroll_refuses_a_wrong_code(access) -> None:
    user = member(access)
    access.totp_setup(user.id)
    with pytest.raises(AuthError):
        access.totp_enroll(user.id, "000000")
    assert not access.user(user.id).totp_enabled


def test_confirmation_window(access, clock) -> None:
    user = member(access)
    session, _ = access.start_session(user, "UA")
    assert not access.confirmed(access.session(session.id))
    access.confirm(session.id)
    assert access.confirmed(access.session(session.id))
    clock.advance(6 * 60)
    assert not access.confirmed(access.session(session.id))


def test_access_levels_and_shares(access) -> None:
    owner, other, admin = member(access, "own"), member(access, "oth"), member(access, "adm", "admin")
    access.register_incident("inc-1", owner.id)
    assert access.access(owner, "inc-1") == "manage" and access.access(other, "inc-1") is None
    access.share("inc-1", other.id, owner.id)
    assert access.access(other, "inc-1") == "investigate" and access.access(admin, "inc-1") == "manage"
    assert access.incidents()["inc-1"]["shares"] == [other.id]
    access.unshare("inc-1", other.id)
    assert access.access(other, "inc-1") is None
    access.register_incident("usb-1", None)
    assert access.access(owner, "usb-1") is None and access.access(admin, "usb-1") == "manage"
    access.register_incident("usb-1", owner.id)  # registering again never steals ownership
    assert access.incidents()["usb-1"]["owner_id"] is None
    access.set_owner("usb-1", owner.id)
    assert access.access(owner, "usb-1") == "manage"
    access.forget_incident("usb-1")
    assert "usb-1" not in access.incidents()


def test_runs_are_recorded(access) -> None:
    access.record_run({"incident_id": "inc-1", "turn": 1, "actor": "user:1", "session": "s", "started_at": "a",
                       "finished_at": "b", "seconds": 12.5, "requests": 3, "tool_calls": 4, "input_tokens": 100,
                       "output_tokens": 20, "model": "m", "provider": "ollama", "citations_ok": 3,
                       "citations_total": 3, "guide": True})
    runs = access.runs({"inc-1"})
    assert runs[0]["seconds"] == 12.5 and runs[0]["guide"] is True and access.runs({"other"}) == []


def test_invalid_usernames_and_roles(access) -> None:
    for bad in ["a", "has space", "x" * 41, "semi;colon", "한글이름"]:
        with pytest.raises(AuthError):
            access.create_user(bad, "X", "member", "t")
    with pytest.raises(AuthError):
        access.create_user("okay", "X", "owner", "t")
    member(access, "taken")
    with pytest.raises(AuthError):
        access.create_user("TAKEN", "X", "member", "t")


def test_a_second_store_sees_changes(tmp_path: Path, access, keys, clock) -> None:
    user = member(access)
    _, token = access.start_session(user, "UA")
    other = AccessStore(tmp_path / "access.sqlite", keys, access.settings, clock=clock)
    member(other, "root", "admin")
    other.set_status(user.id, "suspended")
    assert access.lookup(token) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_store_file_is_private(tmp_path: Path, access) -> None:
    member(access)
    assert stat.S_IMODE((tmp_path / "access.sqlite").stat().st_mode) == 0o600


def test_wrong_codes_lock_the_account_across_sessions(access, clock) -> None:
    user = member(access, "gail", "admin")
    enroll(access, clock, user.id)
    for _ in range(5):  # the password is known; a fresh session each time must not reset the count
        access.start_session(access.authenticate("gail", GOOD), "UA")
        assert not access.totp_check(user.id, "000000")
    with pytest.raises(LoginFailed) as caught:
        access.authenticate("gail", GOOD)
    assert caught.value.locked and access.sessions() == []


def test_wrong_recovery_codes_count_too(access, clock) -> None:
    user = member(access, "hal", "admin")
    enroll(access, clock, user.id)
    for _ in range(5):
        assert access.use_recovery(user.id, "zzzzz-zzzzz") is None
    with pytest.raises(LoginFailed):
        access.authenticate("hal", GOOD)


def test_a_right_code_clears_the_count(access, clock) -> None:
    user = member(access, "ivy", "admin")
    secret, _ = enroll(access, clock, user.id)
    for _ in range(4):
        assert not access.totp_check(user.id, "000000")
    clock.advance(30)
    assert access.totp_check(user.id, totp.code_at(secret, totp.step_of(clock())))
    for _ in range(4):
        assert not access.totp_check(user.id, "000000")
    assert access.authenticate("ivy", GOOD).id == user.id


@pytest.mark.parametrize("role", ["admin", "member"])
@pytest.mark.parametrize("enrolled", [False, True])
def test_paused_totp_uses_password_only_and_preserves_enrollment(access, clock, role, enrolled) -> None:
    user = member(access, "paused", role)
    secret, codes = enroll(access, clock, user.id) if enrolled else (None, None)
    access.settings = replace(access.settings, totp_enabled=False)
    session, token = access.start_session(access.authenticate(user.username, GOOD), "UA")
    assert session.stage == "full" and access.lookup(token) is not None
    assert access.user(user.id).totp_enabled is enrolled
    with pytest.raises(LoginFailed):
        access.authenticate(user.username, "wrong-password")
    access.settings = replace(access.settings, totp_enabled=True)
    assert access.lookup(token) is None
    assert access.session(session.id).end_reason == "auth_policy_changed"
    resumed, _ = access.start_session(access.authenticate(user.username, GOOD), "UA")
    assert resumed.stage == ("totp" if enrolled else "totp_enroll" if role == "admin" else "full")
    if enrolled:
        clock.advance(60)
        assert access.totp_check(user.id, totp.code_at(secret, totp.step_of(clock())))
        assert access.use_recovery(user.id, codes[0]) == 9


@pytest.mark.parametrize("enrolled", [False, True])
def test_pausing_totp_releases_pending_sign_in_after_password_login(access, clock, enrolled) -> None:
    user = member(access, "pending", "admin")
    if enrolled:
        enroll(access, clock, user.id)
    pending, token = access.start_session(access.authenticate(user.username, GOOD), "UA")
    assert pending.stage == ("totp" if enrolled else "totp_enroll")
    access.settings = replace(access.settings, totp_enabled=False)
    assert access.lookup(token) is None
    assert access.session(pending.id).end_reason == "auth_policy_changed"
    assert access.start_session(access.authenticate(user.username, GOOD), "UA")[0].stage == "full"


def test_paused_totp_still_requires_temporary_password_change(access) -> None:
    access.settings = replace(access.settings, totp_enabled=False)
    user, temporary = access.create_user("newadmin", "New Admin", "admin", "test")
    session, _ = access.start_session(access.authenticate(user.username, temporary), "UA")
    assert session.stage == "password_change"
    access.change_password(user.id, GOOD, keep_session=session.id)
    assert access.advance(session.id)[0].stage == "full"


def test_legacy_sessions_are_migrated_with_the_original_totp_policy(access, keys, clock) -> None:
    user = member(access, "legacy", "admin")
    pending, token = access.start_session(user, "UA")
    with sqlite3.connect(access.path) as con:
        con.execute("ALTER TABLE sessions DROP COLUMN totp_policy")
    resumed = AccessStore(access.path, keys, AuthSettings(), clock=clock)
    assert resumed.lookup(token) is None
    assert resumed.session(pending.id).end_reason == "auth_policy_changed"
    assert resumed.start_session(resumed.authenticate(user.username, GOOD), "UA")[0].stage == "full"
