import json
import time
from dataclasses import replace
from pathlib import Path

import pytest
from starlette.routing import Mount

from blacksite.auth import totp
from blacksite.auth.gate import COOKIE
from blacksite.config import load_settings
from blacksite.services import Services
from blacksite.web.app import serve
from conftest import PASSWORD, add_account

UPLOAD = [("files", ("app.log", b"2026-09-27 02:14:00 ERROR boom\n"))]


def test_every_route_declares_a_policy(web) -> None:
    for route in web.app.routes:
        if isinstance(route, Mount):
            continue
        assert hasattr(route.endpoint, "policy"), route.path


def test_anonymous_requests_are_refused(web) -> None:
    anon = web.anonymous()
    assert anon.get("/", follow_redirects=False).headers["location"] == "/login"
    assert anon.get("/admin", follow_redirects=False).headers["location"] == "/login?next=/admin"
    response = anon.get("/api/incidents")
    assert response.status_code == 401 and response.json() == {"error": "Sign in again.", "login": True}
    assert anon.get("/api/incidents/nginx-502-oom/stream").status_code == 401
    assert anon.post("/api/settings", json={"rag": "tool"}).status_code == 401
    assert anon.get("/login").status_code == 200 and anon.get("/static/app.css").status_code == 200
    assert "login.js?v=" in anon.get("/login").text


def test_the_operator_console_is_a_public_shell(web) -> None:
    anon = web.anonymous()
    page = anon.get("/term", follow_redirects=False)
    assert page.status_code == 200
    assert "/static/term/term.js?v=" in page.text and "/static/term/fx.js?v=" in page.text
    assert page.headers["cache-control"] == "no-store"
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert anon.get("/static/term/term.css").status_code == 200
    # The shell holds no data: everything behind it still needs a signed-in session.
    assert anon.get("/api/incidents").status_code == 401
    assert anon.get("/api/me").status_code == 401


def test_a_foreign_host_is_refused(web) -> None:
    assert web.admin.get("/api/status", headers={"Host": "evil.example:8765"}).status_code == 400
    assert web.admin.get("/api/status", headers={"Host": "127.0.0.1:9999"}).status_code == 400
    assert web.admin.get("/api/status", headers={"Host": "localhost:8765"}).status_code == 200


def test_cross_site_changes_are_refused(web) -> None:
    admin = web.admin
    assert admin.post("/api/settings", json={}, headers={"Origin": "http://evil.example"}).status_code == 403
    assert admin.post("/api/settings", json={}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    token = admin.headers.pop("X-CSRF-Token")
    try:
        response = admin.post("/api/settings", json={})
        assert response.status_code == 403 and response.json()["csrf"] is True
    finally:
        admin.headers["X-CSRF-Token"] = token
    ok = admin.post("/api/settings", json={}, headers={"Origin": "http://127.0.0.1:8765", "Sec-Fetch-Site": "same-origin"})
    assert ok.status_code == 200


def test_security_headers(web) -> None:
    headers = web.admin.get("/api/status").headers
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert "script-src 'self';" in headers["content-security-policy"]
    assert headers["cache-control"] == "no-store" and headers["x-content-type-options"] == "nosniff"
    assert web.admin.get("/").headers["cache-control"] == "no-store"
    cookie = web.anonymous().post("/auth/login", json={"username": "admin", "password": PASSWORD}).headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Max-Age" not in cookie


def test_members_cannot_use_admin_routes(web) -> None:
    member = web.client("mina")
    assert member.post("/api/settings", json={"rag": "tool"}).status_code == 403
    assert member.get("/api/settings").status_code == 200
    assert member.post("/api/models", json={"action": "stop"}).status_code == 403
    assert member.get("/api/learning").status_code == 403
    assert member.get("/api/usb").status_code == 403
    assert member.post("/api/incidents/nginx-502-oom/wipe").status_code in (403, 404)


def test_incidents_are_visible_to_owner_shares_and_admins(web) -> None:
    mina, joon = web.client("mina"), web.client("joon")
    assert mina.get("/api/incidents/nginx-502-oom").status_code == 404  # unowned: admins only
    assert web.admin.get("/api/incidents/nginx-502-oom").status_code == 200
    assert [item["id"] for item in mina.get("/api/incidents").json()["incidents"]] == []
    created = mina.post("/api/incidents", data={"title": "Mine"}, files=UPLOAD).json()["id"]
    assert [item["id"] for item in mina.get("/api/incidents").json()["incidents"]] == [created]
    assert joon.get(f"/api/incidents/{created}").status_code == 404
    assert web.admin.get(f"/api/incidents/{created}").status_code == 200
    joon_id = web.services.access.find("joon").id
    assert joon.post(f"/api/incidents/{created}/share", json={"user_id": 1, "action": "share"}).status_code == 404
    assert mina.post(f"/api/incidents/{created}/share", json={"user_id": joon_id, "action": "share"}).status_code == 200
    data = joon.get(f"/api/incidents/{created}").json()
    assert data["access"] == "investigate" and data["owner"]["name"] == "Mina"
    assert joon.post(f"/api/incidents/{created}/reset").status_code == 403  # shared: no start over
    assert mina.post(f"/api/incidents/{created}/reset").status_code == 200
    assert mina.post(f"/api/incidents/{created}/share", json={"user_id": joon_id, "action": "unshare"}).status_code == 200
    assert joon.get(f"/api/incidents/{created}").status_code == 404


def test_members_list_for_sharing(web) -> None:
    mina = web.client("mina")
    web.client("joon")
    names = {item["username"] for item in mina.get("/api/members").json()["members"]}
    assert names == {"admin", "mina", "joon"}


def test_passive_polling_does_not_keep_a_session_alive(web) -> None:
    mina = web.client("mina")
    web.clock.advance(20 * 60)
    assert mina.get("/api/status").status_code == 200  # passive
    web.clock.advance(15 * 60)
    assert mina.get("/api/incidents").status_code == 401  # 35 idle minutes
    joon = web.client("joon")
    web.clock.advance(20 * 60)
    assert joon.get("/api/incidents").status_code == 200  # active
    web.clock.advance(15 * 60)
    assert joon.get("/api/incidents").status_code == 200


def test_suspension_from_another_process_takes_effect(web) -> None:
    mina = web.client("mina")
    other = Services.open(load_settings(web.config, environ={}), clock=web.clock)
    other.access.set_status(other.access.find("mina").id, "suspended")
    response = mina.get("/api/incidents")
    assert response.status_code == 401 and response.json()["login"] is True


def test_a_temporary_password_must_be_changed_first(web) -> None:
    web.services.access.create_user("newbie", "New", "member", "test", password=PASSWORD)
    client = web.anonymous()
    data = client.post("/auth/login", json={"username": "newbie", "password": PASSWORD}).json()
    assert data["stage"] == "password_change"
    client.headers["X-CSRF-Token"] = data["csrf"]
    assert client.get("/api/incidents").json()["stage"] == "password_change"
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/api/me").json()["stage"] == "password_change"
    weak = client.post("/auth/password", json={"new": "short"})
    assert weak.status_code == 400 and "12 characters" in weak.json()["error"]
    data = client.post("/auth/password", json={"new": "a-brand-new-passphrase"}).json()
    assert data["stage"] == "full"
    client.headers["X-CSRF-Token"] = data["csrf"]
    assert client.get("/api/incidents").status_code == 200


def test_a_new_admin_sets_up_two_step_sign_in(web) -> None:
    add_account(web.services, "boss", "admin", two_step=False)
    client = web.anonymous()
    data = client.post("/auth/login", json={"username": "boss", "password": PASSWORD}).json()
    assert data["stage"] == "totp_enroll"
    client.headers["X-CSRF-Token"] = data["csrf"]
    assert client.get("/api/incidents").status_code == 403
    setup = client.get("/auth/totp/setup").json()
    assert setup["qr"].startswith("data:image/svg+xml") and setup["uri"].startswith("otpauth://")
    assert client.get("/auth/totp/setup").json()["secret"] == setup["secret"]  # reloading keeps the same secret
    bad = client.post("/auth/totp/enroll", json={"code": "000000"})
    assert bad.status_code == 400
    code = totp.code_at(setup["secret"], totp.step_of(web.clock()))
    data = client.post("/auth/totp/enroll", json={"code": code}).json()
    assert data["stage"] == "full" and len(data["recovery_codes"]) == 10
    client.headers["X-CSRF-Token"] = data["csrf"]
    assert client.get("/api/incidents").status_code == 200


def test_recovery_code_signs_in(web) -> None:
    user, secret = add_account(web.services, "boss", "admin", two_step=False)
    setup_secret = web.services.access.totp_setup(user.id)
    codes = web.services.access.totp_enroll(user.id, totp.code_at(setup_secret, totp.step_of(web.clock())))
    client = web.anonymous()
    data = client.post("/auth/login", json={"username": "boss", "password": PASSWORD}).json()
    assert data["stage"] == "totp"
    data = client.post("/auth/recovery", json={"code": codes[0]}, headers={"X-CSRF-Token": data["csrf"]}).json()
    assert data["stage"] == "full" and data["remaining"] == 9


def test_too_many_wrong_codes_end_the_session(web) -> None:
    add_account(web.services, "boss", "admin")
    client = web.anonymous()
    data = client.post("/auth/login", json={"username": "boss", "password": PASSWORD}).json()
    client.headers["X-CSRF-Token"] = data["csrf"]
    for _ in range(4):
        assert client.post("/auth/totp/verify", json={"code": "000000"}).status_code == 400
    last = client.post("/auth/totp/verify", json={"code": "000000"})
    assert last.status_code == 401 and last.json()["login"] is True
    assert client.get("/api/me").status_code == 401


def test_wrong_passwords_are_recorded_without_the_name(web) -> None:
    anon = web.anonymous()
    wrong = anon.post("/auth/login", json={"username": "admin", "password": "not-the-password"})
    unknown = anon.post("/auth/login", json={"username": "hunter2-typed-here", "password": "x"})
    assert wrong.status_code == unknown.status_code == 401 and wrong.json() == unknown.json()
    records = web.services.ledger.records(action="auth.login_failed")
    assert records[0].actor == "anonymous" and len(records[0].detail["name"]) == 16
    assert "hunter2" not in json.dumps([record.to_json() for record in records])
    assert records[1].actor.startswith("user:")


def test_sign_out_ends_the_session(web) -> None:
    mina = web.client("mina")
    assert mina.post("/auth/logout").json() == {"ok": True}
    assert mina.get("/api/incidents").status_code == 401


def test_confirmation_needs_the_password_and_code(web) -> None:
    mina = web.client("mina")
    assert mina.post("/auth/confirm", json={"password": "wrong-password-here"}).status_code == 400
    assert mina.post("/auth/confirm", json={"password": PASSWORD}).json()["ok"] is True


def set_totp_policy(web, enabled: bool) -> None:
    auth = replace(web.services.settings.auth, totp_enabled=enabled)
    web.services.settings = replace(web.services.settings, auth=auth)
    web.services.access.settings = auth


@pytest.mark.parametrize("role", ["admin", "member"])
@pytest.mark.parametrize("enrolled", [False, True])
def test_disabled_two_step_keeps_password_login_and_confirmation(web, role, enrolled) -> None:
    user, _ = add_account(web.services, "paused", role, two_step=enrolled)
    set_totp_policy(web, False)
    client = web.anonymous()
    assert client.get("/api/incidents").status_code == 401
    assert client.post("/auth/login", json={"username": user.username, "password": "wrong"}).status_code == 401
    data = client.post("/auth/login", json={"username": user.username, "password": PASSWORD}).json()
    assert data["stage"] == "full"
    client.headers["X-CSRF-Token"] = data["csrf"]
    me = client.get("/api/me").json()
    assert me["auth"] == {"totp_enabled": False}
    assert me["user"]["totp_enabled"] is enrolled
    assert client.get("/api/incidents").status_code == 200
    refused = client.post("/auth/confirm", json={"password": "wrong"})
    assert refused.status_code == 400 and refused.json()["error"] == "That password did not match."
    assert client.post("/auth/confirm", json={"password": PASSWORD}).json()["ok"] is True
    assert client.get("/auth/totp/setup").status_code == 403
    for path in ("/auth/totp/enroll", "/auth/totp/verify", "/auth/recovery"):
        response = client.post(path, json={"code": "000000"})
        assert response.status_code == 403 and "disabled" in response.json()["error"]
    assert web.services.access.user(user.id).totp_enabled is enrolled
    set_totp_policy(web, True)
    assert client.get("/api/incidents").status_code == 401
    resumed = client.post("/auth/login", json={"username": user.username, "password": PASSWORD}).json()
    assert resumed["stage"] == ("totp" if enrolled else "totp_enroll" if role == "admin" else "full")


@pytest.mark.parametrize("enrolled", [False, True])
def test_disabled_two_step_unblocks_an_existing_pending_browser_session(web, enrolled) -> None:
    user, _ = add_account(web.services, "pending", "admin", two_step=enrolled)
    client = web.anonymous()
    data = client.post("/auth/login", json={"username": user.username, "password": PASSWORD}).json()
    assert data["stage"] == ("totp" if enrolled else "totp_enroll")
    set_totp_policy(web, False)
    # Reloading the terminal checks /api/me and returns to its password prompt.
    assert client.get("/term").status_code == 200
    assert client.get("/api/me").status_code == 401
    data = client.post("/auth/login", json={"username": user.username, "password": PASSWORD}).json()
    assert data["stage"] == "full"
    assert client.get("/api/me").json()["auth"]["totp_enabled"] is False


def test_enabled_two_step_still_requires_code_for_sensitive_confirmation(web) -> None:
    assert web.admin.get("/api/me").json()["auth"]["totp_enabled"] is True
    assert web.admin.post("/auth/confirm", json={"password": PASSWORD}).status_code == 400


def test_actions_are_recorded_in_the_ledger(web) -> None:
    mina = web.client("mina")
    created = mina.post("/api/incidents", data={"title": "Mine"}, files=UPLOAD).json()["id"]
    mina.get(f"/api/incidents/{created}")
    mina.get(f"/api/incidents/{created}")
    ledger = web.services.ledger
    record = ledger.records(action="incident.created")[0]
    assert record.target == created and record.detail["files"] == 1 and len(record.detail["sha256"][0]) == 64
    assert len(ledger.records(action="incident.opened", target=created)) == 1  # once per session
    web.admin.post("/api/settings", json={"rag": "tool"})
    changed = ledger.records(action="settings.changed")[0]
    assert changed.detail == {"rag": "tool"} and changed.actor == "user:1"
    assert all(record.session for record in ledger.records(actor="user:1", action="settings."))
    assert ledger.verify().ok


def test_investigation_turns_are_signed(web) -> None:
    admin = web.admin
    assert admin.post("/api/incidents/nginx-502-oom/turn", json={"message": ""}).json() == {"ok": True}
    deadline = time.time() + 10
    while admin.get("/api/incidents/nginx-502-oom").json()["running"] and time.time() < deadline:
        time.sleep(0.05)
    data = admin.get("/api/incidents/nginx-502-oom").json()
    assert data["provenance"][0]["signed"] and data["provenance"][0]["evidence"] == "unchanged"
    detail = admin.get("/api/incidents/nginx-502-oom/provenance", params={"turn": 1}).json()
    assert detail["check"]["signature"] and detail["manifest"]["actor"] == "user:1"
    assert web.services.access.runs({"nginx-502-oom"})[0]["guide"] is True
    actions = [record.action for record in web.services.ledger.records(target="nginx-502-oom")]
    assert "incident.turn_started" in actions and "incident.turn_finished" in actions
    assert admin.post("/api/incidents/nginx-502-oom/reset").json() == {"ok": True}
    assert not (web.incidents / "nginx-502-oom" / "provenance").exists()


def test_a_broken_ledger_pauses_changes(web, monkeypatch) -> None:
    monkeypatch.setattr(web.services.ledger, "broken", True)
    monkeypatch.setattr(web.services.ledger, "probe", lambda: False)
    response = web.admin.post("/api/settings", json={"rag": "tool"})
    assert response.status_code == 503 and "ledger" in response.json()["error"]
    assert web.admin.get("/api/status").status_code == 200  # reading still works


def test_serve_refuses_other_hosts_and_a_missing_admin(tmp_path: Path) -> None:
    config = tmp_path / "blacksite.toml"
    config.write_text('[model]\nprovider = "vllm"\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="only on this computer"):
        serve(config, [], tmp_path / "incidents", "0.0.0.0", 8765)
    with pytest.raises(SystemExit, match="users add NAME --admin"):
        serve(config, [], tmp_path / "incidents", "127.0.0.1", 8765)


def test_cookie_name(web) -> None:
    assert COOKIE in web.anonymous().post("/auth/login", json={"username": "admin", "password": PASSWORD}).cookies


def test_members_cannot_list_model_files(web) -> None:
    assert web.client("mina").get("/api/models").status_code == 403


def test_sign_in_fails_closed_when_the_ledger_cannot_be_written(web, monkeypatch) -> None:
    from blacksite.audit.ledger import LedgerError

    def broken(*args, **kwargs):
        raise LedgerError("Could not write the audit ledger: disk full")

    monkeypatch.setattr(web.services.ledger, "append", broken)
    response = web.anonymous().post("/auth/login", json={"username": "admin", "password": PASSWORD})
    assert response.status_code == 503 and "ledger" in response.json()["error"]
    assert "set-cookie" not in response.headers
