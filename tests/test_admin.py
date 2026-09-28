import json
import os
import sqlite3


from conftest import PASSWORD


def confirm(client) -> None:
    from blacksite.auth import totp

    services = client.app.state.demo.services
    me = client.get("/api/me").json()["user"]
    body = {"password": PASSWORD}
    if me["totp_enabled"]:
        # Sign-in used the next step's code; re-confirmation needs a later one still.
        services.access.clock.advance(60)
        row = services.access._totp_row(me["id"])
        body["code"] = totp.code_at(services.access._decrypt(row["totp_secret"]), totp.step_of(services.access.clock()))
    assert client.post("/auth/confirm", json=body).status_code == 200


def test_admin_routes_are_admin_only(web) -> None:
    mina = web.client("mina")
    for path in ("/api/admin/users", "/api/admin/sessions", "/api/admin/audit", "/api/admin/incidents",
                 "/api/admin/health"):
        assert mina.get(path).status_code == 403, path
        assert web.admin.get(path).status_code == 200, path


def test_creating_a_member_needs_confirmation(web) -> None:
    admin = web.admin
    body = {"username": "mina", "display_name": "민아", "role": "member"}
    refused = admin.post("/api/admin/users", json=body)
    assert refused.status_code == 403 and refused.json()["confirm"] is True
    confirm(admin)
    created = admin.post("/api/admin/users", json=body).json()
    assert created["user"]["username"] == "mina" and created["user"]["must_change"]
    assert len(created["temporary_password"]) == 19
    assert admin.post("/api/admin/users", json=body).status_code == 400  # taken
    users = {user["username"]: user for user in admin.get("/api/admin/users").json()["users"]}
    assert users["mina"]["display_name"] == "민아" and users["admin"]["totp_enabled"]
    record = web.services.ledger.records(action="admin.user_created")[0]
    assert record.actor == "user:1" and created["temporary_password"] not in json.dumps(record.to_json())


def test_member_actions(web) -> None:
    admin = web.admin
    mina = web.client("mina")
    mina_id = web.services.access.find("mina").id
    confirm(admin)
    assert admin.post(f"/api/admin/users/{mina_id}", json={"action": "suspend"}).json()["user"]["status"] == "suspended"
    assert mina.get("/api/incidents").status_code == 401
    assert admin.post(f"/api/admin/users/{mina_id}", json={"action": "activate"}).json()["user"]["status"] == "active"
    reset = admin.post(f"/api/admin/users/{mina_id}", json={"action": "reset_password"}).json()
    assert len(reset["temporary_password"]) == 19 and reset["user"]["must_change"]
    assert admin.post(f"/api/admin/users/{mina_id}", json={"action": "role", "role": "admin"}).json()["user"]["role"] == "admin"
    assert admin.post(f"/api/admin/users/{mina_id}", json={"action": "reset_totp"}).status_code == 200
    assert admin.post(f"/api/admin/users/{mina_id}", json={"action": "explode"}).status_code == 400
    assert admin.post("/api/admin/users/999", json={"action": "suspend"}).status_code == 400


def test_admins_cannot_lock_themselves_out(web) -> None:
    confirm(web.admin)
    for body in ({"action": "suspend"}, {"action": "role", "role": "member"}):
        response = web.admin.post("/api/admin/users/1", json=body)
        assert response.status_code == 400 and "your own account" in response.json()["error"]


def test_sessions_revoke_and_timeline(web) -> None:
    mina = web.client("mina")
    mina.get("/api/incidents")
    sessions = web.admin.get("/api/admin/sessions").json()["sessions"]
    by_user = {item["user"]["username"]: item for item in sessions}
    assert by_user["admin"]["current"] and not by_user["mina"]["current"]
    session_id = by_user["mina"]["id"]
    timeline = web.admin.get(f"/api/admin/sessions/{session_id}/timeline").json()
    assert timeline["user"]["username"] == "mina" and timeline["records"][-1]["action"] == "auth.login"
    assert all(record["session"] == session_id for record in timeline["records"])
    assert web.admin.post(f"/api/admin/sessions/{session_id}/revoke").json()["ok"] is True
    assert mina.get("/api/incidents").status_code == 401
    assert web.admin.get("/api/admin/sessions/nope/timeline").status_code == 404


def test_audit_log_filters_and_names(web) -> None:
    web.client("mina")
    records = web.admin.get("/api/admin/audit", params={"action": "auth."}).json()["records"]
    assert records and all(record["action"].startswith("auth.") for record in records)
    assert {record["actor_name"] for record in records} >= {"Mina", "Admin"}
    page = web.admin.get("/api/admin/audit", params={"limit": 2}).json()
    assert len(page["records"]) == 2 and page["next"] == page["records"][-1]["seq"]
    older = web.admin.get("/api/admin/audit", params={"limit": 2, "before": page["next"]}).json()["records"]
    assert older[0]["seq"] < page["records"][-1]["seq"]


def test_verify_and_export(web, tmp_path) -> None:
    admin = web.admin
    result = admin.post("/api/admin/audit/verify").json()
    assert result["ok"] and result["records"] > 1
    assert admin.post("/api/admin/audit/export").status_code == 403  # needs confirmation
    confirm(admin)
    response = admin.post("/api/admin/audit/export")
    assert response.status_code == 200 and "attachment" in response.headers["content-disposition"]
    lines = [json.loads(line) for line in response.text.splitlines()]
    assert lines[0]["type"] == "key" and any(line["type"] == "checkpoint" for line in lines)
    con = sqlite3.connect(web.services.ledger.path)
    con.executescript("DROP TRIGGER ledger_no_update; UPDATE ledger SET actor = 'user:9' WHERE seq = 2;")
    con.commit()
    con.close()
    broken = admin.post("/api/admin/audit/verify").json()
    assert not broken["ok"] and broken["first_bad"] == 2


def test_incident_access_management(web) -> None:
    mina = web.client("mina")
    mina_id = web.services.access.find("mina").id
    incidents = {item["id"]: item for item in web.admin.get("/api/admin/incidents").json()["incidents"]}
    assert incidents["nginx-502-oom"]["owner"] is None and incidents["nginx-502-oom"]["title"]
    assert web.admin.post("/api/admin/incidents/nginx-502-oom", json={"owner_id": mina_id}).status_code == 200
    assert mina.get("/api/incidents/nginx-502-oom").status_code == 200
    assert web.admin.post("/api/admin/incidents/nginx-502-oom", json={"owner_id": None}).status_code == 200
    assert mina.get("/api/incidents/nginx-502-oom").status_code == 404
    assert web.admin.post("/api/admin/incidents/nginx-502-oom", json={"share": mina_id}).status_code == 200
    assert mina.get("/api/incidents/nginx-502-oom").json()["access"] == "investigate"
    assert web.admin.post("/api/admin/incidents/nginx-502-oom", json={"unshare": mina_id}).status_code == 200
    assert web.admin.post("/api/admin/incidents/nope", json={"owner_id": mina_id}).status_code == 400
    assert web.services.ledger.records(action="admin.owner_assigned")[0].target == "nginx-502-oom"


def test_security_health(web) -> None:
    health = web.admin.get("/api/admin/health").json()
    assert health["admins_without_totp"] == 0 and health["loopback"] is True and health["keys"] is True
    assert len(health["signing_key"]) == 19 and len(health["anchor"]["fingerprint"]) == 19
    assert health["ledger"]["records"] > 1 and health["ledger"]["broken"] is False
    if os.name != "nt":
        assert isinstance(health["private"], bool)
    web.anonymous().post("/auth/login", json={"username": "admin", "password": "wrong-wrong-wrong"})
    assert web.admin.get("/api/admin/health").json()["failed_24h"] == 1


def test_signing_the_current_head_refreshes_the_anchor(web) -> None:
    before = web.admin.get("/api/admin/health").json()["anchor"]
    web.admin.post("/api/settings", json={"rag": "tool"})
    anchor = web.admin.post("/api/admin/audit/anchor").json()["anchor"]
    assert anchor["seq"] > before["seq"] and anchor["fingerprint"] != before["fingerprint"]
    assert web.admin.get("/api/admin/health").json()["anchor"]["seq"] == anchor["seq"]
    assert web.services.ledger.verify(anchors=[anchor]).ok


def test_health_lists_each_private_folder_once(web) -> None:
    paths = web.admin.get("/api/admin/health").json()["private_paths"]
    assert len(paths) == len(set(paths))
