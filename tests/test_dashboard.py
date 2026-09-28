import json
import shutil
from datetime import datetime, timezone

from blacksite.learning.store import LearningStore

UPLOAD = [("files", ("app.log", b"2026-09-27 02:14:00 ERROR disk full\n"))]


def iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def run(incident: str, turn: int, at: str, seconds: float, guide: bool, **extra) -> dict:
    return {"incident_id": incident, "turn": turn, "actor": "user:1", "session": None, "started_at": at,
            "finished_at": at, "seconds": seconds, "requests": 3, "tool_calls": extra.get("tool_calls", 5),
            "input_tokens": 1000, "output_tokens": 200, "model": "m", "provider": "vllm",
            "citations_ok": extra.get("ok", 3), "citations_total": extra.get("total", 3), "guide": guide}


def test_dashboard_numbers(web, tmp_path) -> None:
    admin = web.admin
    created = admin.post("/api/incidents", data={"title": "Disk full"}, files=UPLOAD).json()["id"]
    now = iso(web.clock())
    sample = web.incidents / "nginx-502-oom"
    (sample / "outcome.json").write_text(json.dumps({"outcome": "resolved", "reported_at": now}), encoding="utf-8")
    web.services.access.record_run(run("nginx-502-oom", 1, now, 300.0, True, tool_calls=6))
    web.services.access.record_run(run("nginx-502-oom", 2, now, 500.0, True, ok=2, total=4))
    web.services.access.record_run(run(created, 1, now, 100.0, False, tool_calls=2))
    store = LearningStore(tmp_path / "learning.sqlite")
    store.apply_playbook([{"op": "add", "section": "safety", "text": "Back up configs before editing them."}],
                         source="x", approved=True)
    store.apply_playbook([{"op": "add", "section": "diagnosis", "text": "Check the cgroup limit first."}],
                         source="y", approved=False)

    data = admin.get("/api/dashboard", params={"scope": "all", "range": 30}).json()
    kpis = data["kpis"]
    assert kpis["open"]["value"] == 1 and kpis["open"]["created"] == 2
    assert kpis["awaiting"]["value"] == 0
    assert kpis["resolved_rate"]["value"] == 1.0 and kpis["resolved_rate"]["previous"] is None
    assert kpis["time_to_guide"]["value"] == 400.0
    assert all(len(kpis[name]["spark"]) == len(kpis["open"]["spark"]) for name in kpis)
    assert len(data["trend"]["days"]) == 30 and data["trend"]["days"][-1] == now[:10]
    assert data["trend"]["series"]["new"][-1] == 1 and data["trend"]["series"]["closed"][-1] == 1
    assert data["outcomes"] == {"resolved": 1, "partial": 0, "not_resolved": 0, "turns_per_guide": 1.5}
    runtime = data["runtime"]
    assert len(runtime["runs"]) == 3 and runtime["median_seconds"] == 300.0
    assert runtime["citation_rate"] == round(8 / 10, 3) and runtime["tool_calls"] == round(13 / 3, 1)
    assert data["learning"] == {"pending": 1, "lessons": 1, "cases": 0,
                                "recent": [{"section": "safety", "text": "Back up configs before editing them."}]}
    assert data["attention"] == 1 and data["running"] == 0


def test_members_see_their_own_scope(web) -> None:
    mina = web.client("mina")
    assert mina.get("/api/dashboard", params={"scope": "all"}).status_code == 403
    created = mina.post("/api/incidents", data={"title": "Mine"}, files=UPLOAD).json()["id"]
    data = mina.get("/api/dashboard", params={"scope": "mine", "range": 7}).json()
    assert data["kpis"]["open"]["value"] == 1 and len(data["trend"]["days"]) == 7
    assert set(data["learning"]) == {"lessons", "cases"}
    joon = web.client("joon")
    assert joon.get("/api/dashboard", params={"scope": "shared"}).json()["kpis"]["open"]["value"] == 0
    mina.post(f"/api/incidents/{created}/share", json={"user_id": web.services.access.find("joon").id, "action": "share"})
    assert joon.get("/api/dashboard", params={"scope": "shared"}).json()["kpis"]["open"]["value"] == 1
    assert web.admin.get("/api/dashboard", params={"scope": "range"}).status_code == 400


def test_activity_shows_members_only_what_they_may_see(web) -> None:
    mina = web.client("mina")
    joon = web.client("joon")
    created = mina.post("/api/incidents", data={"title": "Mine"}, files=UPLOAD).json()["id"]
    web.admin.post("/api/settings", json={"rag": "tool"})
    joon.get("/api/incidents")

    def actions(client) -> list[tuple[str, str]]:
        data = client.get("/api/activity").json()
        assert "verification" in data
        return [(item["action"], item["actor"]["name"]) for item in data["items"]]

    seen = actions(mina)
    assert ("incident.created", "Mina") in seen and ("auth.login", "Mina") in seen
    assert ("auth.login", "Joon") not in seen and all(action != "settings.changed" for action, _ in seen)
    assert all(action != "incident.created" for action, _ in actions(joon))
    mina.post(f"/api/incidents/{created}/share", json={"user_id": web.services.access.find("joon").id, "action": "share"})
    shared = joon.get("/api/activity").json()["items"]
    assert any(item["action"] == "incident.created" and item["incident"] == {"id": created, "title": "Mine"}
               for item in shared)
    admin_seen = actions(web.admin)
    assert ("auth.login", "Joon") in admin_seen and ("settings.changed", "Admin") in admin_seen


def test_activity_after_returns_newer_items_only(web) -> None:
    first = web.admin.get("/api/activity").json()["items"]
    newest = first[0]["seq"]
    web.admin.post("/api/settings", json={"rag": "tool"})
    newer = web.admin.get("/api/activity", params={"after": newest}).json()["items"]
    assert [item["action"] for item in newer] == ["settings.changed"]


def test_deleted_incident_folders_are_skipped(web) -> None:
    mina = web.client("mina")
    created = mina.post("/api/incidents", data={"title": "Gone soon"}, files=UPLOAD).json()["id"]
    shutil.rmtree(web.incidents / created)
    shutil.rmtree(web.incidents / "nginx-502-oom")
    assert mina.get("/api/dashboard").status_code == 200
    assert web.admin.get("/api/dashboard", params={"scope": "all"}).json()["kpis"]["open"]["value"] == 0
    items = mina.get("/api/activity").json()["items"]
    assert any(item["incident"] == {"id": created, "title": None} for item in items)
    assert mina.get("/api/incidents").json()["incidents"] == []
    assert web.admin.get("/api/admin/incidents").json()["incidents"] == []
