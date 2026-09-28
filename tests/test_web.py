import json
import re
import time
from pathlib import Path

import pytest

from blacksite.learning.store import LearningStore
from conftest import INCIDENT


@pytest.fixture
def client(web):
    """The web app with an admin signed in (see conftest.web)."""
    return web.admin


def test_page_versions_its_assets(client) -> None:
    html = client.get("/").text
    assert "/static/app.js?v=" in html and "/static/app.css?v=" in html
    assert client.get("/static/app.js").status_code == 200


def test_status_reports_an_unreachable_model(client) -> None:
    status = client.get("/api/status").json()
    assert status["reachable"] is False and status["model"] == "test"


def test_switches_change_the_features(client) -> None:
    data = client.post("/api/settings", json={"rag": "tool", "playbook": "on"}).json()
    assert data["features"]["rag"] == "on (tool, bm25)" and data["features"]["playbook"] == "on (instructions)"
    assert client.post("/api/settings", json={"rag": "always"}).status_code == 400


def test_incident_overview_and_lines(client) -> None:
    data = client.get("/api/incidents/nginx-502-oom").json()
    assert {item["file"] for item in data["artifacts"]} >= {"kern.log", "nginx/error.log"}
    assert data["histogram"]["rows"] and data["patterns"][0]["count"] == 72
    lines = client.get("/api/incidents/nginx-502-oom/lines", params={"file": "kern.log", "line": 3, "context": 1}).json()
    assert [line["n"] for line in lines["lines"]] == [2, 3, 4] and lines["focus"] == [3, 3]
    assert client.get("/api/incidents/../etc").status_code in (400, 404)
    assert client.get("/api/incidents/nope").status_code == 400


def test_search_greps_the_evidence(client) -> None:
    found = client.get("/api/incidents/nginx-502-oom/search", params={"pattern": "oom-killer", "file": "kern.log"}).json()
    assert found["total"] >= 1 and all(line["file"] == "kern.log" and "oom-killer" in line["text"] for line in found["lines"])
    capped = client.get("/api/incidents/nginx-502-oom/search", params={"pattern": ".", "limit": 3}).json()
    assert len(capped["lines"]) == 3 and capped["total"] > 3
    plain = client.get("/api/incidents/nginx-502-oom/search", params={"pattern": "(", "literal": "1"})
    assert plain.status_code == 200
    assert client.get("/api/incidents/nginx-502-oom/search", params={"pattern": "("}).status_code == 400
    assert client.get("/api/incidents/nginx-502-oom/search", params={"pattern": "x", "file": "nope.log"}).status_code == 400


def test_upload_creates_and_indexes_an_incident(client) -> None:
    files = [("files", ("kern.log", (INCIDENT / "artifacts" / "kern.log").read_bytes())),
             ("files", (".hidden", b"x"))]
    created = client.post("/api/incidents", data={"title": "Kernel trouble", "year": "2026"}, files=files).json()
    overview = client.get(f"/api/incidents/{created['id']}").json()
    assert overview["title"] == "Kernel trouble" and [a["file"] for a in overview["artifacts"]] == ["kern.log"]
    assert client.post("/api/incidents", data={"title": "Empty"}).status_code == 400


def test_turn_streams_events_and_saves_the_guide(client) -> None:
    assert client.post("/api/incidents/nginx-502-oom/turn", json={"message": ""}).json() == {"ok": True}
    events = []
    with client.stream("GET", "/api/incidents/nginx-502-oom/stream") as response:
        for line in response.iter_lines():
            if line.startswith("data: ") and line != "data: {}":
                events.append(json.loads(line[6:]))
            if line.startswith("event: end"):
                break
    kinds = [event["type"] for event in events]
    assert kinds[0] == "start" and "guide" in kinds and kinds[-1] == "done"
    deadline = time.time() + 5
    while client.get("/api/incidents/nginx-502-oom").json()["running"] and time.time() < deadline:
        time.sleep(0.05)
    data = client.get("/api/incidents/nginx-502-oom").json()
    assert len(data["turns"]) == 1 and not data["running"]
    assert client.get("/api/incidents/nginx-502-oom/guide.md").text.startswith("# App OOM-killed")
    assert client.post("/api/incidents/nginx-502-oom/reset").json() == {"ok": True}
    assert client.get("/api/incidents/nginx-502-oom").json()["turns"] == []


def test_learning_review(client, tmp_path: Path) -> None:
    store = LearningStore(tmp_path / "learning.sqlite")
    store.apply_playbook([{"op": "add", "section": "safety", "text": "Back up configs before editing them."}],
                         source="x", approved=False)
    data = client.get("/api/learning").json()
    assert data["bullets"][0]["status"] == "pending"
    data = client.post("/api/learning", json={"ids": ["pb-0001"], "action": "approve"}).json()
    assert data["bullets"][0]["status"] == "active"
    assert client.post("/api/learning", json={"ids": ["pb-0001"], "action": "delete"}).status_code == 400
    store.apply_playbook([{"op": "add", "section": "diagnosis", "text": "Read the kernel log before the app log."}],
                         source="y", approved=False)
    client.post("/api/learning", json={"ids": ["pb-0002"], "action": "reject"})
    ledger = client.app.state.demo.services.ledger
    assert [record.action for record in ledger.records(action="learning.")] == ["learning.rejected", "learning.approved"]


STATIC = Path(__file__).parents[1] / "src" / "blacksite" / "web" / "static"


def test_every_ui_string_exists_in_english_and_korean() -> None:
    strings = json.loads((STATIC / "i18n.json").read_text(encoding="utf-8"))
    # "key.one" holds an English singular ("1 error"); Korean needs none.
    singles = {key for key in strings["en"] if key.endswith(".one")}
    assert {key.removesuffix(".one") for key in singles} <= set(strings["en"])
    assert set(strings["en"]) - singles == set(strings["ko"])
    used: set[str] = set()
    for name in ("app.js", "dashboard.js", "admin.js", "login.js"):
        script = (STATIC / name).read_text(encoding="utf-8")
        used |= set(re.findall(r'\bt\("([\w.\- ]+)"', script))
        # Keys passed around before t() sees them, e.g. heading("login.title"); "admin.confirmSuspend" names a group.
        literal = r'"((?:login|prov|health|account|reauth|dash|admin|user|share|nav|role|activity)\.[\w.]+)"'
        used |= {key for key in re.findall(literal, script) if not any(other.startswith(key + ".") for other in strings["en"])}
    for name in ("index.html", "login.html"):
        page = (STATIC / name).read_text(encoding="utf-8")
        used |= set(re.findall(r'data-i18n(?:-placeholder|-title|-aria)?="([\w.\- ]+)"', page))
    missing = sorted(key for key in used if key not in strings["en"])
    assert not missing, missing
    # Keys built at runtime: every server check code and risk reason has a label.
    from blacksite.agent.guide import REASONS
    assert {f"reason.{key}" for key in REASONS} <= set(strings["en"])
    # Every action the ledger records reads as a sentence in the activity feed.
    source = "".join(path.read_text(encoding="utf-8") for path in (STATIC.parents[1]).rglob("*.py"))
    calls = r'(?:ledger\.append\(|_record\((?:state, )?request, |wrong_code\(request, found, )"([a-z]+\.[a-z_]+)"'
    actions = set(re.findall(calls, source))
    assert len(actions) > 30
    actions |= {"learning.approved", "learning.rejected"}
    assert {f"activity.{action}" for action in actions} <= set(strings["en"]), sorted(
        action for action in actions if f"activity.{action}" not in strings["en"])
    for placeholder in re.findall(r"\{(\w+)\}", json.dumps(strings["en"])):
        assert placeholder.isidentifier()


def test_page_versions_translations(client) -> None:
    html = client.get("/").text
    assert "/static/i18n.json?v=" in html
    assert client.get("/static/i18n.json").json()["ko"]["composer.investigate"] == "조사 시작"


def test_language_switch_reaches_the_agent_settings(client) -> None:
    assert client.post("/api/settings", json={"language": "ko"}).json()["switches"]["language"] == "ko"
    assert client.post("/api/settings", json={"language": "fr"}).status_code == 400
