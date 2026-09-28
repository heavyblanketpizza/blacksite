"""Local web demo: upload evidence, watch the agent investigate, review and learn.

Runs entirely on this machine. Each investigation turn runs as a background task that
records its events; the page subscribes over Server-Sent Events, so reloading the page
or losing the connection does not stop a multi-minute run. With USB mode on, a watcher
imports evidence from newly inserted drives into a sandbox and queues investigations.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import anyio
import httpx
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .. import __version__, catalog
from ..agent.guide import upgrade_check
from ..audit import provenance
from ..audit.ledger import LedgerError
from ..auth.gate import LOOPBACK, PUBLIC, Gate, Policy, guarded, principal, refuse
from ..auth.routes import auth_routes, versioned
from ..auth.store import AuthError
from ..agent.investigator import CONVERSATION_FILE, Investigator
from ..backends import DEFAULT_URLS, DISPLAY, PROVIDERS, server_root, serving
from ..backends import status as backend_status
from ..config import ConfigError, ModelSettings, Settings, feature_summary, load_settings
from ..context import open_store
from ..evidence.server import format_artifacts
from ..evidence.store import ARTIFACTS_DIR, INCIDENT_FILE, Evidence, EvidenceError
from ..learning.reflect import OUTCOME_FILE, reflect, record_outcome
from ..learning.store import OUTCOMES, LearningError
from ..llm import ChatClient, LLMError
from ..modelserver import ModelServerError, Supervisor, find_llama_server, find_vllm, plan
from ..keys import private_dir
from ..report import build_solution
from ..services import Services
from .admin import admin_routes
from .dashboard import dashboard_routes
from ..usb import (
    Bundle, UsbError, find_bundles, import_bundle, list_drives, locate_bundle, read_source, wipe, write_source,
    write_solution,
)

STATIC = Path(__file__).parent / "static"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
SWITCH_KEYS = {
    "rag": ("rag.enabled", "rag.mode"),
    "cases": ("learning.cases.enabled", "learning.cases.mode"),
}
MEMBER = Policy()
VIEW, INVESTIGATE, MANAGE = Policy(incident="view"), Policy(incident="investigate"), Policy(incident="manage")
PAGE_ASSETS = ("app.css", "boot.js", "app.js", "dashboard.js", "admin.js", "i18n.json")
# The operator console at /term: a separate, keyboard-first interface over the same API.
TERM_ASSETS = ("term/term.css", "term/fx.js", "term/term.js")
SEARCH_LIMIT = 500


@dataclass
class Run:
    """One investigation turn: its events so far, and whether it has finished."""

    events: list[dict[str, Any]] = field(default_factory=list)
    done: bool = False
    changed: asyncio.Event = field(default_factory=asyncio.Event)

    def add(self, event: dict[str, Any]) -> None:
        self.events.append(event)
        self.changed.set()


@dataclass
class DemoState:
    config_path: Path | None
    base_overrides: list[str]
    incidents: Path
    switches: dict[str, str] = field(default_factory=lambda: {
        "rag": "off", "cases": "off", "playbook": "off", "thinking": "", "language": ""})
    runs: dict[str, Run] = field(default_factory=dict)
    tasks: set[asyncio.Task[Any]] = field(default_factory=set)
    sandbox: Path | None = None
    # USB mode: drives seen with a marker folder, events for the page, and queued incidents.
    drives: list[dict[str, Any]] = field(default_factory=list)
    usb_events: list[dict[str, Any]] = field(default_factory=list)
    queue: list[str] = field(default_factory=list)
    # The model chosen in the page ({provider, base_url, name}; empty: the config's) and the
    # model server the page started, if any.
    model: dict[str, str] = field(default_factory=dict)
    base_model: ModelSettings | None = None
    server: Supervisor | None = None
    switching: bool = False
    # Accounts and the audit ledger; which incidents each session has opened (recorded once);
    # wrong two-step codes per session.
    services: Services | None = None
    opened: set[tuple[str, str]] = field(default_factory=set)
    code_failures: dict[str, int] = field(default_factory=dict)
    host: str = "127.0.0.1"

    def usb_event(self, kind: str, **data: Any) -> None:
        event_id = self.usb_events[-1]["id"] + 1 if self.usb_events else 1
        self.usb_events.append({"id": event_id, "kind": kind, "at": datetime.now().isoformat(timespec="seconds"),
                                **data})
        del self.usb_events[:-200]

    def roots(self) -> list[Path]:
        return [root for root in (self.incidents, self.sandbox) if root is not None]

    def incident_paths(self) -> list[Path]:
        """Incident folders that exist now; ones deleted outside the app simply drop out."""
        return [path for root in self.roots() if root.is_dir() for path in root.iterdir()
                if not path.name.startswith(".") and (path / ARTIFACTS_DIR).is_dir()]

    def overrides(self) -> list[str]:
        result = list(self.base_overrides)
        for name, (enabled, mode) in SWITCH_KEYS.items():
            value = self.switches[name]
            result.append(f"{enabled}={'false' if value == 'off' else 'true'}")
            if value != "off":
                result.append(f"{mode}={value}")
        result.append(f"learning.playbook.enabled={'true' if self.switches['playbook'] == 'on' else 'false'}")
        if self.switches["thinking"]:
            result.append(f"agent.thinking={self.switches['thinking']}")
        if self.switches["language"]:
            result.append(f"agent.language={self.switches['language']}")
        result += [f"model.{key}={value}" for key, value in self.model.items()]
        return result

    def settings(self) -> Settings:
        return load_settings(self.config_path, self.overrides())

    def model_settings(self, provider: str, name: str = "") -> ModelSettings:
        """Settings for talking to ``provider``: the config's URL for its own provider, else the default port."""
        base = self.base_model or self.settings().model
        current = self.settings().model
        url = base.base_url if base.provider == provider else DEFAULT_URLS[provider]
        if not name:
            name = current.name if current.provider == provider else base.name
        return replace(base, provider=provider, base_url=url, name=name)

    def incident_dir(self, incident_id: str) -> Path:
        if not _ID.match(incident_id):
            raise EvidenceError(f"Invalid incident id {incident_id!r}")
        for root in self.roots():
            path = root / incident_id
            if (path / ARTIFACTS_DIR).is_dir():
                return path
        raise EvidenceError(f"No incident {incident_id!r}")


def create_app(config_path: Path | None, overrides: list[str], incidents: Path,
               services: Services | None = None, host: str = "127.0.0.1") -> Starlette:
    state = DemoState(config_path, list(overrides), incidents.resolve(), host=host)
    base = state.settings()
    state.services = services or Services.open(base)
    state.switches["thinking"] = base.agent.thinking
    state.switches["language"] = base.agent.language
    state.switches["rag"] = base.rag.mode if base.rag.enabled else "off"
    state.switches["cases"] = base.learning.cases.mode if base.learning.cases.enabled else "off"
    state.switches["playbook"] = "on" if base.learning.playbook.enabled else "off"
    state.incidents.mkdir(parents=True, exist_ok=True)
    state.sandbox = base.usb.sandbox_dir.resolve()
    state.base_model = base.model
    state.server = Supervisor(state.incidents.parent / "model-server.log")
    _register_folders(state)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        keeper = asyncio.create_task(_keep_model_loaded(state))
        watcher = asyncio.create_task(_watch_usb(state))
        checker = asyncio.create_task(_verify_ledger(state))
        yield
        keeper.cancel()
        watcher.cancel()
        checker.cancel()
        for task in list(state.tasks):
            task.cancel()
        await anyio.to_thread.run_sync(state.server.stop)
        try:
            await anyio.to_thread.run_sync(state.services.ledger.checkpoint)
        except Exception as exc:  # a checkpoint at shutdown is a courtesy, never a reason to hang
            print(f"blacksite: could not sign the ledger head at shutdown: {exc}", file=sys.stderr)

    def api(policy: Policy, handler: Any) -> Any:
        return guarded(policy, _endpoint(state, handler))

    routes = [
        *auth_routes(state),
        Route("/", guarded(MEMBER, _index)),
        Route("/term", guarded(PUBLIC, _term)),
        Route("/api/status", api(Policy(passive=True), _status)),
        Route("/api/settings", api(Policy(write="admin"), _settings), methods=["GET", "POST"]),
        Route("/api/models", api(Policy("admin"), _models), methods=["GET", "POST"]),
        Route("/api/members", api(MEMBER, _members)),
        Route("/api/incidents", api(MEMBER, _incidents), methods=["GET", "POST"]),
        Route("/api/incidents/{id}", api(VIEW, _incident)),
        Route("/api/incidents/{id}/lines", api(VIEW, _lines)),
        Route("/api/incidents/{id}/search", api(VIEW, _search)),
        Route("/api/incidents/{id}/turn", api(INVESTIGATE, _start_turn), methods=["POST"]),
        Route("/api/incidents/{id}/stream", api(Policy(incident="view", passive=True), _stream)),
        Route("/api/incidents/{id}/reset", api(MANAGE, _reset), methods=["POST"]),
        Route("/api/incidents/{id}/outcome", api(INVESTIGATE, _outcome), methods=["POST"]),
        Route("/api/incidents/{id}/guide.md", api(VIEW, _guide_markdown)),
        Route("/api/incidents/{id}/provenance", api(VIEW, _provenance)),
        Route("/api/incidents/{id}/share", api(MANAGE, _share), methods=["POST"]),
        Route("/api/incidents/{id}/export", api(MANAGE, _export), methods=["POST"]),
        Route("/api/incidents/{id}/wipe", api(Policy("admin", incident="manage"), _wipe), methods=["POST"]),
        Route("/api/usb", api(Policy("admin", passive=True), _usb)),
        Route("/api/learning", api(Policy("admin"), _learning), methods=["GET", "POST"]),
        *admin_routes(state, api),
        *dashboard_routes(state, api),
        Mount("/static", StaticFiles(directory=STATIC)),
    ]
    app = Starlette(routes=routes, lifespan=lifespan, middleware=[Middleware(Gate, services=lambda: state.services)])
    app.state.demo = state
    return app


async def _index(request: Request) -> Response:
    return versioned("index.html", PAGE_ASSETS)


async def _term(request: Request) -> Response:
    """The operator console. Public like /login: the shell holds no data, and it signs in
    through the same /auth routes before any /api call can succeed."""
    return versioned("term/index.html", TERM_ASSETS)


def _endpoint(state: DemoState, handler: Any) -> Any:
    async def endpoint(request: Request) -> Response:
        try:
            return await handler(state, request)
        except LedgerError as exc:
            return refuse(503, f"{exc}. Changes are paused until the ledger can be written.")
        except (EvidenceError, LearningError, ConfigError, LLMError, UsbError, ModelServerError, AuthError,
                ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    return endpoint


def _record(state: DemoState, request: Request, action: str, target: str = "", **detail: Any) -> None:
    """Add what the signed-in person just did to the audit ledger."""
    found = principal(request)
    state.services.ledger.append(action, actor=found.actor, session=found.session.id, target=target, detail=detail)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _register_folders(state: DemoState) -> None:
    """Incidents made outside the web app (older folders, the CLI) belong to no one until an admin assigns them.

    Runs recorded before accounts existed are added to the metrics, attributed to no one.
    """
    access = state.services.access
    known = access.incidents()
    recorded = {(run["incident_id"], run["turn"]) for run in access.runs(limit=100_000)}
    for path in state.incident_paths():
        if path.name not in known:
            stamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            access.register_incident(path.name, None, stamp.isoformat(timespec="seconds").replace("+00:00", "Z"))
        turns = _read_json(path / CONVERSATION_FILE).get("turns", [])
        for number, turn in enumerate(turns, 1):
            if (path.name, number) not in recorded:
                access.record_run(_past_run(path.name, number, turn))


def _past_run(incident: str, number: int, turn: dict[str, Any]) -> dict[str, Any]:
    events = turn.get("events", [])
    done = next((event for event in events if event.get("type") == "done"), {})
    start = next((event for event in events if event.get("type") == "start"), {})
    guide = next((event for event in events if event.get("type") == "guide"), None)
    good, total, _ = provenance._citations(guide) if guide else (0, 0, 0)
    return {"incident_id": incident, "turn": number, "actor": "unknown", "session": None,
            "started_at": turn.get("at"), "finished_at": turn.get("at"), "seconds": float(done.get("seconds") or 0),
            "requests": done.get("requests") or 0, "tool_calls": done.get("tool_calls") or 0,
            "input_tokens": done.get("input_tokens") or 0, "output_tokens": done.get("output_tokens") or 0,
            "model": start.get("model"), "provider": None, "citations_ok": good, "citations_total": total,
            "guide": guide is not None}


async def _verify_ledger(state: DemoState) -> None:
    """Check the whole ledger at startup, then new records every few minutes."""
    ledger = state.services.ledger
    check = ledger.verify
    while True:
        try:
            await anyio.to_thread.run_sync(check)
        except Exception as exc:  # reported on the next run and in Security health
            print(f"blacksite: ledger check failed: {exc}", file=sys.stderr)
        check = ledger.verify_incremental
        await asyncio.sleep(state.services.settings.audit.verify_minutes * 60)


# Status and settings -----------------------------------------------------------------

async def _status(state: DemoState, request: Request) -> Response:
    settings = state.settings()
    model = settings.model
    health = await backend_status(model)
    loading, detail = health.loading, health.detail
    server = state.server
    if server is not None and server.provider == model.provider and not health.loaded:
        if server.running:
            loading, detail = True, f"starting {DISPLAY[model.provider]} with {server.model}"
        elif failure := server.failure():
            loading, detail = False, f"{DISPLAY[model.provider]} stopped: {failure}"
    return JSONResponse({"version": __version__, "provider": model.provider, "backend": DISPLAY[model.provider],
                         "model": model.name, "base_url": model.base_url, "reachable": health.reachable,
                         "loaded": health.loaded, "loading": loading, "detail": detail,
                         "switching": state.switching, "features": feature_summary(settings),
                         "thinking": settings.agent.thinking})


# Model servers and models ------------------------------------------------------------

async def _models(state: DemoState, request: Request) -> Response:
    if request.method == "POST":
        body = await request.json()
        if body.get("action") == "stop":
            await anyio.to_thread.run_sync(state.server.stop)
            _record(state, request, "model.stopped")
        else:
            provider, model = str(body.get("provider", "")), str(body.get("model", ""))
            await _switch_model(state, provider, model)
            _record(state, request, "model.switched", provider=provider, model=state.model.get("name", model))
    backends = await asyncio.gather(*(_backend(state, provider) for provider in PROVIDERS))
    current = state.settings().model
    return JSONResponse({
        "current": {"provider": current.provider, "name": current.name, "base_url": current.base_url},
        "managed": {"running": state.server.running, "provider": state.server.provider, "model": state.server.model},
        "context": current.context, "backends": [entry for entry, _ in backends]})


async def _backend(state: DemoState, provider: str) -> tuple[dict[str, Any], list[catalog.LocalModel]]:
    """One server kind: whether it is installed and running, what it serves, and the models on disk."""
    model = state.model_settings(provider)
    entry: dict[str, Any] = {"id": provider, "name": DISPLAY[provider], "base_url": model.base_url,
                             "installed": True, "detail": ""}
    if provider == "ollama":
        try:
            models = await catalog.ollama_models(server_root(model))
        except (httpx.HTTPError, ValueError):
            models, entry["installed"] = [], False
            entry["detail"] = "Ollama is not running. Open the Ollama app, or run: ollama serve"
    else:
        try:
            find_llama_server() if provider == "llamacpp" else find_vllm()
        except ModelServerError as exc:
            entry["installed"], entry["detail"] = False, str(exc)
        models = await anyio.to_thread.run_sync(catalog.gguf_models if provider == "llamacpp" else catalog.hf_models)
    entry["running"] = (await backend_status(model)).reachable
    entry["serving"] = await serving(model) if entry["running"] else []
    current, server = state.settings().model, state.server

    def in_use(item: catalog.LocalModel) -> bool:
        if current.provider != provider:
            return False
        if provider == "ollama":
            return item.id == current.name
        if server.running and server.provider == provider:
            return server.model == item.label
        return any(served["name"] == current.name and _same_model(served["source"], item) for served in entry["serving"])

    entry["models"] = [{**item.to_json(), "in_use": in_use(item)} for item in models]
    return entry, models


def _same_model(source: str, model: catalog.LocalModel) -> bool:
    if source == model.id:
        return True
    if "/" in model.id and f"models--{model.id.replace('/', '--')}" in source:
        return True  # vLLM reports the cached folder when started offline
    try:
        return Path(source).resolve() == Path(model.id).resolve()
    except (OSError, ValueError):
        return False


async def _switch_model(state: DemoState, provider: str, model_id: str) -> None:
    """Use a model already on this computer, starting or stopping model servers as needed.

    Only models found on disk can be chosen, so the page can never make the demo launch an
    arbitrary path. A server this page did not start is used as it is or left alone.
    """
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown model server {provider!r}")
    if any(not run.done for run in state.runs.values()):
        raise ValueError("Wait for the running investigation to finish before switching models.")
    if state.switching:
        raise ValueError("Already switching models.")
    state.switching = True
    try:
        entry, models = await _backend(state, provider)
        if not entry["installed"]:
            raise ValueError(entry["detail"])
        chosen = next((item for item in models if item.id == model_id), None)
        if chosen is None:
            raise ValueError("That model is not on this computer.")
        if not chosen.usable:
            reason = "its file has no chat template" if chosen.note == "no-template" else "it has no tool calling"
            raise ValueError(f"{chosen.label} cannot run the agent: {reason}.")
        previous = state.settings().model
        target = state.model_settings(provider)
        server = state.server
        if provider == "ollama":
            name = chosen.id  # Ollama sets the context per model; the status check reports a small one
        if previous.provider == "ollama" and (provider != "ollama" or previous.name != name):
            await _unload_ollama(previous)  # free its memory before another model loads
        if provider == "ollama":
            await anyio.to_thread.run_sync(server.stop)
            if chosen.thinking is False:
                state.switches["thinking"] = "none"  # Ollama rejects a thinking request for such models
        else:
            name = catalog.served_name(chosen)
            ours = server.running and server.provider == provider
            if ours and server.model == chosen.label:
                name = previous.name if previous.provider == provider else name
            elif entry["serving"] and not ours:
                match = next((item for item in entry["serving"] if _same_model(item["source"], chosen)), None)
                if match is None:
                    raise ValueError(
                        f"{DISPLAY[provider]} at {target.base_url} is already serving {entry['serving'][0]['name']}, "
                        "and this page did not start it. Stop that server, or choose its model.")
                name = match["name"]
                await anyio.to_thread.run_sync(server.stop)
            else:
                await anyio.to_thread.run_sync(server.stop)
                overrides = [*state.overrides(), f"model.provider={provider}", f"model.base_url={target.base_url}",
                             f"model.name={name}"]
                launch = plan(load_settings(state.config_path, overrides), model=chosen.id, offline=True)
                server.start(launch, provider, target.base_url, chosen.label)
        state.model = {"provider": provider, "base_url": target.base_url, "name": name}
        if provider == "ollama":  # load it now, so the status (and its context check) is current
            task = asyncio.create_task(_warm_ollama(replace(target, name=name)))
            state.tasks.add(task)
            task.add_done_callback(state.tasks.discard)
    finally:
        state.switching = False


async def _unload_ollama(model: ModelSettings) -> None:
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            await client.post(f"{server_root(model)}/api/generate", json={"model": model.name, "keep_alive": 0})
    except httpx.HTTPError:
        pass


async def _settings(state: DemoState, request: Request) -> Response:
    if request.method == "POST":
        body = await request.json()
        allowed = {"rag": {"off", "tool", "inject"}, "cases": {"off", "tool", "inject"},
                   "playbook": {"off", "on"}, "thinking": {"none", "low", "medium"}, "language": {"en", "ko"}}
        for key, value in body.items():
            if key not in allowed or value not in allowed[key]:
                raise ValueError(f"Invalid setting {key}={value!r}")
            state.switches[key] = value
        state.settings()  # validate the combination
        if body:
            _record(state, request, "settings.changed", **{str(key): str(value) for key, value in body.items()})
    return JSONResponse({"switches": state.switches, "features": feature_summary(state.settings())})


# Incidents ---------------------------------------------------------------------------

async def _incidents(state: DemoState, request: Request) -> Response:
    if request.method == "POST":
        return await _create_incident(state, request)
    found = principal(request)
    access = state.services.access
    items = []
    known = access.incidents()
    names = {user.id: user.display_name for user in access.users()}
    for path in sorted(state.incident_paths(), key=lambda item: item.stat().st_mtime, reverse=True):
        if path.name not in known:
            access.register_incident(path.name, None)
            known[path.name] = {"owner_id": None, "shares": []}
        if access.access(found.user, path.name) is None:
            continue
        meta = _read_json(path / INCIDENT_FILE)
        source = read_source(path)
        owner = known[path.name]["owner_id"]
        items.append({"id": path.name, "title": meta.get("title") or path.name,
                      "status": _status_of(path), "running": _running(state, path.name),
                      "queued": path.name in state.queue,
                      "usb": {"drive": source["drive_label"]} if source else None,
                      "mine": owner == found.user.id, "owner": names.get(owner) if owner is not None else None,
                      "shared": found.user.id in known[path.name]["shares"]})
    return JSONResponse({"incidents": items})


async def _members(state: DemoState, request: Request) -> Response:
    """Active accounts, for choosing whom to share an incident with."""
    users = [user for user in state.services.access.users() if user.status == "active"]
    return JSONResponse({"members": [{"id": user.id, "username": user.username, "display_name": user.display_name}
                                     for user in users]})


async def _create_incident(state: DemoState, request: Request) -> Response:
    form = await request.form()
    title = str(form.get("title") or "").strip()
    if not title:
        raise ValueError("A title is required")
    base = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40] or "incident"
    incident_id = f"{datetime.now().strftime('%Y%m%d-%H%M')}-{base}"
    target = state.incidents / incident_id
    artifacts = target / ARTIFACTS_DIR
    artifacts.mkdir(parents=True)
    count = 0
    for upload in form.getlist("files"):
        if not hasattr(upload, "filename") or not upload.filename:
            continue
        name = _safe_filename(upload.filename)
        if not name:
            continue
        with (artifacts / name).open("wb") as stream:
            shutil.copyfileobj(upload.file, stream)
        count += 1
    if not count:
        shutil.rmtree(target)
        raise ValueError("Add at least one log or config file")
    meta: dict[str, Any] = {"id": incident_id, "title": title,
                            "description": str(form.get("description") or "").strip()}
    year = str(form.get("year") or "").strip()
    if year.isdigit():
        meta["year"] = int(year)
    (target / INCIDENT_FILE).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    await anyio.to_thread.run_sync(_ingest, target, state.settings())
    found = principal(request)
    state.services.access.register_incident(incident_id, found.user.id)
    files = await anyio.to_thread.run_sync(provenance.evidence_files, target)
    _record(state, request, "incident.created", incident_id, files=len(files),
            bytes=sum(item["bytes"] for item in files), sha256=[item["sha256"] for item in files])
    return JSONResponse({"id": incident_id})


def _ingest(path: Path, settings: Settings) -> None:
    with Evidence(path, settings.evidence) as evidence:
        evidence.refresh()


async def _incident(state: DemoState, request: Request) -> Response:
    path = state.incident_dir(request.path_params["id"])
    settings = state.settings()
    data = await anyio.to_thread.run_sync(_overview, path, settings)
    conversation = _read_json(path / CONVERSATION_FILE) or {"turns": []}
    for turn in conversation.get("turns", []):
        for event in turn.get("events", []):
            if "checks" in event:
                event["checks"] = [upgrade_check(check) for check in event["checks"]]
    found = principal(request)
    services = state.services
    access = services.access
    turns = conversation.get("turns", [])
    level = access.access(found.user, path.name)
    entry = access.incidents().get(path.name, {"owner_id": None, "shares": []})
    names = {user.id: user.display_name for user in access.users()}
    owner = entry["owner_id"]
    signed = await anyio.to_thread.run_sync(provenance.summary, path, turns, services.keys.public_pem())
    data.update({"turns": turns, "outcome": _read_json(path / OUTCOME_FILE) or None,
                 "running": _running(state, path.name), "queued": path.name in state.queue,
                 "usb": _usb_summary(state, path), "access": level, "provenance": signed,
                 "owner": {"id": owner, "name": names.get(owner)} if owner is not None else None,
                 "shares": [{"id": user_id, "name": names.get(user_id)} for user_id in entry["shares"]]
                 if level == "manage" else []})
    key = (found.session.id, path.name)
    if key not in state.opened:
        _record(state, request, "incident.opened", path.name)
        state.opened.add(key)
    return JSONResponse(data)


async def _provenance(state: DemoState, request: Request) -> Response:
    path = state.incident_dir(request.path_params["id"])
    turn = int(request.query_params.get("turn", "0"))
    manifest = provenance.load(path, turn)
    if manifest is None:
        return refuse(404, "This guide has no signed provenance.")
    turns = _read_json(path / CONVERSATION_FILE).get("turns", [])
    event = provenance._guide_event(turns[turn - 1].get("events", [])) if 0 < turn <= len(turns) else None
    services = state.services
    check = await anyio.to_thread.run_sync(provenance.check, manifest, services.keys.public_pem(), path,
                                           event.get("guide") if event else None)
    actor = str(manifest.get("actor", ""))
    user = services.access.user(int(actor[5:])) if actor.startswith("user:") and actor[5:].isdigit() else None
    return JSONResponse({"manifest": manifest, "check": check, "actor_name": user.display_name if user else None})


async def _share(state: DemoState, request: Request) -> Response:
    path = state.incident_dir(request.path_params["id"])
    body = await request.json()
    try:
        user_id = int(body.get("user_id"))
    except (TypeError, ValueError):
        raise ValueError("Choose a member to share with.") from None
    access = state.services.access
    entry = access.incidents().get(path.name, {})
    if body.get("action") == "unshare":
        access.unshare(path.name, user_id)
        _record(state, request, "incident.unshared", path.name, user=f"user:{user_id}")
    elif body.get("action") == "share":
        if user_id == entry.get("owner_id"):
            raise ValueError("That member already owns this incident.")
        access.share(path.name, user_id, principal(request).user.id)
        _record(state, request, "incident.shared", path.name, user=f"user:{user_id}")
    else:
        raise ValueError("action must be share or unshare")
    return JSONResponse({"shares": access.incidents()[path.name]["shares"]})


def _usb_summary(state: DemoState, path: Path) -> dict[str, Any] | None:
    source = read_source(path)
    if source is None:
        return None
    files = source.get("files", [])
    return {"drive": source["drive_label"], "bundle": source["bundle"], "imported_at": source["imported_at"],
            "files": len(files), "bytes": sum(item.get("bytes", 0) for item in files),
            "skipped": source.get("skipped", []), "exported_to": source.get("exported_to"),
            "present": any(drive["name"] == source.get("drive_name") for drive in state.drives)}


def _overview(path: Path, settings: Settings) -> dict[str, Any]:
    with Evidence(path, settings.evidence) as evidence:
        evidence.refresh()
        incident = evidence.incident
        artifacts = evidence.artifacts()
        start, size, buckets = evidence.histogram()
        first, last = evidence.time_range()
        patterns = evidence.patterns(top=12)
        return {
            "id": path.name, "title": incident.title or path.name, "description": incident.description,
            "summary": format_artifacts(evidence),
            "range": [_iso(first), _iso(last)],
            "artifacts": [{"file": item.file, "kind": item.kind, "lines": item.lines, "errors": item.errors,
                           "redactions": item.redactions, "flagged": item.flagged,
                           "first": _iso(item.first_ts), "last": _iso(item.last_ts)} for item in artifacts],
            "histogram": {"start": _iso(start), "bucket_seconds": size,
                          "rows": [{"bucket": b, "file": f, "count": c} for b, f, c in buckets]},
            "patterns": [{"template": p.template, "count": p.count, "level": p.level, "guessed": p.guessed,
                          "files": p.files, "sample": f"{p.sample_file}:{p.sample_line}",
                          "first": _iso(p.first_ts), "last": _iso(p.last_ts)} for p in patterns],
        }


async def _lines(state: DemoState, request: Request) -> Response:
    path = state.incident_dir(request.path_params["id"])
    file = request.query_params.get("file", "")
    line = int(request.query_params.get("line", "1"))
    end = int(request.query_params.get("end", str(line)))
    context = min(int(request.query_params.get("context", "12")), 60)

    def read() -> dict[str, Any]:
        with Evidence(path, state.settings().evidence) as evidence:
            total = evidence.line_count(file)
            start = max(1, line - context)
            stop = min(total, max(end, line) + context)
            rows = evidence.read_lines(file, start, stop)
            return {"file": file, "total": total, "focus": [line, max(end, line)],
                    "lines": [{"n": row.line_no, "text": row.text, "level": row.level, "guessed": row.guessed,
                               "flagged": row.flagged, "ts": _iso(row.ts)} for row in rows]}

    return JSONResponse(await anyio.to_thread.run_sync(read))


async def _search(state: DemoState, request: Request) -> Response:
    """Lines matching an RE2 regex (or plain text with literal=1), for the operator console's grep.
    The same search the agent's search_logs tool runs; RE2 cannot backtrack catastrophically."""
    path = state.incident_dir(request.path_params["id"])
    query = request.query_params
    pattern = query.get("pattern", "")
    file, level = query.get("file") or None, query.get("level") or None
    limit = min(max(int(query.get("limit", "100")), 1), SEARCH_LIMIT)
    ignore_case, literal = query.get("case") != "1", query.get("literal") == "1"

    def read() -> dict[str, Any]:
        with Evidence(path, state.settings().evidence) as evidence:
            rows, total = evidence.search(pattern, file, level, None, None, limit, ignore_case, literal)
            return {"total": total, "lines": [{"file": row.file, "n": row.line_no, "text": row.text, "level": row.level,
                                               "flagged": row.flagged, "ts": _iso(row.ts)} for row in rows]}

    return JSONResponse(await anyio.to_thread.run_sync(read))


async def _reset(state: DemoState, request: Request) -> Response:
    path = state.incident_dir(request.path_params["id"])
    if _running(state, path.name):
        raise ValueError("An investigation is running")
    for name in (CONVERSATION_FILE, "guide.md", OUTCOME_FILE):
        (path / name).unlink(missing_ok=True)
    pasted = path / ARTIFACTS_DIR / "pasted"
    if pasted.is_dir():
        shutil.rmtree(pasted)
    shutil.rmtree(path / provenance.MANIFEST_DIR, ignore_errors=True)
    _record(state, request, "incident.reset", path.name)
    return JSONResponse({"ok": True})


# Investigation turns -----------------------------------------------------------------

async def _start_turn(state: DemoState, request: Request) -> Response:
    path = state.incident_dir(request.path_params["id"])
    if _running(state, path.name):
        return JSONResponse({"error": "An investigation is already running"}, status_code=409)
    body = await request.json()
    if path.name in state.queue:
        state.queue.remove(path.name)
    found = principal(request)
    start_turn(state, path, str(body.get("message") or ""), str(body.get("pasted") or ""),
               actor=found.actor, session=found.session.id)
    return JSONResponse({"ok": True})


def start_turn(state: DemoState, path: Path, message: str = "", pasted: str = "", *, actor: str,
               session: str | None) -> None:
    """Run one investigation turn in the background, recording its events for the page.

    When it ends, its metrics are stored and, if it wrote a guide, a signed manifest.
    """
    run = Run()
    state.runs[path.name] = run
    settings = state.settings()
    investigator = Investigator(settings, path, state.config_path, state.overrides())
    number = len(_read_json(path / CONVERSATION_FILE).get("turns", [])) + 1
    started = _utc_now()
    state.services.ledger.append("incident.turn_started", actor=actor, session=session, target=path.name,
                                 detail={"turn": number, "pasted": bool(pasted.strip()),
                                         "model": settings.model.name})

    def record(events: list[dict[str, Any]]) -> None:
        provenance.record_turn(state.services, settings, path, number, events, actor=actor, session=session,
                               started_at=started)

    async def work() -> None:
        events: list[dict[str, Any]] = []
        try:
            async for event in investigator.turn(message, pasted):
                events.append(event)
                run.add(event)
        except Exception as exc:  # report anything unexpected to the page instead of hanging
            run.add({"type": "error", "message": str(exc)[:600]})
        finally:
            investigator.evidence.close()
            try:
                await anyio.to_thread.run_sync(record, events)
            except Exception as exc:
                run.add({"type": "error", "message": f"Could not record this turn in the audit ledger: {exc}"[:600]})
            run.done = True
            run.changed.set()

    task = asyncio.create_task(work())
    state.tasks.add(task)
    task.add_done_callback(state.tasks.discard)


async def _stream(state: DemoState, request: Request) -> Response:
    incident_id = request.path_params["id"]
    run = state.runs.get(incident_id)
    if run is None:
        return JSONResponse({"error": "No investigation has run since the demo started"}, status_code=404)
    position = int(request.query_params.get("from", "0"))

    async def events() -> AsyncIterator[str]:
        nonlocal position
        while True:
            while position < len(run.events):
                yield f"data: {json.dumps(run.events[position])}\n\n"
                position += 1
            if run.done:
                yield "event: end\ndata: {}\n\n"
                return
            run.changed.clear()
            try:
                await asyncio.wait_for(run.changed.wait(), timeout=15)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


async def _guide_markdown(state: DemoState, request: Request) -> Response:
    path = state.incident_dir(request.path_params["id"])
    guide = path / "guide.md"
    if not guide.is_file():
        return PlainTextResponse("No guide yet", status_code=404)
    return PlainTextResponse(guide.read_text(encoding="utf-8"), media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="{path.name}-guide.md"'})


# USB mode ----------------------------------------------------------------------------

async def _usb(state: DemoState, request: Request) -> Response:
    settings = state.settings().usb
    after = int(request.query_params.get("after", "0"))
    return JSONResponse({"enabled": settings.enabled, "marker": settings.marker, "drives": state.drives,
                         "events": [event for event in state.usb_events if event["id"] > after],
                         "queue": state.queue})


async def _export(state: DemoState, request: Request) -> Response:
    """Save the latest guide to the incident's drive, then wipe the sandbox if configured."""
    path = state.incident_dir(request.path_params["id"])
    source = read_source(path)
    if source is None:
        raise UsbError("Only incidents that came from a drive can be exported to one")
    if _running(state, path.name):
        return JSONResponse({"error": "An investigation is running; export when it finishes"}, status_code=409)
    body = await request.json() if await request.body() else {}
    settings = state.settings()
    language = body.get("language") if body.get("language") in ("en", "ko") else settings.agent.language
    conversation = _read_json(path / CONVERSATION_FILE)
    turns = list(enumerate(conversation.get("turns", []), 1))
    found = next(((number, turn, event) for number, turn in reversed(turns)
                  for event in reversed(turn.get("events", [])) if event.get("type") == "guide"), None)
    if found is None:
        raise UsbError("There is no guide to export yet")
    number, turn, guide = found
    who = principal(request)
    services = state.services
    manifest = provenance.load(path, number)
    # Credit the model that wrote the guide, not whichever model is selected now.
    model = next((str(event["model"]) for event in turn.get("events", [])
                  if event.get("type") == "start" and event.get("model")), settings.model.name)

    def export() -> dict[str, Any]:
        bundle = locate_bundle(source, settings.usb.roots)
        if bundle is None:
            raise UsbError(f"Insert the drive {source['drive_label']} to save the solution")
        anchor = services.ledger.checkpoint() or services.ledger.anchor()
        with Evidence(path, settings.evidence) as evidence:
            files = build_solution(evidence, guide, language, source, model, provenance=manifest,
                                   public_pem=services.keys.public_pem() if manifest else None, anchor=anchor)
        target = write_solution(bundle, files)
        source["exported_to"] = str(target)
        write_source(path, source)
        services.ledger.append("incident.exported", actor=who.actor, session=who.session.id, target=path.name,
                               detail={"drive": source.get("drive_label"), "turn": number, "signed": manifest is not None,
                                       "files": sorted(files)})
        wiped = False
        if settings.usb.wipe_after_export:
            wipe(path)
            services.access.forget_incident(path.name)
            services.ledger.append("incident.wiped", actor=who.actor, session=who.session.id, target=path.name,
                                   detail={"drive": source.get("drive_label")})
            wiped = True
        return {"path": str(target), "wiped": wiped, "drive": source["drive_label"], "files": sorted(files)}

    result = await anyio.to_thread.run_sync(export)
    state.usb_event("exported", incident=path.name, drive=source["drive_label"], path=result["path"],
                    wiped=result["wiped"])
    return JSONResponse(result)


async def _wipe(state: DemoState, request: Request) -> Response:
    path = state.incident_dir(request.path_params["id"])
    source = read_source(path)
    if source is None:
        raise UsbError("Only sandboxed drive incidents can be wiped")
    if _running(state, path.name):
        return JSONResponse({"error": "An investigation is running"}, status_code=409)
    if path.name in state.queue:
        state.queue.remove(path.name)
    await anyio.to_thread.run_sync(wipe, path)
    state.services.access.forget_incident(path.name)
    _record(state, request, "incident.wiped", path.name, drive=source.get("drive_label"))
    state.usb_event("wiped", incident=path.name, drive=source["drive_label"])
    return JSONResponse({"wiped": True})


async def _watch_usb(state: DemoState) -> None:
    """Poll for drives with a marker folder; import new incidents and queue investigations."""
    previous: set[str] = set()
    while True:
        usb = state.settings().usb
        if usb.enabled:
            try:
                await _scan_drives(state, previous)
            except Exception as exc:  # a flaky drive must not stop the watcher
                state.usb_event("error", message=str(exc)[:300])
            _start_queued(state)
        await asyncio.sleep(usb.poll_seconds if usb.enabled else 5)


async def _scan_drives(state: DemoState, previous: set[str]) -> None:
    settings = state.settings()
    usb = settings.usb
    drives = await anyio.to_thread.run_sync(list_drives, usb.roots)
    found: list[tuple[Any, list[Bundle]]] = []
    for drive in drives:
        bundles = await anyio.to_thread.run_sync(find_bundles, drive, usb.marker)
        if bundles:
            found.append((drive, bundles))
    state.drives = [{"name": drive.name, "label": drive.label, "path": str(drive.path),
                     "incidents": len(bundles), "open": sum(not b.solved for b in bundles)} for drive, bundles in found]
    current = {drive.name for drive, _ in found}
    for name in sorted(previous - current):
        state.usb_event("removed", drive=name)
    for drive, _ in found:
        if drive.name not in previous:
            state.usb_event("inserted", drive=drive.label)
    previous.clear()
    previous.update(current)

    known = _known_bundles(state)
    for drive, bundles in found:
        for bundle in bundles:
            key = (drive.name, bundle.relative)
            if bundle.solved or known.get(key) == bundle.fingerprint:
                continue
            try:
                path = await anyio.to_thread.run_sync(import_bundle, bundle, state.sandbox, usb)
            except UsbError as exc:
                state.usb_event("error", drive=drive.label, message=str(exc))
                known[key] = bundle.fingerprint
                continue
            source = read_source(path) or {}
            state.services.access.register_incident(path.name, None)
            imported_files = source.get("files", [])
            state.services.ledger.append("usb.imported", actor="system:usb", target=path.name, detail={
                "drive": source.get("drive_label"), "files": len(imported_files),
                "bytes": sum(item.get("bytes", 0) for item in imported_files),
                "skipped": len(source.get("skipped", []))})
            meta = _read_json(path / INCIDENT_FILE)
            state.usb_event("imported", incident=path.name, title=meta.get("title", path.name), drive=drive.label,
                            files=len(source.get("files", [])), skipped=len(source.get("skipped", [])))
            known[key] = bundle.fingerprint
            if usb.auto_investigate:
                state.queue.append(path.name)


def _known_bundles(state: DemoState) -> dict[tuple[str, str], str]:
    """Drive bundles already in the sandbox, so reinserting a drive does not import twice."""
    known: dict[tuple[str, str], str] = {}
    if state.sandbox and state.sandbox.is_dir():
        for path in state.sandbox.iterdir():
            source = read_source(path) if path.is_dir() else None
            if source:
                known[(source.get("drive_name", ""), source["bundle"])] = source.get("fingerprint", "")
    return known


def _start_queued(state: DemoState) -> None:
    """One investigation at a time: a laptop model serves one request well, not two."""
    if not state.queue or any(not run.done for run in state.runs.values()):
        return
    incident_id = state.queue.pop(0)
    try:
        path = state.incident_dir(incident_id)
    except EvidenceError:
        return
    start_turn(state, path, actor="system:usb", session=None)
    state.usb_event("started", incident=incident_id)


# Learning ----------------------------------------------------------------------------

async def _outcome(state: DemoState, request: Request) -> Response:
    path = state.incident_dir(request.path_params["id"])
    body = await request.json()
    outcome = str(body.get("outcome") or "")
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of {', '.join(OUTCOMES)}")
    record_outcome(path, outcome, str(body.get("notes") or ""), str(body.get("root_cause") or ""))
    _record(state, request, "incident.outcome", path.name, outcome=outcome)
    settings = state.settings()

    def learn() -> dict[str, Any]:
        chat = ChatClient(settings.model, thinking=settings.agent.thinking)
        try:
            with Evidence(path, settings.evidence) as evidence:
                report = reflect(evidence, open_store(settings), chat, settings, force=True)
        finally:
            chat.close()
        return {"case": report.case_id, "approved": report.approved, "added": report.playbook.added,
                "merged": report.playbook.merged, "tagged": report.playbook.tagged,
                "retired": report.playbook.retired, "ignored": report.playbook.ignored}

    result = await anyio.to_thread.run_sync(learn)
    return JSONResponse(result)


async def _learning(state: DemoState, request: Request) -> Response:
    store = open_store(state.settings())
    if request.method == "POST":
        body = await request.json()
        ids = [str(item) for item in body.get("ids", [])]
        action = body.get("action")
        if action == "approve":
            changed = store.approve(ids)
        elif action == "reject":
            changed = store.reject(ids)
        else:
            raise ValueError("action must be approve or reject")
        if changed:
            _record(state, request, "learning.approved" if action == "approve" else "learning.rejected", ids=changed)
    cases = [{"id": c.id, "incident": c.incident, "status": c.status, "outcome": c.outcome, "title": c.title,
              "symptoms": c.symptoms, "root_cause": c.root_cause, "resolution": c.resolution,
              "lessons": c.lessons, "created": c.created} for c in reversed(store.cases())]
    bullets = [{"id": b.id, "section": b.section, "text": b.text, "helpful": b.helpful, "harmful": b.harmful,
                "status": b.status, "source": b.source} for b in reversed(store.bullets())]
    return JSONResponse({"cases": cases, "bullets": bullets})


# Helpers -----------------------------------------------------------------------------

async def _keep_model_loaded(state: DemoState) -> None:
    """Load the model at startup and keep it resident, so the first question is not slow."""
    while True:
        settings = state.settings()
        if settings.model.provider == "ollama":
            await _warm_ollama(settings.model)
        await asyncio.sleep(240)


async def _warm_ollama(model: ModelSettings) -> None:
    try:
        async with httpx.AsyncClient(timeout=300) as client:
            await client.post(f"{server_root(model)}/api/generate", json={"model": model.name, "keep_alive": "30m"})
    except httpx.HTTPError:
        pass


_WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def _safe_filename(raw: str) -> str:
    """A file name that is valid on Windows, macOS, and Linux, or '' to skip the upload."""
    name = re.split(r"[\\/]", raw)[-1].strip()  # browsers may send a full Windows path
    if name.startswith("."):
        return ""  # hidden files are never evidence
    name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name).rstrip(" .")
    if not name or name.split(".")[0].lower() in _WINDOWS_RESERVED:
        return ""
    return name[:180]


def _running(state: DemoState, incident_id: str) -> bool:
    run = state.runs.get(incident_id)
    return run is not None and not run.done


def _status_of(path: Path) -> str:
    if (path / OUTCOME_FILE).is_file():
        return "closed"
    if (path / "guide.md").is_file():
        return "guide"
    if (path / CONVERSATION_FILE).is_file():
        return "in progress"
    return "new"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat(sep=" ") if value else None


def serve(config_path: Path | None, overrides: list[str], incidents: Path, host: str, port: int) -> None:
    import uvicorn

    if host.strip("[]").lower() not in LOOPBACK:
        raise SystemExit(f"blacksite: the web app runs only on this computer (127.0.0.1, ::1, or localhost), "
                         f"not {host}.")
    settings = load_settings(config_path, overrides)
    for directory in {settings.auth.store_path.parent, settings.audit.store_path.parent, settings.auth.keys_dir}:
        private_dir(directory)
    services = Services.open(settings)
    if services.access.active_admins() == 0:
        config = f"--config {config_path} " if config_path else ""
        raise SystemExit("blacksite: no admin account yet. Create one, then start the demo again:\n"
                         f"  blacksite {config}users add NAME --admin")
    app = create_app(config_path, overrides, incidents, services=services, host=host)
    print(f"Blacksite demo: http://{host}:{port}  (incidents in {incidents})")
    uvicorn.run(app, host=host, port=port, log_level="warning")

