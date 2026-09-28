"""The dashboard's numbers and the team activity feed, limited to what the viewer may see.

Members see their own incidents (or ones shared with them) and only the ledger records
about those incidents or about themselves; admins may look at everything.
"""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ..auth.gate import Policy, principal, refuse
from ..auth.store import User
from ..context import open_store
from ..evidence.store import INCIDENT_FILE
from ..learning.reflect import OUTCOME_FILE
from ..learning.store import LearningError
from .admin import actor_name

if TYPE_CHECKING:
    from .app import DemoState

SCOPES = ("mine", "shared", "all")
RANGES = (7, 30, 90)
STATUSES = ("new", "in progress", "guide", "closed")
MAX_BUCKETS = 15
RECENT_RUNS = 14


def parse_time(text: Any) -> datetime | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 1) if values else None


def _rate(outcomes: list[str]) -> float | None:
    return round(sum(outcome == "resolved" for outcome in outcomes) / len(outcomes), 3) if outcomes else None


def _read_json(path: Path) -> dict[str, Any]:
    from .app import _read_json

    return _read_json(path)


def in_scope(entry: dict[str, Any], user: User, scope: str) -> bool:
    if scope == "all":
        return user.admin
    if scope == "mine":
        return entry.get("owner_id") == user.id
    return user.id in entry.get("shares", [])


def compute(state: DemoState, user: User, scope: str, days: int) -> dict[str, Any]:
    from .app import _running, _status_of

    access = state.services.access
    entries = access.incidents()
    now = datetime.fromtimestamp(access.clock(), timezone.utc)
    start, previous_start = now - timedelta(days=days), now - timedelta(days=2 * days)
    buckets = min(days, MAX_BUCKETS)
    size = timedelta(days=days) / buckets

    def bucket(moment: datetime | None) -> int | None:
        if moment is None or not start <= moment <= now:
            return None
        return min(int((moment - start) / size), buckets - 1)

    incidents = []
    for path in state.incident_paths():
        entry = entries.get(path.name, {"owner_id": None, "shares": [], "created_at": None})
        if not in_scope(entry, user, scope):
            continue
        outcome = _read_json(path / OUTCOME_FILE)
        created = parse_time(entry.get("created_at")) or datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        incidents.append({"id": path.name, "status": _status_of(path), "created": created,
                          "outcome": outcome.get("outcome"), "reported": parse_time(outcome.get("reported_at"))})
    ids = {item["id"] for item in incidents}
    runs = [{**run, "at": parse_time(run["finished_at"])} for run in access.runs(ids, limit=100_000)] if ids else []

    def within(moment: datetime | None, lower: datetime, upper: datetime) -> bool:
        return moment is not None and lower <= moment <= upper

    # KPIs, each with a sparkline over the range.
    created_spark = [0] * buckets
    guide_spark = [0] * buckets
    outcome_buckets: list[list[str]] = [[] for _ in range(buckets)]
    guide_seconds: list[list[float]] = [[] for _ in range(buckets)]
    for item in incidents:
        if (index := bucket(item["created"])) is not None:
            created_spark[index] += 1
        if item["outcome"] and (index := bucket(item["reported"])) is not None:
            outcome_buckets[index].append(item["outcome"])
    for run in runs:
        if run["guide"] and (index := bucket(run["at"])) is not None:
            guide_spark[index] += 1
            guide_seconds[index].append(run["seconds"])
    current_outcomes = [item["outcome"] for item in incidents if item["outcome"] and within(item["reported"], start, now)]
    previous_outcomes = [item["outcome"] for item in incidents
                         if item["outcome"] and within(item["reported"], previous_start, start)]
    current_guides = [run["seconds"] for run in runs if run["guide"] and within(run["at"], start, now)]
    previous_guides = [run["seconds"] for run in runs if run["guide"] and within(run["at"], previous_start, start)]
    kpis = {
        "open": {"value": sum(item["status"] != "closed" for item in incidents),
                 "created": sum(created_spark), "spark": created_spark},
        "awaiting": {"value": sum(item["status"] == "guide" for item in incidents), "spark": guide_spark},
        "resolved_rate": {"value": _rate(current_outcomes), "previous": _rate(previous_outcomes),
                          "spark": [_rate(items) for items in outcome_buckets]},
        "time_to_guide": {"value": _median(current_guides), "previous": _median(previous_guides),
                          "spark": [_median(items) for items in guide_seconds]},
    }

    # Incidents created per day, by where they stand now.
    first_day = now.date() - timedelta(days=days - 1)
    day_list = [(first_day + timedelta(days=offset)).isoformat() for offset in range(days)]
    series = {status: [0] * days for status in STATUSES}
    for item in incidents:
        offset = (item["created"].date() - first_day).days
        if 0 <= offset < days:
            series[item["status"] if item["status"] in series else "new"][offset] += 1

    in_range = [run for run in runs if within(run["at"], start, now)]
    guides_in_range = sum(run["guide"] for run in in_range)
    outcomes = {name: sum(outcome == name for outcome in current_outcomes)
                for name in ("resolved", "partial", "not_resolved")}
    outcomes["turns_per_guide"] = round(len(in_range) / guides_in_range, 1) if guides_in_range else None

    recent = sorted((run for run in runs if run["at"]), key=lambda run: run["at"])[-RECENT_RUNS:]
    cited = sum(run["citations_total"] for run in recent)
    runtime = {
        "runs": [{"seconds": run["seconds"], "tool_calls": run["tool_calls"], "input_tokens": run["input_tokens"],
                  "output_tokens": run["output_tokens"], "citations_ok": run["citations_ok"],
                  "citations_total": run["citations_total"], "guide": run["guide"], "model": run["model"],
                  "at": run["finished_at"]} for run in recent],
        "median_seconds": _median([run["seconds"] for run in recent]),
        "citation_rate": round(sum(run["citations_ok"] for run in recent) / cited, 3) if cited else None,
        "tool_calls": round(sum(run["tool_calls"] for run in recent) / len(recent), 1) if recent else None,
        "tokens_in": round(statistics.mean(run["input_tokens"] for run in recent)) if recent else None,
        "tokens_out": round(statistics.mean(run["output_tokens"] for run in recent)) if recent else None,
    }
    return {"scope": scope, "range": days, "kpis": kpis, "trend": {"days": day_list, "series": series},
            "outcomes": outcomes, "runtime": runtime, "learning": _learning(state, user),
            "attention": kpis["open"]["value"], "running": sum(_running(state, item) for item in ids),
            "incidents": len(incidents)}


def _learning(state: DemoState, user: User) -> dict[str, Any]:
    try:
        store = open_store(state.settings())
        cases, bullets = store.cases(), store.bullets()
    except (LearningError, OSError):
        return {"lessons": 0, "cases": 0} if not user.admin else {"pending": 0, "lessons": 0, "cases": 0, "recent": []}
    active = [bullet for bullet in bullets if bullet.status == "active"]
    counts = {"lessons": len(active), "cases": sum(case.status == "approved" for case in cases)}
    if not user.admin:
        return counts  # lesson and case text can describe incidents this member may not see
    pending = sum(case.status == "pending" for case in cases) + sum(bullet.status == "pending" for bullet in bullets)
    return {"pending": pending, **counts,
            "recent": [{"section": bullet.section, "text": bullet.text} for bullet in reversed(active[-3:])]}


def dashboard_routes(state: DemoState, api: Any) -> list[Route]:
    services = state.services

    async def dashboard(state: DemoState, request: Request) -> Response:
        found = principal(request)
        query = request.query_params
        scope = query.get("scope") or ("all" if found.admin else "mine")
        if scope not in SCOPES:
            raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
        if scope == "all" and not found.admin:
            return refuse(403, "Only an admin can see every incident.")
        days = int(query.get("range", "30")) if query.get("range", "30").isdigit() else 0
        if days not in RANGES:
            raise ValueError("range must be 7, 30, or 90 days")
        return JSONResponse(await anyio.to_thread.run_sync(compute, state, found.user, scope, days))

    async def activity(state: DemoState, request: Request) -> Response:
        found = principal(request)
        query = request.query_params
        after = int(query["after"]) if query.get("after", "").isdigit() else 0
        limit = max(1, min(int(query["limit"]) if query.get("limit", "").isdigit() else 50, 200))
        access = services.access
        allowed: dict[str, bool] = {}

        def visible(record: Any) -> bool:
            if found.admin or record.actor == found.actor:
                return True
            if not record.target or not record.action.startswith(("incident.", "usb.")):
                return False
            if record.target not in allowed:
                allowed[record.target] = access.access(found.user, record.target) is not None
            return allowed[record.target]

        records = await anyio.to_thread.run_sync(
            lambda: services.ledger.records(after=after, limit=limit, where=visible))
        people = {user.id: user for user in access.users()}
        paths = {path.name: path for path in state.incident_paths()}
        titles: dict[str, str | None] = {}
        items = []
        for record in records:
            incident = None
            if record.target and not record.target.startswith("user:"):
                if record.target not in titles:
                    path = paths.get(record.target)
                    titles[record.target] = (_read_json(path / INCIDENT_FILE).get("title") or record.target) if path else None
                incident = {"id": record.target, "title": titles[record.target]}
            kind = "user" if record.actor.startswith("user:") else "cli" if record.actor.startswith("cli:") else "system"
            detail = dict(record.detail)
            if isinstance(detail.get("user"), str):
                detail["user_name"] = actor_name(detail["user"], people)
            items.append({"seq": record.seq, "at": record.at, "action": record.action, "incident": incident,
                          "actor": {"kind": kind, "id": int(record.actor[5:]) if kind == "user" and
                                    record.actor[5:].isdigit() else None, "name": actor_name(record.actor, people)},
                          "target_name": actor_name(record.target, people) if record.target.startswith("user:") else None,
                          "detail": detail})
        last = services.ledger.last_verification()
        verification = {key: last.get(key) for key in ("ok", "records", "at", "reason", "first_bad")} if last else None
        return JSONResponse({"items": items, "verification": verification, "head": services.ledger.head()[0]})

    return [
        Route("/api/dashboard", api(Policy(passive=True), dashboard)),
        Route("/api/activity", api(Policy(passive=True), activity)),
    ]
