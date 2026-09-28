"""The admin console's endpoints: members, sessions, the audit log, incident access, and security health."""

from __future__ import annotations

import os
import stat
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ..auth.gate import Policy, principal, refuse
from ..auth.store import AuthError, User
from ..evidence.store import INCIDENT_FILE

if TYPE_CHECKING:
    from .app import DemoState

ADMIN = Policy("admin")
SENSITIVE = Policy("admin", confirm=True)


def _iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _names(state: DemoState) -> dict[int, User]:
    return {user.id: user for user in state.services.access.users()}


def actor_name(actor: str, users: dict[int, User]) -> str:
    """How the console shows an actor: a person's name, or what the system part was."""
    if actor.startswith("user:") and actor[5:].isdigit():
        user = users.get(int(actor[5:]))
        return user.display_name if user else f"Deleted user #{actor[5:]}"
    return {"system": "Blacksite", "system:usb": "USB intake", "anonymous": "Unknown name"}.get(actor, actor)


def record_json(record: Any, users: dict[int, User]) -> dict[str, Any]:
    data = record.to_json()
    data.pop("mac", None)
    data["actor_name"] = actor_name(record.actor, users)
    if record.target.startswith("user:"):
        data["target_name"] = actor_name(record.target, users)
    return data


def admin_routes(state: DemoState, api: Any) -> list[Route]:
    """``api(policy, handler)`` wraps a handler with the app's policy and error handling."""
    services = state.services

    async def users(state: DemoState, request: Request) -> Response:
        access = services.access
        if request.method == "POST":
            body = await request.json()
            user, temporary = access.create_user(str(body.get("username") or ""), str(body.get("display_name") or ""),
                                                 str(body.get("role") or "member"), principal(request).actor)
            _record(request, "admin.user_created", user.actor(), role=user.role)
            return JSONResponse({"user": user.to_json(), "temporary_password": temporary})
        active = access.sessions()
        owned: dict[int, int] = {}
        for entry in access.incidents().values():
            if entry["owner_id"] is not None:
                owned[entry["owner_id"]] = owned.get(entry["owner_id"], 0) + 1
        return JSONResponse({"users": [{**user.to_json(),
                                        "sessions": sum(1 for session in active if session.user_id == user.id),
                                        "incidents": owned.get(user.id, 0)} for user in access.users()]})

    async def user(state: DemoState, request: Request) -> Response:
        access = services.access
        body = await request.json()
        me = principal(request)
        try:
            user_id = int(request.path_params["uid"])
        except ValueError:
            raise AuthError("No such user.") from None
        target = access.user(user_id)
        if target is None:
            raise AuthError("No such user.")
        action = body.get("action")
        result: dict[str, Any] = {}
        if user_id == me.user.id and action in ("suspend", "role", "reset_totp", "reset_password"):
            raise AuthError("You cannot do that to your own account here; use Account, or ask another admin.")
        if action == "suspend":
            ended = access.set_status(user_id, "suspended")
            _record(request, "admin.user_suspended", target.actor(), sessions=len(ended))
        elif action == "activate":
            access.set_status(user_id, "active")
            _record(request, "admin.user_activated", target.actor())
        elif action == "reset_password":
            temporary, ended = access.reset_password(user_id)
            result["temporary_password"] = temporary
            _record(request, "admin.password_reset", target.actor(), sessions=len(ended))
        elif action == "reset_totp":
            ended = access.reset_totp(user_id)
            _record(request, "admin.totp_reset", target.actor(), sessions=len(ended))
        elif action == "role":
            role = str(body.get("role") or "")
            access.set_role(user_id, role)
            _record(request, "admin.role_changed", target.actor(), role=role)
        else:
            raise AuthError("Unknown action.")
        return JSONResponse({"user": access.user(user_id).to_json(), **result})

    async def sessions(state: DemoState, request: Request) -> Response:
        me = principal(request)
        people = _names(state)
        items = []
        for session in services.access.sessions(active=request.query_params.get("all") != "1"):
            user = people.get(session.user_id)
            items.append({**session.to_json(), "current": session.id == me.session.id,
                          "user": {"id": session.user_id, "username": user.username if user else None,
                                   "display_name": user.display_name if user else None}})
        return JSONResponse({"sessions": items, "idle_minutes": services.settings.auth.idle_minutes})

    async def revoke(state: DemoState, request: Request) -> Response:
        session_id = request.path_params["sid"]
        session = services.access.session(session_id)
        if session is None:
            return refuse(404, "No such session.")
        if services.access.end_session(session_id, "revoked"):
            _record(request, "admin.session_revoked", f"user:{session.user_id}", revoked=session_id)
        return JSONResponse({"ok": True})

    async def timeline(state: DemoState, request: Request) -> Response:
        session_id = request.path_params["sid"]
        session = services.access.session(session_id)
        if session is None:
            return refuse(404, "No such session.")
        people = _names(state)
        user = people.get(session.user_id)
        records = services.ledger.records(session=session_id, limit=1000)
        return JSONResponse({"session": session.to_json(),
                             "user": {"id": session.user_id, "username": user.username if user else None,
                                      "display_name": user.display_name if user else None},
                             "records": [record_json(record, people) for record in records]})

    async def audit(state: DemoState, request: Request) -> Response:
        query = request.query_params
        limit = max(1, min(int(query.get("limit", "100")), 500))
        before = int(query["before"]) if query.get("before", "").isdigit() else None
        records = services.ledger.records(limit=limit, before=before, actor=query.get("actor") or None,
                                          action=query.get("action") or None, target=query.get("target") or None,
                                          session=query.get("session") or None, since=query.get("since") or None,
                                          until=query.get("until") or None)
        people = _names(state)
        return JSONResponse({"records": [record_json(record, people) for record in records],
                             "next": records[-1].seq if len(records) == limit else None,
                             "head": services.ledger.head()[0]})

    async def verify(state: DemoState, request: Request) -> Response:
        result = await anyio.to_thread.run_sync(services.ledger.verify)
        _record(request, "audit.verified", ok=result.ok, records=result.records, first_bad=result.first_bad)
        return JSONResponse(result.to_json())

    async def export(state: DemoState, request: Request) -> Response:
        with tempfile.TemporaryDirectory(prefix="blacksite-audit-") as scratch:
            path = Path(scratch) / "audit.jsonl"
            count = await anyio.to_thread.run_sync(services.ledger.export, path)
            content = path.read_bytes()
        _record(request, "audit.exported", records=count)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return Response(content, media_type="application/x-ndjson",
                        headers={"Content-Disposition": f'attachment; filename="blacksite-audit-{stamp}.jsonl"'})

    async def anchor(state: DemoState, request: Request) -> Response:
        """Sign the ledger head now, so the fingerprint an admin writes down covers everything so far."""
        signed = await anyio.to_thread.run_sync(services.ledger.checkpoint)
        current = services.ledger.anchor()
        _record(request, "audit.anchored", seq=current["seq"] if current else 0, new=signed is not None)
        return JSONResponse({"anchor": services.ledger.anchor()})

    async def incidents(state: DemoState, request: Request) -> Response:
        from .app import _read_json, _status_of

        people = _names(state)
        entries = services.access.incidents()
        items = []
        for path in state.incident_paths():
            entry = entries.get(path.name, {"owner_id": None, "shares": [], "created_at": None})
            owner = entry["owner_id"]
            items.append({"id": path.name, "title": _read_json(path / INCIDENT_FILE).get("title") or path.name,
                          "status": _status_of(path), "created_at": entry.get("created_at"),
                          "sandbox": state.sandbox is not None and path.parent == state.sandbox,
                          "owner": {"id": owner, "name": people[owner].display_name}
                          if owner is not None and owner in people else None,
                          "shares": [{"id": uid, "name": people[uid].display_name}
                                     for uid in entry["shares"] if uid in people]})
        items.sort(key=lambda item: item["created_at"] or "", reverse=True)
        return JSONResponse({"incidents": items})

    async def incident(state: DemoState, request: Request) -> Response:
        path = state.incident_dir(request.path_params["id"])
        body = await request.json()
        access = services.access
        me = principal(request)
        if "owner_id" in body:
            owner = body["owner_id"]
            owner_id = int(owner) if owner is not None else None
            access.set_owner(path.name, owner_id)
            _record(request, "admin.owner_assigned", path.name,
                    owner=f"user:{owner_id}" if owner_id is not None else None)
        if body.get("share") is not None:
            access.share(path.name, int(body["share"]), me.user.id)
            _record(request, "incident.shared", path.name, user=f"user:{int(body['share'])}")
        if body.get("unshare") is not None:
            access.unshare(path.name, int(body["unshare"]))
            _record(request, "incident.unshared", path.name, user=f"user:{int(body['unshare'])}")
        return JSONResponse({"ok": True})

    async def health(state: DemoState, request: Request) -> Response:
        access, ledger, settings = services.access, services.ledger, services.settings
        people = access.users()
        now = time.time()
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds").replace("+00:00", "Z")
        failed = ledger.records(action="auth.login_failed", since=since, limit=10_000)
        paths = list(dict.fromkeys([settings.auth.store_path.parent, settings.audit.store_path.parent,
                                    settings.auth.keys_dir]))
        private = None if os.name == "nt" else all(
            not stat.S_IMODE(path.stat().st_mode) & 0o077 for path in paths if path.exists())
        head = ledger.head()[0]
        return JSONResponse({
            "private": private, "private_paths": [str(path) for path in paths],
            "loopback": True, "host": state.host,
            "keys": (settings.auth.keys_dir / "master.key").is_file() and (settings.auth.keys_dir / "signing.key").is_file(),
            "admins_without_totp": sum(1 for user in people if user.admin and user.status == "active"
                                       and not user.totp_enabled),
            "admins": sum(1 for user in people if user.admin and user.status == "active"),
            "members": len(people),
            "locked": sum(1 for user in people if user.locked_until and user.locked_until > now),
            "suspended": sum(1 for user in people if user.status == "suspended"),
            "failed_24h": len(failed), "active_sessions": len(access.sessions()),
            "last_verification": ledger.last_verification(), "anchor": ledger.anchor(),
            "signing_key": services.keys.fingerprint,
            "ledger": {"records": head, "broken": ledger.broken},
            "session_hours": settings.auth.session_hours, "idle_minutes": settings.auth.idle_minutes,
        })

    def _record(request: Request, action: str, target: str = "", **detail: Any) -> None:
        found = principal(request)
        services.ledger.append(action, actor=found.actor, session=found.session.id, target=target, detail=detail)

    return [
        Route("/api/admin/users", api(Policy("admin", write="admin", confirm=True), users), methods=["GET", "POST"]),
        Route("/api/admin/users/{uid}", api(SENSITIVE, user), methods=["POST"]),
        Route("/api/admin/sessions", api(ADMIN, sessions)),
        Route("/api/admin/sessions/{sid}/revoke", api(ADMIN, revoke), methods=["POST"]),
        Route("/api/admin/sessions/{sid}/timeline", api(ADMIN, timeline)),
        Route("/api/admin/audit", api(ADMIN, audit)),
        Route("/api/admin/audit/verify", api(ADMIN, verify), methods=["POST"]),
        Route("/api/admin/audit/export", api(SENSITIVE, export), methods=["POST"]),
        Route("/api/admin/audit/anchor", api(ADMIN, anchor), methods=["POST"]),
        Route("/api/admin/incidents", api(ADMIN, incidents)),
        Route("/api/admin/incidents/{id}", api(ADMIN, incident), methods=["POST"]),
        Route("/api/admin/health", api(ADMIN, health)),
    ]
