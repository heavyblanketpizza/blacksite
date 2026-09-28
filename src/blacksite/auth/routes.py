"""Sign-in, sign-out, and account endpoints, and the standalone sign-in page."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import anyio
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from . import totp
from .gate import PUBLIC, Policy, Principal, clear_cookie, guarded, principal, refuse, services_of, set_cookie
from ..audit.ledger import LedgerError
from .passwords import PasswordPolicyError
from .store import AuthError, LoginFailed

STATIC = Path(__file__).resolve().parents[1] / "web" / "static"
SESSION = Policy("session")
MAX_CODE_FAILURES = 5


def versioned(page: str, assets: tuple[str, ...]) -> HTMLResponse:
    """A page with asset URLs versioned by modification time, so edits are never cached."""
    html = (STATIC / page).read_text(encoding="utf-8")
    for name in assets:
        if not (STATIC / name).is_file():
            continue
        version = int((STATIC / name).stat().st_mtime)
        html = html.replace(f"/static/{name}\"", f"/static/{name}?v={version}\"")
    return HTMLResponse(html)


async def _body(request: Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _me(found: Principal) -> dict[str, Any]:
    user, session = found.user, found.session
    return {"user": {"id": user.id, "username": user.username, "display_name": user.display_name,
                     "role": user.role, "totp_enabled": user.totp_enabled},
            "stage": session.stage, "csrf": session.csrf,
            "session": {"id": session.id, "expires_at": session.expires_at, "last_seen_at": session.last_seen_at}}


def auth_routes(state: Any) -> list[Route]:
    """``state`` is the web app's state; it keeps per-session counts of wrong codes."""
    failures: dict[str, int] = state.code_failures

    async def login_page(request: Request) -> Response:
        found = request.scope.get("state", {}).get("principal")
        if found is not None and found.session.stage == "full":
            return RedirectResponse("/", status_code=302)
        return versioned("login.html", ("app.css", "boot.js", "login.js", "i18n.json"))

    async def login(request: Request) -> Response:
        services = services_of(request)
        body = await _body(request)
        username, password = str(body.get("username") or ""), str(body.get("password") or "")
        if services.access.throttled():
            await asyncio.sleep(1)
        try:
            user = await anyio.to_thread.run_sync(services.access.authenticate, username, password)
        except LoginFailed as exc:
            actor = f"user:{exc.user_id}" if exc.user_id is not None else "anonymous"
            detail = {"locked": exc.locked} | ({} if exc.user_id is not None else {"name": exc.hashed_name})
            services.ledger.append("auth.login_failed", actor=actor, detail=detail)
            return refuse(401, str(exc))
        previous = request.scope.get("state", {}).get("principal")
        if previous is not None:
            services.access.end_session(previous.session.id, "replaced")
        session, token = services.access.start_session(user, request.headers.get("user-agent", ""))
        try:
            services.ledger.append("auth.login", actor=user.actor(), session=session.id,
                                   detail={"stage": session.stage, "browser": session.ua_hash})
        except LedgerError:
            services.access.end_session(session.id, "ledger_unavailable")  # no unrecorded sign-ins
            raise
        response = JSONResponse({"stage": session.stage, "csrf": session.csrf})
        set_cookie(response, token)
        return response

    async def logout(request: Request) -> Response:
        found = principal(request)
        services = services_of(request)
        services.access.end_session(found.session.id, "signed_out")
        services.ledger.append("auth.logout", actor=found.actor, session=found.session.id)
        response = JSONResponse({"ok": True})
        clear_cookie(response)
        return response

    async def me(request: Request) -> Response:
        found = principal(request)
        services = services_of(request)
        data = _me(found)
        data["auth"] = {"totp_enabled": services.settings.auth.totp_enabled}
        data["session"]["idle_minutes"] = services.settings.auth.idle_minutes
        return JSONResponse(data)

    def advanced(request: Request, found: Principal, extra: dict[str, Any] | None = None) -> JSONResponse:
        """Move the session to its next sign-in step with a fresh token."""
        services = services_of(request)
        if found.session.stage == "full":
            return JSONResponse({"stage": "full", "csrf": found.session.csrf, **(extra or {})})
        session, token = services.access.advance(found.session.id)
        if session.stage == "full":
            services.ledger.append("auth.signed_in", actor=found.actor, session=session.id)
        response = JSONResponse({"stage": session.stage, "csrf": session.csrf, **(extra or {})})
        set_cookie(response, token)
        return response

    def wrong_code(request: Request, found: Principal, action: str,
                   message: str = "That code did not match. Check that your phone's clock is right, then try the next code.") -> Response:
        services = services_of(request)
        count = failures.get(found.session.id, 0) + 1
        failures[found.session.id] = count
        services.ledger.append(action, actor=found.actor, session=found.session.id, detail={"count": count})
        if count >= MAX_CODE_FAILURES:
            services.access.end_session(found.session.id, "too_many_codes")
            failures.pop(found.session.id, None)
            response = refuse(401, "Too many failed attempts. Sign in again.", login=True)
            clear_cookie(response)
            return response
        return refuse(400, message)

    async def password(request: Request) -> Response:
        found = principal(request)
        services = services_of(request)
        body = await _body(request)
        new = str(body.get("new") or "")
        if found.session.stage == "full":
            current = str(body.get("current") or "")
            ok = await anyio.to_thread.run_sync(services.access.check_password, found.user.id, current)
            if not ok:
                services.ledger.append("auth.password_change_failed", actor=found.actor, session=found.session.id)
                return refuse(400, "Your current password is not right.")
        try:
            ended = await anyio.to_thread.run_sync(
                lambda: services.access.change_password(found.user.id, new, keep_session=found.session.id))
        except (PasswordPolicyError, AuthError) as exc:
            return refuse(400, str(exc))
        services.ledger.append("auth.password_changed", actor=found.actor, session=found.session.id,
                               detail={"sessions_ended": len(ended)})
        refreshed = Principal(services.access.user(found.user.id), services.access.session(found.session.id))
        return advanced(request, refreshed)

    async def totp_setup(request: Request) -> Response:
        found = principal(request)
        services = services_of(request)
        if not services.settings.auth.totp_enabled:
            return refuse(403, "Two-step sign-in is currently disabled.")
        if found.user.totp_enabled:
            return refuse(400, "Two-step sign-in is already on.")
        secret = services.access.totp_pending_secret(found.user.id) or services.access.totp_setup(found.user.id)
        uri = totp.provisioning_uri(secret, found.user.username)
        return JSONResponse({"secret": secret, "uri": uri, "qr": totp.qr_data_uri(uri)})

    async def totp_enroll(request: Request) -> Response:
        found = principal(request)
        services = services_of(request)
        if not services.settings.auth.totp_enabled:
            return refuse(403, "Two-step sign-in is currently disabled.")
        body = await _body(request)
        try:
            codes = services.access.totp_enroll(found.user.id, str(body.get("code") or ""))
        except AuthError:
            return wrong_code(request, found, "auth.totp_failed")
        failures.pop(found.session.id, None)
        services.ledger.append("auth.totp_enrolled", actor=found.actor, session=found.session.id)
        refreshed = Principal(services.access.user(found.user.id), services.access.session(found.session.id))
        return advanced(request, refreshed, {"recovery_codes": codes})

    async def totp_verify(request: Request) -> Response:
        found = principal(request)
        services = services_of(request)
        if not services.settings.auth.totp_enabled:
            return refuse(403, "Two-step sign-in is currently disabled.")
        body = await _body(request)
        if not services.access.totp_check(found.user.id, str(body.get("code") or "")):
            return wrong_code(request, found, "auth.totp_failed")
        failures.pop(found.session.id, None)
        return advanced(request, found)

    async def recovery(request: Request) -> Response:
        found = principal(request)
        services = services_of(request)
        if not services.settings.auth.totp_enabled:
            return refuse(403, "Two-step sign-in is currently disabled.")
        body = await _body(request)
        remaining = services.access.use_recovery(found.user.id, str(body.get("code") or ""))
        if remaining is None:
            return wrong_code(request, found, "auth.recovery_failed")
        failures.pop(found.session.id, None)
        services.ledger.append("auth.recovery_used", actor=found.actor, session=found.session.id,
                               detail={"remaining": remaining})
        return advanced(request, found, {"remaining": remaining})

    async def confirm(request: Request) -> Response:
        found = principal(request)
        services = services_of(request)
        body = await _body(request)
        ok = await anyio.to_thread.run_sync(services.access.check_password, found.user.id,
                                            str(body.get("password") or ""))
        needs_code = services.settings.auth.totp_enabled and found.user.totp_enabled
        if ok and needs_code:
            ok = services.access.totp_check(found.user.id, str(body.get("code") or ""))
        if not ok:
            return wrong_code(request, found, "auth.confirm_failed",
                              "That password or code did not match." if needs_code else "That password did not match.")
        failures.pop(found.session.id, None)
        services.access.confirm(found.session.id)
        services.ledger.append("auth.confirmed", actor=found.actor, session=found.session.id)
        return JSONResponse({"ok": True, "minutes": services.settings.auth.confirm_minutes})

    def recorded(handler: Any) -> Any:
        """Refuse, rather than continue unrecorded, when the audit ledger cannot be written."""

        async def endpoint(request: Request) -> Response:
            try:
                return await handler(request)
            except LedgerError as exc:
                return refuse(503, f"{exc}. Sign-in is paused until the ledger can be written.")

        endpoint.__name__ = handler.__name__
        return endpoint

    login, logout, password, totp_setup, totp_enroll, totp_verify, recovery, confirm = (
        recorded(handler) for handler in (login, logout, password, totp_setup, totp_enroll, totp_verify, recovery, confirm))

    return [
        Route("/login", guarded(PUBLIC, login_page)),
        Route("/auth/login", guarded(PUBLIC, login), methods=["POST"]),
        Route("/auth/logout", guarded(SESSION, logout), methods=["POST"]),
        Route("/api/me", guarded(Policy("session", passive=True), me)),
        Route("/auth/password", guarded(SESSION, password), methods=["POST"]),
        Route("/auth/totp/setup", guarded(SESSION, totp_setup)),
        Route("/auth/totp/enroll", guarded(SESSION, totp_enroll), methods=["POST"]),
        Route("/auth/totp/verify", guarded(SESSION, totp_verify), methods=["POST"]),
        Route("/auth/recovery", guarded(SESSION, recovery), methods=["POST"]),
        Route("/auth/confirm", guarded(Policy("member"), confirm), methods=["POST"]),
    ]
