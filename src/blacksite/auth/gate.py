"""The request gate: every request passes here before any route sees it.

The middleware checks what applies to every request: the Host header (a page on another
site cannot reach this server through DNS rebinding), the Origin and CSRF token on
changes, security headers, and the session. Each route is then wrapped by ``guarded``
with a ``Policy`` saying who may call it; a test fails if any route lacks one, so nothing
is open by accident.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable
from urllib.parse import quote

from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .store import Session, User

if TYPE_CHECKING:
    from ..services import Services

COOKIE = "blacksite_session"
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# /term is the operator console: a static shell that signs in through /auth itself.
PUBLIC_PATHS = frozenset({"/login", "/auth/login", "/term"})
ANY_STAGE = frozenset({"/auth/logout", "/api/me"})
STAGE_PATHS = {
    "password_change": frozenset({"/auth/password"}),
    "totp_enroll": frozenset({"/auth/totp/setup", "/auth/totp/enroll"}),
    "totp": frozenset({"/auth/totp/verify", "/auth/recovery"}),
}
LEVELS = {"view": 1, "investigate": 2, "manage": 3}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"x-frame-options", b"DENY"),
]


@dataclass(frozen=True)
class Policy:
    """Who may call a route. ``role``: public, session (any sign-in step), member, or admin."""

    role: str = "member"
    write: str | None = None       # role for methods that change things, when stricter than ``role``
    incident: str | None = None    # view, investigate, or manage, for routes with an {id}
    passive: bool = False          # background polling: does not count as activity
    confirm: bool = False          # changes need a fresh password (and code) confirmation


PUBLIC = Policy("public")


@dataclass(frozen=True)
class Principal:
    user: User
    session: Session

    @property
    def admin(self) -> bool:
        return self.user.admin

    @property
    def actor(self) -> str:
        return self.user.actor()


def principal(request: Request) -> Principal:
    found = request.scope.get("state", {}).get("principal")
    if found is None:
        raise RuntimeError("no signed-in principal on this request")
    return found


def services_of(request: Request) -> Services:
    return request.scope["state"]["services"]


def set_cookie(response: Response, token: str) -> None:
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/")


def clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict")


def refuse(status: int, error: str, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": error, **extra}, status_code=status)


def _wants_page(path: str) -> bool:
    return not path.startswith(("/api/", "/auth/", "/static/"))


def _host_ok(scope: Scope, headers: Headers) -> bool:
    host = headers.get("host", "")
    server = scope.get("server") or ("", 80)
    if host.startswith("["):
        name, _, rest = host[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        name, _, port = host.partition(":")
    if name.lower() not in LOOPBACK:
        return False
    expected = str(server[1]) if server[1] else ""
    return port == expected or (not port and expected in ("80", ""))


def guarded(policy: Policy, endpoint: Callable[[Request], Awaitable[Response]]) -> Callable[[Request], Awaitable[Response]]:
    """Wrap a route so it runs only for callers the policy allows."""

    async def wrapped(request: Request) -> Response:
        if policy.role == "public":
            return await endpoint(request)
        found: Principal | None = request.scope.get("state", {}).get("principal")
        if found is None:
            return refuse(401, "Sign in again.", login=True)
        if policy.role != "session" and found.session.stage != "full":
            return refuse(403, "Finish signing in first.", stage=found.session.stage)
        changing = request.method not in SAFE_METHODS
        needed = (policy.write or policy.role) if changing else policy.role
        if needed == "admin" and not found.admin:
            return refuse(403, "Only an admin can do this.")
        services = services_of(request)
        if policy.incident:
            level = services.access.access(found.user, str(request.path_params.get("id", "")))
            if level is None:
                return refuse(404, "Not found")
            if LEVELS[level] < LEVELS[policy.incident]:
                return refuse(403, "Only the incident's owner or an admin can do this.")
        if policy.confirm and changing and not services.access.confirmed(found.session):
            return refuse(403, "Confirm your password to continue.", confirm=True)
        if not policy.passive:
            services.access.touch(found.session.id)
        return await endpoint(request)

    wrapped.policy = policy  # type: ignore[attr-defined]
    wrapped.__name__ = getattr(endpoint, "__name__", "endpoint")
    return wrapped


class Gate:
    def __init__(self, app: ASGIApp, services: Callable[[], Services]) -> None:
        self.app = app
        self.services = services

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        path = scope["path"]
        no_store = path.startswith(("/api/", "/auth/")) or path in ("/", "/login", "/term")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = {name.lower() for name, _ in message.get("headers", [])}
                extra = [(name, value) for name, value in SECURITY_HEADERS if name not in existing]
                if no_store:
                    extra = [item for item in extra if item[0] != b"cache-control"] + [(b"cache-control", b"no-store")]
                    message["headers"] = [item for item in message.get("headers", [])
                                          if item[0].lower() != b"cache-control"]
                message["headers"] = list(message.get("headers", [])) + extra
            await send(message)

        async def reply(response: Response) -> None:
            await response(scope, receive, send_with_headers)

        if not _host_ok(scope, headers):
            await reply(Response("Blacksite answers only on this computer's own address.", status_code=400,
                                 media_type="text/plain"))
            return
        changing = scope["method"] not in SAFE_METHODS
        if changing:
            origin = headers.get("origin")
            own = f"{scope.get('scheme', 'http')}://{headers.get('host', '')}"
            site = headers.get("sec-fetch-site")
            if (origin and origin != own) or (site and site != "same-origin"):
                await reply(refuse(403, "Requests from other sites are refused."))
                return
        services = self.services()
        if changing and services.ledger.broken and not services.ledger.probe():
            await reply(refuse(503, "The audit ledger cannot be written, so changes are paused. "
                                    "Check the disk and the var/ folder, then reload."))
            return
        state = scope.setdefault("state", {})
        state["services"] = services
        token = _cookie(headers)
        found = services.access.lookup(token) if token else None
        public = path in PUBLIC_PATHS or path.startswith("/static/")
        if found is not None:
            session, user = found
            state["principal"] = Principal(user, session)
        if not public:
            if found is None:
                if _wants_page(path):
                    target = "/login" if path == "/" else f"/login?next={quote(path)}"
                    response: Response = RedirectResponse(target, status_code=302)
                else:
                    response = refuse(401, "Sign in again.", login=True)
                if token:
                    clear_cookie(response)
                await reply(response)
                return
            session = found[0]
            if session.stage != "full" and path not in ANY_STAGE | STAGE_PATHS.get(session.stage, frozenset()):
                if _wants_page(path):
                    await reply(RedirectResponse("/login", status_code=302))
                else:
                    await reply(refuse(403, "Finish signing in first.", stage=session.stage))
                return
            if changing and not hmac.compare_digest(headers.get("x-csrf-token", ""), session.csrf):
                await reply(refuse(403, "This page is out of date. Reload it and try again.", csrf=True))
                return
        await self.app(scope, receive, send_with_headers)


def _cookie(headers: Headers) -> str:
    for part in headers.get("cookie", "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE:
            return value.strip().strip('"')
    return ""
