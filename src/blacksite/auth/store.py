"""Accounts, login sessions, incident ownership, and run metrics in one SQLite file.

Only hashes of secrets are stored: scrypt for passwords, SHA-256 for session tokens,
keyed HMACs for recovery codes and for user agents. TOTP secrets must be readable to
check a code, so they are encrypted with a key derived from ``var/keys/master.key``.

Every call opens its own short-lived connection, so the CLI and the web server can
change the same file at once and each sees the other's changes on its next request.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import AuthSettings
from ..keys import Keys, private_file
from . import passwords, totp

ROLES = ("admin", "member")
STATUSES = ("active", "suspended")
STAGES = ("password_change", "totp_enroll", "totp", "full")
USERNAME = re.compile(r"^[a-z0-9._-]{2,40}$")
LOGIN_FAILED = "Wrong username or password."
THROTTLE_LIMIT, THROTTLE_WINDOW = 20, 60.0
MAX_LOCK_SECONDS = 24 * 3600

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    password_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 1,
    totp_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0, totp_last_step INTEGER,
    recovery TEXT NOT NULL DEFAULT '[]', failed INTEGER NOT NULL DEFAULT 0, code_failed INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    lockouts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, created_by TEXT NOT NULL,
    password_changed_at TEXT, last_login_at TEXT);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL REFERENCES users(id),
    stage TEXT NOT NULL, csrf TEXT NOT NULL, created_at REAL NOT NULL, last_seen_at REAL NOT NULL,
    expires_at REAL NOT NULL, confirmed_at REAL, ua_hash TEXT NOT NULL DEFAULT '',
    ended_at REAL, end_reason TEXT, totp_policy INTEGER NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, owner_id INTEGER REFERENCES users(id), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shares (
    incident_id TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id), granted_by INTEGER,
    granted_at TEXT NOT NULL, PRIMARY KEY (incident_id, user_id));
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, turn INTEGER NOT NULL, actor TEXT NOT NULL,
    session TEXT, started_at TEXT, finished_at TEXT, seconds REAL NOT NULL DEFAULT 0,
    requests INTEGER NOT NULL DEFAULT 0, tool_calls INTEGER NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, model TEXT,
    provider TEXT, citations_ok INTEGER NOT NULL DEFAULT 0, citations_total INTEGER NOT NULL DEFAULT 0,
    guide INTEGER NOT NULL DEFAULT 0, UNIQUE (incident_id, turn));
CREATE TABLE IF NOT EXISTS throttle (at REAL NOT NULL);
"""

_RUN_FIELDS = ("incident_id", "turn", "actor", "session", "started_at", "finished_at", "seconds", "requests",
               "tool_calls", "input_tokens", "output_tokens", "model", "provider", "citations_ok",
               "citations_total", "guide")


class AuthError(ValueError):
    """A refused account change or login step; the message is safe to show."""


class LoginFailed(AuthError):
    """Always the same message, whatever went wrong, so it reveals nothing."""

    def __init__(self, user_id: int | None, locked: bool, hashed_name: str) -> None:
        super().__init__(LOGIN_FAILED)
        self.user_id = user_id
        self.locked = locked
        self.hashed_name = hashed_name


@dataclass(frozen=True)
class User:
    id: int
    username: str
    display_name: str
    role: str
    status: str
    must_change: bool
    totp_enabled: bool
    created_at: str
    created_by: str
    last_login_at: str | None
    locked_until: float | None

    def actor(self) -> str:
        return f"user:{self.id}"

    @property
    def admin(self) -> bool:
        return self.role == "admin"

    def to_json(self) -> dict[str, Any]:
        return {"id": self.id, "username": self.username, "display_name": self.display_name, "role": self.role,
                "status": self.status, "must_change": self.must_change, "totp_enabled": self.totp_enabled,
                "created_at": self.created_at, "created_by": self.created_by, "last_login_at": self.last_login_at,
                "locked_until": self.locked_until}


@dataclass(frozen=True)
class Session:
    id: str
    user_id: int
    stage: str
    csrf: str
    created_at: float
    last_seen_at: float
    expires_at: float
    confirmed_at: float | None
    ended_at: float | None
    end_reason: str | None
    ua_hash: str
    totp_policy: bool

    def to_json(self) -> dict[str, Any]:
        return {"id": self.id, "user_id": self.user_id, "stage": self.stage, "created_at": self.created_at,
                "last_seen_at": self.last_seen_at, "expires_at": self.expires_at, "ended_at": self.ended_at,
                "end_reason": self.end_reason, "ua_hash": self.ua_hash}


def normalize_username(username: str) -> str:
    return (username or "").strip().lower()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class AccessStore:
    def __init__(self, path: Path, keys: Keys, settings: AuthSettings,
                 clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self.settings = settings
        self.clock = clock
        self._totp_key = keys.derive("totp")
        self._recovery_key = keys.derive("recovery")
        self._pseudonym_key = keys.derive("pseudonym")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=10)) as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript(_SCHEMA)
            columns = {row[1] for row in con.execute("PRAGMA table_info(users)")}
            if "code_failed" not in columns:  # stores made before this column existed
                con.execute("ALTER TABLE users ADD COLUMN code_failed INTEGER NOT NULL DEFAULT 0")
            session_columns = {row[1] for row in con.execute("PRAGMA table_info(sessions)")}
            if "totp_policy" not in session_columns:
                # Sessions from before this switch always used the enabled policy.
                con.execute("ALTER TABLE sessions ADD COLUMN totp_policy INTEGER NOT NULL DEFAULT 1")
            con.commit()
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            if candidate.exists():
                private_file(candidate)

    # Plumbing ---------------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        return con

    def _rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with closing(self._connect()) as con:
            return con.execute(sql, params).fetchall()

    def _write(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with closing(self._connect()) as con, con:
            return con.execute(sql, params).rowcount

    def pseudonym(self, text: str) -> str:
        return hmac.new(self._pseudonym_key, text.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    # Users ------------------------------------------------------------------------------

    def create_user(self, username: str, display_name: str, role: str, created_by: str,
                    password: str | None = None, must_change: bool = True) -> tuple[User, str]:
        name = normalize_username(username)
        if not USERNAME.match(name):
            raise AuthError("Usernames are 2 to 40 letters, digits, dots, dashes, or underscores.")
        if role not in ROLES:
            raise AuthError(f"Role must be one of {', '.join(ROLES)}.")
        display = (display_name or "").strip()[:80] or name
        if password is None:
            password = passwords.temporary_password()
        else:
            passwords.check_policy(password, name)
        now = _iso(self.clock())
        try:
            with closing(self._connect()) as con, con:
                cursor = con.execute(
                    "INSERT INTO users (username, display_name, role, password_hash, must_change, created_at,"
                    " created_by, password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (name, display, role, passwords.hash_password(password), int(must_change), now, created_by, now))
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            raise AuthError(f"The username {name} is taken.") from None
        return self._user_by_id(user_id), password

    def _user_from(self, row: sqlite3.Row | None) -> User | None:
        if row is None:
            return None
        return User(id=row["id"], username=row["username"], display_name=row["display_name"], role=row["role"],
                    status=row["status"], must_change=bool(row["must_change"]),
                    totp_enabled=bool(row["totp_enabled"]), created_at=row["created_at"],
                    created_by=row["created_by"], last_login_at=row["last_login_at"],
                    locked_until=row["locked_until"])

    def _user_by_id(self, user_id: int) -> User:
        user = self.user(user_id)
        if user is None:
            raise AuthError("No such user.")
        return user

    def user(self, user_id: int) -> User | None:
        rows = self._rows("SELECT * FROM users WHERE id = ?", (user_id,))
        return self._user_from(rows[0] if rows else None)

    def find(self, username: str) -> User | None:
        name = normalize_username(username)
        if not USERNAME.match(name):
            return None
        rows = self._rows("SELECT * FROM users WHERE username = ?", (name,))
        return self._user_from(rows[0] if rows else None)

    def users(self) -> list[User]:
        return [self._user_from(row) for row in self._rows("SELECT * FROM users ORDER BY username")]

    def active_admins(self) -> int:
        return self._rows("SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'")[0][0]

    def _guard_last_admin(self, user: User) -> None:
        if user.role == "admin" and user.status == "active" and self.active_admins() <= 1:
            raise AuthError("This is the last active admin. Add another admin first.")

    def set_status(self, user_id: int, status: str) -> list[str]:
        if status not in STATUSES:
            raise AuthError(f"Status must be one of {', '.join(STATUSES)}.")
        user = self._user_by_id(user_id)
        if status == "suspended":
            self._guard_last_admin(user)
            self._write("UPDATE users SET status = 'suspended' WHERE id = ?", (user_id,))
            return self.end_user_sessions(user_id, "suspended")
        self._write("UPDATE users SET status = 'active', failed = 0, locked_until = NULL WHERE id = ?", (user_id,))
        return []

    def set_role(self, user_id: int, role: str) -> list[str]:
        if role not in ROLES:
            raise AuthError(f"Role must be one of {', '.join(ROLES)}.")
        user = self._user_by_id(user_id)
        if user.role == role:
            return []
        if role == "member":
            self._guard_last_admin(user)
        self._write("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        return self.end_user_sessions(user_id, "role_changed")

    def reset_password(self, user_id: int) -> tuple[str, list[str]]:
        self._user_by_id(user_id)
        temporary = passwords.temporary_password()
        self._write("UPDATE users SET password_hash = ?, must_change = 1, failed = 0, locked_until = NULL,"
                    " lockouts = 0, password_changed_at = ? WHERE id = ?",
                    (passwords.hash_password(temporary), _iso(self.clock()), user_id))
        return temporary, self.end_user_sessions(user_id, "password_reset")

    def check_password(self, user_id: int, password: str) -> bool:
        rows = self._rows("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        return bool(rows) and passwords.verify_password(password, rows[0]["password_hash"])

    def change_password(self, user_id: int, new: str, keep_session: str | None = None) -> list[str]:
        user = self._user_by_id(user_id)
        passwords.check_policy(new, user.username)
        if self.check_password(user_id, new):
            raise AuthError("Choose a password different from the current one.")
        self._write("UPDATE users SET password_hash = ?, must_change = 0, password_changed_at = ? WHERE id = ?",
                    (passwords.hash_password(new), _iso(self.clock()), user_id))
        return self.end_user_sessions(user_id, "password_changed", keep=keep_session)

    # Login and sessions -----------------------------------------------------------------

    def throttled(self) -> bool:
        since = self.clock() - THROTTLE_WINDOW
        return self._rows("SELECT COUNT(*) FROM throttle WHERE at > ?", (since,))[0][0] > THROTTLE_LIMIT

    def _note_failure(self) -> None:
        now = self.clock()
        with closing(self._connect()) as con, con:
            con.execute("DELETE FROM throttle WHERE at <= ?", (now - THROTTLE_WINDOW,))
            con.execute("INSERT INTO throttle (at) VALUES (?)", (now,))

    def authenticate(self, username: str, password: str) -> User:
        name = normalize_username(username)
        rows = self._rows("SELECT * FROM users WHERE username = ?", (name,)) if USERNAME.match(name) else []
        if not rows:
            passwords.dummy_verify(password)
            self._note_failure()
            raise LoginFailed(None, False, self.pseudonym(name))
        row = rows[0]
        now = self.clock()
        matches = passwords.verify_password(password, row["password_hash"])
        locked = row["locked_until"] is not None and now < row["locked_until"]
        if locked or row["status"] != "active":
            self._note_failure()
            raise LoginFailed(row["id"], locked, self.pseudonym(name))
        if not matches:
            self._note_failure()
            failed = row["failed"] + 1
            if failed >= self.settings.lockout_attempts:
                self._lock(row["id"], row["lockouts"])
                raise LoginFailed(row["id"], True, self.pseudonym(name))
            self._write("UPDATE users SET failed = ? WHERE id = ?", (failed, row["id"]))
            raise LoginFailed(row["id"], False, self.pseudonym(name))
        # A quiet day forgives earlier lockouts; until then each one lasts twice as long.
        forgive = row["locked_until"] is not None and now - row["locked_until"] > MAX_LOCK_SECONDS
        rehash = passwords.hash_password(password) if passwords.needs_rehash(row["password_hash"]) else None
        self._write("UPDATE users SET failed = 0, locked_until = NULL, last_login_at = ?,"
                    " lockouts = CASE WHEN ? THEN 0 ELSE lockouts END,"
                    " password_hash = COALESCE(?, password_hash) WHERE id = ?",
                    (_iso(now), int(forgive), rehash, row["id"]))
        return self._user_by_id(row["id"])

    def _lock(self, user_id: int, lockouts: int) -> None:
        seconds = min(self.settings.lockout_minutes * 60 * 2 ** lockouts, MAX_LOCK_SECONDS)
        self._write("UPDATE users SET failed = 0, code_failed = 0, locked_until = ?, lockouts = lockouts + 1"
                    " WHERE id = ?", (self.clock() + seconds, user_id))

    def _code_failed(self, user_id: int) -> None:
        """Count a wrong two-step or recovery code against the account, not the session.

        A new sign-in with the right password does not reset this count, so knowing the
        password does not buy unlimited guesses at the code.
        """
        self._note_failure()
        rows = self._rows("SELECT code_failed, lockouts FROM users WHERE id = ?", (user_id,))
        if not rows:
            return
        count = rows[0]["code_failed"] + 1
        if count >= self.settings.lockout_attempts:
            self._lock(user_id, rows[0]["lockouts"])
            self.end_user_sessions(user_id, "too_many_codes")
        else:
            self._write("UPDATE users SET code_failed = ? WHERE id = ?", (count, user_id))

    def _code_passed(self, user_id: int) -> None:
        self._write("UPDATE users SET code_failed = 0 WHERE id = ?", (user_id,))

    def _next_stage(self, user: User, current: str | None) -> str:
        if user.must_change:
            return "password_change"
        if not self.settings.totp_enabled:
            return "full"
        if user.admin and not user.totp_enabled:
            return "totp_enroll"
        if user.totp_enabled and current in (None, "password_change"):
            return "totp"
        return "full"

    def _session_from(self, row: sqlite3.Row | None) -> Session | None:
        if row is None:
            return None
        return Session(id=row["id"], user_id=row["user_id"], stage=row["stage"], csrf=row["csrf"],
                       created_at=row["created_at"], last_seen_at=row["last_seen_at"], expires_at=row["expires_at"],
                       confirmed_at=row["confirmed_at"], ended_at=row["ended_at"], end_reason=row["end_reason"],
                       ua_hash=row["ua_hash"], totp_policy=bool(row["totp_policy"]))

    def start_session(self, user: User, user_agent: str) -> tuple[Session, str]:
        now = self.clock()
        session_id = secrets.token_hex(16)
        token = secrets.token_urlsafe(32)
        self._write("INSERT INTO sessions (id, token_hash, user_id, stage, csrf, created_at, last_seen_at,"
                    " expires_at, ua_hash, totp_policy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (session_id, token_hash(token), user.id, self._next_stage(user, None), secrets.token_urlsafe(24),
                     now, now, now + self.settings.session_hours * 3600, self.pseudonym(user_agent or ""),
                     int(self.settings.totp_enabled)))
        return self.session(session_id), token

    def session(self, session_id: str) -> Session | None:
        rows = self._rows("SELECT * FROM sessions WHERE id = ?", (session_id,))
        return self._session_from(rows[0] if rows else None)

    def lookup(self, token: str) -> tuple[Session, User] | None:
        if not token:
            return None
        rows = self._rows("SELECT * FROM sessions WHERE token_hash = ?", (token_hash(token),))
        session = self._session_from(rows[0] if rows else None)
        if session is None or session.ended_at is not None:
            return None
        if session.totp_policy != self.settings.totp_enabled:
            # Reauthenticate on either policy change, including incomplete enrollment.
            # In particular, re-enabling TOTP must revoke password-only sessions.
            self.end_session(session.id, "auth_policy_changed")
            return None
        now = self.clock()
        if now >= session.expires_at:
            self.end_session(session.id, "expired")
            return None
        if now - session.last_seen_at > self.settings.idle_minutes * 60:
            self.end_session(session.id, "idle")
            return None
        user = self.user(session.user_id)
        if user is None or user.status != "active":
            self.end_session(session.id, "suspended")
            return None
        return session, user

    def touch(self, session_id: str) -> None:
        self._write("UPDATE sessions SET last_seen_at = ? WHERE id = ? AND ended_at IS NULL",
                    (self.clock(), session_id))

    def advance(self, session_id: str) -> tuple[Session, str]:
        session = self.session(session_id)
        if session is None or session.ended_at is not None:
            raise AuthError("Sign in again.")
        user = self._user_by_id(session.user_id)
        token = secrets.token_urlsafe(32)
        self._write("UPDATE sessions SET stage = ?, token_hash = ?, csrf = ?, last_seen_at = ? WHERE id = ?",
                    (self._next_stage(user, session.stage), token_hash(token), secrets.token_urlsafe(24),
                     self.clock(), session_id))
        return self.session(session_id), token

    def end_session(self, session_id: str, reason: str) -> bool:
        return self._write("UPDATE sessions SET ended_at = ?, end_reason = ? WHERE id = ? AND ended_at IS NULL",
                           (self.clock(), reason, session_id)) > 0

    def end_user_sessions(self, user_id: int, reason: str, keep: str | None = None) -> list[str]:
        ids = [row["id"] for row in self._rows(
            "SELECT id FROM sessions WHERE user_id = ? AND ended_at IS NULL AND id != ?", (user_id, keep or ""))]
        for session_id in ids:
            self.end_session(session_id, reason)
        return ids

    def confirm(self, session_id: str) -> None:
        self._write("UPDATE sessions SET confirmed_at = ? WHERE id = ?", (self.clock(), session_id))

    def confirmed(self, session: Session) -> bool:
        return (session.confirmed_at is not None
                and self.clock() - session.confirmed_at <= self.settings.confirm_minutes * 60)

    def sessions(self, active: bool = True, limit: int = 200) -> list[Session]:
        if not active:
            rows = self._rows("SELECT * FROM sessions ORDER BY last_seen_at DESC LIMIT ?", (limit,))
            return [self._session_from(row) for row in rows]
        now = self.clock()
        rows = self._rows("SELECT * FROM sessions WHERE ended_at IS NULL AND expires_at > ? AND last_seen_at >= ?"
                          " ORDER BY last_seen_at DESC LIMIT ?", (now, now - self.settings.idle_minutes * 60, limit))
        return [self._session_from(row) for row in rows]  # idle ones end lazily; they are not active

    # Two-factor sign-in -----------------------------------------------------------------

    def _encrypt(self, secret: str) -> str:
        nonce = os.urandom(12)
        return base64.b64encode(nonce + AESGCM(self._totp_key).encrypt(nonce, secret.encode(), None)).decode()

    def _decrypt(self, blob: str) -> str:
        raw = base64.b64decode(blob)
        return AESGCM(self._totp_key).decrypt(raw[:12], raw[12:], None).decode()

    def _totp_row(self, user_id: int) -> sqlite3.Row:
        rows = self._rows("SELECT totp_secret, totp_enabled, totp_last_step, recovery FROM users WHERE id = ?",
                          (user_id,))
        if not rows:
            raise AuthError("No such user.")
        return rows[0]

    def totp_setup(self, user_id: int) -> str:
        if self._totp_row(user_id)["totp_enabled"]:
            raise AuthError("Two-step sign-in is already on.")
        secret = totp.new_secret()
        self._write("UPDATE users SET totp_secret = ?, totp_last_step = NULL WHERE id = ?",
                    (self._encrypt(secret), user_id))
        return secret

    def totp_pending_secret(self, user_id: int) -> str | None:
        row = self._totp_row(user_id)
        if row["totp_enabled"] or not row["totp_secret"]:
            return None
        return self._decrypt(row["totp_secret"])

    def totp_enroll(self, user_id: int, code: str) -> list[str]:
        row = self._totp_row(user_id)
        if row["totp_enabled"] or not row["totp_secret"]:
            raise AuthError("Start two-step sign-in setup again.")
        step = totp.verify(self._decrypt(row["totp_secret"]), code, self.clock(), None)
        if step is None:
            raise AuthError("That code did not match. Check that your phone's clock is right, then try the next code.")
        codes = totp.new_recovery_codes()
        self._write("UPDATE users SET totp_enabled = 1, totp_last_step = ?, recovery = ? WHERE id = ?",
                    (step, json.dumps([self._recovery_hash(code) for code in codes]), user_id))
        return codes

    def totp_check(self, user_id: int, code: str) -> bool:
        row = self._totp_row(user_id)
        if not row["totp_enabled"] or not row["totp_secret"]:
            return False
        step = totp.verify(self._decrypt(row["totp_secret"]), code, self.clock(), row["totp_last_step"])
        # Conditional update: two requests racing with the same code cannot both succeed.
        if step is None or not self._write("UPDATE users SET totp_last_step = ? WHERE id = ? AND"
                                           " (totp_last_step IS NULL OR totp_last_step < ?)", (step, user_id, step)):
            self._code_failed(user_id)
            return False
        self._code_passed(user_id)
        return True

    def _recovery_hash(self, code: str) -> str:
        return hmac.new(self._recovery_key, totp.normalize_code(code).encode(), hashlib.sha256).hexdigest()

    def use_recovery(self, user_id: int, code: str) -> int | None:
        row = self._totp_row(user_id)
        remaining = json.loads(row["recovery"] or "[]")
        digest = self._recovery_hash(code)
        match = next((item for item in remaining if hmac.compare_digest(item, digest)), None)
        if not row["totp_enabled"] or match is None:
            self._code_failed(user_id)
            return None
        remaining.remove(match)
        changed = self._write("UPDATE users SET recovery = ? WHERE id = ? AND recovery = ?",
                              (json.dumps(remaining), user_id, row["recovery"]))
        if not changed:
            return None
        self._code_passed(user_id)
        return len(remaining)

    def reset_totp(self, user_id: int) -> list[str]:
        self._user_by_id(user_id)
        self._write("UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = NULL, recovery = '[]'"
                    " WHERE id = ?", (user_id,))
        return self.end_user_sessions(user_id, "totp_reset")

    # Incidents and shares ---------------------------------------------------------------

    def register_incident(self, incident_id: str, owner_id: int | None, created_at: str | None = None) -> None:
        self._write("INSERT OR IGNORE INTO incidents (id, owner_id, created_at) VALUES (?, ?, ?)",
                    (incident_id, owner_id, created_at or _iso(self.clock())))

    def incidents(self) -> dict[str, dict[str, Any]]:
        result = {row["id"]: {"owner_id": row["owner_id"], "created_at": row["created_at"], "shares": []}
                  for row in self._rows("SELECT * FROM incidents")}
        for row in self._rows("SELECT incident_id, user_id FROM shares ORDER BY user_id"):
            if row["incident_id"] in result:
                result[row["incident_id"]]["shares"].append(row["user_id"])
        return result

    def set_owner(self, incident_id: str, owner_id: int | None) -> None:
        if owner_id is not None:
            self._user_by_id(owner_id)
        self.register_incident(incident_id, owner_id)
        self._write("UPDATE incidents SET owner_id = ? WHERE id = ?", (owner_id, incident_id))
        if owner_id is not None:
            self._write("DELETE FROM shares WHERE incident_id = ? AND user_id = ?", (incident_id, owner_id))

    def share(self, incident_id: str, user_id: int, granted_by: int) -> None:
        user = self._user_by_id(user_id)
        if user.status != "active":
            raise AuthError(f"{user.display_name} is suspended.")
        self._write("INSERT OR IGNORE INTO shares (incident_id, user_id, granted_by, granted_at) VALUES (?, ?, ?, ?)",
                    (incident_id, user_id, granted_by, _iso(self.clock())))

    def unshare(self, incident_id: str, user_id: int) -> None:
        self._write("DELETE FROM shares WHERE incident_id = ? AND user_id = ?", (incident_id, user_id))

    def forget_incident(self, incident_id: str) -> None:
        with closing(self._connect()) as con, con:
            con.execute("DELETE FROM shares WHERE incident_id = ?", (incident_id,))
            con.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))

    def access(self, user: User, incident_id: str) -> str | None:
        """What ``user`` may do with the incident: manage, investigate, or nothing."""
        if user.status != "active":
            return None
        if user.admin:
            return "manage"
        rows = self._rows("SELECT owner_id FROM incidents WHERE id = ?", (incident_id,))
        if rows and rows[0]["owner_id"] == user.id:
            return "manage"
        if self._rows("SELECT 1 FROM shares WHERE incident_id = ? AND user_id = ?", (incident_id, user.id)):
            return "investigate"
        return None

    # Runs -------------------------------------------------------------------------------

    def record_run(self, run: dict[str, Any]) -> None:
        values = tuple(int(bool(run.get(name))) if name == "guide" else run.get(name) for name in _RUN_FIELDS)
        self._write(f"INSERT OR REPLACE INTO runs ({', '.join(_RUN_FIELDS)}) "
                    f"VALUES ({', '.join('?' for _ in _RUN_FIELDS)})", values)

    def runs(self, incident_ids: set[str] | None = None, limit: int = 500) -> list[dict[str, Any]]:
        rows = self._rows("SELECT * FROM runs ORDER BY finished_at DESC, id DESC")
        result = []
        for row in rows:
            if incident_ids is not None and row["incident_id"] not in incident_ids:
                continue
            item = {name: row[name] for name in _RUN_FIELDS}
            item["guide"] = bool(item["guide"])
            result.append(item)
            if len(result) >= limit:
                break
        return result
