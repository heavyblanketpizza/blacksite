"""Persistent memory of past incidents (cases) and approved lessons (playbook bullets).

Cases follow ReasoningBank (Ouyang et al., 2025): distilled records of what was seen,
what caused it, and what did or did not fix it, recalled for similar incidents. The
playbook follows ACE (Zhang et al., ICLR 2026): itemized bullets with helpful/harmful
counters, changed only through small deterministic updates, never by rewriting the
whole text, which avoids gradually losing detail. Both papers report that learning from
unreliable feedback makes an agent worse, so Blacksite learns only from outcomes a
person reported, and new entries wait for approval by default.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SECTIONS = ("diagnosis", "remediation", "safety", "guide-writing")
OUTCOMES = ("resolved", "partial", "not_resolved")
DUPLICATE_SIMILARITY = 0.6
RRF_K = 60

_WORD = re.compile(r"[^\W\d_][\w]{1,}")
# Mask tokens and English filler; two-letter words stay because many Korean words are two syllables.
_MASK_WORDS = {"num", "hex", "uuid", "empty", "ip", "ts", "the", "and", "for", "with", "on", "no", "of", "to",
               "in", "is", "at", "by", "or", "an", "as", "be", "it", "was", "not", "from"}
_ID = re.compile(r"^(case|pb)-(\d+)$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    num INTEGER PRIMARY KEY AUTOINCREMENT, incident TEXT NOT NULL, created TEXT NOT NULL,
    status TEXT NOT NULL, outcome TEXT NOT NULL, title TEXT NOT NULL, symptoms TEXT NOT NULL,
    root_cause TEXT NOT NULL, resolution TEXT NOT NULL, lessons TEXT NOT NULL, signature TEXT NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS cases_fts USING fts5(
    title, symptoms, root_cause, resolution, lessons, tokenize='porter unicode61');
CREATE TABLE IF NOT EXISTS bullets (
    num INTEGER PRIMARY KEY AUTOINCREMENT, section TEXT NOT NULL, text TEXT NOT NULL,
    helpful INTEGER NOT NULL DEFAULT 0, harmful INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
    source TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    at TEXT NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL, detail TEXT NOT NULL);
"""


class LearningError(ValueError):
    """An invalid change to the learning store."""


@dataclass(frozen=True)
class Case:
    id: str
    incident: str
    created: str
    status: str
    outcome: str
    title: str
    symptoms: str
    root_cause: str
    resolution: str
    lessons: list[str]
    signature: list[str]


@dataclass(frozen=True)
class Bullet:
    id: str
    section: str
    text: str
    helpful: int
    harmful: int
    status: str
    source: str


@dataclass
class ApplyReport:
    added: list[str] = field(default_factory=list)
    merged: list[str] = field(default_factory=list)
    tagged: list[str] = field(default_factory=list)
    retired: list[str] = field(default_factory=list)
    ignored: list[str] = field(default_factory=list)


class LearningStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as con:
            con.executescript(_SCHEMA)

    # Cases ---------------------------------------------------------------------------

    def add_case(self, *, incident: str, outcome: str, title: str, symptoms: str, root_cause: str,
                 resolution: str, lessons: list[str], signature: list[str], approved: bool) -> str:
        if outcome not in OUTCOMES:
            raise LearningError(f"outcome must be one of {', '.join(OUTCOMES)}")
        status = "approved" if approved else "pending"
        with self._connect() as con:
            cursor = con.execute(
                "INSERT INTO cases (incident, created, status, outcome, title, symptoms, root_cause, "
                "resolution, lessons, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (incident, _now(), status, outcome, title, symptoms, root_cause, resolution,
                 json.dumps(lessons), json.dumps(signature)),
            )
            num = cursor.lastrowid
            con.execute(
                "INSERT INTO cases_fts (rowid, title, symptoms, root_cause, resolution, lessons) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (num, title, symptoms, root_cause, resolution, " ".join(lessons)),
            )
            case_id = _case_id(num)
            _event(con, "case-added", case_id, f"{status}; incident {incident}; {outcome}")
        return case_id

    def has_case_for(self, incident: str) -> bool:
        with self._connect() as con:
            row = con.execute(
                "SELECT 1 FROM cases WHERE incident = ? AND status != 'rejected' LIMIT 1", (incident,)
            ).fetchone()
        return row is not None

    def cases(self, status: str | None = None) -> list[Case]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM cases WHERE ? IS NULL OR status = ? ORDER BY num", (status, status)
            ).fetchall()
        return [_case(row) for row in rows]

    def recall(self, query: str = "", signature: Iterable[str] = (), top_k: int = 3,
               exclude_incident: str | None = None) -> list[tuple[Case, float]]:
        """Approved cases most like this incident, by log signature and by text."""
        rankings: list[list[int]] = []
        with self._connect() as con:
            candidates = {
                row["num"]: row
                for row in con.execute("SELECT * FROM cases WHERE status = 'approved'").fetchall()
                if row["incident"] != exclude_incident
            }
            if not candidates:
                return []
            words = list(dict.fromkeys(_WORD.findall(query.lower())))
            if words:
                expression = " OR ".join(f'"{word}"' for word in words)
                rows = con.execute(
                    "SELECT rowid FROM cases_fts WHERE cases_fts MATCH ? ORDER BY bm25(cases_fts)",
                    (expression,),
                ).fetchall()
                rankings.append([row[0] for row in rows if row[0] in candidates])
        tokens = _tokens(" ".join(signature))
        if tokens:
            scored = []
            for num, row in candidates.items():
                similarity = _jaccard(tokens, _tokens(" ".join(json.loads(row["signature"]))))
                if similarity >= 0.1:
                    scored.append((similarity, num))
            rankings.append([num for _, num in sorted(scored, key=lambda item: (-item[0], item[1]))])
        fused = _rrf(rankings)
        return [(_case(candidates[num]), score) for num, score in fused[:top_k]]

    # Playbook ------------------------------------------------------------------------

    def bullets(self, status: str | None = None) -> list[Bullet]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM bullets WHERE ? IS NULL OR status = ? ORDER BY num", (status, status)
            ).fetchall()
        return [_bullet(row) for row in rows]

    def active_bullets(self, limit: int) -> list[Bullet]:
        """Active bullets by section, the most helpful first."""
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM bullets WHERE status = 'active' "
                "ORDER BY helpful - harmful DESC, num LIMIT ?",
                (limit,),
            ).fetchall()
        bullets = [_bullet(row) for row in rows]
        return sorted(bullets, key=lambda bullet: SECTIONS.index(bullet.section))

    def apply_playbook(self, updates: list[dict[str, Any]], source: str, approved: bool) -> ApplyReport:
        """Merge updates deterministically: add (or merge into a near-duplicate), then tag."""
        report = ApplyReport()
        with self._connect() as con:
            existing = [
                (row["num"], _tokens(row["text"]))
                for row in con.execute("SELECT num, text FROM bullets WHERE status IN ('active', 'pending')")
            ]
            for update in updates:
                op = update.get("op")
                if op == "add":
                    section, text = update.get("section"), " ".join(str(update.get("text", "")).split())
                    if section not in SECTIONS or not text:
                        report.ignored.append(f"add: invalid section or empty text ({section!r})")
                        continue
                    tokens = _tokens(text)
                    duplicate = max(
                        ((num, _jaccard(tokens, other)) for num, other in existing),
                        key=lambda item: item[1], default=(None, 0.0),
                    )
                    if duplicate[0] is not None and duplicate[1] >= DUPLICATE_SIMILARITY:
                        con.execute("UPDATE bullets SET helpful = helpful + 1, updated = ? WHERE num = ?",
                                    (_now(), duplicate[0]))
                        report.merged.append(_bullet_id(duplicate[0]))
                        continue
                    status = "active" if approved else "pending"
                    cursor = con.execute(
                        "INSERT INTO bullets (section, text, status, source, created, updated) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (section, text, status, source, _now(), _now()),
                    )
                    existing.append((cursor.lastrowid, tokens))
                    report.added.append(_bullet_id(cursor.lastrowid))
                    _event(con, "bullet-added", _bullet_id(cursor.lastrowid), f"{status}; from {source}")
                elif op in ("helpful", "harmful"):
                    num = _parse_id(str(update.get("id", "")), "pb")
                    changed = num is not None and con.execute(
                        f"UPDATE bullets SET {op} = {op} + 1, updated = ? "
                        "WHERE num = ? AND status IN ('active', 'pending')",
                        (_now(), num),
                    ).rowcount
                    if changed:
                        report.tagged.append(f"{_bullet_id(num)} {op}")
                        _event(con, f"bullet-{op}", _bullet_id(num), f"from {source}")
                    else:
                        report.ignored.append(f"{op}: unknown bullet {update.get('id')!r}")
                else:
                    report.ignored.append(f"unknown op {op!r}")
            for row in con.execute(
                "SELECT num FROM bullets WHERE status = 'active' AND harmful >= 2 AND harmful > helpful"
            ).fetchall():
                con.execute("UPDATE bullets SET status = 'retired', updated = ? WHERE num = ?", (_now(), row[0]))
                report.retired.append(_bullet_id(row[0]))
                _event(con, "bullet-retired", _bullet_id(row[0]), "marked harmful more often than helpful")
        return report

    # Review --------------------------------------------------------------------------

    def approve(self, ids: Iterable[str]) -> list[str]:
        """Approve pending cases and bullets; also reactivates retired bullets."""
        return self._set_status(ids, case_status="approved", bullet_status="active",
                                allowed={"pending", "retired", "rejected"})

    def reject(self, ids: Iterable[str]) -> list[str]:
        return self._set_status(ids, case_status="rejected", bullet_status="rejected",
                                allowed={"pending", "approved", "active", "retired"})

    def _set_status(self, ids: Iterable[str], case_status: str, bullet_status: str,
                    allowed: set[str]) -> list[str]:
        changed = []
        with self._connect() as con:
            for item in ids:
                match = _ID.match(item.strip())
                if not match:
                    raise LearningError(f"Not a case or bullet id: {item!r} (expected case-0001 or pb-0001)")
                table = "cases" if match.group(1) == "case" else "bullets"
                status = case_status if table == "cases" else bullet_status
                marks = ",".join("?" * len(allowed))
                cursor = con.execute(
                    f"UPDATE {table} SET status = ?{', updated = ?' if table == 'bullets' else ''} "
                    f"WHERE num = ? AND status IN ({marks})",
                    (status, *([_now()] if table == "bullets" else []), int(match.group(2)), *sorted(allowed)),
                )
                if cursor.rowcount:
                    changed.append(item.strip())
                    _event(con, f"status-{status}", item.strip(), "by reviewer")
        return changed

    def _connect(self) -> Any:
        return _Transaction(self.path, self._lock)


class _Transaction:
    """Serialized connection that commits on success and always closes."""

    def __init__(self, path: Path, lock: threading.RLock) -> None:
        self.path, self.lock = path, lock

    def __enter__(self) -> sqlite3.Connection:
        self.lock.acquire()
        self.con = sqlite3.connect(self.path, timeout=30)
        self.con.row_factory = sqlite3.Row
        return self.con

    def __exit__(self, kind: object, *_: object) -> None:
        try:
            with closing(self.con):
                if kind is None:
                    self.con.commit()
                else:
                    self.con.rollback()
        finally:
            self.lock.release()


def _event(con: sqlite3.Connection, kind: str, ref: str, detail: str) -> None:
    con.execute("INSERT INTO events VALUES (?, ?, ?, ?)", (_now(), kind, ref, detail))


def _case(row: sqlite3.Row) -> Case:
    return Case(
        id=_case_id(row["num"]), incident=row["incident"], created=row["created"], status=row["status"],
        outcome=row["outcome"], title=row["title"], symptoms=row["symptoms"], root_cause=row["root_cause"],
        resolution=row["resolution"], lessons=json.loads(row["lessons"]), signature=json.loads(row["signature"]),
    )


def _bullet(row: sqlite3.Row) -> Bullet:
    return Bullet(_bullet_id(row["num"]), row["section"], row["text"], row["helpful"], row["harmful"],
                  row["status"], row["source"])


def _case_id(num: int) -> str:
    return f"case-{num:04d}"


def _bullet_id(num: int) -> str:
    return f"pb-{num:04d}"


def _parse_id(value: str, prefix: str) -> int | None:
    match = _ID.match(value.strip())
    return int(match.group(2)) if match and match.group(1) == prefix else None


def _tokens(text: str) -> set[str]:
    return {word for word in _WORD.findall(text.lower()) if word not in _MASK_WORDS}


def _jaccard(first: set[str], second: set[str]) -> float:
    if not first or not second:
        return 0.0
    return len(first & second) / len(first | second)


def _rrf(rankings: list[list[int]]) -> list[tuple[int, float]]:
    scores: dict[int, float] = {}
    for ranking in rankings:
        for rank, num in enumerate(ranking):
            scores[num] = scores.get(num, 0.0) + 1.0 / (RRF_K + rank + 1)
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
