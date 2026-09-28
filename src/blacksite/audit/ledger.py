"""An append-only, hash-chained record of actions, with signed checkpoints.

Each record's ``hash`` is SHA-256 over its fields and the previous record's hash, so
changing, removing, or reordering a record breaks every link after it. Anyone can
recompute that chain, so each record also carries ``mac``, an HMAC of the hash under a
key only this machine's Blacksite account can read: rewriting the whole chain needs the
key. Checkpoints sign the head with Ed25519; copies of a checkpoint that leave the
machine (in guide provenance, USB exports, or written down) show later whether history
up to that point was rewritten or cut off, even by someone holding the keys.

Records hold identifiers, counts, sizes, and hashes. Never evidence text, prompts, guide
text, passwords, codes, or session tokens.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from ..keys import Keys, canonical, group, load_public_key, private_file, sha256_hex, verify_signature

GENESIS = sha256_hex(b"blacksite-ledger-v1")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
    seq INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, session TEXT, action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL,
    mac TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ledger_session ON ledger(session);
CREATE INDEX IF NOT EXISTS ledger_target ON ledger(target);
CREATE TABLE IF NOT EXISTS checkpoints (
    seq INTEGER PRIMARY KEY, at TEXT NOT NULL, hash TEXT NOT NULL, key_id TEXT NOT NULL, signature TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger
    BEGIN SELECT RAISE(ABORT, 'the ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger
    BEGIN SELECT RAISE(ABORT, 'the ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS checkpoints_no_update BEFORE UPDATE ON checkpoints
    BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only'); END;
CREATE TRIGGER IF NOT EXISTS checkpoints_no_delete BEFORE DELETE ON checkpoints
    BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only'); END;
"""


class LedgerError(RuntimeError):
    """The ledger could not be written; Blacksite refuses changes until it can."""


@dataclass(frozen=True)
class Record:
    seq: int
    at: str
    actor: str
    session: str | None
    action: str
    target: str
    detail: dict[str, Any]
    prev: str
    hash: str
    mac: str

    def fields(self) -> dict[str, Any]:
        return {"seq": self.seq, "at": self.at, "actor": self.actor, "session": self.session,
                "action": self.action, "target": self.target, "detail": self.detail, "prev": self.prev}

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Verification:
    ok: bool
    records: int
    checked_from: int
    first_bad: int | None
    reason: str
    last_checkpoint: dict[str, Any] | None
    at: str
    key_fingerprint: str | None = None

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def _utc(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def record_hash(fields: dict[str, Any]) -> str:
    return sha256_hex(canonical(fields))


def checkpoint_payload(seq: int, digest: str, at: str) -> bytes:
    return canonical({"seq": seq, "hash": digest, "at": at})


def anchor_fingerprint(seq: int, digest: str, at: str) -> str:
    return group(sha256_hex(checkpoint_payload(seq, digest, at)))


def _record(row: sqlite3.Row | tuple[Any, ...]) -> Record:
    seq, at, actor, session, action, target, detail, prev, digest, mac = tuple(row)
    return Record(seq, at, actor, session, action, target, json.loads(detail), prev, digest, mac)


class _Checker:
    """Walks records in order and reports the first one that is out of place."""

    def __init__(self, prev: str, expected: int, mac_key: bytes | None) -> None:
        self.prev = prev
        self.expected = expected
        self.mac_key = mac_key

    def check(self, record: Record) -> tuple[int, str] | None:
        if record.seq != self.expected:
            return self.expected, f"Record {self.expected} is missing."
        if record.prev != self.prev:
            return record.seq, f"Record {record.seq} does not follow record {record.seq - 1}."
        if record_hash(record.fields()) != record.hash:
            return record.seq, f"Record {record.seq} was changed after it was written."
        if self.mac_key is not None:
            mac = hmac.new(self.mac_key, record.hash.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, record.mac):
                return record.seq, f"Record {record.seq} was rewritten by someone without the ledger key."
        self.prev = record.hash
        self.expected += 1
        return None


def _check_signed(items: Iterable[dict[str, Any]], hashes: Callable[[int], str | None], total: int,
                  public: Any, label: str) -> tuple[int, str] | None:
    for item in items:
        seq = int(item["seq"])
        if not verify_signature(public, checkpoint_payload(seq, item["hash"], item["at"]), item["signature"]):
            return seq, f"{label} {seq} has a bad signature."
        if seq > total:
            return total + 1, f"The ledger was truncated: {label.lower()} {seq} is past the last record, {total}."
        if hashes(seq) != item["hash"]:
            return seq, f"Record {seq} differs from its signed {label.lower()}."
    return None


class Ledger:
    def __init__(self, path: Path, keys: Keys, checkpoint_every: int = 100,
                 clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self.keys = keys
        self.checkpoint_every = max(1, int(checkpoint_every))
        self.clock = clock
        self.broken = False
        self._mac_key = keys.derive("ledger")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=10)) as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript(_SCHEMA)
            con.commit()
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            if candidate.exists():
                private_file(candidate)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=15, isolation_level=None)

    # Writing ----------------------------------------------------------------------------

    def append(self, action: str, *, actor: str, session: str | None = None, target: str = "",
               detail: dict[str, Any] | None = None) -> Record:
        try:
            record = self._append(action, actor, session, target, detail or {})
        except (sqlite3.Error, OSError, TypeError, ValueError) as exc:
            self.broken = True
            raise LedgerError(f"Could not write the audit ledger: {exc}") from exc
        self.broken = False
        return record

    def _append(self, action: str, actor: str, session: str | None, target: str,
                detail: dict[str, Any]) -> Record:
        detail_json = canonical(detail).decode("utf-8")  # fails early on values JSON cannot hold
        with closing(self._connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                head = con.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
                seq, prev = (head[0] + 1, head[1]) if head else (1, GENESIS)
                fields = {"seq": seq, "at": _utc(self.clock()), "actor": actor, "session": session,
                          "action": action, "target": target, "detail": json.loads(detail_json), "prev": prev}
                digest = record_hash(fields)
                mac = hmac.new(self._mac_key, digest.encode(), hashlib.sha256).hexdigest()
                con.execute("INSERT INTO ledger VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (seq, fields["at"], actor, session, action, target, detail_json, prev, digest, mac))
                last = con.execute("SELECT at FROM checkpoints ORDER BY seq DESC LIMIT 1").fetchone()
                if seq % self.checkpoint_every == 0 or last is None or last[0][:10] != fields["at"][:10]:
                    self._sign(con, seq, digest, fields["at"])
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
        return Record(seq, fields["at"], actor, session, action, target, fields["detail"], prev, digest, mac)

    def _sign(self, con: sqlite3.Connection, seq: int, digest: str, at: str) -> dict[str, Any]:
        signature = self.keys.sign(checkpoint_payload(seq, digest, at))
        con.execute("INSERT OR IGNORE INTO checkpoints VALUES (?, ?, ?, ?, ?)",
                    (seq, at, digest, self.keys.key_id, signature))
        return {"seq": seq, "hash": digest, "at": at, "key_id": self.keys.key_id, "signature": signature,
                "fingerprint": anchor_fingerprint(seq, digest, at)}

    def checkpoint(self) -> dict[str, Any] | None:
        """Sign the head now if it is not signed yet (at shutdown, before an export)."""
        with closing(self._connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                head = con.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
                last = con.execute("SELECT seq FROM checkpoints ORDER BY seq DESC LIMIT 1").fetchone()
                result = None
                if head and (last is None or last[0] < head[0]):
                    result = self._sign(con, head[0], head[1], _utc(self.clock()))
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
        return result

    def probe(self) -> bool:
        """Check the ledger can be written again after a failure."""
        try:
            with closing(self._connect()) as con:
                con.execute("BEGIN IMMEDIATE")
                con.execute("ROLLBACK")
        except sqlite3.Error:
            self.broken = True
            return False
        self.broken = False
        return True

    # Reading ----------------------------------------------------------------------------

    def head(self) -> tuple[int, str]:
        with closing(self._connect()) as con:
            row = con.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1]) if row else (0, GENESIS)

    def anchor(self) -> dict[str, Any] | None:
        with closing(self._connect()) as con:
            row = con.execute("SELECT seq, at, hash, key_id, signature FROM checkpoints ORDER BY seq DESC LIMIT 1"
                              ).fetchone()
        if row is None:
            return None
        seq, at, digest, key_id, signature = row
        return {"seq": seq, "hash": digest, "at": at, "key_id": key_id, "signature": signature,
                "fingerprint": anchor_fingerprint(seq, digest, at)}

    def records(self, *, after: int = 0, before: int | None = None, limit: int = 100, actor: str | None = None,
                action: str | None = None, target: str | None = None, session: str | None = None,
                since: str | None = None, until: str | None = None,
                where: Callable[[Record], bool] | None = None) -> list[Record]:
        """Newest first. ``action`` matches a prefix ("auth." finds every sign-in event)."""
        clauses, params = ["seq > ?"], [after]
        for column, value in (("actor", actor), ("target", target), ("session", session)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        if action:
            clauses.append("substr(action, 1, ?) = ?")
            params += [len(action), action]
        if since:
            clauses.append("at >= ?")
            params.append(since)
        if until:
            clauses.append("at <= ?")
            params.append(until)
        result: list[Record] = []
        cursor = before
        with closing(self._connect()) as con:
            while len(result) < limit:
                bound = ["seq < ?"] if cursor is not None else []
                rows = con.execute(
                    f"SELECT * FROM ledger WHERE {' AND '.join(clauses + bound)} ORDER BY seq DESC LIMIT 500",
                    params + ([cursor] if cursor is not None else [])).fetchall()
                if not rows:
                    break
                for row in rows:
                    record = _record(row)
                    if where is None or where(record):
                        result.append(record)
                        if len(result) >= limit:
                            break
                cursor = rows[-1][0]
        return result

    # Verification -----------------------------------------------------------------------

    def verify(self, since: int = 1, anchors: Iterable[dict[str, Any]] = ()) -> Verification:
        since = max(1, since)
        with closing(self._connect()) as con:
            if since == 1:
                prev = GENESIS
            else:
                row = con.execute("SELECT hash FROM ledger WHERE seq = ?", (since - 1,)).fetchone()
                if row is None:
                    return self._finish(since - 1, since, since - 1, "Record {} is missing.".format(since - 1))
                prev = row[0]
            checker = _Checker(prev, since, self._mac_key)
            for row in con.execute("SELECT * FROM ledger WHERE seq >= ? ORDER BY seq", (since,)):
                problem = checker.check(_record(row))
                if problem:
                    return self._finish(checker.expected - 1, since, *problem)
            total = checker.expected - 1
            checkpoints = [dict(zip(("seq", "at", "hash", "key_id", "signature"), row)) for row in
                           con.execute("SELECT seq, at, hash, key_id, signature FROM checkpoints ORDER BY seq")]

            def hashes(seq: int) -> str | None:
                found = con.execute("SELECT hash FROM ledger WHERE seq = ?", (seq,)).fetchone()
                return found[0] if found else None

            problem = (_check_signed(checkpoints, hashes, total, self.keys.public, "Checkpoint")
                       or _check_signed(list(anchors), hashes, total, self.keys.public, "Anchor"))
        if problem:
            return self._finish(total, since, *problem)
        return self._finish(total, since, None, f"All {total} records verified.")

    def _finish(self, total: int, since: int, first_bad: int | None, reason: str) -> Verification:
        result = Verification(ok=first_bad is None, records=total, checked_from=since, first_bad=first_bad,
                              reason=reason, last_checkpoint=self.anchor(), at=_utc(self.clock()),
                              key_fingerprint=self.keys.fingerprint)
        values = {"last_verification": json.dumps(result.to_json())}
        if result.ok:
            values["verified_seq"] = str(total)
            values["verified_hash"] = self.head()[1] if total else GENESIS
        with closing(self._connect()) as con:
            con.executemany("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", values.items())
        return result

    def _meta(self, key: str) -> str | None:
        with closing(self._connect()) as con:
            row = con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def verify_incremental(self) -> Verification:
        """Check records added since the last good run; a changed earlier record forces a full check."""
        seq, digest = self._meta("verified_seq"), self._meta("verified_hash")
        if not seq or not digest or int(seq) == 0:
            return self.verify()
        with closing(self._connect()) as con:
            row = con.execute("SELECT hash FROM ledger WHERE seq = ?", (int(seq),)).fetchone()
        if row is None or row[0] != digest:
            return self.verify()
        return self.verify(since=int(seq) + 1)

    def last_verification(self) -> dict[str, Any] | None:
        text = self._meta("last_verification")
        return json.loads(text) if text else None

    # Export -----------------------------------------------------------------------------

    def export(self, path: Path) -> int:
        """Write records, checkpoints, and the public key as JSON lines; returns the record count."""
        self.checkpoint()
        count = 0
        with closing(self._connect()) as con, Path(path).open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps({"type": "key", "key_id": self.keys.key_id,
                                     "pem": self.keys.public_pem().decode("ascii")}) + "\n")
            for row in con.execute("SELECT * FROM ledger ORDER BY seq"):
                record = _record(row)
                item = record.to_json()
                item.pop("mac")
                stream.write(json.dumps({"type": "record", **item}, ensure_ascii=False) + "\n")
                count += 1
            for row in con.execute("SELECT seq, at, hash, key_id, signature FROM checkpoints ORDER BY seq"):
                stream.write(json.dumps({"type": "checkpoint",
                                         **dict(zip(("seq", "at", "hash", "key_id", "signature"), row))}) + "\n")
        return count


def verify_export(path: Path, anchors: Iterable[dict[str, Any]] = ()) -> Verification:
    """Check an exported ledger on any machine, using only the public key inside it."""
    now = _utc(time.time())
    key, records, checkpoints = None, [], []
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            kind = item.pop("type", None)
            if kind == "key":
                key = item
            elif kind == "record":
                records.append(Record(mac="", **item))
            elif kind == "checkpoint":
                checkpoints.append(item)
    except (OSError, ValueError, TypeError) as exc:
        return Verification(False, 0, 1, 1, f"Cannot read the export: {exc}", None, now)
    if key is None:
        return Verification(False, len(records), 1, 1, "The export has no public key.", None, now)
    public = load_public_key(key["pem"].encode("ascii"))
    fingerprint = group(key["key_id"])
    checker = _Checker(GENESIS, 1, None)
    for record in sorted(records, key=lambda item: item.seq):
        problem = checker.check(record)
        if problem:
            return Verification(False, len(records), 1, problem[0], problem[1], None, now, fingerprint)
    total = checker.expected - 1
    by_seq = {record.seq: record.hash for record in records}
    last = checkpoints[-1] if checkpoints else None
    problem = (_check_signed(checkpoints, by_seq.get, total, public, "Checkpoint")
               or _check_signed(list(anchors), by_seq.get, total, public, "Anchor"))
    if problem:
        return Verification(False, total, 1, problem[0], problem[1], last, now, fingerprint)
    return Verification(True, total, 1, None, f"All {total} records verified.", last, now, fingerprint)
