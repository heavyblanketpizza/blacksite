"""Ingest an incident's uploaded files into DuckDB and answer read-only queries over them.

An incident is a directory::

    incident.json               optional: {"id", "title", "description", "year"}
    artifacts/                  uploaded logs, configs, and pasted command output (read-only)
    evidence.<fingerprint>.duckdb   built here; a new one whenever artifacts change

Each index is named after the content it was built from and is never overwritten, so
readers in other processes (the MCP server, the web demo) are never disturbed by a
rebuild. Windows cannot replace a file that another process has open.

The model never reads files directly. Every query goes through this index, which holds
redacted text only.

A record that spans several lines (a stack trace after an error line) is folded: its first
line carries the template, and its later lines carry the record's time and level but no
template, so patterns and the timeline count records while search still finds every line.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import os
import tempfile
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import duckdb

from .._fs import remove_quietly, replace
from ..config import EvidenceSettings
from .kinds import classify, summarize
from .parse import SEVERITIES, SEVERITY_RANK, TRACEBACK_PREAMBLE, LineParser, RecordFolder, parse_time_filter
from .patterns import TemplateMiner
from .safety import RULES_VERSION, Redactor, looks_like_instructions

SCHEMA_VERSION = 3
ARTIFACTS_DIR = "artifacts"
INCIDENT_FILE = "incident.json"
DB_PREFIX = "evidence."
DB_SUFFIX = ".duckdb"
_SNIFF = 65536  # bytes read first: a binary check and the sample that decides a file's kind
MAX_OUTPUT_LINES = 5000  # of command output kept for its facts
# Separates a folded record's first line from its exception line in a template.
DETAIL_SEPARATOR = "⏎"

# ``rec`` is the ord of the line that starts the record; ``detail`` is a folded record's
# first unindented continuation line, usually the exception.
_LINE_COLUMNS = {
    "ord": "BIGINT", "file": "VARCHAR", "line_no": "BIGINT", "ts": "TIMESTAMP", "sev": "TINYINT",
    "guessed": "BOOLEAN", "template_id": "INTEGER", "flagged": "BOOLEAN", "text": "VARCHAR",
    "rec": "BIGINT", "detail": "VARCHAR",
}
_LINE_SELECT = "file, line_no, ts, sev, guessed, flagged, coalesce(text, ''), rec <> ord, detail"


class EvidenceError(ValueError):
    """A query the model can correct: unknown file, bad regex, unreadable time."""


@dataclass(frozen=True)
class Incident:
    root: Path
    id: str
    title: str
    description: str
    year: int | None

    @classmethod
    def load(cls, root: Path) -> Incident:
        root = Path(root)
        data: dict[str, Any] = {}
        path = root / INCIDENT_FILE
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError as exc:
                raise EvidenceError(f"{path} is not valid JSON: {exc}") from None
            if not isinstance(data, dict):
                raise EvidenceError(f"{path} must contain a JSON object")
        year = data.get("year")
        return cls(
            root=root,
            id=str(data.get("id") or root.name),
            title=str(data.get("title") or ""),
            description=str(data.get("description") or ""),
            year=year if isinstance(year, int) and not isinstance(year, bool) else None,
        )


@dataclass(frozen=True)
class ArtifactInfo:
    file: str
    kind: str  # log, config, output, or binary
    compressed: bool
    bytes: int
    lines: int
    first_ts: datetime | None
    last_ts: datetime | None
    errors: int
    redactions: int
    flagged: int
    tools: tuple[str, ...]  # the commands an output file came from
    facts: tuple[str, ...]  # what that output states


@dataclass(frozen=True)
class Pattern:
    id: int
    template: str
    count: int
    level: str | None
    guessed: bool
    first_ts: datetime | None
    last_ts: datetime | None
    files: list[str]
    sample_file: str
    sample_line: int


@dataclass(frozen=True)
class LogLine:
    file: str
    line_no: int
    ts: datetime | None
    level: str | None
    guessed: bool
    flagged: bool
    text: str
    cont: bool  # continues the record above; the time and level are that record's
    detail: str | None


@dataclass(frozen=True)
class Event:
    first_ts: datetime
    last_ts: datetime
    count: int
    level: str | None
    guessed: bool
    file: str
    line_no: int
    text: str
    detail: str | None


@dataclass(frozen=True)
class Change:
    """How often a pattern occurred in a window and in the baseline it is compared with."""

    template: str
    level: str | None
    guessed: bool
    files: list[str]
    sample_file: str
    sample_line: int
    window_count: int
    baseline_count: int
    window_rate: float  # per minute
    baseline_rate: float


@dataclass(frozen=True)
class Comparison:
    window: tuple[datetime, datetime]
    baseline: tuple[datetime, datetime] | None  # None when nothing precedes the window
    new: list[Change]  # in the window, never in the baseline
    rising: list[Change]  # much more frequent per minute than in the baseline
    stopped: list[Change]  # frequent in the baseline, absent from the window


class Evidence:
    """Read-only access to one incident's evidence; safe to share between threads."""

    def __init__(self, root: Path | str, settings: EvidenceSettings | None = None) -> None:
        self.root = Path(root)
        self.settings = settings or EvidenceSettings()
        self.incident = Incident.load(self.root)
        self._lock = threading.RLock()
        self._con: duckdb.DuckDBPyConnection | None = None
        self._open_path: Path | None = None
        if not (self.root / ARTIFACTS_DIR).is_dir():
            raise EvidenceError(f"No {ARTIFACTS_DIR}/ directory in {self.root}")

    @property
    def db_path(self) -> Path | None:
        """The index currently open, if any."""
        return self._open_path

    def refresh(self) -> bool:
        """Re-ingest if files were added or changed since the index was built.

        Call before answering each request so pasted command output is picked up.
        Returns True when it re-ingested.
        """
        with self._lock:
            target = self.root / f"{DB_PREFIX}{self._fingerprint()[:16]}{DB_SUFFIX}"
            if self._con is not None and self._open_path == target:
                return False
            self.close()
            built = False
            if not target.exists():
                self.incident = Incident.load(self.root)
                _Ingest(self, target).run()
                built = True
            try:
                self._open(target)
            except duckdb.Error:
                if built:
                    raise
                remove_quietly(target)  # a damaged index from an interrupted build
                _Ingest(self, target).run()
                self._open(target)
                built = True
            self.incident = Incident.load(self.root)
            for stale in self.root.glob(f"{DB_PREFIX}*{DB_SUFFIX}"):
                if stale != target:
                    remove_quietly(stale)
            return built

    def close(self) -> None:
        with self._lock:
            if self._con is not None:
                self._con.close()
                self._con = None
                self._open_path = None

    def __enter__(self) -> Evidence:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # Queries -------------------------------------------------------------------------

    def artifacts(self) -> list[ArtifactInfo]:
        rows = self._query(
            "SELECT file, kind, compressed, bytes, lines, first_ts, last_ts, errors, redactions, flagged, tools, facts "
            "FROM artifacts ORDER BY file"
        )
        return [ArtifactInfo(file, kind, compressed, size, lines, first, last, errors, redactions, flagged,
                             tuple(tools.split(",")) if tools else (), tuple(json.loads(facts)))
                for file, kind, compressed, size, lines, first, last, errors, redactions, flagged, tools, facts in rows]

    def time_range(self) -> tuple[datetime | None, datetime | None]:
        return self._query("SELECT min(ts), max(ts) FROM lines")[0]

    def pattern_count(self, file: str | None = None, level: str | None = None,
                      since: str | None = None, until: str | None = None) -> int:
        where, params = self._filters(file, level, since, until)
        return self._query(f"SELECT count(DISTINCT template_id) FROM lines WHERE {where}", params)[0][0]

    def patterns(self, file: str | None = None, level: str | None = None, since: str | None = None,
                 until: str | None = None, top: int = 30) -> list[Pattern]:
        where, params = self._filters(file, level, since, until, alias="l.")
        rows = self._query(
            "SELECT l.template_id, t.template, count(*) AS n, max(l.sev) AS max_sev, "
            "coalesce(bool_and(l.guessed) FILTER (WHERE l.sev IS NOT NULL), false), "
            "min(l.ts), max(l.ts), list(DISTINCT l.file ORDER BY l.file), "
            "arg_min(l.file, l.ord), arg_min(l.line_no, l.ord) "
            f"FROM lines l JOIN templates t ON t.id = l.template_id WHERE {where} "
            "GROUP BY l.template_id, t.template ORDER BY max_sev DESC NULLS LAST, n DESC, l.template_id LIMIT ?",
            [*params, top],
        )
        return [
            Pattern(row[0], row[1], row[2], _level(row[3]), row[4], row[5], row[6], row[7], row[8], row[9])
            for row in rows
        ]

    def search(self, pattern: str, file: str | None = None, level: str | None = None,
               since: str | None = None, until: str | None = None, limit: int = 50,
               ignore_case: bool = True, literal: bool = False,
               flagged_only: bool = False) -> tuple[list[LogLine], int]:
        if not pattern:
            raise EvidenceError("pattern is empty")
        where, params = self._filters(file, level, since, until)
        if literal:
            match = ("contains(lower(coalesce(text, '')), lower(?))" if ignore_case
                     else "contains(coalesce(text, ''), ?)")
        else:
            match = "regexp_matches(coalesce(text, ''), ?)"
            pattern = f"(?i){pattern}" if ignore_case else pattern
        where = f"{where} AND {match}" + (" AND flagged" if flagged_only else "")
        params = [*params, pattern]
        try:
            total = self._query(f"SELECT count(*) FROM lines WHERE {where}", params)[0][0]
            rows = self._query(f"SELECT {_LINE_SELECT} FROM lines WHERE {where} ORDER BY ord LIMIT ?", [*params, limit])
        except duckdb.InvalidInputException as exc:
            raise EvidenceError(
                f"Invalid RE2 regular expression ({_first_line(exc)}). "
                "Escape special characters, or set literal=true to search for plain text."
            ) from None
        return [_log_line(row) for row in rows], total

    def read_lines(self, file: str, start: int, end: int) -> list[LogLine]:
        self._require_file(file)
        rows = self._query(
            f"SELECT {_LINE_SELECT} FROM lines WHERE file = ? AND line_no BETWEEN ? AND ? ORDER BY line_no",
            [file, start, end],
        )
        return [_log_line(row) for row in rows]

    def line_count(self, file: str) -> int:
        self._require_file(file)
        return self._query("SELECT lines FROM artifacts WHERE file = ?", [file])[0][0]

    def timeline(self, since: str | None = None, until: str | None = None, level: str = "warning",
                 limit: int = 60, gap_seconds: int = 60) -> tuple[list[Event], int]:
        """Dated events in time order; repeats of a pattern less than ``gap_seconds`` apart merge."""
        where, params = self._filters(None, level, since, until)
        runs = (
            "WITH base AS (SELECT *, CASE WHEN lag(ts) OVER w IS NULL "
            "OR ts - lag(ts) OVER w > to_seconds(CAST(? AS DOUBLE)) THEN 1 ELSE 0 END AS starts "
            f"FROM lines WHERE ts IS NOT NULL AND template_id IS NOT NULL AND {where} "
            "WINDOW w AS (PARTITION BY template_id ORDER BY ts, ord)), "
            "runs AS (SELECT *, sum(starts) OVER (PARTITION BY template_id ORDER BY ts, ord "
            "ROWS UNBOUNDED PRECEDING) AS run FROM base) "
            "SELECT min(ts) AS first_ts, max(ts), count(*), max(sev), "
            "coalesce(bool_and(guessed) FILTER (WHERE sev IS NOT NULL), false), "
            "arg_min(file, ord), arg_min(line_no, ord), arg_min(coalesce(text, ''), ord), arg_min(detail, ord), "
            "min(ord) AS first_ord FROM runs GROUP BY template_id, run"
        )
        run_params = [gap_seconds, *params]
        total = self._query(f"SELECT count(*) FROM ({runs})", run_params)[0][0]
        rows = self._query(f"{runs} ORDER BY first_ts, first_ord LIMIT ?", [*run_params, limit])
        events = [Event(row[0], row[1], row[2], _level(row[3]), row[4], row[5], row[6], row[7], row[8]) for row in rows]
        return events, total

    def compare(self, since: str, until: str, baseline_since: str | None = None, baseline_until: str | None = None,
                file: str | None = None, level: str | None = None, top: int = 15) -> Comparison:
        """Patterns that are new, much more frequent, or gone in a window, against a baseline.

        The baseline is the time before the window unless one is given. Rates are per
        minute, so windows of different lengths compare.
        """
        first, last = self.time_range()
        if first is None or last is None:
            raise EvidenceError("No line has a timestamp, so there is nothing to compare")
        try:
            start, end = parse_time_filter(since, first, last), parse_time_filter(until, first, last, end=True)
            base_start = parse_time_filter(baseline_since, first, last) if baseline_since else first
            base_end = start
            if baseline_until:
                base_end = parse_time_filter(baseline_until, first, last, end=True) + timedelta(microseconds=1)
        except ValueError as exc:
            raise EvidenceError(str(exc)) from None
        if end < start:
            raise EvidenceError("until must be at or after since")
        where, params = self._filters(file, level, None, None)
        group = ("template_id, count(*) AS n, max(sev) AS sev, "
                 "coalesce(bool_and(guessed) FILTER (WHERE sev IS NOT NULL), false) AS guessed, "
                 "list(DISTINCT file ORDER BY file) AS files, arg_min(file, ord) AS sample_file, "
                 "arg_min(line_no, ord) AS sample_line")
        rows = self._query(
            f"WITH w AS (SELECT {group} FROM lines WHERE template_id IS NOT NULL AND ts BETWEEN ? AND ? AND {where} "
            "GROUP BY template_id), "
            f"b AS (SELECT {group} FROM lines WHERE template_id IS NOT NULL AND ts >= ? AND ts < ? AND {where} "
            "GROUP BY template_id) "
            "SELECT t.template, coalesce(w.n, 0), coalesce(b.n, 0), coalesce(w.sev, b.sev), "
            "coalesce(w.guessed, b.guessed), coalesce(w.files, b.files), coalesce(w.sample_file, b.sample_file), "
            "coalesce(w.sample_line, b.sample_line) FROM templates t "
            "LEFT JOIN w ON w.template_id = t.id LEFT JOIN b ON b.template_id = t.id "
            "WHERE w.n IS NOT NULL OR b.n IS NOT NULL ORDER BY t.id",
            [start, end, *params, base_start, base_end, *params],
        )
        window_minutes = max((end - start).total_seconds() / 60, 1 / 60)
        baseline_minutes = (base_end - base_start).total_seconds() / 60
        new, rising, stopped = [], [], []
        for template, in_window, in_baseline, sev, guessed, files, sample_file, sample_line in rows:
            window_rate = in_window / window_minutes
            baseline_rate = in_baseline / baseline_minutes if baseline_minutes > 0 else 0.0
            change = Change(template, _level(sev), guessed, list(files), sample_file, sample_line, in_window,
                            in_baseline, window_rate, baseline_rate)
            if in_window and not in_baseline:
                new.append(change)
            elif in_window >= 2 and window_rate >= 3 * baseline_rate:
                rising.append(change)
            elif not in_window and baseline_rate * window_minutes >= 3:
                stopped.append(change)
        new.sort(key=lambda change: (-change.window_count, change.template))
        rising.sort(key=lambda change: (-change.window_rate / change.baseline_rate, change.template))
        stopped.sort(key=lambda change: (-change.baseline_rate, change.template))
        baseline = (base_start, base_end) if baseline_minutes > 0 else None
        return Comparison((start, end), baseline, new[:top], rising[:top], stopped[:top])

    def histogram(self, level: str = "warning",
                  buckets: int = 60) -> tuple[datetime | None, int, list[tuple[int, str, int]]]:
        """Counts of dated lines at ``level`` or worse per time bucket and file.

        Returns (start, bucket_seconds, [(bucket_index, file, count)]).
        """
        first, last = self.time_range()
        if first is None or last is None:
            return None, 0, []
        span = max((last - first).total_seconds(), 1)
        size = max(10, int(-(-span // buckets) + 9) // 10 * 10)
        rows = self._query(
            "SELECT CAST(floor((epoch(ts) - epoch(CAST(? AS TIMESTAMP))) / ?) AS INTEGER) AS bucket, file, count(*) "
            "FROM lines WHERE ts IS NOT NULL AND template_id IS NOT NULL AND sev >= ? "
            "GROUP BY bucket, file ORDER BY bucket, file",
            [first, size, SEVERITY_RANK[level]],
        )
        return first, size, [(row[0], row[1], row[2]) for row in rows]

    def signature(self, top: int = 12) -> list[str]:
        """The most frequent warning-or-worse templates: this incident's fingerprint."""
        rows = self._query(
            "SELECT t.template FROM lines l JOIN templates t ON t.id = l.template_id "
            "WHERE l.sev >= ? GROUP BY t.id, t.template ORDER BY count(*) DESC, t.id LIMIT ?",
            [SEVERITY_RANK["warning"], top],
        )
        return [row[0] for row in rows]

    # Internals -----------------------------------------------------------------------

    def _query(self, sql: str, params: list[Any] | None = None) -> list[tuple[Any, ...]]:
        with self._lock:
            if self._con is None:
                self.refresh()
            assert self._con is not None
            return self._con.execute(sql, params or []).fetchall()

    def _filters(self, file: str | None, level: str | None, since: str | None, until: str | None,
                 alias: str = "") -> tuple[str, list[Any]]:
        clauses: list[str] = ["true"]
        params: list[Any] = []
        if file:
            self._require_file(file)
            clauses.append(f"{alias}file = ?")
            params.append(file)
        if level:
            if level not in SEVERITY_RANK:
                raise EvidenceError(f"level must be one of {', '.join(SEVERITIES)}")
            clauses.append(f"{alias}sev >= ?")
            params.append(SEVERITY_RANK[level])
        if since or until:
            first, last = self.time_range()
            try:
                if since:
                    clauses.append(f"{alias}ts >= ?")
                    params.append(parse_time_filter(since, first, last))
                if until:
                    clauses.append(f"{alias}ts <= ?")
                    params.append(parse_time_filter(until, first, last, end=True))
            except ValueError as exc:
                raise EvidenceError(str(exc)) from None
        return " AND ".join(clauses), params

    def _require_file(self, file: str) -> None:
        known = [row[0] for row in self._query("SELECT file FROM artifacts ORDER BY file")]
        if file not in known:
            raise EvidenceError(f"Unknown file {file!r}. Files: {', '.join(known) or 'none'}")

    def _open(self, path: Path) -> None:
        self._con = duckdb.connect(str(path), read_only=True)
        self._open_path = path

    def _fingerprint(self) -> str:
        digest = hashlib.sha256()
        settings = (SCHEMA_VERSION, RULES_VERSION, self.settings.redact, self.settings.max_line_chars)
        digest.update(repr(settings).encode())
        incident_file = self.root / INCIDENT_FILE
        if incident_file.is_file():
            digest.update(incident_file.read_bytes())
        for path, relative in artifact_files(self.root / ARTIFACTS_DIR):
            stat = path.stat()
            digest.update(f"{relative}\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode())
        return digest.hexdigest()


@dataclass
class _Record:
    """One log record as its lines are read: the first line and any continuation lines."""

    line_no: int
    text: str
    ts: datetime | None
    level: str | None
    guessed: bool
    message: str
    flagged: bool
    continuations: list[tuple[int, str, bool]] = field(default_factory=list)
    detail: str | None = None

    def add(self, line_no: int, text: str, flagged: bool) -> None:
        self.continuations.append((line_no, text, flagged))
        if self.detail is None and not text[0].isspace() and not TRACEBACK_PREAMBLE.match(text):
            self.detail = text


class _Ingest:
    def __init__(self, evidence: Evidence, target: Path) -> None:
        self.evidence = evidence
        self.settings = evidence.settings
        self.target = target
        self.miner = TemplateMiner()
        self.ord = 0

    def run(self) -> None:
        root = self.evidence.root
        artifacts: list[tuple[Any, ...]] = []
        tmp_db = root / f".evidence.{os.getpid()}.{threading.get_ident()}.tmp"
        remove_quietly(tmp_db)
        with tempfile.TemporaryDirectory(prefix="blacksite-ingest-") as scratch:
            lines_csv = Path(scratch) / "lines.csv"
            with lines_csv.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                for path, relative in artifact_files(root / ARTIFACTS_DIR):
                    artifacts.append(self._ingest_file(path, relative, writer))
            templates_csv = Path(scratch) / "templates.csv"
            with templates_csv.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                for cluster_id, cluster in enumerate(self.miner.clusters):
                    writer.writerow([cluster_id, cluster.template])

            con = duckdb.connect(str(tmp_db))
            try:
                con.execute(
                    f"CREATE TABLE lines AS SELECT * FROM read_csv(?, {_csv_options(_LINE_COLUMNS)})",
                    [str(lines_csv)],
                )
                con.execute(
                    "CREATE TABLE templates AS SELECT * FROM read_csv(?, "
                    f"{_csv_options({'id': 'INTEGER', 'template': 'VARCHAR'})})",
                    [str(templates_csv)],
                )
                con.execute(
                    "CREATE TABLE artifacts (file VARCHAR, kind VARCHAR, compressed BOOLEAN, bytes BIGINT, "
                    "lines BIGINT, first_ts TIMESTAMP, last_ts TIMESTAMP, errors BIGINT, redactions BIGINT, "
                    "flagged BIGINT, tools VARCHAR, facts VARCHAR)"
                )
                if artifacts:
                    con.executemany("INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", artifacts)
                con.execute("CREATE TABLE meta (key VARCHAR, value VARCHAR)")
                con.executemany(
                    "INSERT INTO meta VALUES (?, ?)",
                    [["index", self.target.name], ["schema", str(SCHEMA_VERSION)],
                     ["ingested_at", datetime.now(UTC).isoformat(timespec="seconds")]],
                )
            finally:
                con.close()
        if self.target.exists():
            remove_quietly(tmp_db)  # another process built the same index meanwhile
        else:
            replace(tmp_db, self.target)

    def _ingest_file(self, path: Path, relative: str, writer: Any) -> tuple[Any, ...]:
        size = path.stat().st_size
        compressed = path.suffix == ".gz"
        opener = gzip.open if compressed else open
        with opener(path, "rb") as handle:
            head = handle.read(_SNIFF)
        if b"\0" in head:
            return (relative, "binary", compressed, size, 0, None, None, 0, 0, 0, "", "[]")
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).replace(tzinfo=None)
        parser = LineParser(year=self.evidence.incident.year or mtime.year,
                            latest=None if self.evidence.incident.year else mtime)
        sample = head.decode("utf-8", errors="replace").splitlines()
        kind = classify(relative, sample[:-1] if len(head) == _SNIFF else sample, parser)
        redactor = Redactor()
        folder = RecordFolder()
        count = errors = redactions = flagged = 0
        first = last = None
        limit = self.settings.max_line_chars
        record: _Record | None = None
        kept: list[str] = []  # command output, for its facts
        with opener(path, "rb") as handle:
            for count, raw in enumerate(handle, 1):
                text = raw.decode("utf-8", errors="replace").rstrip("\r\n").replace("\r", " ").replace("\0", "")
                if len(text) > limit:
                    text = text[:limit] + f" …[{len(text) - limit} more chars]"
                if self.settings.redact:
                    text, found = redactor.redact(text)
                    redactions += found
                suspicious = looks_like_instructions(text)
                flagged += suspicious
                if kind != "log":  # verbatim: no time, level, or template
                    writer.writerow([self.ord, relative, count, "", "", False, "", suspicious, text, self.ord, ""])
                    self.ord += 1
                    if kind == "output" and len(kept) < MAX_OUTPUT_LINES:
                        kept.append(text)
                    continue
                parsed = parser.parse(text)
                if folder.feed(text, parsed.ts is not None) and record is not None:
                    record.add(count, text, suspicious)
                    continue
                errors += self._write(writer, relative, record)
                record = _Record(count, text, parsed.ts, parsed.level, parsed.level_guessed, parsed.message, suspicious)
                if parsed.ts:
                    first = parsed.ts if first is None or parsed.ts < first else first
                    last = parsed.ts if last is None or parsed.ts > last else last
            errors += self._write(writer, relative, record)
        tools, facts = summarize(kept) if kind == "output" else ([], [])
        return (relative, kind, compressed, size, count, first, last, errors, redactions, flagged, ",".join(tools),
                json.dumps(facts))

    def _write(self, writer: Any, relative: str, record: _Record | None) -> int:
        """Write a record's rows: the first line with its template, then any continuation lines.

        Returns 1 when the record is an error or worse, so files count records, not lines.
        """
        if record is None:
            return 0
        message = record.message if record.detail is None else f"{record.message} {DETAIL_SEPARATOR} {record.detail}"
        template = self.miner.add(message, record.level or "")
        ts = record.ts.isoformat(sep=" ") if record.ts else ""
        rank = SEVERITY_RANK[record.level] if record.level else None
        sev = "" if rank is None else rank
        head = self.ord
        writer.writerow([head, relative, record.line_no, ts, sev, record.guessed, template, record.flagged,
                         record.text, head, record.detail or ""])
        for offset, (line_no, text, flagged) in enumerate(record.continuations, 1):
            writer.writerow([head + offset, relative, line_no, ts, sev, record.guessed, "", flagged, text, head, ""])
        self.ord = head + len(record.continuations) + 1
        return int(rank is not None and rank >= SEVERITY_RANK["error"])


def artifact_files(directory: Path) -> Iterator[tuple[Path, str]]:
    """Regular, non-hidden files under ``directory``; symlinks are never followed."""
    base = directory.resolve()
    for current, dirs, files in os.walk(directory, followlinks=False):
        dirs[:] = sorted(name for name in dirs if not name.startswith("."))
        for name in sorted(files):
            path = Path(current) / name
            if name.startswith(".") or path.is_symlink() or not path.is_file():
                continue
            if not path.resolve().is_relative_to(base):
                continue
            yield path, path.relative_to(directory).as_posix()


def _csv_options(columns: dict[str, str]) -> str:
    spec = ", ".join(f"'{name}': '{kind}'" for name, kind in columns.items())
    return f"header=false, auto_detect=false, delim=',', quote='\"', escape='\"', nullstr='', columns={{{spec}}}"


def _level(sev: int | None) -> str | None:
    return None if sev is None else SEVERITIES[sev]


def _log_line(row: tuple[Any, ...]) -> LogLine:
    return LogLine(row[0], row[1], row[2], _level(row[3]), row[4], row[5], row[6], row[7], row[8])


def _first_line(exc: Exception) -> str:
    return str(exc).splitlines()[0].removeprefix("Invalid Input Error: ")
