"""Timestamps, severity, and message text for common server log formats, and the folding of
multi-line records (stack traces, tracebacks, indented detail) into the line that started them."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

SEVERITIES = ("debug", "info", "warning", "error", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1
    )
}
_LEVEL_NAMES = {
    "emerg": "critical", "emergency": "critical", "alert": "critical", "crit": "critical",
    "critical": "critical", "fatal": "critical", "panic": "critical", "severe": "critical",
    "error": "error", "err": "error",
    "warn": "warning", "warning": "warning",
    "notice": "info", "info": "info", "information": "info",
    "debug": "debug", "trace": "debug", "verbose": "debug",
}

_ISO = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})(?:[.,](?P<frac>\d{1,9}))?"
    r"\s?(?P<tz>Z|UTC|GMT|[+-]\d{2}:?\d{2}\b)?"
)
_SLASH = re.compile(r"(?P<y>\d{4})/(?P<m>\d{2})/(?P<d>\d{2}) (?P<time>\d{2}:\d{2}:\d{2})")
_CLF = re.compile(
    r"\[(?P<d>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<y>\d{4}):(?P<time>\d{2}:\d{2}:\d{2}) (?P<tz>[+-]\d{4})\]"
)
# Syslog and journalctl (short-precise adds microseconds): Oct 21 02:14:06.123456 web1 app[12]:
_SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<d>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,6}))? "
                     r"(?P<host>\S+) ")
# Apache error logs and `dmesg -T`: [Tue Oct 21 02:14:05.123456 2026]
_CTIME = re.compile(r"[A-Z][a-z]{2} (?P<mon>[A-Z][a-z]{2}) {1,2}(?P<d>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})"
                    r"(?:\.(?P<frac>\d{1,6}))? (?P<y>\d{4})")
# Kubernetes components (klog): I1021 02:14:05.123456       1 main.go:42] started
_KLOG = re.compile(r"^(?P<lvl>[IWEF])(?P<m>\d{2})(?P<d>\d{2}) (?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,6}))?"
                   r"\s+\d+\s+[\w./-]+:\d+\] ")
_KLOG_LEVELS = {"I": "info", "W": "warning", "E": "error", "F": "critical"}
_LEADING = (_ISO, _SLASH, _CTIME, _CLF)  # tried at the start of the line first
_ANYWHERE = (_ISO, _CLF, _CTIME, _SLASH)  # then anywhere in the first characters
_TS_SEARCH_WINDOW = 80

_LEVEL_WORD = re.compile(
    r"\b(EMERG(?:ENCY)?|ALERT|CRIT(?:ICAL)?|FATAL|SEVERE|PANIC|ERROR|ERR|WARN(?:ING)?|NOTICE|INFO|DEBUG|TRACE)\b"
)
_LEVEL_BRACKET = re.compile(r"\[(?:[a-z_]+:)?(emerg|alert|crit|error|warn|notice|info|debug)\]")
_LEVEL_KV = re.compile(r"(?i)\b(?:level|severity|lvl)[=:]\s*\"?(\w+)")
_LEVEL_WINDOW = 120
_HTTP_STATUS = re.compile(r'"[A-Z]+ \S+ HTTP/[\d.]+" (?P<status>[1-5]\d\d) ')
_ERROR_WORDS = re.compile(
    r"(?i)\b(out of memory|oom[-_ ]?kill\w*|killed process|segfault|kernel panic|traceback|exception|"
    r"fatal|failed|failure|refused|denied|timed? ?out|unable to|cannot|can't|no space left|"
    r"status=\d+/\w+|code=(?:killed|dumped|exited))\b"
)
_WARNING_WORDS = re.compile(r"(?i)\b(warn\w*|deprecated|retry\w*|degraded|slow)\b")

# The last entries are journalctl's JSON export.
_JSON_TIME_KEYS = ("ts", "time", "timestamp", "@timestamp", "t", "datetime", "__REALTIME_TIMESTAMP")
_JSON_LEVEL_KEYS = ("level", "severity", "lvl", "levelname", "log.level", "PRIORITY")
_JSON_MESSAGE_KEYS = ("msg", "message", "event", "log", "MESSAGE")
_SYSLOG_PRIORITIES = {0: "critical", 1: "critical", 2: "critical", 3: "error", 4: "warning", 5: "info", 6: "info",
                      7: "debug"}
# Bunyan/pino numeric levels: 10 trace ... 60 fatal.
_PINO_LEVELS = {10: "debug", 20: "debug", 30: "info", 40: "warning", 50: "error", 60: "critical"}

MAX_CONTINUATION = 1000
TRACEBACK_PREAMBLE = re.compile(r"^Traceback \(most recent call last\):")
# Java frames and chained causes, which are not indented.
_CONTINUATION = re.compile(r"^(?:at |Caused by: |Suppressed: |\.\.\. \d+ more\b)")


@dataclass(frozen=True, slots=True)
class ParsedLine:
    ts: datetime | None
    level: str | None
    level_guessed: bool
    message: str


class LineParser:
    """Parses one file's lines; ``year`` fills in year-less syslog timestamps."""

    def __init__(self, year: int, latest: datetime | None = None) -> None:
        self._year = year
        # Year-less dates later than this belong to the previous year (log spanning New Year).
        self._latest = latest

    def parse(self, text: str) -> ParsedLine:
        stripped = text.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            parsed = self._parse_json(stripped)
            if parsed is not None:
                return parsed
        match = _KLOG.match(text)
        if match:
            ts = self._yearless(int(match["m"]), int(match["d"]), match["time"], match["frac"])
            return ParsedLine(ts, _KLOG_LEVELS[match["lvl"]], False, text[match.end():])

        ts, message = self._timestamp(text)
        head = message[:_LEVEL_WINDOW]
        level = _explicit_level(head)
        guessed = False
        if level is None:
            status = _HTTP_STATUS.search(message)
            if status:
                code = int(status.group("status"))
                level = "error" if code >= 500 else "warning" if code >= 400 else "info"
            elif _ERROR_WORDS.search(message):
                level, guessed = "error", True
            elif _WARNING_WORDS.search(message):
                level, guessed = "warning", True
        return ParsedLine(ts, level, guessed, message)

    def _timestamp(self, text: str) -> tuple[datetime | None, str]:
        match = _SYSLOG.match(text)
        if match:
            month = _MONTHS.get(match["mon"].lower())
            if month:
                return self._yearless(month, int(match["d"]), match["time"], match["frac"]), text[match.end():]
        # Most formats put the time first; only when none does is the window searched.
        at = 1 if text[:1] == "[" else 0
        found = next((m for pattern in _LEADING if (m := pattern.match(text, at))), None)
        if found is None:
            window = text[:_TS_SEARCH_WINDOW]
            found = next((m for pattern in _ANYWHERE if (m := pattern.search(window))), None)
        if found is None:
            return None, text
        return self._convert(found), _cut(text, found)

    def _convert(self, match: re.Match[str]) -> datetime | None:
        pattern = match.re
        if pattern is _ISO:
            return _parse_iso(match)
        if pattern is _SLASH:
            return _safe_datetime(int(match["y"]), int(match["m"]), int(match["d"]), match["time"])
        month = _MONTHS.get(match["mon"].lower())
        if month is None:
            return None
        if pattern is _CTIME:
            return _safe_datetime(int(match["y"]), month, int(match["d"]), match["time"], match["frac"])
        ts = _safe_datetime(int(match["y"]), month, int(match["d"]), match["time"])
        return _apply_offset(ts, match["tz"]) if ts else None

    def _yearless(self, month: int, day: int, clock: str, frac: str | None) -> datetime | None:
        """A date without a year gets the file's; later than the file itself means the year before."""
        ts = _safe_datetime(self._year, month, day, clock, frac)
        if ts and self._latest and ts > self._latest + timedelta(days=1):
            ts = _safe_datetime(self._year - 1, month, day, clock, frac)
        return ts

    def _parse_json(self, text: str) -> ParsedLine | None:
        try:
            record = json.loads(text)
        except ValueError:
            return None
        if not isinstance(record, dict):
            return None
        ts = None
        for key in _JSON_TIME_KEYS:
            if key in record:
                ts = _json_time(record[key])
                if ts:
                    break
        level = None
        for key in _JSON_LEVEL_KEYS:
            value = record.get(key)
            if key == "PRIORITY" and str(value).isdigit():
                level = _SYSLOG_PRIORITIES.get(int(str(value)))
            elif isinstance(value, str):
                level = _LEVEL_NAMES.get(value.strip().lower())
            elif isinstance(value, int) and not isinstance(value, bool):
                level = _PINO_LEVELS.get(value)
            if level:
                break
        message = next(
            (str(record[key]) for key in _JSON_MESSAGE_KEYS if isinstance(record.get(key), (str, int, float))),
            text,
        )
        guessed = False
        if level is None and _ERROR_WORDS.search(message):
            level, guessed = "error", True
        return ParsedLine(ts, level, guessed, message)


def severity_at_least(level: str) -> list[str]:
    """Severity names at or above ``level``."""
    return list(SEVERITIES[SEVERITY_RANK[level]:])


def parse_time_filter(value: str, first: datetime | None, last: datetime | None, end: bool = False) -> datetime:
    """Parse a ``since``/``until`` value.

    A bare time is accepted when every dated line falls on one date. With ``end``, a
    value without seconds covers its whole minute (or day), so ``until`` is inclusive.
    """
    value = value.strip()
    layouts = [
        ("%Y-%m-%dT%H:%M:%S", timedelta()), ("%Y-%m-%d %H:%M:%S", timedelta()),
        ("%Y-%m-%dT%H:%M", timedelta(seconds=59)), ("%Y-%m-%d %H:%M", timedelta(seconds=59)),
        ("%Y-%m-%d", timedelta(days=1, microseconds=-1)),
    ]
    for layout, span in layouts:
        try:
            moment = datetime.strptime(value, layout)
        except ValueError:
            continue
        return moment + span if end else moment
    for layout, span in (("%H:%M:%S", timedelta()), ("%H:%M", timedelta(seconds=59))):
        try:
            clock = datetime.strptime(value, layout).time()
        except ValueError:
            continue
        if first is None or last is None:
            raise ValueError(f"'{value}' has no date and no line has a timestamp")
        # Use the one date on which this time falls inside the logs; ambiguous only if several do.
        days = [first.date() + timedelta(days=offset) for offset in range((last.date() - first.date()).days + 1)]
        inside = [day for day in days
                  if first - timedelta(minutes=1) <= datetime.combine(day, clock) <= last + timedelta(minutes=1)]
        if len(inside) > 1:
            raise ValueError(
                f"'{value}' has no date and occurs on {len(inside)} days in the logs ({first.date()} to "
                f"{last.date()}); use YYYY-MM-DD HH:MM"
            )
        moment = datetime.combine(inside[0] if inside else last.date(), clock)
        return moment + span if end else moment
    raise ValueError(f"Cannot read time '{value}'; use YYYY-MM-DD HH:MM[:SS]")


def _explicit_level(head: str) -> str | None:
    for pattern in (_LEVEL_BRACKET, _LEVEL_KV, _LEVEL_WORD):
        match = pattern.search(head)
        if match:
            level = _LEVEL_NAMES.get(match.group(1).lower())
            if level:
                return level
    return None


def _cut(text: str, match: re.Match[str]) -> str:
    """Remove the timestamp (and brackets around it) from the message used for templates."""
    start, end = match.span()
    if start > 0 and text[start - 1] == "[" and text[end:end + 1] == "]":
        start, end = start - 1, end + 1
    return (text[:start] + text[end:]).strip()


def _parse_iso(match: re.Match[str]) -> datetime | None:
    try:
        ts = datetime.fromisoformat(f"{match['date']}T{match['time']}")
    except ValueError:
        return None
    if match["frac"]:
        ts = ts.replace(microsecond=int(match["frac"][:6].ljust(6, "0")))
    if match["tz"]:
        ts = _apply_offset(ts, match["tz"])
    return ts


def _apply_offset(ts: datetime, tz: str) -> datetime:
    """Convert to naive UTC so lines from differently configured files sort together."""
    if tz in ("Z", "UTC", "GMT"):
        return ts
    sign = 1 if tz[0] == "+" else -1
    digits = tz[1:].replace(":", "")
    offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
    return ts - sign * offset


def _json_time(value: object) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, (int, float)):
        # Seconds, milliseconds, or microseconds (journalctl) since the epoch.
        seconds = value / 1_000_000 if value > 1e14 else value / 1000 if value > 1e11 else value
        try:
            return datetime.fromtimestamp(seconds, tz=UTC).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        match = _ISO.search(value)
        if match:
            return _parse_iso(match)
    return None


def _safe_datetime(year: int, month: int, day: int, clock: str, frac: str | None = None) -> datetime | None:
    try:
        hour, minute, second = (int(part) for part in clock.split(":"))
        return datetime(year, month, day, hour, minute, second, int(frac[:6].ljust(6, "0")) if frac else 0)
    except ValueError:
        return None


class RecordFolder:
    """Decides whether a line continues the record before it.

    A line without a timestamp of its own continues the previous record when that record
    started with a timestamp (a stack trace after a log line), when it is indented, when it
    is a Java frame or cause, or when it is the exception that ends a Python traceback.
    Blank lines always start a new record.
    """

    def __init__(self) -> None:
        self._timed = False      # the current record's first line carried a timestamp
        self._traceback = False  # the current record is a Python traceback whose last line is still to come
        self._indented = False   # the previous line of the current record was indented
        self._length = 0         # continuation lines in the current record

    def feed(self, text: str, timed: bool) -> bool:
        """True when ``text`` continues the current record; False when it starts a new one."""
        if not timed and text.strip() and self._length < MAX_CONTINUATION:
            indented = text[0].isspace()
            closing = self._traceback and self._indented and not indented
            if self._timed or indented or closing or _CONTINUATION.match(text):
                self._length += 1
                self._indented = indented
                if closing:
                    self._traceback = False
                return True
        self._timed = timed
        self._traceback = TRACEBACK_PREAMBLE.match(text) is not None
        self._indented = False
        self._length = 0
        return False
