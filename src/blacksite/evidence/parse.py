"""Timestamps, severity, and message text for common server log formats."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

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
    r"\s?(?P<tz>Z|[+-]\d{2}:?\d{2}\b)?"
)
_SLASH = re.compile(r"(?P<y>\d{4})/(?P<m>\d{2})/(?P<d>\d{2}) (?P<time>\d{2}:\d{2}:\d{2})")
_CLF = re.compile(
    r"\[(?P<d>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<y>\d{4}):(?P<time>\d{2}:\d{2}:\d{2}) (?P<tz>[+-]\d{4})\]"
)
_SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<d>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) ")
_TS_SEARCH_WINDOW = 80

_LEVEL_WORD = re.compile(
    r"\b(EMERG(?:ENCY)?|ALERT|CRIT(?:ICAL)?|FATAL|SEVERE|PANIC|ERROR|ERR|WARN(?:ING)?|NOTICE|INFO|DEBUG|TRACE)\b"
)
_LEVEL_BRACKET = re.compile(r"\[(emerg|alert|crit|error|warn|notice|info|debug)\]")
_LEVEL_KV = re.compile(r"(?i)\b(?:level|severity|lvl)[=:]\s*\"?(\w+)")
_LEVEL_WINDOW = 120
_HTTP_STATUS = re.compile(r'"[A-Z]+ \S+ HTTP/[\d.]+" (?P<status>[1-5]\d\d) ')
_ERROR_WORDS = re.compile(
    r"(?i)\b(out of memory|oom[-_ ]?kill\w*|killed process|segfault|kernel panic|traceback|exception|"
    r"fatal|failed|failure|refused|denied|timed? ?out|unable to|cannot|can't|no space left|"
    r"status=\d+/\w+|code=(?:killed|dumped|exited))\b"
)
_WARNING_WORDS = re.compile(r"(?i)\b(warn\w*|deprecated|retry\w*|degraded|slow)\b")

_JSON_TIME_KEYS = ("ts", "time", "timestamp", "@timestamp", "t", "datetime")
_JSON_LEVEL_KEYS = ("level", "severity", "lvl", "levelname", "log.level")
_JSON_MESSAGE_KEYS = ("msg", "message", "event", "log")


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
        window = text[:_TS_SEARCH_WINDOW]
        match = _SYSLOG.match(text)
        if match:
            month = _MONTHS.get(match["mon"].lower())
            if month:
                ts = _safe_datetime(self._year, month, int(match["d"]), match["time"])
                if ts and self._latest and ts > self._latest + timedelta(days=1):
                    ts = _safe_datetime(self._year - 1, month, int(match["d"]), match["time"])
                return ts, text[match.end():]
        match = _ISO.search(window)
        if match:
            ts = _parse_iso(match)
            return ts, _cut(text, match)
        match = _CLF.search(window)
        if match:
            month = _MONTHS.get(match["mon"].lower())
            ts = _safe_datetime(int(match["y"]), month, int(match["d"]), match["time"]) if month else None
            if ts:
                ts = _apply_offset(ts, match["tz"])
            return ts, _cut(text, match)
        match = _SLASH.search(window)
        if match:
            ts = _safe_datetime(int(match["y"]), int(match["m"]), int(match["d"]), match["time"])
            return ts, _cut(text, match)
        return None, text

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
            if isinstance(value, str):
                level = _LEVEL_NAMES.get(value.strip().lower())
            elif isinstance(value, int) and not isinstance(value, bool):
                # Bunyan/pino numeric levels: 10 trace ... 60 fatal.
                level = {10: "debug", 20: "debug", 30: "info", 40: "warning", 50: "error", 60: "critical"}.get(value)
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
    if tz == "Z":
        return ts
    sign = 1 if tz[0] == "+" else -1
    digits = tz[1:].replace(":", "")
    offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
    return ts - sign * offset


def _json_time(value: object) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        match = _ISO.search(value)
        if match:
            return _parse_iso(match)
    return None


def _safe_datetime(year: int, month: int, day: int, clock: str) -> datetime | None:
    try:
        hour, minute, second = (int(part) for part in clock.split(":"))
        return datetime(year, month, day, hour, minute, second)
    except ValueError:
        return None
