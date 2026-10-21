"""What an uploaded file is, and the facts a command's output states.

Logs are parsed line by line into timed, levelled records. Configuration files and
command output are kept verbatim: searched and read, never templated or given a
severity. Recognized command output (df, free, ps, ss, netstat, systemctl status,
uptime) is also summarized into a few facts that list_artifacts shows, so the agent
sees a full disk or a killed service before it searches for anything.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import PurePosixPath

from .parse import LineParser

KINDS = ("log", "config", "output", "binary")
SAMPLE_LINES = 60
HEADER_LINES = 5  # a command's header may follow a prompt line or two
MAX_ITEMS = 4

CONFIG_SUFFIXES = frozenset({
    ".cfg", ".cnf", ".conf", ".env", ".hcl", ".ini", ".mount", ".plist", ".properties", ".rules", ".service",
    ".socket", ".target", ".tf", ".timer", ".toml", ".xml", ".yaml", ".yml",
})
CONFIG_NAMES = frozenset({"dockerfile", "caddyfile", "makefile", "procfile", "vagrantfile", ".env"})

_HEADERS: dict[str, re.Pattern[str]] = {
    "df": re.compile(r"^Filesystem\s+.*Mounted on\s*$"),
    "free": re.compile(r"^\s+total\s+used\s+free\b"),
    "ps": re.compile(r"^\s*(?:USER\s+PID\s+%CPU\s+%MEM|UID\s+PID\s+PPID\s+C\s+STIME|PID\s+TTY\s+.*\bCMD\s*$)"),
    "ss": re.compile(r"^(?:Netid\s+)?State\s+Recv-Q\s+Send-Q\b"),
    "netstat": re.compile(r"^Proto\s+Recv-Q\s+Send-Q\s+Local Address"),
    "systemctl": re.compile(r"^[●○×*] \S+\.(?:service|socket|timer|mount|target|path)\b"),
    "uptime": re.compile(r"\bload average: "),
}
_COMMENT = re.compile(r"^\s*(?:#|;|//)")
_CONFIG_LINE = re.compile(
    r"^\s*(?:\[[^\]]+\]\s*$"           # [section]
    r"|[\w.\-\"'/$]+\s*[=:]\s*\S"     # key = value, key: value
    r"|\S.*[;{}]\s*$"                  # nginx and Apache directives and blocks
    r"|[{}]\s*$)"
)
_SIZE = re.compile(r"(\d+(?:\.\d+)?)([KMGTPE]?)i?B?")
_PROCESS = re.compile(r'\("([^"]+)",pid=(\d+)')
_UNIT = re.compile(r"^[●○×*] (\S+)")
_UNIT_FIELD = re.compile(r"^\s+(Loaded|Active|Main PID|Memory):\s*(.*)$")
_LOAD = re.compile(r"load average: ([\d.]+),\s*([\d.]+),\s*([\d.]+)")
_UP = re.compile(r"\bup (.+?),\s+\d+ users?,")


def classify(name: str, lines: Sequence[str], parser: LineParser) -> str:
    """The kind of a file, from its name and its first lines."""
    sample = [line for line in lines if line.strip()][:SAMPLE_LINES]
    if not sample:
        return "log"
    timed = [parser.parse(line).ts is not None for line in sample]
    first = zip(sample[:HEADER_LINES], timed[:HEADER_LINES], strict=True)
    if any(_is_header(line) for line, has_time in first if not has_time):
        return "output"
    json_lines = sum(line.lstrip().startswith("{") and line.rstrip().endswith("}") for line in sample)
    if sum(timed) * 5 >= len(sample) or json_lines * 2 >= len(sample):
        return "log"
    base = PurePosixPath(name).name.lower()
    suffix = PurePosixPath(base).suffix
    if suffix in CONFIG_SUFFIXES or base in CONFIG_NAMES or base.startswith("docker-compose"):
        return "config"
    if suffix == ".json":
        return "config"  # one document, since it is not one object per line
    body = [line for line in sample if not _COMMENT.match(line)]
    if body and sum(bool(_CONFIG_LINE.match(line)) for line in body) * 5 >= len(body) * 3:
        return "config"
    return "log"


def summarize(lines: Sequence[str]) -> tuple[list[str], list[str]]:
    """The commands whose output a file holds, and the facts that output states."""
    tools, facts = [], []
    for tool, parse in _PARSERS.items():
        found = parse(lines)
        if found is not None:
            tools.append(tool)
            facts.extend(found)
    return tools, facts


def _is_header(line: str) -> bool:
    return any(header.search(line) for header in _HEADERS.values())


def _section(lines: Sequence[str], tool: str) -> tuple[str, list[str]] | None:
    """A command's header line and the rows under it, up to a blank line or another header."""
    header = _HEADERS[tool]
    for index, line in enumerate(lines):
        if header.search(line):
            rows = []
            for row in lines[index + 1:]:
                if not row.strip() or _is_header(row):
                    break
                rows.append(row)
            return line, rows
    return None


def _size(token: str | None) -> float | None:
    match = _SIZE.fullmatch(token or "")
    if not match:
        return None
    return float(match.group(1)) * 1024 ** "BKMGTPE".index(match.group(2) or "B")


def _df(lines: Sequence[str]) -> list[str] | None:
    found = _section(lines, "df")
    if found is None:
        return None
    header, rows = found
    seen = []
    pending = ""
    for row in rows:
        parts = f"{pending} {row}".split() if pending else row.split()
        pending = ""
        if len(parts) == 1:
            pending = parts[0]  # a long device name wraps onto its own line
            continue
        if len(parts) < 6 or not parts[-2].endswith("%") or not parts[-2][:-1].isdigit():
            continue
        seen.append((int(parts[-2][:-1]), parts[-1], parts[-3]))
    if not seen:
        return []
    seen.sort(key=lambda item: (-item[0], item[1]))
    label = "inodes" if "IUse%" in header else "disk"
    return [f"{label}: " + "; ".join(f"{mount} {use}% used, {free} free" for use, mount, free in seen[:MAX_ITEMS])]


def _free(lines: Sequence[str]) -> list[str] | None:
    found = _section(lines, "free")
    if found is None:
        return None
    header, rows = found
    columns = header.split()
    parts = []
    for row in rows:
        fields = row.split()
        if len(fields) < 3 or not fields[0].endswith(":"):
            continue
        values = dict(zip(columns, fields[1:], strict=False))
        total = _size(values.get("total"))
        if not total:
            if fields[0].lower() == "swap:":
                parts.append("no swap")
            continue
        if fields[0].lower() == "mem:" and (available := _size(values.get("available"))) is not None:
            parts.append(f"memory {round(100 * (1 - available / total))}% used "
                         f"({values['available']} of {values['total']} available)")
        elif (used := _size(values.get("used"))) is not None:
            name = "memory" if fields[0].lower() == "mem:" else fields[0][:-1].lower()
            parts.append(f"{name} {round(100 * used / total)}% used ({values['used']} of {values['total']})")
    return ["; ".join(parts)] if parts else []


def _ps(lines: Sequence[str]) -> list[str] | None:
    found = _section(lines, "ps")
    if found is None:
        return None
    header, rows = found
    if header.split()[:4] != ["USER", "PID", "%CPU", "%MEM"]:
        return [f"{len(rows)} processes"]
    processes = []
    zombies = waiting = 0
    for row in rows:
        fields = row.split(maxsplit=10)  # USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
        if len(fields) < 11:
            continue
        try:
            cpu, memory = float(fields[2]), float(fields[3])
        except ValueError:
            continue
        zombies += fields[7].startswith("Z")
        waiting += fields[7].startswith("D")
        name = fields[10].split()[0].rsplit("/", 1)[-1].rstrip(":")[:30]
        processes.append((name, fields[1], cpu, memory))
    if not processes:
        return [f"{len(rows)} processes"]
    by_memory = sorted(processes, key=lambda item: -item[3])[:3]
    by_cpu = sorted(processes, key=lambda item: -item[2])[:3]
    count = f"{len(processes)} processes"
    if zombies:
        count += f", {zombies} zombie{'s' if zombies != 1 else ''}"
    if waiting:
        count += f", {waiting} in uninterruptible wait"
    return ["top memory: " + ", ".join(f"{name} {memory:.1f}% (pid {pid})" for name, pid, _, memory in by_memory),
            "top cpu: " + ", ".join(f"{name} {cpu:.1f}% (pid {pid})" for name, pid, cpu, _ in by_cpu), count]


def _ss(lines: Sequence[str]) -> list[str] | None:
    found = _section(lines, "ss")
    if found is None:
        return None
    header, rows = found
    offset = 1 if header.split()[0] == "Netid" else 0
    listening: list[str] = []
    states: Counter[str] = Counter()
    for row in rows:
        fields = row.split()
        if len(fields) < offset + 5:
            continue
        state, local = fields[offset], fields[offset + 3]
        if state == "LISTEN":
            process = _PROCESS.search(row)
            listening.append(f"{local} ({process.group(1)}, pid {process.group(2)})" if process else local)
        else:
            states[state] += 1
    return _sockets(listening, states)


def _netstat(lines: Sequence[str]) -> list[str] | None:
    found = _section(lines, "netstat")
    if found is None:
        return None
    listening: list[str] = []
    states: Counter[str] = Counter()
    for row in found[1]:
        fields = row.split()
        if len(fields) < 5 or not fields[0].startswith(("tcp", "udp")):
            continue
        state = fields[5] if len(fields) > 5 and fields[5].isupper() else ""
        program = fields[-1] if "/" in fields[-1] and fields[-1][0].isdigit() else ""
        if state == "LISTEN":
            pid, _, name = program.partition("/")
            listening.append(f"{fields[3]} ({name}, pid {pid})" if program else fields[3])
        elif state:
            states[state] += 1
    return _sockets(listening, states)


def _sockets(listening: list[str], states: Counter[str]) -> list[str]:
    facts = []
    if listening:
        more = f", {len(listening) - 2 * MAX_ITEMS} more" if len(listening) > 2 * MAX_ITEMS else ""
        facts.append("listening: " + ", ".join(listening[:2 * MAX_ITEMS]) + more)
    if states:
        facts.append("connections: " + ", ".join(f"{count} {state}" for state, count in states.most_common(MAX_ITEMS)))
    return facts


def _systemctl(lines: Sequence[str]) -> list[str] | None:
    units: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in lines:
        unit = _UNIT.match(line)
        if unit:
            current = {"unit": unit.group(1)}
            units.append(current)
        elif current is not None and not line.strip():
            current = None  # the journal excerpt follows a blank line
        elif current is not None and (field := _UNIT_FIELD.match(line)):
            current.setdefault(field.group(1), field.group(2).strip())
    if not units:
        return None
    facts = []
    for found in units:
        parts = [f"{found['unit']}: {found.get('Active', 'state unknown').split(' since', 1)[0]}"]
        if "Main PID" in found:
            parts.append(f"main PID {found['Main PID']}")
        if "Memory" in found:
            parts.append(f"memory {found['Memory']}")
        facts.append("; ".join(parts))
    return facts


def _uptime(lines: Sequence[str]) -> list[str] | None:
    for line in lines:
        load = _LOAD.search(line)
        if load:
            up = _UP.search(line)
            return [f"load average {load.group(1)}, {load.group(2)}, {load.group(3)}"
                    + (f"; up {up.group(1)}" if up else "")]
    return None


_PARSERS: dict[str, Callable[[Sequence[str]], list[str] | None]] = {
    "df": _df, "free": _free, "ps": _ps, "ss": _ss, "netstat": _netstat, "systemctl": _systemctl, "uptime": _uptime,
}
