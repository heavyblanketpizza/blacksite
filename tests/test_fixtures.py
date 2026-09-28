"""Guard against real logs landing in the published fixtures."""

import ipaddress
import re
from pathlib import Path

from blacksite.evidence.safety import Redactor

FIXTURES = Path(__file__).parent / "fixtures"
ALLOWED_NETWORKS = [ipaddress.ip_network(net) for net in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",      # private and loopback
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",                  # documentation (RFC 5737)
)]
ALLOWED_HOST = re.compile(r"(^|\.)(example\.(com|net|org)|example|internal|local|test|invalid|localhost)$|^[a-z0-9-]+$")
FAKE_SECRETS = ("EXAMPLE", "Tr0ub4dor")
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
URL_HOST = re.compile(r"[a-z][a-z0-9+.-]*://(?:[^@/\s\"]*@)?([^/:\s\"]+)", re.I)
HOST_FIELD = re.compile(r"\b(?:server|host)[:=]\s*\"?([A-Za-z0-9.-]+)")


def _lines():
    for path in sorted(FIXTURES.rglob("*")):
        if path.is_file() and path.suffix not in (".py",):
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                yield f"{path.relative_to(FIXTURES).as_posix()}:{number}", line


def test_addresses_are_private_or_reserved_for_documentation() -> None:
    bad = []
    for where, line in _lines():
        for text in IPV4.findall(line):
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                continue
            if not any(address in network for network in ALLOWED_NETWORKS):
                bad.append(f"{where}: {text}")
    assert not bad, "Public IP addresses in fixtures (use 203.0.113.0/24 or 10.0.0.0/8):\n" + "\n".join(bad[:20])


def test_hosts_use_reserved_names() -> None:
    bad = []
    for where, line in _lines():
        for host in URL_HOST.findall(line) + HOST_FIELD.findall(line):
            host = host.lower().rstrip(".")
            if IPV4.fullmatch(host):
                continue
            if not ALLOWED_HOST.search(host):
                bad.append(f"{where}: {host}")
    assert not bad, "Real-looking host names in fixtures (use example.com or .internal):\n" + "\n".join(bad[:20])


def test_secrets_are_obviously_fake() -> None:
    bad = []
    for where, line in _lines():
        redacted, found = Redactor().redact(line)
        if found and not any(marker in line for marker in FAKE_SECRETS):
            bad.append(f"{where}: {line[:120]}")
    assert not bad, "Secret-like values in fixtures must contain EXAMPLE:\n" + "\n".join(bad[:20])
