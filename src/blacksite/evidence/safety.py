"""Protections applied to evidence before the model sees it.

Log text is attacker-influenced: request paths, user agents, and usernames all end up
in logs. Secrets are redacted at ingest, lines that read like instructions to an AI are
flagged, and chat-template or tool-call markup is defanged on output so a quoted
``<tool_call>`` cannot be parsed as a real call (see vLLM issue #58147).
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"
# Bump when redaction or flagging rules change, so existing indexes are rebuilt.
RULES_VERSION = 2

_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----")
_KEY_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----")

# (pattern, replacement); replacements keep the key name so the line stays readable.
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(authorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token)\s+)[^\s\"',;]+"), r"\1" + REDACTED),
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@"), r"\1" + REDACTED + "@"),
    (
        re.compile(
            r"(?i)(\b(?:[a-z0-9]+[_-])*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"
            r"\b[\"']?\s*[:=]\s*[\"']?)([^\s\"',;&}]+)"
        ),
        r"\1" + REDACTED,
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), REDACTED),
    (re.compile(r"\b[rsp]k_(?:live|test)_[A-Za-z0-9]{10,}\b"), REDACTED),
]

# Cheap pre-check: a line without any of these cannot match a secret pattern above.
_SECRET_HINT = re.compile(
    r"(?i)authorization|://[^/\s:@]+:[^@\s/]+@|pass|pwd|secret|token|key|AKIA|ASIA|eyJ|gh[pousr]_|xox[abprs]-|sk-"
)

_INSTRUCTION_PATTERNS = re.compile(
    r"(?i)("
    r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|your)\b.{0,20}"
    r"\b(instructions?|prompts?|rules|directions)\b"
    r"|\byou are now\b|\bnew instructions\b|\bsystem prompt\b"
    r"|\b(as an?|dear)\s+(ai|llm|assistant|language model|chatbot)\b"
    r"|\b(tell|instruct|advise)\s+the\s+(user|developer|operator|admin)\s+to\b"
    r"|<\|im_start\|>|<\|im_end\|>|</?tool_call>|<function=|</?think>"
    r"|\b(curl|wget)\b[^|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b"
    r"|\bbase64\s+(-d|--decode)\b[^|]{0,100}\|\s*(sudo\s+)?(ba|z)?sh\b"
    r")"
)

_MARKUP = re.compile(r"<(/?)(tool_call|tool_response|think|function[=>]|parameter[=>]|\|im_start\||\|im_end\|)")


class Redactor:
    """Masks credentials line by line; tracks multi-line private key blocks per file."""

    def __init__(self) -> None:
        self._in_key_block = False

    def redact(self, line: str) -> tuple[str, int]:
        if self._in_key_block:
            if _KEY_END.search(line):
                self._in_key_block = False
            return REDACTED, 1
        if _KEY_BEGIN.search(line):
            self._in_key_block = not _KEY_END.search(line)
            return _KEY_BEGIN.split(line, maxsplit=1)[0] + REDACTED, 1
        count = 0
        if not _SECRET_HINT.search(line):
            return line, count
        for pattern, replacement in _SECRET_PATTERNS:
            line, found = pattern.subn(replacement, line)
            count += found
        return line, count


def looks_like_instructions(text: str) -> bool:
    """True when a log line reads like an attempt to instruct the model or the reader."""
    return bool(_INSTRUCTION_PATTERNS.search(text))


def defang(text: str) -> str:
    """Neutralize chat-template and tool-call markup while keeping it readable."""
    return _MARKUP.sub(lambda match: "‹" + match.group(1) + match.group(2), text)
