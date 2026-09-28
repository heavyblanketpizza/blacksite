"""What the agent hands the developer, and the checks run before they see it.

The checks are deterministic code, not another model call: every cited line must
exist in the evidence, state-changing commands are labelled by risk, and risky steps
need a way back. Problems the model can fix are sent back to it once; anything left
over is shown to the developer as a warning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..evidence.safety import looks_like_instructions
from ..evidence.store import Evidence, EvidenceError

Risk = Literal["read-only", "low", "high"]


class Citation(BaseModel):
    ref: str = Field(description="Exactly as the tools print it: file:line or file:first-last.")
    shows: str = Field(description="What this line proves, in one sentence.")


class Step(BaseModel):
    title: str = Field(description="Short imperative title.")
    why: str = Field(description="Why this step, citing evidence refs where relevant.")
    commands: list[str] = Field(default_factory=list, description="Exact shell commands, one per item.")
    expected: str = Field(description="What the developer should see if the step worked.")
    risk: Risk = Field(description="read-only: inspects only. low: easy to undo. high: restarts, edits, deletes.")
    rollback: str | None = Field(default=None, description="How to undo this step. Required when risk is high.")


class Guide(BaseModel):
    """A step-by-step guide the developer follows on the real server."""

    title: str = Field(description="The problem in a few words.")
    summary: str = Field(description="Two or three sentences: what happened and what to do.")
    root_cause: str = Field(description="The underlying cause, not just the symptom.")
    confidence: Literal["high", "medium", "low"]
    evidence: list[Citation] = Field(min_length=1, description="The lines that support the root cause.")
    steps: list[Step] = Field(min_length=1, description="Confirm first with read-only steps, then fix, then verify.")
    verify: list[str] = Field(description="How to confirm the incident is over.")
    unknowns: list[str] = Field(default_factory=list, description="What the evidence cannot answer yet.")
    security_notes: list[str] = Field(default_factory=list, description="Suspicious log content (lines marked ⚠) worth reporting.")


class InfoRequest(BaseModel):
    """Ask the developer for facts or command output before writing the guide."""

    reason: str = Field(description="What is missing and how it would change the diagnosis.")
    questions: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list, description="Read-only commands to run and paste back.")


@dataclass(frozen=True)
class Check:
    """One check result. ``code`` and ``params`` let the page show it in any language."""

    level: Literal["ok", "warn", "error"]
    text: str
    code: str = ""
    params: dict[str, object] = field(default_factory=dict)


# file:line, file:first-last, or several of them: kern.log:5-6,8,11-12
_REF = re.compile(r"^\s*(?P<file>[^\s:][^:]*?):(?P<spans>\d+(?:\s*[-–]\s*\d+)?(?:\s*,\s*\d+(?:\s*[-–]\s*\d+)?)*)\s*$")
_SPAN = re.compile(r"(\d+)(?:\s*[-–]\s*(\d+))?")
_CASE_REF = re.compile(r"^case-\d{4,}$")

# Commands that change state: (pattern, minimum risk, reason key). See REASONS for labels.
_STATE_CHANGING: list[tuple[re.Pattern[str], Risk, str]] = [
    (re.compile(p), risk, label) for p, risk, label in [
        (r"\brm\s+(-\w*[rf]\w*\s+)", "high", "recursive_delete"),
        (r"\brm\s", "high", "delete"),
        (r"\b(dd|mkfs(\.\w+)?|fdisk|parted|wipefs|shred)\b", "high", "disk_write"),
        (r"\btruncate\s+(-s|--size)\b|^\s*:?\s*>\s*/\S+", "high", "file_truncation"),
        (r"(?i)\b(drop|truncate)\s+(table|database|schema)\b|\bdelete\s+from\b", "high", "data_deletion"),
        (r"\biptables\s+-(F|X|D)\b|\bufw\s+(disable|reset)\b", "high", "firewall_change"),
        (r"\bchmod\s+-R\b|\bchown\s+-R\b|\bchmod\s+777\b", "high", "recursive_permissions"),
        (r"\b(reboot|shutdown|halt|poweroff)\b", "high", "host_restart"),
        (r"\bkill(all)?\s+-9\b|\bpkill\b|\bkillall\b", "high", "process_kill"),
        (r"\bsystemctl\s+(stop|disable|mask|kill)\b", "high", "service_stop"),
        (r"\b(docker|podman)\s+(rm|rmi|system\s+prune|volume\s+rm)\b|\bkubectl\s+delete\b", "high", "container_deletion"),
        (r"\bgit\s+(reset\s+--hard|clean\s+-\w*f)", "high", "discard_changes"),
        (r"\b(apt(-get)?|yum|dnf)\s+(remove|purge|autoremove)\b", "high", "package_removal"),
        (r"\bcrontab\s+-r\b|\buserdel\b", "high", "account_deletion"),
        (r"\bsystemctl\s+(restart|reload|start|edit|daemon-reload|enable|revert)\b|\bservice\s+\S+\s+(restart|reload|start)\b",
         "low", "service_change"),
        (r"\bsed\s+-i\b|\btee\b(?!\s+-a\s+/dev/null)|(?<![<>&\d])>\s*/(etc|var|opt|usr)/", "low", "file_edit"),
        (r"\b(apt(-get)?|yum|dnf|pip)\s+install\b|\bsysctl\s+-w\b|\bulimit\s", "low", "system_change"),
        (r"\blogrotate\s+-f\b|\bjournalctl\s+--vacuum", "low", "log_cleanup"),
    ]
]
_RANK = {"read-only": 0, "low": 1, "high": 2}
REASONS = {
    "recursive_delete": "recursive or forced delete", "delete": "delete", "disk_write": "disk write",
    "file_truncation": "file truncation", "data_deletion": "data deletion", "firewall_change": "firewall change",
    "recursive_permissions": "recursive permission change", "host_restart": "host restart",
    "process_kill": "process kill", "service_stop": "service stop", "container_deletion": "container deletion",
    "discard_changes": "discard changes", "package_removal": "package removal",
    "account_deletion": "account or schedule deletion", "service_change": "service change",
    "file_edit": "file edit", "system_change": "system change", "log_cleanup": "log cleanup", "unsafe": "unsafe",
}


def command_risk(command: str) -> tuple[Risk, str | None]:
    """The minimum risk a command implies, with the reason key (see REASONS)."""
    worst: tuple[Risk, str | None] = ("read-only", None)
    for pattern, risk, label in _STATE_CHANGING:
        if pattern.search(command) and _RANK[risk] > _RANK[worst[0]]:
            worst = (risk, label)
    return worst


def review_guide(guide: Guide, evidence: Evidence, known_docs: set[str] = frozenset(),
                 known_cases: set[str] = frozenset()) -> tuple[list[Check], list[str]]:
    """Check a guide. Returns (checks for the developer, problems the model must fix)."""
    checks: list[Check] = []
    fixes: list[str] = []

    bad_refs = [ref for ref in _all_refs(guide) if not _ref_exists(ref, evidence, known_docs, known_cases)]
    good = len(guide.evidence) - sum(1 for citation in guide.evidence if citation.ref in bad_refs)
    if bad_refs:
        fixes.append(
            "These citations do not match any file and line in the evidence: "
            + ", ".join(bad_refs)
            + ". Cite only file:line references printed by the tools. Files: "
            + ", ".join(f"{item.file} ({item.lines} lines)" for item in evidence.artifacts())
        )
        checks.append(Check("error", f"{count(len(bad_refs), 'citation')} not found in the evidence: {', '.join(bad_refs)}",
                            "citations_bad", {"count": len(bad_refs), "refs": ", ".join(bad_refs)}))
    if good:
        checks.append(Check("ok", f"{count(good, 'citation')} verified against the evidence", "citations_ok", {"count": good}))

    for number, step in enumerate(guide.steps, 1):
        for command in step.commands:
            if looks_like_instructions(command):
                fixes.append(f"Step {number} runs `{command}`, which pipes a download into a shell or echoes "
                             "instructions found in logs. Remove it.")
                checks.append(Check("error", f"Step {number}: blocked an unsafe command", "unsafe_command",
                                    {"step": number}))
            implied, reason = command_risk(command)
            if _RANK[implied] > _RANK[step.risk]:
                checks.append(Check(
                    "warn", f"Step {number}: raised risk from {step.risk} to {implied} ({REASONS[reason]}: `{command}`)",
                    "risk_raised", {"step": number, "from": step.risk, "to": implied, "reason": reason, "command": command}))
                step.risk = implied
        if step.risk == "high" and not (step.rollback or "").strip():
            fixes.append(f"Step {number} ({step.title}) is high risk but has no rollback. Add one.")
            checks.append(Check("warn", f"Step {number} is high risk with no rollback", "no_rollback", {"step": number}))

    high = sum(step.risk == "high" for step in guide.steps)
    changing = sum(step.risk != "read-only" for step in guide.steps)
    counts = {"readonly": len(guide.steps) - changing, "changing": changing, "high": high}
    checks.append(Check("ok", f"{count(counts['readonly'], 'read-only step')}, {changing} changing state"
                              + (f", {high} high risk with rollback" if high else ""),
                        "steps_summary_high" if high else "steps_summary", counts))
    if guide.steps and guide.steps[0].risk != "read-only":
        checks.append(Check("warn", "The guide changes state before confirming the diagnosis", "state_before_confirm"))
    return checks, fixes


def count(n: int, noun: str) -> str:
    """'1 citation', '3 citations'."""
    return f"{n} {noun}{'' if n == 1 else 's'}"


# Guides recorded before checks carried codes: recognise their text so the page can
# translate and pluralise them like new ones.
_LEGACY_CHECKS = [
    (re.compile(r"^(?P<count>\d+) citation\(s\) verified against the evidence$"), "citations_ok"),
    (re.compile(r"^(?P<readonly>\d+) read-only step\(s\), (?P<changing>\d+) changing state"
                r"(?:, (?P<high>\d+) high risk with rollback)?$"), "steps_summary"),
]


def upgrade_check(check: dict[str, Any]) -> dict[str, Any]:
    """A stored check with a code and parameters; checks that already have one are unchanged."""
    if check.get("code"):
        return check
    for pattern, code in _LEGACY_CHECKS:
        match = pattern.match(str(check.get("text", "")))
        if match:
            params = {key: int(value) for key, value in match.groupdict().items() if value is not None}
            if code == "steps_summary" and "high" in params:
                code = "steps_summary_high"
            return {**check, "code": code, "params": params}
    return check


def review_request(request: InfoRequest) -> tuple[list[Check], list[str]]:
    checks: list[Check] = []
    fixes: list[str] = []
    for command in request.commands:
        risk, reason = command_risk(command)
        if risk != "read-only" or looks_like_instructions(command):
            fixes.append(f"`{command}` changes state ({REASONS[reason or 'unsafe']}). Ask only for read-only commands.")
            checks.append(Check("error", f"Blocked a state-changing command: `{command}`", "request_blocked",
                                {"command": command}))
    if request.commands and not fixes:
        checks.append(Check("ok", f"{count(len(request.commands), 'requested command')} "
                                  f"{'is' if len(request.commands) == 1 else 'are'} read-only", "request_ok",
                            {"count": len(request.commands)}))
    return checks, fixes


ANSWER_TEMPLATE = """\
When the evidence supports a root cause, reply with the guide in exactly this Markdown \
format and nothing else:

# <the problem in a few words>
Confidence: <high, medium, or low>

<Two or three sentences: what happened and what to do.>

## Root cause
<The underlying cause, citing file:line.>

## Evidence
- file:line: <what this line proves>

## Steps
### 1. <Imperative title> (read-only)
<Why this step, citing file:line.>
```bash
<exact command>
```
Expected: <what the developer should see>
Undo: <how to roll back; required when the risk is high>

## Verify
- <how to confirm the incident is over>

## Still unknown
- <what the evidence cannot answer>

## Security notes
- <lines marked ⚠, if any; otherwise leave this section out>

Mark each step (read-only), (low), or (high). At most 8 evidence lines and 6 steps.

If one specific fact or command output would change the diagnosis, reply instead with:

# Need more information
<What is missing and how it would change the diagnosis.>

## Questions
- <question>

## Commands
```bash
<read-only command for the developer to run and paste back>
```"""

_FENCE_LINE = re.compile(r"^\s*(```|~~~)")
_H1 = re.compile(r"^#\s+(.+?)\s*#*\s*$")
_H2 = re.compile(r"^##\s+(.+?)\s*#*\s*$")
# The template keeps English headings and labels; Korean equivalents are accepted too,
# because a model asked to answer in Korean sometimes translates them.
_H3 = re.compile(r"^###\s+(?:step\s+|단계\s*)?(?:\d+\s*(?:단계)?\s*[.):-]?\s*)?(.+?)\s*#*\s*$", re.I)
_RISK_WORDS = {"read-only": "read-only", "read only": "read-only", "읽기 전용": "read-only", "읽기전용": "read-only",
               "low": "low", "낮음": "low", "보통": "low", "중간": "low", "high": "high", "높음": "high"}
_RISK_TAIL = re.compile(r"\s*[(\[]\s*(read[- ]only|low|high|읽기\s?전용|낮음|보통|중간|높음)(?:\s+risk|\s*위험)?\s*[)\]]\s*$",
                        re.I)
_CONFIDENCE = re.compile(r"^\W*(?:confidence|신뢰도)\W*\s*[:\-]?\s*\W*(high|medium|low|높음|보통|중간|낮음)", re.I)
_CONFIDENCE_WORDS = {"높음": "high", "보통": "medium", "중간": "medium", "낮음": "low"}
_FIELD = re.compile(
    r"^\W{0,3}(why|expected|expect|undo|rollback|risk|이유|예상 결과|예상|기대 결과|되돌리기|롤백|위험도|위험)\W{0,3}\s*[:\-]\s*(.*)$",
    re.I)
_FIELD_NAMES = {"expect": "expected", "undo": "rollback", "이유": "why", "예상 결과": "expected", "예상": "expected",
                "기대 결과": "expected", "되돌리기": "rollback", "롤백": "rollback", "위험도": "risk", "위험": "risk"}
_BULLET = re.compile(r"^\s*(?:[-*+•]|\d+[.)])\s+(?:\[[ xX]\]\s+)?(.*\S)\s*$")
_EVIDENCE_ITEM = re.compile(
    r"^`?(?P<ref>[^\s`:][^\s`]*?:\d+(?:\s*[-–]\s*\d+)?(?:\s*,\s*\d+(?:\s*[-–]\s*\d+)?)*)`?"
    r"\s*(?:[—–:\-]+\s*)?(?P<shows>.*)$"
)
_MORE_INFO = re.compile(r"need|more information|question|추가 정보|정보 필요|질문", re.I)


class AnswerFormatError(ValueError):
    """The model's answer does not follow the template; the message says what to fix."""


def parse_answer(text: str) -> Guide | InfoRequest:
    """Turn the model's Markdown answer into a Guide or InfoRequest."""
    lines = text.strip().splitlines()
    start = next((i for i, line in enumerate(lines) if _H1.match(line)), None)
    if start is None:
        raise AnswerFormatError("Reply with the guide template, starting with a '# ' title line.")
    title = _H1.match(lines[start]).group(1).strip()
    preamble, sections = _sections(lines[start + 1:])
    if "questions" in sections or "commands" in sections or ("steps" not in sections and _MORE_INFO.search(title)):
        reason = " ".join(line.strip() for line in preamble if line.strip())
        reason = reason or " ".join(sections.get("why", []) + sections.get("reason", [])).strip()
        return InfoRequest(reason=reason or title, questions=_bullets(sections.get("questions", [])),
                           commands=_fenced(sections.get("commands", [])))

    confidence = "medium"
    summary = []
    for line in preamble:
        match = _CONFIDENCE.match(line.strip())
        if match:
            value = match.group(1).lower()
            confidence = _CONFIDENCE_WORDS.get(value, value)
        elif line.strip():
            summary.append(line.strip())
    summary = summary or [line.strip() for line in sections.get("summary", []) if line.strip()]
    evidence = []
    for item in _bullets(sections.get("evidence", [])):
        match = _EVIDENCE_ITEM.match(item)
        if match:
            evidence.append(Citation(ref=match["ref"].strip(), shows=match["shows"].strip() or "Cited evidence."))
    steps = _steps(sections.get("steps", []))
    problems = []
    if not evidence:
        problems.append("the Evidence section needs bullet lines like '- nginx/error.log:3: what it proves'")
    if not steps:
        problems.append("the Steps section needs '### 1. Title (read-only)' steps")
    root_cause = " ".join(line.strip() for line in sections.get("root cause", []) if line.strip())
    if not root_cause:
        problems.append("the '## Root cause' section is missing")
    if problems:
        raise AnswerFormatError("Your answer does not follow the template: " + "; ".join(problems) + ".")
    return Guide(
        title=title, summary=" ".join(summary) or root_cause, root_cause=root_cause,
        confidence=confidence, evidence=evidence, steps=steps,
        verify=_bullets(sections.get("verify", [])), unknowns=_bullets(sections.get("still unknown", [])),
        security_notes=_bullets(sections.get("security notes", [])),
    )


_SECTION_NAMES = {
    "root cause": "root cause", "cause": "root cause", "evidence": "evidence", "steps": "steps",
    "verify": "verify", "verification": "verify", "still unknown": "still unknown", "unknowns": "still unknown",
    "unknown": "still unknown", "open questions": "still unknown", "security notes": "security notes",
    "security": "security notes", "summary": "summary", "questions": "questions", "commands": "commands",
    "why": "why", "reason": "reason",
    "근본 원인": "root cause", "원인": "root cause", "증거": "evidence", "근거": "evidence", "조치 단계": "steps",
    "해결 단계": "steps", "단계": "steps", "확인": "verify", "검증": "verify", "아직 모르는 것": "still unknown",
    "미확인": "still unknown", "알 수 없는 것": "still unknown", "보안 참고": "security notes", "보안": "security notes",
    "요약": "summary", "질문": "questions", "명령어": "commands", "명령": "commands", "이유": "why",
}


def _sections(lines: list[str]) -> tuple[list[str], dict[str, list[str]]]:
    preamble: list[str] = []
    sections: dict[str, list[str]] = {}
    current = preamble
    in_fence = False
    for line in lines:
        if _FENCE_LINE.match(line):
            in_fence = not in_fence
        heading = None if in_fence else _H2.match(line)
        if heading and not line.startswith("###"):
            name = re.sub(r"[^\w ]|[\d_]", "", heading.group(1).lower()).strip()
            key = _SECTION_NAMES.get(name) or next((v for k, v in _SECTION_NAMES.items() if k in name), name)
            current = sections.setdefault(key, [])
            continue
        current.append(line)
    return preamble, sections


def _bullets(lines: list[str]) -> list[str]:
    items = []
    for line in lines:
        match = _BULLET.match(line)
        if match:
            items.append(match.group(1).strip())
        elif line.strip() and items and line.startswith((" ", "\t")):
            items[-1] += " " + line.strip()
    return items


def _fenced(lines: list[str]) -> list[str]:
    commands, in_fence = [], False
    for line in lines:
        if _FENCE_LINE.match(line):
            in_fence = not in_fence
            continue
        if in_fence and line.strip():
            commands.append(line.strip().removeprefix("$ "))
    return commands


def _steps(lines: list[str]) -> list[Step]:
    steps: list[dict[str, object]] = []
    in_fence = False
    field = "why"
    for line in lines:
        if _FENCE_LINE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            if steps and line.strip():
                steps[-1]["commands"].append(line.strip().removeprefix("$ "))  # type: ignore[union-attr]
            continue
        heading = _H3.match(line)
        if heading:
            title = heading.group(1).strip()
            risk = "read-only"
            tail = _RISK_TAIL.search(title)
            if tail:
                risk = _RISK_WORDS.get(tail.group(1).lower().replace("-", " ").replace("  ", " "),
                                       _RISK_WORDS.get(tail.group(1).lower(), "read-only"))
                title = title[:tail.start()].strip()
            steps.append({"title": title, "why": "", "commands": [], "expected": "", "risk": risk, "rollback": ""})
            field = "why"
            continue
        if not steps or not line.strip():
            continue
        match = _FIELD.match(line.strip())
        if match:
            name = match.group(1).lower()
            field = _FIELD_NAMES.get(name, name)
            if field == "risk":
                value = match.group(2).strip().lower().strip("()[]")
                steps[-1]["risk"] = _RISK_WORDS.get(value.replace("-", " "), _RISK_WORDS.get(value, steps[-1]["risk"]))
                field = "why"
                continue
            steps[-1][field] = f"{steps[-1][field]} {match.group(2).strip()}".strip()
            continue
        text = _BULLET.match(line).group(1) if _BULLET.match(line) else line.strip()
        steps[-1][field] = f"{steps[-1][field]} {text}".strip()
    return [
        Step(title=str(step["title"]), why=str(step["why"]) or str(step["title"]), commands=list(step["commands"]),
             expected=str(step["expected"]) or "No errors.", risk=step["risk"],  # type: ignore[arg-type]
             rollback=str(step["rollback"]) or None)
        for step in steps
    ]


LANGUAGES = ("en", "ko")

_EXPORT_LABELS = {
    "en": {"confidence": "Confidence", "root cause": "Root cause", "evidence": "Evidence", "steps": "Steps",
           "expected": "Expected", "rollback": "Rollback", "verify": "Verify", "unknown": "Still unknown",
           "security": "Security notes", "checks": "Automatic checks",
           "read-only": "read-only", "low": "low", "high": "high",
           "ok": "ok", "warn": "warning", "error": "error"},
    "ko": {"confidence": "신뢰도", "root cause": "근본 원인", "evidence": "증거", "steps": "단계",
           "expected": "예상 결과", "rollback": "되돌리기", "verify": "확인", "unknown": "아직 모르는 것",
           "security": "보안 참고", "checks": "자동 검사",
           "read-only": "읽기 전용", "low": "낮음", "high": "높음",
           "ok": "통과", "warn": "경고", "error": "오류",
           "confidence-high": "높음", "confidence-medium": "보통", "confidence-low": "낮음"},
}

LANGUAGE_INSTRUCTIONS = {
    "en": "",
    "ko": (
        "Write the answer in Korean (한국어): the title, summary, root cause, explanations, expected results, "
        "undo steps, verification items, unknowns, security notes, and questions. Keep the Markdown headings, "
        "'Confidence:', 'Expected:', 'Undo:', and the risk labels (read-only), (low), (high) exactly in English "
        "as in the template. Keep commands, file names, file:line references, and quoted log text unchanged. "
        "Write natural Korean using only Hangul and English; never use Chinese characters or Japanese."
    ),
}

# Han ideographs and Japanese kana: a small quantized model sometimes slips into them.
_FOREIGN_SCRIPT = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]+")


def language_checks(guide: Guide | InfoRequest, language: str) -> list[Check]:
    """Flag text in a script the reader did not ask for (Korean guides only)."""
    if language != "ko":
        return []
    found = _FOREIGN_SCRIPT.findall(guide.model_dump_json())
    if not found:
        return []
    sample = ", ".join(dict.fromkeys(found))[:60]
    return [Check("warn", f"Contains Chinese or Japanese text: {sample}", "mixed_script", {"sample": sample})]


def guide_markdown(guide: Guide, checks: list[Check] = (), language: str = "en") -> str:
    """The guide as a Markdown document for export, with headings in ``language``."""
    label = _EXPORT_LABELS.get(language, _EXPORT_LABELS["en"])
    confidence = label.get(f"confidence-{guide.confidence}", guide.confidence)
    lines = [f"# {guide.title}", "", f"**{label['confidence']}:** {confidence}", "", guide.summary, "",
             f"## {label['root cause']}", "", guide.root_cause, "", f"## {label['evidence']}", ""]
    lines += [f"- `{citation.ref}`: {citation.shows}" for citation in guide.evidence]
    lines += ["", f"## {label['steps']}", ""]
    for number, step in enumerate(guide.steps, 1):
        lines += [f"### {number}. {step.title} ({label[step.risk]})", "", step.why, ""]
        if step.commands:
            lines += ["```bash", *step.commands, "```", ""]
        lines += [f"**{label['expected']}:** {step.expected}", ""]
        if step.rollback:
            lines += [f"**{label['rollback']}:** {step.rollback}", ""]
    lines += [f"## {label['verify']}", "", *[f"- [ ] {item}" for item in guide.verify], ""]
    if guide.unknowns:
        lines += [f"## {label['unknown']}", "", *[f"- {item}" for item in guide.unknowns], ""]
    if guide.security_notes:
        lines += [f"## {label['security']}", "", *[f"- {item}" for item in guide.security_notes], ""]
    if checks:
        lines += [f"## {label['checks']}", "", *[f"- {label[check.level]}: {check.text}" for check in checks], ""]
    return "\n".join(lines)


def _all_refs(guide: Guide) -> list[str]:
    return list(dict.fromkeys(citation.ref.strip().strip("`") for citation in guide.evidence))


def parse_reference(ref: str) -> tuple[str, list[tuple[int, int]]] | None:
    """Split 'file:3-5,8' into ('file', [(3, 5), (8, 8)]); None if it is not a file reference."""
    match = _REF.match(ref.strip().strip("`"))
    if not match:
        return None
    return match["file"].strip(), [(int(start), int(end or start)) for start, end in _SPAN.findall(match["spans"])]


def _ref_exists(ref: str, evidence: Evidence, known_docs: set[str], known_cases: set[str]) -> bool:
    if _CASE_REF.match(ref):
        return ref in known_cases
    parsed = parse_reference(ref)
    if parsed is None:
        return False
    file, spans = parsed
    if file in known_docs:
        return all(1 <= start <= end for start, end in spans)
    try:
        total = evidence.line_count(file)
    except EvidenceError:
        return False
    return all(1 <= start <= end <= total for start, end in spans)
