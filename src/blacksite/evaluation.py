"""Score the agent's guides against labeled incidents, with each knowledge switch on or off.

A labeled incident is an incident directory whose ``incident.json`` carries an ``expected``
block of case-insensitive regular expressions and artifact paths::

    "expected": {
      "root_cause": ["out of memory|OOM", "cache"],       # each must match the root cause or summary
      "cited_files": ["kern.log", "app/app.log"],         # each must appear in the Evidence section
      "steps": ["roll ?back|2\\\\.13\\\\.2"],                # each must match a step
      "forbidden_commands": ["rm -rf", "systemctl stop"]  # no step command may match
    }

``blacksite eval`` runs the agent over each incident under one or more presets (which
switches are on), scores every run against its labels and the guide's own checks, and
writes a scorecard, so a team can see whether a switch helps on its own incidents
before turning it on for everyone.
"""

from __future__ import annotations

import json
import re
import shutil
import statistics
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import anyio

from .agent.guide import parse_reference
from .agent.investigator import Investigator
from .config import ConfigError, Settings, load_settings
from .evidence.store import ARTIFACTS_DIR, INCIDENT_FILE, EvidenceError

# Each preset sets all three switches, so the config file's own choices cannot leak into a run.
PRESETS: dict[str, tuple[str, ...]] = {
    "baseline": ("rag.enabled=false", "learning.cases.enabled=false", "learning.playbook.enabled=false"),
    "rag": ("rag.enabled=true", "rag.mode=tool", "learning.cases.enabled=false", "learning.playbook.enabled=false"),
    "rag-inject": ("rag.enabled=true", "rag.mode=inject", "learning.cases.enabled=false",
                   "learning.playbook.enabled=false"),
    "cases": ("rag.enabled=false", "learning.cases.enabled=true", "learning.cases.mode=tool",
              "learning.playbook.enabled=false"),
    "cases-inject": ("rag.enabled=false", "learning.cases.enabled=true", "learning.cases.mode=inject",
                     "learning.playbook.enabled=false"),
    "playbook": ("rag.enabled=false", "learning.cases.enabled=false", "learning.playbook.enabled=true"),
    "all": ("rag.enabled=true", "rag.mode=tool", "learning.cases.enabled=true", "learning.cases.mode=tool",
            "learning.playbook.enabled=true"),
}


@dataclass(frozen=True)
class Expected:
    """What a correct guide for one incident must and must not contain."""

    root_cause: tuple[re.Pattern[str], ...] = ()
    cited_files: tuple[str, ...] = ()
    steps: tuple[re.Pattern[str], ...] = ()
    forbidden_commands: tuple[re.Pattern[str], ...] = ()

    @classmethod
    def load(cls, incident_dir: Path) -> Expected | None:
        """The incident's labels, or None when its incident.json has no ``expected`` block."""
        path = incident_dir / INCIDENT_FILE
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise EvidenceError(f"Cannot read {path}: {exc}") from None
        labels = data.get("expected") if isinstance(data, dict) else None
        if labels is None:
            return None
        if not isinstance(labels, dict):
            raise EvidenceError(f"{path}: expected must be a JSON object")
        try:
            return cls(root_cause=_patterns(labels, "root_cause"), cited_files=_strings(labels, "cited_files"),
                       steps=_patterns(labels, "steps"), forbidden_commands=_patterns(labels, "forbidden_commands"))
        except (TypeError, re.error) as exc:
            raise EvidenceError(f"{path}: bad expected block: {exc}") from None


def _strings(labels: Mapping[str, Any], key: str) -> tuple[str, ...]:
    values = labels.get(key, [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise TypeError(f"{key} must be a list of strings")
    return tuple(values)


def _patterns(labels: Mapping[str, Any], key: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(value, re.I) for value in _strings(labels, key))


@dataclass
class Score:
    """How one run did against the incident's labels and the guide's own checks."""

    guide: bool = False  # the answer was a guide, not a question or an error
    root_cause: bool = False  # every root-cause pattern matched the diagnosis
    files_cited: bool = False  # every expected file was cited
    steps: bool = False  # every step pattern matched a step
    forbidden: int = 0  # commands that matched a forbidden pattern
    citations_bad: int = 0  # citations the checks could not find in the evidence
    citations_unsupported: int = 0  # citations whose lines may not show what they claim
    unsafe: int = 0  # commands the checks blocked
    seconds: float = 0.0
    tool_calls: int = 0
    tokens: int = 0  # input and output
    problems: list[str] = field(default_factory=list)  # why the run failed, in the order found

    @property
    def passed(self) -> bool:
        return not self.problems


@dataclass
class Result:
    incident: str
    preset: str
    run: int
    score: Score

    def as_json(self) -> dict[str, Any]:
        return {"incident": self.incident, "preset": self.preset, "run": self.run, "passed": self.score.passed,
                **asdict(self.score)}


Progress = Callable[[Result], None]


def score(expected: Expected, events: Sequence[Mapping[str, Any]]) -> Score:
    """Score one turn's events (as ``Investigator.turn`` yields them) against the labels."""
    by_type = {event["type"]: event for event in events}
    result = Score()
    done = by_type.get("done")
    if done:
        result.seconds, result.tool_calls = float(done["seconds"]), int(done["tool_calls"])
        result.tokens = int(done.get("input_tokens") or 0) + int(done.get("output_tokens") or 0)
    answer = by_type.get("guide") or by_type.get("question")
    for check in answer["checks"] if answer else []:
        count = int(check.get("params", {}).get("count", 1))
        if check["code"] == "citations_bad":
            result.citations_bad += count
        elif check["code"] == "citations_unsupported":
            result.citations_unsupported += count
        elif check["code"] in ("unsafe_command", "request_blocked"):
            result.unsafe += 1

    if "guide" in by_type:
        guide = by_type["guide"]["guide"]
        result.guide = True
        diagnosis = f"{guide['root_cause']}\n{guide['summary']}"
        result.root_cause = _matches(expected.root_cause, diagnosis, "root cause does not match", result.problems)
        cited = {parsed[0] for citation in guide["evidence"] if (parsed := parse_reference(citation["ref"]))}
        absent = [file for file in expected.cited_files if file not in cited]
        result.files_cited = not absent
        result.problems += [f"no citation of {file}" for file in absent]
        steps = "\n".join("\n".join([step["title"], step["why"], step["expected"], *step["commands"]])
                          for step in guide["steps"])
        result.steps = _matches(expected.steps, steps, "no step matching", result.problems)
        commands = [command for step in guide["steps"] for command in step["commands"]]
    elif "question" in by_type:
        result.problems.append("no guide: the agent asked for information")
        commands = list(by_type["question"]["request"]["commands"])
    else:
        error = by_type.get("error", {}).get("message", "the turn produced no answer")
        result.problems.append(f"no guide: {error}")
        commands = []
    for command in commands:
        if any(pattern.search(command) for pattern in expected.forbidden_commands):
            result.forbidden += 1
            result.problems.append(f"forbidden command: {command}")
    if result.citations_bad:
        result.problems.append(f"{result.citations_bad} bad citation{'s' if result.citations_bad > 1 else ''}")
    if result.unsafe:
        result.problems.append(f"{result.unsafe} unsafe command{'s' if result.unsafe > 1 else ''}")
    return result


def _matches(patterns: Sequence[re.Pattern[str]], text: str, problem: str, problems: list[str]) -> bool:
    missed = [pattern.pattern for pattern in patterns if not pattern.search(text)]
    problems += [f"{problem}: {pattern}" for pattern in missed]
    return not missed


def find_incidents(paths: Iterable[Path]) -> list[Path]:
    """Incident directories: each path that holds incident.json, else the path's subdirectories that do."""
    found: list[Path] = []
    for path in paths:
        if (path / INCIDENT_FILE).is_file():
            found.append(path)
        elif path.is_dir():
            found.extend(sorted(child for child in path.iterdir() if (child / INCIDENT_FILE).is_file()))
        else:
            raise EvidenceError(f"{path} is not an incident directory")
    return found


def run_incident(settings: Settings, incident: Path, work: Path, config_path: Path | None = None,
                 overrides: Sequence[str] = ()) -> list[dict[str, Any]]:
    """One turn of the agent over a fresh copy of the incident's description and artifacts; returns its events."""
    target = work / incident.name
    if target.exists():  # a previous run in the same work directory; its conversation must not carry over
        shutil.rmtree(target)
    target.mkdir(parents=True)
    shutil.copy2(incident / INCIDENT_FILE, target / INCIDENT_FILE)
    if (incident / ARTIFACTS_DIR).is_dir():
        shutil.copytree(incident / ARTIFACTS_DIR, target / ARTIFACTS_DIR)
    investigator = Investigator(settings, target, config_path, list(overrides))

    async def run() -> list[dict[str, Any]]:
        return [event async for event in investigator.turn()]

    with investigator.evidence:
        investigator.evidence.refresh()  # indexing time is not the agent's
        return anyio.run(run)


def evaluate(incidents: Sequence[Path], presets: Sequence[str], work: Path, config_path: Path | None = None,
             overrides: Sequence[str] = (), repeat: int = 1, progress: Progress | None = None) -> list[Result]:
    """Run every incident under each preset ``repeat`` times, each run in its own copy under ``work``."""
    unknown = [name for name in presets if name not in PRESETS]
    if unknown:
        raise ConfigError(f"Unknown preset {', '.join(unknown)}; choose from {', '.join(PRESETS)}")
    if repeat < 1:
        raise ConfigError("repeat must be at least 1")
    labels = {incident: Expected.load(incident) for incident in incidents}
    unlabeled = [incident.name for incident, expected in labels.items() if expected is None]
    if unlabeled:
        raise EvidenceError(f"No expected block in incident.json: {', '.join(unlabeled)}")
    results: list[Result] = []
    for name in presets:
        settings_overrides = [*overrides, *PRESETS[name]]
        settings = load_settings(config_path, settings_overrides)
        for run in range(1, repeat + 1):
            for incident, expected in labels.items():
                assert expected is not None
                events = run_incident(settings, incident, work / name / str(run), config_path, settings_overrides)
                results.append(Result(incident.name, name, run, score(expected, events)))
                if progress:
                    progress(results[-1])
    return results


def report_markdown(results: Sequence[Result]) -> str:
    """A scorecard per preset, each incident's record under every preset, and what the failed runs lacked."""
    presets = list(dict.fromkeys(result.preset for result in results))
    incidents = list(dict.fromkeys(result.incident for result in results))
    runs = max((result.run for result in results), default=0)
    lines = ["# Evaluation scorecard", "",
             f"{len(incidents)} incident(s), {runs} run(s) each, under {len(presets)} preset(s). "
             "A run passes when the guide meets every label, cites only lines that exist, "
             "and runs no command the checks block.", "",
             _table(["Preset", "Passed", "Guides", "Root cause", "Files cited", "Steps", "Forbidden",
                     "Bad citations", "Unsupported", "Unsafe", "Median s", "Tool calls", "Tokens"],
                    [_preset_row(name, [r.score for r in results if r.preset == name]) for name in presets]),
             "",
             _table(["Incident", *presets],
                    [[incident, *(_passed([r.score for r in results if r.preset == name and r.incident == incident])
                                  for name in presets)] for incident in incidents])]
    failed = [r for r in results if not r.score.passed]
    if failed:
        lines += ["", "## What the failed runs lacked", ""]
        lines += [f"- {r.incident}, {r.preset}, run {r.run}: {'; '.join(r.score.problems)}" for r in failed]
    return "\n".join(lines) + "\n"


def _preset_row(name: str, scores: Sequence[Score]) -> list[str]:
    def passed(flag: Callable[[Score], bool]) -> str:
        return f"{sum(1 for score in scores if flag(score))}/{len(scores)}"

    return [name, passed(lambda s: s.passed), passed(lambda s: s.guide), passed(lambda s: s.root_cause),
            passed(lambda s: s.files_cited), passed(lambda s: s.steps),
            str(sum(s.forbidden for s in scores)), str(sum(s.citations_bad for s in scores)),
            str(sum(s.citations_unsupported for s in scores)), str(sum(s.unsafe for s in scores)),
            f"{statistics.median(s.seconds for s in scores):.0f}",
            f"{statistics.mean(s.tool_calls for s in scores):.1f}",
            f"{statistics.mean(s.tokens for s in scores):.0f}"]


def _passed(scores: Sequence[Score]) -> str:
    return f"{sum(1 for score in scores if score.passed)}/{len(scores)}"


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + " --- |" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)
