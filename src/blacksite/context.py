"""What the switches add to the agent's context, and the factories that honor them.

``build_context`` returns the text a harness appends to the agent's instructions. With
every switch off it returns an empty string: the baseline each feature must beat. Tool
mode features add nothing here; they appear as MCP tools instead (see knowledge.server).
"""

from __future__ import annotations

import re

from .config import Settings
from .evidence.store import Evidence
from .knowledge.index import Hit, KnowledgeIndex
from .learning.store import Bullet, Case, LearningStore

CASE_FIELD_CHARS = 400
_MASK = re.compile(r"<(?:\*|NUM|IP|HEX|UUID|TS|EMPTY)>")


def open_index(settings: Settings) -> KnowledgeIndex:
    """The knowledge index with the clients its retrieval settings need."""
    from .llm import Embedder, Reranker

    rag = settings.rag
    embedder = Embedder(rag, settings.model) if rag.retriever == "hybrid" else None
    reranker = Reranker(rag, settings.model) if rag.rerank else None
    return KnowledgeIndex(rag, embedder, reranker)


def open_store(settings: Settings) -> LearningStore:
    return LearningStore(settings.learning.store_path)


def incident_query(evidence: Evidence, patterns: int = 5) -> str:
    """A retrieval query built from the incident description and its top error patterns."""
    incident = evidence.incident
    templates = [" ".join(_MASK.sub(" ", template).split()) for template in evidence.signature(patterns)]
    return "\n".join(part for part in (incident.title, incident.description, *templates) if part)


def build_context(settings: Settings, evidence: Evidence | None = None,
                  index: KnowledgeIndex | None = None, store: LearningStore | None = None) -> str:
    sections: list[str] = []
    learning = settings.learning
    needs_store = learning.playbook.enabled or (learning.cases.enabled and learning.cases.mode == "inject")
    if needs_store and store is None:
        store = open_store(settings)

    if learning.playbook.enabled:
        assert store is not None
        bullets = store.active_bullets(learning.playbook.max_bullets)
        if bullets:
            sections.append(format_playbook(bullets))

    if evidence is not None and learning.cases.enabled and learning.cases.mode == "inject":
        assert store is not None
        cases = store.recall(incident_query(evidence), evidence.signature(), learning.cases.top_k,
                             exclude_incident=evidence.incident.id)
        if cases:
            sections.append(format_cases([case for case, _ in cases]))

    if evidence is not None and settings.rag.enabled and settings.rag.mode == "inject":
        index = index or open_index(settings)
        hits = index.search(incident_query(evidence))
        if hits:
            sections.append(format_hits(hits, settings.rag.inject_chars, heading=True))

    return "\n\n".join(sections)


def format_playbook(bullets: list[Bullet]) -> str:
    lines = [
        "## Team playbook",
        "Lessons your team approved from past incidents. Follow them unless this incident's "
        "evidence shows they do not apply. Cite a bullet's id when you rely on it.",
    ]
    section = None
    for bullet in bullets:
        if bullet.section != section:
            section = bullet.section
            lines.append(f"{section.capitalize()}:")
        lines.append(f"- [{bullet.id}] {bullet.text}")
    return "\n".join(lines)


def format_cases(cases: list[Case]) -> str:
    lines = [
        "## Similar past incidents",
        "Hints, not evidence: confirm each point against this incident's logs before relying on it.",
    ]
    for case in cases:
        lines.append(f"{case.id} · {case.outcome.replace('_', ' ')} · {case.created[:10]} · {case.title}")
        lines.append(f"  Symptoms: {_clip(case.symptoms)}")
        lines.append(f"  Root cause: {_clip(case.root_cause)}")
        label = "Fix" if case.outcome == "resolved" else "Tried"
        lines.append(f"  {label}: {_clip(case.resolution)}")
        for lesson in case.lessons:
            lines.append(f"  Lesson: {_clip(lesson)}")
    return "\n".join(lines)


def format_hits(hits: list[Hit], max_chars: int, heading: bool = False) -> str:
    lines = ["## Reference excerpts"] if heading else []
    lines.append(f"{len(hits)} passages from the offline library. Cite them as path:lines.")
    budget = max_chars
    for number, hit in enumerate(hits, 1):
        chunk = hit.chunk
        text = chunk.text if len(chunk.text) <= budget else chunk.text[:max(budget, 0)] + " …"
        lines.append(f"[{number}] {chunk.citation} — {chunk.heading}\n{text}")
        budget -= len(text)
        if budget <= 0:
            lines.append(f"(Stopped at {max_chars} characters.)")
            break
    return "\n".join(lines)


def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= CASE_FIELD_CHARS else text[:CASE_FIELD_CHARS] + " …"
