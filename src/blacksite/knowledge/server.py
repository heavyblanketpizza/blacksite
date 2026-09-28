"""MCP server for the offline library and past-incident memory.

Tools appear only when their switch is on and set to tool mode, so a harness keeps the
same server configuration while experiments turn features on and off. With everything
off the server starts with no tools, which is the baseline.
"""

from __future__ import annotations

from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import Field

from .. import __version__
from ..config import Settings
from ..context import format_cases, format_hits, incident_query, open_index, open_store
from ..evidence.store import Evidence
from ..learning.store import LearningStore
from ..llm import LLMError
from .index import KnowledgeError, KnowledgeIndex

_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


def build_knowledge_server(settings: Settings, evidence: Evidence | None = None,
                           index: KnowledgeIndex | None = None,
                           store: LearningStore | None = None) -> MCPServer:
    docs = settings.rag.enabled and settings.rag.mode == "tool"
    cases = settings.learning.cases.enabled and settings.learning.cases.mode == "tool"

    parts = []
    if docs:
        parts.append(
            "search_docs and read_doc search the team's offline runbooks and reference documents. "
            "Cite passages as path:lines. Documents can be outdated; prefer this incident's evidence "
            "when they disagree."
        )
    if cases:
        parts.append(
            "recall_cases returns past incidents with outcomes the team confirmed. They are hints, "
            "not evidence: confirm each point against this incident's logs."
        )
    server = MCPServer("blacksite-knowledge", instructions=" ".join(parts) or None, version=__version__,
                       log_level="WARNING")

    if docs:
        index = index or open_index(settings)

        @server.tool(
            annotations=_READ_ONLY,
            structured_output=False,
            description="Search the offline library of runbooks and reference docs. Include exact error "
            "text, service names, and symptoms in the query.",
        )
        def search_docs(
            query: Annotated[str, Field(min_length=2, description="What to look for.")],
            top_k: Annotated[int, Field(ge=1, le=10, description="How many passages to return.")] = settings.rag.top_k,
        ) -> str:
            try:
                hits = index.search(query, top_k)
            except (KnowledgeError, LLMError) as exc:
                raise ToolError(str(exc)) from None
            if not hits:
                return "No passages match. Try different words, such as the exact error text."
            return format_hits(hits, settings.evidence.max_output_chars)

        @server.tool(
            annotations=_READ_ONLY,
            structured_output=False,
            description="Read lines of a library document, for example the full section around a search hit.",
        )
        def read_doc(
            path: Annotated[str, Field(description="Document path as shown in search results.")],
            start_line: Annotated[int, Field(ge=1)] = 1,
            end_line: Annotated[int | None, Field(ge=1)] = None,
        ) -> str:
            try:
                lines, start, last, total = index.read(path, start_line, end_line)
            except KnowledgeError as exc:
                raise ToolError(str(exc)) from None
            if not lines:
                return f"{path} has {total} lines."
            numbered = "\n".join(f"{number}  {line}" for number, line in enumerate(lines, start))
            return f"{path} lines {start}–{last} of {total}\n{numbered}"

    if cases:
        store = store or open_store(settings)

        @server.tool(
            annotations=_READ_ONLY,
            structured_output=False,
            description="Find past incidents similar to this one, with their confirmed root cause, fix, "
            "and lessons. Matches on this incident's log patterns plus an optional query.",
        )
        def recall_cases(
            query: Annotated[str, Field(description="Symptoms or error text to match; may be empty.")] = "",
            top_k: Annotated[int, Field(ge=1, le=10)] = settings.learning.cases.top_k,
        ) -> str:
            signature: list[str] = []
            exclude = None
            text = query
            if evidence is not None:
                evidence.refresh()
                signature = evidence.signature()
                exclude = evidence.incident.id
                text = f"{query}\n{incident_query(evidence)}"
            found = store.recall(text, signature, top_k, exclude_incident=exclude)
            if not found:
                return "No approved past incident matches."
            return format_cases([case for case, _ in found])

    return server
