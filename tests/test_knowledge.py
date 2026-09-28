import json
import math

import httpx
import pytest

from blacksite.knowledge.index import KnowledgeError, KnowledgeIndex, chunk_document
from blacksite.knowledge.server import build_knowledge_server
from blacksite.llm import Embedder, Reranker
from conftest import call_tool, tool_names

VOCABULARY = ["oom", "memory", "killed", "nginx", "502", "upstream", "disk", "space", "inode", "restart"]


class FakeEmbedder:
    """Bag-of-words vectors over a tiny vocabulary: deterministic and dependency-free."""

    def __init__(self) -> None:
        self.calls = 0

    def embed(self, texts: list[str]) -> list[list[float]]:
        self.calls += 1
        return [[float(text.lower().count(word)) for word in VOCABULARY] for text in texts]


class FakeReranker:
    def __init__(self, preferred: str) -> None:
        self.preferred = preferred

    def scores(self, query: str, documents: list[str]) -> list[float]:
        return [1.0 if self.preferred in document else 0.0 for document in documents]


def test_markdown_is_chunked_by_heading_with_line_numbers() -> None:
    text = "# Title\nintro\n\n## Part A\nalpha\n```\n# not a heading\n```\n## Part B\nbeta\n"
    pieces = chunk_document(text, "runbooks/sample.md")
    assert [(start, end, heading) for start, end, heading, _ in pieces] == [
        (1, 3, "Title"), (4, 8, "Title > Part A"), (9, 10, "Title > Part B"),
    ]
    assert "# not a heading" in pieces[1][3]


def test_bm25_finds_the_runbook_for_the_error_text(make_settings) -> None:
    index = KnowledgeIndex(make_settings().rag)
    hits = index.search("connect() failed (111: Connection refused) while connecting to upstream")
    assert hits[0].chunk.path == "runbooks/nginx-502.md"
    assert hits[0].chunk.citation.startswith("runbooks/nginx-502.md:")
    hits = index.search("Memory cgroup out of memory Killed process")
    assert hits[0].chunk.path == "runbooks/oom-killer.md"


def test_index_rebuilds_when_documents_change(make_settings) -> None:
    settings = make_settings()
    index = KnowledgeIndex(settings.rag)
    assert index.ensure_current() is True
    assert index.ensure_current() is False
    (settings.rag.docs_dir / "runbooks" / "tls.md").write_text("# TLS certificate expired\nRenew with certbot.\n", encoding="utf-8")
    assert index.search("certificate expired certbot")[0].chunk.path == "runbooks/tls.md"


def test_hybrid_fuses_dense_and_keyword_rankings(make_settings) -> None:
    embedder = FakeEmbedder()
    index = KnowledgeIndex(make_settings("rag.retriever=hybrid").rag, embedder=embedder)
    hits = index.search("inode")
    assert hits[0].chunk.path == "runbooks/disk-full.md"
    assert embedder.calls == 2  # one batch for the documents, one for the query


def test_reranker_reorders_candidates(make_settings) -> None:
    settings = make_settings("rag.rerank=true")
    index = KnowledgeIndex(settings.rag, reranker=FakeReranker("lsof"))
    hits = index.search("process memory disk restart", top_k=2)
    assert "lsof" in hits[0].chunk.text


def test_hybrid_and_rerank_require_their_clients(make_settings) -> None:
    with pytest.raises(KnowledgeError, match="embedding client"):
        KnowledgeIndex(make_settings("rag.retriever=hybrid").rag)
    with pytest.raises(KnowledgeError, match="rerank client"):
        KnowledgeIndex(make_settings("rag.rerank=true").rag)


def test_read_refuses_paths_outside_the_library(make_settings) -> None:
    index = KnowledgeIndex(make_settings().rag)
    lines, start, last, total = index.read("runbooks/oom-killer.md", 1, 3)
    assert lines[0] == "# Process killed by the OOM killer" and (start, last) == (1, 3) and total > 10
    with pytest.raises(KnowledgeError, match="Unknown document"):
        index.read("../../etc/passwd")


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ((), set()),
        (("rag.enabled=true",), {"search_docs", "read_doc"}),
        (("rag.enabled=true", "rag.mode=inject"), set()),
        (("learning.cases.enabled=true",), {"recall_cases"}),
        (("rag.enabled=true", "learning.cases.enabled=true"), {"search_docs", "read_doc", "recall_cases"}),
    ],
)
def test_switches_decide_which_tools_exist(make_settings, overrides, expected) -> None:
    assert tool_names(build_knowledge_server(make_settings(*overrides))) == expected


def test_search_docs_tool_returns_citations(make_settings) -> None:
    server = build_knowledge_server(make_settings("rag.enabled=true"))
    is_error, text = call_tool(server, "search_docs", {"query": "upstream prematurely closed connection"})
    assert not is_error and "[1] runbooks/nginx-502.md:" in text
    is_error, text = call_tool(server, "read_doc", {"path": "secrets.md"})
    assert is_error and "Unknown document" in text


def test_http_clients_speak_the_openai_compatible_endpoints(make_settings, monkeypatch) -> None:
    monkeypatch.setenv("VLLM_API_KEY", "k")
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.headers.get("authorization"), json.loads(request.content)))
        body = json.loads(request.content)
        if request.url.path.endswith("/embeddings"):
            data = [{"index": i, "embedding": [float(len(text)), 1.0]} for i, text in enumerate(body["input"])]
            return httpx.Response(200, json={"data": list(reversed(data))})
        return httpx.Response(200, json={"results": [{"index": 1, "relevance_score": 0.9},
                                                     {"index": 0, "relevance_score": 0.1}]})

    settings = make_settings()
    transport = httpx.MockTransport(handler)
    vectors = Embedder(settings.rag, settings.model, transport).embed(["a", "bbb"])
    scores = Reranker(settings.rag, settings.model, transport).scores("q", ["x", "y"])
    assert vectors == [[1.0, 1.0], [3.0, 1.0]]
    assert scores == [0.1, 0.9]
    assert seen[0][:2] == ("/v1/embeddings", "Bearer k")
    assert seen[0][2]["model"] == "Qwen/Qwen3-Embedding-0.6B"
    assert seen[1][0] == "/v1/rerank" and seen[1][2]["documents"] == ["x", "y"]
    assert not any(math.isinf(score) for score in scores)
