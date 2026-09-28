"""Search over a local library of runbooks and reference documents.

``bm25`` uses SQLite FTS5 keyword ranking, which needs nothing beyond the standard
library and handles the exact error strings, unit names, and flags that dominate
troubleshooting queries. ``hybrid`` adds dense retrieval through a local embedding
server and merges the two rankings with reciprocal rank fusion; a cross-encoder
reranker can reorder the fused candidates. Start with ``bm25`` and turn the others on
only when evaluation shows they help.
"""

from __future__ import annotations

import hashlib
import os
from contextlib import closing
import re
import sqlite3
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from .._fs import remove_quietly, replace
from ..config import RagSettings

if TYPE_CHECKING:
    import numpy

SCHEMA_VERSION = 1
SUFFIXES = {".md", ".markdown", ".txt", ".rst"}
MAX_CHUNK_CHARS = 1500
MAX_READ_LINES = 200
RRF_K = 60
# Qwen3-Embedding expects an instruction on queries (not on documents).
EMBED_TASK = "Given a question about a failing server, retrieve documentation that helps diagnose or fix it"

_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")
# Unicode word characters, so Korean (and other) queries match too.
_WORD = re.compile(r"\w{2,}")


class KnowledgeError(ValueError):
    """A request the model can correct, such as an unknown document."""


class EmbedderLike(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...


class RerankerLike(Protocol):
    def scores(self, query: str, documents: list[str]) -> list[float]: ...


@dataclass(frozen=True)
class Chunk:
    id: int
    path: str
    start: int
    end: int
    heading: str
    text: str

    @property
    def citation(self) -> str:
        return f"{self.path}:{self.start}-{self.end}"


@dataclass(frozen=True)
class Hit:
    chunk: Chunk
    score: float


class KnowledgeIndex:
    """Builds and queries the index; rebuilds automatically when documents change."""

    def __init__(self, settings: RagSettings, embedder: EmbedderLike | None = None,
                 reranker: RerankerLike | None = None) -> None:
        self.settings = settings
        self.embedder = embedder
        self.reranker = reranker
        self._lock = threading.RLock()
        self._matrix: numpy.ndarray | None = None
        self._matrix_ids: list[int] = []
        if settings.retriever == "hybrid" and embedder is None:
            raise KnowledgeError("rag.retriever = hybrid needs an embedding client")
        if settings.rerank and reranker is None:
            raise KnowledgeError("rag.rerank = true needs a rerank client")

    @property
    def docs_dir(self) -> Path:
        return self.settings.docs_dir

    def ensure_current(self) -> bool:
        """Rebuild if documents or retrieval settings changed. Returns True if rebuilt."""
        with self._lock:
            fingerprint = self._fingerprint()
            if self._stored_fingerprint() == fingerprint:
                return False
            self.build(fingerprint)
            return True

    def build(self, fingerprint: str | None = None) -> int:
        """Index every document under docs_dir. Returns the number of chunks."""
        with self._lock:
            fingerprint = fingerprint or self._fingerprint()
            chunks: list[tuple[str, int, int, str, str]] = []
            for path, relative in _documents(self.docs_dir):
                text = path.read_text(encoding="utf-8", errors="replace")
                chunks.extend((relative, *piece) for piece in chunk_document(text, relative))
            vectors = None
            if self.settings.retriever == "hybrid" and chunks:
                assert self.embedder is not None
                vectors = self.embedder.embed([f"{heading}\n{text}" for _, _, _, heading, text in chunks])

            target = self.settings.index_path
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp")
            remove_quietly(tmp)
            con = sqlite3.connect(tmp)
            try:
                con.executescript(
                    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
                    "CREATE TABLE chunks (id INTEGER PRIMARY KEY, path TEXT, start INTEGER, end INTEGER, "
                    "heading TEXT, text TEXT);"
                    "CREATE VIRTUAL TABLE chunks_fts USING fts5(heading, text, tokenize='porter unicode61');"
                    "CREATE TABLE vectors (id INTEGER PRIMARY KEY, vec BLOB);"
                )
                for chunk_id, row in enumerate(chunks, 1):
                    con.execute("INSERT INTO chunks VALUES (?, ?, ?, ?, ?, ?)", (chunk_id, *row))
                    con.execute("INSERT INTO chunks_fts (rowid, heading, text) VALUES (?, ?, ?)",
                                (chunk_id, row[3], row[4]))
                    if vectors is not None:
                        con.execute("INSERT INTO vectors VALUES (?, ?)", (chunk_id, _pack(vectors[chunk_id - 1])))
                con.execute("INSERT INTO meta VALUES ('fingerprint', ?)", (fingerprint,))
                con.commit()
            finally:
                con.close()
            replace(tmp, target)
            self._matrix = None
            return len(chunks)

    def search(self, query: str, top_k: int | None = None) -> list[Hit]:
        top_k = top_k or self.settings.top_k
        with self._lock:
            self.ensure_current()
            with self._connect() as con:
                pool = max(self.settings.candidates, top_k)
                rankings = [self._keyword(con, query, pool)]
                if self.settings.retriever == "hybrid":
                    rankings.append(self._dense(con, query, pool))
                fused = _rrf(rankings)[:pool]
                if not fused:
                    return []
                chunks = {chunk.id: chunk for chunk in self._chunks(con, [chunk_id for chunk_id, _ in fused])}
            hits = [Hit(chunks[chunk_id], score) for chunk_id, score in fused if chunk_id in chunks]
            if self.settings.rerank and self.reranker is not None:
                scores = self.reranker.scores(query, [f"{hit.chunk.heading}\n{hit.chunk.text}" for hit in hits])
                hits = sorted((Hit(hit.chunk, score) for hit, score in zip(hits, scores, strict=True)),
                              key=lambda hit: hit.score, reverse=True)
            return hits[:top_k]

    def read(self, path: str, start: int = 1, end: int | None = None) -> tuple[list[str], int, int, int]:
        """Lines ``start``..``end`` of an indexed document: (lines, start, last, total)."""
        documents = dict((relative, doc) for doc, relative in _documents(self.docs_dir))
        if path not in documents:
            known = ", ".join(sorted(documents)[:20]) or "none"
            raise KnowledgeError(f"Unknown document {path!r}. Documents include: {known}")
        lines = documents[path].read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, start)
        last = min(len(lines), end or start + MAX_READ_LINES - 1, start + MAX_READ_LINES - 1)
        return lines[start - 1:last], start, last, len(lines)

    # Internals -----------------------------------------------------------------------

    def _connect(self) -> closing[sqlite3.Connection]:
        # as_uri() gives file:///C:/... on Windows and percent-encodes spaces.
        uri = self.settings.index_path.resolve().as_uri() + "?mode=ro"
        return closing(sqlite3.connect(uri, uri=True))

    def _keyword(self, con: sqlite3.Connection, query: str, limit: int) -> list[int]:
        words = list(dict.fromkeys(word.lower() for word in _WORD.findall(query)))
        if not words:
            return []
        expression = " OR ".join(f'"{word}"' for word in words)
        rows = con.execute(
            "SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH ? ORDER BY bm25(chunks_fts, 2.0, 1.0) LIMIT ?",
            (expression, limit),
        ).fetchall()
        return [row[0] for row in rows]

    def _dense(self, con: sqlite3.Connection, query: str, limit: int) -> list[int]:
        import numpy

        if self._matrix is None:
            rows = con.execute("SELECT id, vec FROM vectors ORDER BY id").fetchall()
            if not rows:
                return []
            matrix = numpy.array([_unpack(vec) for _, vec in rows], dtype=numpy.float32)
            norms = numpy.linalg.norm(matrix, axis=1, keepdims=True)
            self._matrix = matrix / numpy.where(norms == 0, 1, norms)
            self._matrix_ids = [row[0] for row in rows]
        assert self.embedder is not None
        vector = numpy.array(self.embedder.embed([f"Instruct: {EMBED_TASK}\nQuery:{query}"])[0], dtype=numpy.float32)
        vector /= numpy.linalg.norm(vector) or 1.0
        order = numpy.argsort(-(self._matrix @ vector))[:limit]
        return [self._matrix_ids[index] for index in order]

    def _chunks(self, con: sqlite3.Connection, ids: list[int]) -> list[Chunk]:
        marks = ",".join("?" * len(ids))
        rows = con.execute(f"SELECT id, path, start, end, heading, text FROM chunks WHERE id IN ({marks})", ids)
        return [Chunk(*row) for row in rows]

    def _stored_fingerprint(self) -> str | None:
        if not self.settings.index_path.exists():
            return None
        try:
            with self._connect() as con:
                row = con.execute("SELECT value FROM meta WHERE key = 'fingerprint'").fetchone()
        except sqlite3.Error:
            return None
        return row[0] if row else None

    def _fingerprint(self) -> str:
        digest = hashlib.sha256()
        model = self.settings.embedding_model if self.settings.retriever == "hybrid" else ""
        digest.update(repr((SCHEMA_VERSION, self.settings.retriever, model, MAX_CHUNK_CHARS)).encode())
        for path, relative in _documents(self.docs_dir):
            stat = path.stat()
            digest.update(f"{relative}\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode())
        return digest.hexdigest()


def chunk_document(text: str, path: str) -> list[tuple[int, int, str, str]]:
    """Split a document into (start_line, end_line, heading_path, text) pieces.

    Markdown splits at headings, then at blank lines when a section is long.
    """
    title = Path(path).stem.replace("-", " ").replace("_", " ")
    sections: list[tuple[str, list[tuple[int, str]]]] = []
    stack: list[tuple[int, str]] = []
    current: list[tuple[int, str]] = []
    heading = title
    in_fence = False
    markdown = Path(path).suffix in {".md", ".markdown"}
    for number, line in enumerate(text.splitlines(), 1):
        if markdown and _FENCE.match(line):
            in_fence = not in_fence
        match = _HEADING.match(line) if markdown and not in_fence else None
        if match:
            if any(body.strip() for _, body in current):
                sections.append((heading, current))
            level = len(match.group(1))
            stack = [item for item in stack if item[0] < level] + [(level, match.group(2))]
            heading = " > ".join(name for _, name in stack)
            current = [(number, line)]
        else:
            current.append((number, line))
    if any(body.strip() for _, body in current):
        sections.append((heading, current))

    pieces: list[tuple[int, int, str, str]] = []
    for heading, lines in sections:
        for group in _split(lines):
            body = "\n".join(line for _, line in group).strip()
            if body:
                pieces.append((group[0][0], group[-1][0], heading, body))
    return pieces


def _split(lines: list[tuple[int, str]]) -> list[list[tuple[int, str]]]:
    """Group lines into pieces under MAX_CHUNK_CHARS, preferring blank-line boundaries."""
    groups: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []
    size = 0
    paragraph: list[tuple[int, str]] = []

    def flush_paragraph() -> None:
        nonlocal current, size, paragraph
        length = sum(len(line) + 1 for _, line in paragraph)
        if current and size + length > MAX_CHUNK_CHARS:
            groups.append(current)
            current, size = [], 0
        for item in paragraph:
            if current and size + len(item[1]) + 1 > MAX_CHUNK_CHARS:
                groups.append(current)
                current, size = [], 0
            current.append(item)
            size += len(item[1]) + 1
        paragraph = []

    for item in lines:
        paragraph.append(item)
        if not item[1].strip():
            flush_paragraph()
    flush_paragraph()
    if current:
        groups.append(current)
    return groups


def document_paths(directory: Path) -> list[str]:
    """Library documents as the relative paths used in citations."""
    return [relative for _, relative in _documents(directory)]


def _documents(directory: Path) -> list[tuple[Path, str]]:
    if not directory.is_dir():
        return []
    base = directory.resolve()
    found = []
    for current, dirs, files in os.walk(directory, followlinks=False):
        dirs[:] = sorted(name for name in dirs if not name.startswith("."))
        for name in sorted(files):
            path = Path(current) / name
            if name.startswith(".") or path.suffix.lower() not in SUFFIXES or path.is_symlink():
                continue
            if path.resolve().is_relative_to(base):
                found.append((path, path.relative_to(directory).as_posix()))
    return found


def _rrf(rankings: list[list[int]]) -> list[tuple[int, float]]:
    scores: dict[int, float] = {}
    for ranking in rankings:
        for rank, chunk_id in enumerate(ranking):
            scores[chunk_id] = scores.get(chunk_id, 0.0) + 1.0 / (RRF_K + rank + 1)
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def _pack(vector: list[float]) -> bytes:
    return struct.pack(f"<{len(vector)}f", *vector)


def _unpack(blob: bytes) -> tuple[Any, ...]:
    return struct.unpack(f"<{len(blob) // 4}f", blob)
