"""Small clients for local OpenAI-compatible endpoints: chat, embeddings, and rerank.

All three talk to vLLM (or another compatible server) on the local network. Each accepts
an ``httpx`` transport so tests can run without a model.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from .config import ModelSettings, RagSettings

EMBED_BATCH = 32


class LLMError(RuntimeError):
    """The model server was unreachable or returned something unusable."""


class _Endpoint:
    def __init__(self, base_url: str, api_key_env: str, timeout: float,
                 transport: httpx.BaseTransport | None = None) -> None:
        headers = {}
        key = os.environ.get(api_key_env, "")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        self._client = httpx.Client(base_url=base_url.rstrip("/") + "/", headers=headers,
                                    timeout=timeout, transport=transport)

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post(path, json=payload)
        except httpx.HTTPError as exc:
            raise LLMError(f"Cannot reach {self._client.base_url}{path}: {exc}") from None
        if response.status_code >= 400:
            raise LLMError(f"{self._client.base_url}{path} returned HTTP {response.status_code}: {response.text[:300]}")
        try:
            data = response.json()
        except ValueError:
            raise LLMError(f"{self._client.base_url}{path} returned invalid JSON") from None
        if not isinstance(data, dict):
            raise LLMError(f"{self._client.base_url}{path} returned an unexpected response")
        return data

    def close(self) -> None:
        self._client.close()


class ChatClient(_Endpoint):
    def __init__(self, settings: ModelSettings, transport: httpx.BaseTransport | None = None,
                 thinking: str | None = None) -> None:
        super().__init__(settings.base_url, settings.api_key_env, settings.timeout, transport)
        self.model = settings.name
        self.extra: dict[str, Any] = {}
        if thinking:
            from .backends import thinking_fields

            self.extra = thinking_fields(settings.provider, thinking)

    def complete(self, messages: list[dict[str, str]], schema: dict[str, Any] | None = None,
                 max_tokens: int = 16_384) -> str:
        """Return the assistant's answer text; ``schema`` constrains it to JSON."""
        payload: dict[str, Any] = {"model": self.model, "messages": messages, "max_tokens": max_tokens, **self.extra}
        if schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "response", "schema": schema},
            }
        data = self.post("chat/completions", payload)
        try:
            choice = data["choices"][0]
            content = choice["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise LLMError("Chat response has no message content") from None
        if choice.get("finish_reason") == "length":
            raise LLMError("The model ran out of output tokens before finishing")
        if not isinstance(content, str) or not content.strip():
            raise LLMError("The model returned an empty answer")
        return content


class Embedder(_Endpoint):
    def __init__(self, settings: RagSettings, model: ModelSettings,
                 transport: httpx.BaseTransport | None = None) -> None:
        super().__init__(settings.embedding_url, model.api_key_env, model.timeout, transport)
        self.model = settings.embedding_model

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for start in range(0, len(texts), EMBED_BATCH):
            batch = texts[start:start + EMBED_BATCH]
            data = self.post("embeddings", {"model": self.model, "input": batch})
            try:
                items = sorted(data["data"], key=lambda item: item["index"])
                vectors.extend([float(value) for value in item["embedding"]] for item in items)
            except (KeyError, TypeError, ValueError):
                raise LLMError("Embedding response is malformed") from None
            if len(vectors) != start + len(batch):
                raise LLMError("Embedding response has the wrong number of vectors")
        return vectors


class Reranker(_Endpoint):
    def __init__(self, settings: RagSettings, model: ModelSettings,
                 transport: httpx.BaseTransport | None = None) -> None:
        super().__init__(settings.rerank_url, model.api_key_env, model.timeout, transport)
        self.model = settings.rerank_model

    def scores(self, query: str, documents: list[str]) -> list[float]:
        """Relevance score per document, in the order given."""
        if not documents:
            return []
        data = self.post("rerank", {"model": self.model, "query": query, "documents": documents})
        scores = [float("-inf")] * len(documents)
        try:
            for item in data["results"]:
                scores[int(item["index"])] = float(item["relevance_score"])
        except (KeyError, TypeError, ValueError, IndexError):
            raise LLMError("Rerank response is malformed") from None
        return scores
