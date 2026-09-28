"""`blacksite check`: prove a model server can run Blacksite before an incident depends on it.

Each check sends a real request the way Blacksite does and explains how to fix the
server when it fails. Model output is only compared with expected values; nothing the
model returns is ever executed.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterator

import anyio
import httpx

from .backends import DISPLAY, api_key, status, thinking_fields
from .config import Settings

PROBE_TOOL = {
    "type": "function",
    "function": {
        "name": "search_logs",
        "description": "Search the incident's log lines.",
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}},
                       "required": ["pattern"], "additionalProperties": False},
    },
}
PROBE_PROMPT = "nginx has returned 502 since 02:14. Call search_logs once with the pattern OOM. Do not answer yet."
JSON_SCHEMA = {
    "type": "object",
    "properties": {"title": {"type": "string"}, "steps": {"type": "array", "items": {"type": "string"}, "maxItems": 3}},
    "required": ["title", "steps"],
    "additionalProperties": False,
}

HINTS = {
    "ollama": {
        "server": "Start Ollama, then create the model: ollama create blacksite-qwen3.8 -f demo/Modelfile",
        "tools": "Use a model whose `ollama show` output lists the tools capability.",
        "reasoning": "Use a model whose `ollama show` output lists the thinking capability.",
        "json": "Update Ollama; structured outputs need a recent version.",
        "stop": "Recreate the model from demo/Modelfile; it did not end its turn after the tool call.",
    },
    "llamacpp": {
        "server": "Start it with: blacksite serve model  (or llama-server -m MODEL.gguf --jinja -np 1)",
        "tools": "Run llama-server with --jinja and a GGUF whose chat template supports tools.",
        "reasoning": "Run llama-server with --reasoning-format deepseek so thinking is returned separately.",
        "json": "Update llama.cpp; json_schema response formats need a recent build.",
        "stop": "Check the GGUF's chat template; the model did not end its turn after the tool call.",
    },
    "vllm": {
        "server": "Start it with: blacksite serve model  (or vllm serve MODEL --served-model-name NAME ...)",
        "tools": "Run vllm serve with --enable-auto-tool-choice --tool-call-parser qwen3_xml.",
        "stop": "Start vllm with VLLM_ENFORCE_STRICT_TOOL_CALLING=0; its tool grammar keeps the model from stopping.",
        "reasoning": "Run vllm serve with --reasoning-parser qwen3.",
        "json": "Update vLLM; structured outputs need a recent release.",
    },
}


@dataclass(frozen=True)
class Result:
    name: str
    ok: bool
    detail: str
    seconds: float
    hint: str = ""


class CheckFailed(Exception):
    def __init__(self, detail: str, hint: str = "") -> None:
        super().__init__(detail)
        self.hint = hint


def run_checks(settings: Settings, transport: httpx.BaseTransport | None = None,
               async_transport: httpx.AsyncBaseTransport | None = None) -> Iterator[Result]:
    """Yield one Result per check; later checks are skipped once the server is unusable."""
    model = settings.model
    hints = HINTS[model.provider]
    client = httpx.Client(base_url=model.base_url.rstrip("/") + "/", timeout=model.timeout, transport=transport,
                          headers={"Authorization": f"Bearer {api_key(model)}"})
    extra = thinking_fields(model.provider, settings.agent.thinking)
    state: dict[str, Any] = {}

    def timed(name: str, check: Callable[[], str]) -> Result:
        started = time.monotonic()
        try:
            detail = check()
            return Result(name, True, detail, time.monotonic() - started)
        except CheckFailed as exc:
            return Result(name, False, str(exc), time.monotonic() - started, exc.hint)
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
            return Result(name, False, f"{type(exc).__name__}: {exc}", time.monotonic() - started, hints["server"])

    def server() -> str:
        health = anyio.run(lambda: status(model, async_transport))
        if health.loaded or (health.loading and model.provider == "ollama"):
            return f"{DISPLAY[model.provider]} at {model.base_url} serves {model.name}"
        raise CheckFailed(health.detail or "not ready", hints["server"])

    def chat(payload: dict[str, Any], hint: str = "tools") -> dict[str, Any]:
        response = client.post("chat/completions", json={"model": model.name, "max_tokens": 2048, **extra, **payload})
        if response.status_code >= 400:
            raise CheckFailed(f"HTTP {response.status_code}: {response.text[:300]}", hints[hint])
        return response.json()

    def tool_call() -> str:
        body = chat({"messages": [{"role": "user", "content": PROBE_PROMPT}], "tools": [PROBE_TOOL]})
        if body["choices"][0].get("finish_reason") == "length":
            raise CheckFailed("the model kept generating after its tool call until max_tokens", hints["stop"])
        message = body["choices"][0]["message"]
        calls = message.get("tool_calls") or []
        if len(calls) != 1 or calls[0]["function"]["name"] != "search_logs":
            raise CheckFailed(f"expected one search_logs call, got {calls or repr((message.get('content') or '')[:120])}",
                              hints["tools"])
        arguments = json.loads(calls[0]["function"]["arguments"])
        if not isinstance(arguments.get("pattern"), str):
            raise CheckFailed(f"tool arguments are not usable: {arguments}", hints["tools"])
        state["message"], state["call"] = message, calls[0]
        return f"search_logs({json.dumps(arguments)})"

    def tool_result() -> str:
        if "call" not in state:
            raise CheckFailed("skipped: the tool call check failed", hints["tools"])
        code = secrets.token_hex(4)
        call = state["call"]
        assistant = {"role": "assistant", "content": state["message"].get("content") or "", "tool_calls": [call]}
        body = chat({"messages": [
            {"role": "user", "content": PROBE_PROMPT},
            assistant,
            {"role": "tool", "tool_call_id": call.get("id") or "call-1",
             "content": f"verification code {code}: 4 lines match 'Killed process'"},
            {"role": "user", "content": "Reply with only the verification code from the tool result."},
        ], "tools": [PROBE_TOOL]})
        answer = body["choices"][0]["message"].get("content") or ""
        if code not in answer:
            raise CheckFailed(f"the answer did not use the tool result: {answer[:120]!r}", hints["tools"])
        return "the model read the tool result"

    def streaming() -> str:
        payload = {"model": model.name, "max_tokens": 2048, **extra, "stream": True, "tools": [PROBE_TOOL],
                   "messages": [{"role": "user", "content": PROBE_PROMPT}]}
        names, arguments, chunks, reasoning = "", "", 0, 0
        with client.stream("POST", "chat/completions", json=payload) as response:
            if response.status_code >= 400:
                raise CheckFailed(f"HTTP {response.status_code}", hints["tools"])
            for line in response.iter_lines():
                if not line.startswith("data: ") or line == "data: [DONE]":
                    continue
                choices = json.loads(line[6:]).get("choices") or []
                if not choices:
                    continue
                delta = choices[0].get("delta") or {}
                reasoning += bool(delta.get("reasoning") or delta.get("reasoning_content"))
                for call in delta.get("tool_calls") or []:
                    chunks += 1
                    names += (call.get("function") or {}).get("name") or ""
                    arguments += (call.get("function") or {}).get("arguments") or ""
        if names != "search_logs" or "pattern" not in json.loads(arguments or "{}"):
            raise CheckFailed(f"streamed tool call was {names!r} {arguments!r}", hints["tools"])
        state["streamed_reasoning"] = reasoning
        return f"tool call arrived in {chunks} chunk{'s' if chunks != 1 else ''}"

    def reasoning() -> str:
        if settings.agent.thinking == "none":
            return "thinking is off (agent.thinking = none)"
        message = state.get("message") or {}
        text = message.get("reasoning") or message.get("reasoning_content") or ""
        if "<think>" in (message.get("content") or "") or not (text or state.get("streamed_reasoning")):
            raise CheckFailed("reasoning is not returned separately from the answer", hints["reasoning"])
        return f"{len(text)} characters of reasoning, kept out of the answer"

    def structured() -> str:
        body = chat({"messages": [{"role": "user", "content": "Give a title and at most 3 steps to free a full disk."}],
                     "response_format": {"type": "json_schema", "json_schema": {"name": "plan", "schema": JSON_SCHEMA}}},
                    "json")
        content = body["choices"][0]["message"].get("content") or ""
        try:
            data = json.loads(content)
        except ValueError:
            raise CheckFailed(f"not JSON: {content[:120]!r}", hints["json"]) from None
        if not isinstance(data, dict) or not isinstance(data.get("steps"), list):
            raise CheckFailed(f"JSON does not match the schema: {content[:120]!r}", hints["json"])
        return f"valid JSON with {len(data['steps'])} steps"

    try:
        first = timed("Server", server)
        yield first
        if not first.ok:
            return
        for name, check in (("Tool call", tool_call), ("Tool result", tool_result), ("Streaming", streaming),
                            ("Reasoning", reasoning), ("Structured JSON", structured)):
            yield timed(name, check)
    finally:
        client.close()
