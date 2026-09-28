"""The model servers Blacksite runs on: Ollama, llama.cpp (llama-server), and vLLM.

All three speak the OpenAI Chat Completions API. They differ in how a request turns
Qwen3.8's thinking on or off, where the reasoning comes back, and how to tell whether
the model is loaded, so every such difference lives here.

Qwen3.8's chat template takes ``enable_thinking`` and ``reasoning_effort`` in
{low, medium, xhigh} and raises an error on anything else; without them it thinks at
``xhigh``, the slowest level. Ollama translates its own ``reasoning_effort`` request
field; llama.cpp and vLLM pass ``chat_template_kwargs`` straight to the template.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

from .config import ModelSettings, Settings

PROVIDERS = ("ollama", "llamacpp", "vllm")
DISPLAY = {"ollama": "Ollama", "llamacpp": "llama.cpp", "vllm": "vLLM"}
DEFAULT_URLS = {"ollama": "http://127.0.0.1:11434/v1", "llamacpp": "http://127.0.0.1:8080/v1",
                "vllm": "http://127.0.0.1:8000/v1"}
AGENT_MAX_TOKENS = 12_000


def thinking_fields(provider: str, thinking: str) -> dict[str, Any]:
    """Extra request fields that set the model's reasoning effort (none, low, or medium)."""
    if provider == "ollama":
        return {"reasoning_effort": thinking}
    if thinking == "none":
        return {"chat_template_kwargs": {"enable_thinking": False}}
    return {"chat_template_kwargs": {"enable_thinking": True, "reasoning_effort": thinking}}


def api_key(model: ModelSettings) -> str:
    return os.environ.get(model.api_key_env) or "local"


def server_root(model: ModelSettings) -> str:
    """The server URL without the OpenAI ``/v1`` suffix, for health and admin endpoints."""
    return model.base_url.rstrip("/").removesuffix("/v1")


def agent_model(settings: Settings, http_client: httpx.AsyncClient | None = None) -> Any:
    """A Pydantic AI model for the configured server."""
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.ollama import OllamaProvider
    from pydantic_ai.providers.openai import OpenAIProvider
    from pydantic_ai.providers.vllm import VLLMProvider

    model = settings.model
    options: dict[str, Any] = {"base_url": model.base_url, "api_key": api_key(model)}
    if http_client is not None:
        options["http_client"] = http_client
    if model.provider == "ollama":
        provider: Any = OllamaProvider(**options)
    elif model.provider == "vllm":
        provider = VLLMProvider(**options)
    else:
        provider = OpenAIProvider(**options)  # llama-server is a plain OpenAI-compatible endpoint
    return OpenAIChatModel(model.name, provider=provider)


def agent_settings(settings: Settings) -> dict[str, Any]:
    """Per-request model settings for the agent."""
    thinking = settings.agent.thinking
    if settings.model.provider == "ollama":
        return {"openai_reasoning_effort": thinking, "max_tokens": AGENT_MAX_TOKENS}
    return {"extra_body": thinking_fields(settings.model.provider, thinking), "max_tokens": AGENT_MAX_TOKENS}


@dataclass(frozen=True)
class Status:
    reachable: bool
    loaded: bool
    detail: str = ""
    loading: bool = False  # not ready yet, but will be without anyone's help


async def serving(model: ModelSettings, transport: httpx.AsyncBaseTransport | None = None) -> list[dict[str, str]]:
    """What the server at ``model.base_url`` is serving now, as {name, source}; [] when nothing answers.

    ``source`` is the Ollama model, the GGUF path (llama.cpp), or the model ID or folder (vLLM).
    """
    root = server_root(model)
    try:
        async with httpx.AsyncClient(timeout=3, headers={"Authorization": f"Bearer {api_key(model)}"},
                                     transport=transport) as client:
            if model.provider == "ollama":
                loaded = (await client.get(f"{root}/api/ps")).json().get("models", [])
                return [{"name": str(item.get("name", "")).removesuffix(":latest"),
                         "source": str(item.get("model", "")).removesuffix(":latest")} for item in loaded]
            listed = (await client.get(f"{model.base_url.rstrip('/')}/models")).json().get("data", [])
            if model.provider == "llamacpp":
                path = (await client.get(f"{root}/props")).json().get("model_path", "")
                return [{"name": str(item.get("id", "")), "source": str(path)} for item in listed[:1]]
            return [{"name": str(item.get("id", "")), "source": str(item.get("root", ""))} for item in listed]
    except (httpx.HTTPError, ValueError, AttributeError):
        return []


async def status(model: ModelSettings, transport: httpx.AsyncBaseTransport | None = None) -> Status:
    """Whether the server answers and the model is ready to serve."""
    root = server_root(model)
    headers = {"Authorization": f"Bearer {api_key(model)}"}
    try:
        async with httpx.AsyncClient(timeout=3, headers=headers, transport=transport) as client:
            if model.provider == "ollama":
                # An alias such as blacksite-qwen3.8 runs under its parent model's name.
                shown = await client.post(f"{root}/api/show", json={"model": model.name})
                parent = shown.json().get("details", {}).get("parent_model") if shown.status_code == 200 else None
                if shown.status_code == 404:
                    return Status(True, False, f"model {model.name} is not installed in Ollama")
                loaded = [item for item in (await client.get(f"{root}/api/ps")).json().get("models", [])
                          if item.get("name") in {model.name, f"{model.name}:latest", parent}]
                if not loaded:
                    return Status(True, False, "Ollama loads the model on the first request", loading=True)
                context = int(loaded[0].get("context_length") or 0)
                if context and context < model.context:
                    # Ollama's OpenAI API cannot raise a model's context per request.
                    return Status(True, False, f"Ollama runs {model.name} with a {context}-token context; the agent "
                                  f"needs {model.context}. Raise Ollama's context length, or run the same model "
                                  "with llama.cpp, which sets the context itself.")
                return Status(True, True)
            health = await client.get(f"{root}/health")
            if health.status_code == 503:
                return Status(True, False, "loading the model", loading=True)
            if health.status_code >= 400:
                return Status(True, False, f"health check returned HTTP {health.status_code}")
            if model.provider == "llamacpp":
                return Status(True, True)  # llama-server serves one model under any requested name
            served = [item.get("id") for item in (await client.get(f"{model.base_url.rstrip('/')}/models")).json().get("data", [])]
            if model.name not in served:
                return Status(True, False, f"serving {', '.join(map(str, served)) or 'nothing'}, not {model.name}")
            return Status(True, True)
    except (httpx.HTTPError, ValueError):
        return Status(False, False, f"no answer from {root}")
