"""What each model family needs from a server: how to ask for reasoning, which parsers to run.

Blacksite's reference model is Qwen3.8, but any tool-calling model served through an
OpenAI-compatible API can run the agent. The family is read from the model's name, or set
with ``model.family``; a name that says nothing, such as ``blacksite``, gets the reference.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from .config import ModelSettings

Thinking = Literal["qwen", "toggle", "deepseek", "effort", "none"]


@dataclass(frozen=True)
class Profile:
    family: str
    label: str
    # How the model is asked to reason: Qwen3.5+ takes enable_thinking and reasoning_effort
    # in its template, "toggle" families enable_thinking only, DeepSeek a thinking flag,
    # gpt-oss the OpenAI reasoning_effort field, and "none" families never reason apart.
    thinking: Thinking
    vllm_tool_parser: str
    vllm_reasoning_parser: str | None
    llamacpp_reasoning_format: str  # --reasoning-format; deepseek returns thinking separately
    strict_tool_calling: bool  # vLLM's tool-call grammar; Qwen3.5+ never stops with it on
    speculative_mtp: bool  # has a multi-token-prediction head that vLLM can use


PROFILES: dict[str, Profile] = {item.family: item for item in (
    Profile("qwen3-hybrid", "Qwen3.5+", "qwen", "qwen3_xml", "qwen3", "deepseek", False, True),
    Profile("qwen3-coder", "Qwen3-Coder", "none", "qwen3_coder", None, "none", True, False),
    Profile("qwen3", "Qwen3", "toggle", "hermes", "qwen3", "deepseek", True, False),
    Profile("gpt-oss", "gpt-oss", "effort", "openai", "openai_gptoss", "auto", True, False),
    Profile("glm", "GLM-4.5+", "toggle", "glm45", "glm45", "deepseek", True, True),
    Profile("deepseek", "DeepSeek V3.1+", "deepseek", "deepseek_v31", "deepseek_r1", "deepseek", True, True),
    Profile("llama", "Llama", "none", "llama3_json", None, "none", True, False),
    Profile("mistral", "Mistral", "none", "mistral", None, "none", True, False),
    Profile("kimi", "Kimi K2", "none", "kimi_k2", None, "none", True, False),
    Profile("generic", "generic", "none", "hermes", None, "none", True, False),
)}
REFERENCE = PROFILES["qwen3-hybrid"]

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"qwen-?3[._-]?coder"), "qwen3-coder"),
    (re.compile(r"qwen-?3[._-]?[5-9]"), "qwen3-hybrid"),  # qwen3.8, Qwen3-5, qwen36
    (re.compile(r"qwen-?3"), "qwen3"),
    (re.compile(r"gpt-?oss"), "gpt-oss"),
    (re.compile(r"glm"), "glm"),
    (re.compile(r"deepseek"), "deepseek"),
    (re.compile(r"llama"), "llama"),
    (re.compile(r"mistral|mixtral|magistral|devstral|ministral"), "mistral"),
    (re.compile(r"kimi"), "kimi"),
    (re.compile(r"gemma|phi-?\d|nemotron|granite|olmo|smol|command-?[ar]|aya"), "generic"),
]


def profile(model: ModelSettings) -> Profile:
    """The profile ``model.family`` names, else the one the model's name implies, else the reference."""
    if model.family != "auto":
        return PROFILES[model.family]
    name = model.name.lower()
    return next((PROFILES[family] for pattern, family in _PATTERNS if pattern.search(name)), REFERENCE)


def thinking_fields(model: ModelSettings, thinking: str) -> dict[str, Any]:
    """Extra request fields that set the model's reasoning effort (none, low, or medium)."""
    mode = profile(model).thinking
    if mode == "none":
        return {}
    if mode == "effort":
        return {"reasoning_effort": "low" if thinking == "none" else thinking}
    if model.provider == "ollama":
        return {"reasoning_effort": thinking}  # Ollama translates it for each family
    if mode == "deepseek":
        return {"chat_template_kwargs": {"thinking": thinking != "none"}}
    if mode == "toggle" or thinking == "none":
        return {"chat_template_kwargs": {"enable_thinking": thinking != "none"}}
    return {"chat_template_kwargs": {"enable_thinking": True, "reasoning_effort": thinking}}
