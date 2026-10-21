import pytest

from blacksite.check import hints
from blacksite.config import ModelSettings
from blacksite.modelserver import plan
from blacksite.profiles import PROFILES, profile, thinking_fields


@pytest.mark.parametrize(("name", "family"), [
    ("blacksite-qwen3.8", "qwen3-hybrid"), ("Qwen/Qwen3.8-27B-FP8", "qwen3-hybrid"), ("qwen3-5-35b", "qwen3-hybrid"),
    ("qwen3:32b", "qwen3"), ("Qwen3-Coder-30B-A3B", "qwen3-coder"), ("gpt-oss:20b", "gpt-oss"),
    ("zai-org/GLM-4.7", "glm"), ("deepseek-v3.2", "deepseek"), ("llama3.3:70b", "llama"),
    ("mistral-small", "mistral"), ("moonshotai/Kimi-K2.5", "kimi"), ("gemma4:27b", "generic"),
    ("blacksite", "qwen3-hybrid"),  # the default served name says nothing: the reference model
])
def test_family_is_read_from_the_model_name(name: str, family: str) -> None:
    assert profile(ModelSettings(name=name)).family == family


def test_family_setting_overrides_the_name() -> None:
    assert profile(ModelSettings(name="blacksite", family="gpt-oss")).family == "gpt-oss"
    assert set(PROFILES) == {"qwen3-hybrid", "qwen3-coder", "qwen3", "gpt-oss", "glm", "deepseek", "llama",
                             "mistral", "kimi", "generic"}


@pytest.mark.parametrize(("family", "provider", "thinking", "fields"), [
    ("qwen3-hybrid", "llamacpp", "low", {"chat_template_kwargs": {"enable_thinking": True, "reasoning_effort": "low"}}),
    ("qwen3-hybrid", "vllm", "none", {"chat_template_kwargs": {"enable_thinking": False}}),
    ("qwen3-hybrid", "ollama", "medium", {"reasoning_effort": "medium"}),
    ("qwen3", "vllm", "low", {"chat_template_kwargs": {"enable_thinking": True}}),
    ("glm", "llamacpp", "none", {"chat_template_kwargs": {"enable_thinking": False}}),
    ("gpt-oss", "vllm", "none", {"reasoning_effort": "low"}),
    ("gpt-oss", "ollama", "medium", {"reasoning_effort": "medium"}),
    ("deepseek", "llamacpp", "low", {"chat_template_kwargs": {"thinking": True}}),
    ("llama", "vllm", "low", {}),
    ("llama", "ollama", "low", {}),
])
def test_thinking_fields_follow_the_family(family: str, provider: str, thinking: str, fields: dict) -> None:
    model = ModelSettings(provider=provider, name="served", family=family)  # type: ignore[arg-type]
    assert thinking_fields(model, thinking) == fields


def test_server_flags_follow_the_family(make_settings, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setenv("HF_HUB_CACHE", str(tmp_path / "empty-cache"))
    oss = plan(make_settings("model.provider=vllm", "model.name=gpt-oss-120b"), binary="vllm", offline=True)
    joined = " ".join(oss.command)
    assert "--tool-call-parser openai" in joined and "--reasoning-parser openai_gptoss" in joined
    assert "--speculative-config" not in joined and "VLLM_ENFORCE_STRICT_TOOL_CALLING" not in oss.env
    llama = plan(make_settings("model.provider=vllm", "model.name=llama-3.3-70b"), binary="vllm", offline=True)
    assert "--reasoning-parser" not in llama.command and "--tool-call-parser llama3_json" in " ".join(llama.command)
    gguf = tmp_path / "model.gguf"
    gguf.write_bytes(b"GGUF")
    local = plan(make_settings("model.provider=llamacpp", "model.name=mistral-small"), model=str(gguf),
                 binary="llama-server")
    assert local.command[local.command.index("--reasoning-format") + 1] == "none"


def test_check_hints_name_the_familys_parsers() -> None:
    oss = hints(ModelSettings(provider="vllm", name="gpt-oss-20b"))
    assert "--tool-call-parser openai" in oss["tools"] and "openai_gptoss" in oss["reasoning"]
    assert "VLLM_ENFORCE_STRICT_TOOL_CALLING" not in oss["stop"]
    qwen = hints(ModelSettings(provider="vllm", name="blacksite"))
    assert "qwen3_xml" in qwen["tools"] and "VLLM_ENFORCE_STRICT_TOOL_CALLING=0" in qwen["stop"]
    assert "no separate reasoning" in hints(ModelSettings(provider="vllm", name="llama3"))["reasoning"]
    assert "--reasoning-format deepseek" in hints(ModelSettings(provider="llamacpp", name="qwen3.8"))["reasoning"]
