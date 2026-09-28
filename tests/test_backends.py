import json
import re
import sys
from pathlib import Path

import anyio
import httpx
import pytest

from blacksite import modelserver
from blacksite.backends import agent_model, agent_settings, status, thinking_fields
from blacksite.check import run_checks
from blacksite.cli import main
from blacksite.llm import ChatClient
from blacksite.modelserver import ModelServerError, ollama_model_path, plan

BACKENDS = {
    "ollama": "http://localhost:11434/v1",
    "llamacpp": "http://127.0.0.1:8080/v1",
    "vllm": "http://127.0.0.1:8000/v1",
}


def backend(make_settings, provider: str, *overrides: str):
    return make_settings(f"model.provider={provider}", f"model.base_url={BACKENDS[provider]}",
                         "model.name=blacksite-qwen3.8", *overrides)


@pytest.mark.parametrize("provider", ["llamacpp", "vllm"])
def test_template_servers_get_thinking_through_chat_template_kwargs(provider) -> None:
    assert thinking_fields(provider, "low") == {"chat_template_kwargs": {"enable_thinking": True, "reasoning_effort": "low"}}
    assert thinking_fields(provider, "none") == {"chat_template_kwargs": {"enable_thinking": False}}
    assert thinking_fields("ollama", "medium") == {"reasoning_effort": "medium"}


@pytest.mark.filterwarnings("ignore:`httpx.AsyncClient` support")  # the injected mock client
@pytest.mark.parametrize("provider", sorted(BACKENDS))
def test_agent_requests_carry_each_servers_thinking_fields(make_settings, provider) -> None:
    from pydantic_ai import Agent

    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={
            "id": "1", "object": "chat.completion", "created": 0, "model": "blacksite-qwen3.8",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "done", "reasoning_content": "hm"}}],
        })

    settings = backend(make_settings, provider)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    agent = Agent(agent_model(settings, client), model_settings=agent_settings(settings))
    assert agent.run_sync("hello").output == "done"
    body = bodies[0]
    assert body["model"] == "blacksite-qwen3.8"
    assert 12_000 in (body.get("max_tokens"), body.get("max_completion_tokens"))
    if provider == "ollama":
        assert body["reasoning_effort"] == "low" and "chat_template_kwargs" not in body
    else:
        assert body["chat_template_kwargs"] == {"enable_thinking": True, "reasoning_effort": "low"}
        assert "reasoning_effort" not in body  # the template would think at xhigh or reject it


@pytest.mark.parametrize("provider", sorted(BACKENDS))
def test_chat_client_sends_the_same_thinking_fields(make_settings, provider) -> None:
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}]})

    settings = backend(make_settings, provider)
    ChatClient(settings.model, httpx.MockTransport(handler), thinking="none").complete([])
    assert {key: value for key, value in bodies[0].items() if key not in ("model", "messages", "max_tokens")} \
        == thinking_fields(provider, "none")


def serve(routes: dict[str, httpx.Response]) -> httpx.AsyncBaseTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return routes.get(f"{request.method} {request.url.path}", httpx.Response(404))

    return httpx.MockTransport(handler)


def test_status_reads_each_servers_health_endpoints(make_settings) -> None:
    llamacpp = backend(make_settings, "llamacpp").model
    vllm = backend(make_settings, "vllm").model
    ollama = backend(make_settings, "ollama").model
    models = httpx.Response(200, json={"data": [{"id": "blacksite-qwen3.8"}]})
    cases = [
        (llamacpp, {"GET /health": httpx.Response(200)}, (True, True)),
        (llamacpp, {"GET /health": httpx.Response(503)}, (True, False, "loading the model", True)),
        (vllm, {"GET /health": httpx.Response(200), "GET /v1/models": models}, (True, True)),
        (vllm, {"GET /health": httpx.Response(200), "GET /v1/models": httpx.Response(200, json={"data": [{"id": "other"}]})},
         (True, False, "serving other, not blacksite-qwen3.8", False)),
        (ollama, {"GET /api/ps": httpx.Response(200, json={"models": [{"name": "qwen3.8:27b-q4_K_M"}]}),
                  "POST /api/show": httpx.Response(200, json={"details": {"parent_model": "qwen3.8:27b-q4_K_M"}})},
         (True, True)),
        (ollama, {"GET /api/ps": httpx.Response(200, json={"models": []}), "POST /api/show": httpx.Response(200, json={})},
         (True, False, "Ollama loads the model on the first request", True)),
        (ollama, {"GET /api/ps": httpx.Response(200, json={"models": []}), "POST /api/show": httpx.Response(404)},
         (True, False, "model blacksite-qwen3.8 is not installed in Ollama", False)),
    ]
    for model, routes, expected in cases:
        result = anyio.run(status, model, serve(routes))
        assert (result.reachable, result.loaded, result.detail, result.loading)[:len(expected)] == expected, model.provider

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    down = anyio.run(status, vllm, httpx.MockTransport(refuse))
    assert (down.reachable, down.detail) == (False, "no answer from http://127.0.0.1:8000")


def fake_server(tool_call: bool = True, runaway: bool = False):
    """A llama-server stand-in that behaves like Qwen3.8 with --jinja and --reasoning-format deepseek."""
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200)
        body = json.loads(request.content)
        bodies.append(body)
        call = {"id": "c1", "type": "function", "function": {"name": "search_logs", "arguments": '{"pattern": "OOM"}'}}
        if body.get("stream"):
            chunks = [{"choices": [{"delta": {"reasoning_content": "Look for OOM."}}]},
                      {"choices": [{"delta": {"tool_calls": [{"index": 0, **call, "function": {"name": "search_logs", "arguments": ""}}]}}]},
                      {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": '{"pattern": "OOM"}'}}]}}]}]
            text = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks) + "data: [DONE]\n\n"
            return httpx.Response(200, text=text, headers={"content-type": "text/event-stream"})
        if "response_format" in body:
            content = json.dumps({"title": "Free the disk", "steps": ["find", "delete", "verify"]})
            return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})
        if body["messages"][-1]["role"] == "user" and len(body["messages"]) > 1:
            code = re.search(r"verification code (\w+)", body["messages"][2]["content"]).group(1)
            return httpx.Response(200, json={"choices": [{"message": {"content": code}}]})
        message = {"role": "assistant", "content": "", "reasoning_content": "The user wants a search.",
                   "tool_calls": [call] if tool_call else None}
        if not tool_call:
            message["content"] = '<tool_call>{"name": "search_logs"}</tool_call>'
        finish = "length" if runaway else "tool_calls"
        return httpx.Response(200, json={"choices": [{"message": message, "finish_reason": finish}]})

    return bodies, handler


def test_check_passes_on_a_server_that_does_everything(make_settings) -> None:
    bodies, handler = fake_server()
    settings = backend(make_settings, "llamacpp")
    results = list(run_checks(settings, httpx.MockTransport(handler), httpx.MockTransport(handler)))
    assert [(result.name, result.ok) for result in results] == [
        ("Server", True), ("Tool call", True), ("Tool result", True), ("Streaming", True),
        ("Reasoning", True), ("Structured JSON", True)]
    assert results[3].detail == "tool call arrived in 2 chunks"
    assert all(body["chat_template_kwargs"]["reasoning_effort"] == "low" for body in bodies)


def test_check_explains_a_server_without_tool_parsing(make_settings) -> None:
    _, handler = fake_server(tool_call=False)
    results = {result.name: result for result in run_checks(
        backend(make_settings, "vllm"), httpx.MockTransport(handler), httpx.MockTransport(handler))}
    assert not results["Server"].ok  # the stand-in lists no models for vLLM
    results = {result.name: result for result in run_checks(
        backend(make_settings, "llamacpp"), httpx.MockTransport(handler), httpx.MockTransport(handler))}
    assert not results["Tool call"].ok and "--jinja" in results["Tool call"].hint
    assert not results["Tool result"].ok and results["Tool result"].detail.startswith("skipped")


def test_check_catches_a_model_that_does_not_stop_after_a_tool_call(make_settings) -> None:
    _, handler = fake_server(runaway=True)
    results = {result.name: result for result in run_checks(
        backend(make_settings, "llamacpp"), httpx.MockTransport(handler), httpx.MockTransport(handler))}
    assert not results["Tool call"].ok and "until max_tokens" in results["Tool call"].detail


def test_check_command_stops_after_an_unreachable_server(make_settings, tmp_path: Path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["--set", "model.provider=llamacpp", "--set", "model.base_url=http://127.0.0.1:9/v1",
                 "--set", "model.timeout=2", "check"]) == 1
    out = capsys.readouterr().out
    assert "FAIL Server" in out and "blacksite serve model" in out and "Tool call" not in out


def fake_ollama(root: Path, name: str = "library/qwen3.8", tag: str = "27b-q4_K_M") -> Path:
    blob = root / "blobs" / "sha256-abc"
    blob.parent.mkdir(parents=True)
    blob.write_bytes(b"GGUF")
    manifest = root / "manifests" / "registry.ollama.ai" / name / tag
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"layers": [
        {"mediaType": "application/vnd.ollama.image.template", "digest": "sha256:def"},
        {"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:abc"}]}), encoding="utf-8")
    return blob


def test_ollama_models_resolve_to_their_gguf(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path))
    blob = fake_ollama(tmp_path)
    assert ollama_model_path("qwen3.8:27b-q4_K_M") == blob
    with pytest.raises(ModelServerError, match="ollama list"):
        ollama_model_path("qwen3.8")  # the latest tag was never pulled


def test_llama_server_command_matches_the_agent_settings(make_settings, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "ollama"))
    monkeypatch.setenv("LLAMA_API_KEY", "secret")
    blob = fake_ollama(tmp_path / "ollama")
    settings = backend(make_settings, "llamacpp", "model.api_key_env=LLAMA_API_KEY", "model.context=32768")
    command = plan(settings, from_ollama="qwen3.8:27b-q4_K_M", binary="llama-server").command
    assert command[:3] == ["llama-server", "-m", str(blob)]
    joined = " ".join(command)
    for flag in ("--alias blacksite-qwen3.8", "--host 127.0.0.1", "--port 8080", "-c 32768", "-np 1", "--jinja",
                 "--reasoning-format deepseek", "--api-key secret"):
        assert flag in joined
    with pytest.raises(ModelServerError, match="--from-ollama"):
        plan(settings, binary="llama-server")
    with pytest.raises(ModelServerError, match="No GGUF"):
        plan(settings, model=str(tmp_path / "missing.gguf"), binary="llama-server")


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_vllm_command_enables_tool_and_reasoning_parsers(make_settings, tmp_path: Path, monkeypatch, platform) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setenv("HF_HUB_CACHE", str(tmp_path / "empty-cache"))
    monkeypatch.delenv("VLLM_API_KEY", raising=False)
    launch = plan(backend(make_settings, "vllm"), binary="vllm", offline=True)
    joined = " ".join(launch.command)
    assert launch.command[:2] == ["vllm", "serve"]
    for flag in ("--served-model-name blacksite-qwen3.8", "--port 8000", "--max-model-len 65536",
                 "--enable-auto-tool-choice", "--tool-call-parser qwen3_xml", "--reasoning-parser qwen3"):
        assert flag in joined
    assert "--api-key" not in joined
    assert launch.env["VLLM_NO_USAGE_STATS"] == "1" and launch.env["HF_HUB_OFFLINE"] == "1"
    assert launch.env["VLLM_ENFORCE_STRICT_TOOL_CALLING"] == "0"
    if platform == "darwin":
        assert launch.command[2] == "mlx-community/Qwen3.8-27B-4bit" and "--kv-cache-dtype" not in joined
        assert "--gpu-memory-utilization" not in joined  # weights not downloaded: keep vLLM's default
    else:
        assert launch.command[2] == "Qwen/Qwen3.8-27B-FP8" and "--kv-cache-dtype fp8" in joined
        assert '"method": "mtp"' in joined


def test_mac_vllm_reserves_the_weights_plus_headroom(make_settings, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setenv("HF_HUB_CACHE", str(tmp_path))
    snapshot = tmp_path / "models--mlx-community--Qwen3.8-27B-4bit" / "snapshots" / "abc"
    snapshot.mkdir(parents=True)
    # Scaled down 1024 times: 15 GiB of weights and 9 GiB of headroom on a 96 GiB Mac.
    (snapshot / "model-00001-of-00001.safetensors").write_bytes(bytes(15 * 2**20))
    monkeypatch.setattr(modelserver, "METAL_HEADROOM", 9 * 2**20)
    ram = {"SC_PAGE_SIZE": 2**14, "SC_PHYS_PAGES": 96 * 2**20 // 2**14}
    monkeypatch.setattr(modelserver.os, "sysconf", ram.__getitem__, raising=False)  # Windows has no sysconf
    assert modelserver.metal_memory_fraction("mlx-community/Qwen3.8-27B-4bit") == 0.34
    command = plan(backend(make_settings, "vllm"), binary="vllm").command
    assert command[-2:] == ["--gpu-memory-utilization", "0.34"]
    command = plan(backend(make_settings, "vllm"), binary="vllm", extra=["--gpu-memory-utilization=0.5"]).command
    assert command.count("--gpu-memory-utilization") == 0 and command[-1] == "--gpu-memory-utilization=0.5"
    ram["SC_PHYS_PAGES"] = 32 * 2**20 // 2**14  # a small Mac: never more than 90%
    assert modelserver.metal_memory_fraction("mlx-community/Qwen3.8-27B-4bit") == 0.9


def test_serve_model_dry_run_and_missing_binaries(tmp_path: Path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(modelserver.shutil, "which", lambda name: None)
    assert main(["--set", "model.provider=vllm", "serve", "model", "--binary", "vllm", "--dry-run",
                 "--", "--tensor-parallel-size", "2"]) == 0
    out = capsys.readouterr().out
    assert "VLLM_ENFORCE_STRICT_TOOL_CALLING=0 vllm serve " in out and out.rstrip().endswith("--tensor-parallel-size 2")
    assert main(["--set", "model.provider=vllm", "serve", "model"]) == 1
    assert "vllm is not installed" in capsys.readouterr().err
    assert main(["--set", "model.provider=ollama", "serve", "model"]) == 1
    assert "ollama create" in capsys.readouterr().err
