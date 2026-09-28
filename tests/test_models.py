import json
import os
import shutil
import struct
import sys
import time
from pathlib import Path

import anyio
import httpx
import pytest
from starlette.testclient import TestClient

from blacksite import catalog
from blacksite.backends import Status, serving, status
from blacksite.cli import main
from blacksite.config import load_settings
from blacksite.modelserver import Launch, Supervisor
from blacksite.web import app as app_module
from blacksite.web.app import Run, create_app
from conftest import BASE_URL, sign_in
from conftest import INCIDENT

TOOL_TEMPLATE = "{% if tools %}<tools>{{ tools }}</tools>{% endif %}{% if enable_thinking %}<think>{% endif %}"


def gguf(path: Path, template: str | None = TOOL_TEMPLATE, context: int = 262_144) -> Path:
    """A minimal GGUF v3 header: strings, an integer, and a vocabulary array to skip."""
    def text(value: str) -> bytes:
        data = value.encode()
        return struct.pack("<Q", len(data)) + data

    kvs = [text("general.architecture") + struct.pack("<I", 8) + text("qwen35"),
           text("tokenizer.ggml.tokens") + struct.pack("<IIQ", 9, 8, 3) + text("a") + text("b") + text("c"),
           text("tokenizer.ggml.scores") + struct.pack("<IIQ", 9, 6, 2) + struct.pack("<ff", 0.5, 0.25),
           text("qwen35.context_length") + struct.pack("<II", 4, context)]
    if template is not None:
        kvs.append(text("tokenizer.chat_template") + struct.pack("<I", 8) + text(template))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 0, len(kvs)) + b"".join(kvs) + bytes(64))
    return path


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    """An empty home, Ollama store, and caches, so tests never see this machine's models."""
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("OLLAMA_MODELS", str(home / "ollama"))
    monkeypatch.setenv("HF_HUB_CACHE", str(home / "hub"))
    monkeypatch.setenv("LLAMA_CACHE", str(home / "llama.cpp"))
    return home


def ollama_store(root: Path, names: list[str], blob: Path, family: str = "qwen35") -> None:
    digest = "sha256-" + blob.name.removeprefix("sha256-")
    (root / "blobs").mkdir(parents=True, exist_ok=True)
    config = root / "blobs" / "sha256-config"
    config.write_text(json.dumps({"model_family": family}), encoding="utf-8")
    for name in names:
        model, _, tag = name.partition(":")
        manifest = root / "manifests" / "registry.ollama.ai" / "library" / model / (tag or "latest")
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({"config": {"digest": "sha256:config"}, "layers": [
            {"mediaType": "application/vnd.ollama.image.model", "digest": digest.replace("-", ":", 1)}]}), encoding="utf-8")


def test_gguf_header_gives_template_and_context(tmp_path: Path) -> None:
    path = gguf(tmp_path / "m.gguf")
    info = catalog.gguf_metadata(str(path))
    assert info["tokenizer.chat_template"] == TOOL_TEMPLATE and info["qwen35.context_length"] == 262_144
    (tmp_path / "junk.gguf").write_bytes(b"not a gguf")
    assert catalog.gguf_metadata(str(tmp_path / "junk.gguf")) == {}


def test_gguf_models_reuse_ollama_files_and_skip_non_chat_files(home: Path) -> None:
    blob = gguf(home / "ollama" / "blobs" / "sha256-abc")
    ollama_store(home / "ollama", ["qwen3.8:27b-q4_K_M", "blacksite-qwen3.8"], blob)
    hub = home / "hub" / "models--org--repo" / "snapshots" / "s1"
    gguf(hub / "Chat-Q4_K_M.gguf")
    gguf(hub / "Chat-Q4_K_M-00002-of-00003.gguf")  # later shard of a split file
    gguf(hub / "mmproj-Chat-f16.gguf")  # vision projector
    gguf(home / "llama.cpp" / "nomic-embed-text.gguf")
    gguf(home / ".lmstudio" / "models" / "Plain.gguf", template="{{ messages }}")
    gguf(home / ".lmstudio" / "models" / "Bare.gguf", template=None)
    models = {model.label: model for model in catalog.gguf_models()}
    assert set(models) == {"qwen3.8:27b-q4_K_M", "Chat-Q4_K_M", "Plain", "Bare"}  # one entry per file
    assert models["qwen3.8:27b-q4_K_M"].id == str(blob) and models["qwen3.8:27b-q4_K_M"].source == "Ollama"
    assert models["Chat-Q4_K_M"].usable and models["Chat-Q4_K_M"].context == 262_144
    assert (models["Plain"].usable, models["Plain"].note) == (False, "no-tools")
    assert (models["Bare"].usable, models["Bare"].note) == (False, "no-template")


def test_hf_models_lists_chat_models_with_weights(home: Path) -> None:
    def repo(name: str, architecture: str, template: str | None, weights: bool = True, ref: bool = False) -> None:
        root = home / "hub" / f"models--{name.replace('/', '--')}"
        folder = root / "snapshots" / "main1"
        folder.mkdir(parents=True)
        (folder / "config.json").write_text(json.dumps({"architectures": [architecture]}), encoding="utf-8")
        if template is not None:
            (folder / "chat_template.jinja").write_text(template, encoding="utf-8")
        if weights:
            (folder / "model.safetensors").write_bytes(bytes(2048))
        if ref:
            (root / "refs").mkdir()
            (root / "refs" / "main").write_text("main1", encoding="utf-8")

    repo("mlx-community/Qwen3.8-27B-4bit", "Qwen3_5ForConditionalGeneration", TOOL_TEMPLATE, ref=True)
    repo("acme/Chat-Only", "LlamaForCausalLM", "{{ messages }}")
    repo("sentence-transformers/all-MiniLM-L6-v2", "BertModel", None)
    repo("acme/No-Weights", "LlamaForCausalLM", TOOL_TEMPLATE, weights=False)
    models = catalog.hf_models()
    assert [(model.id, model.usable, model.note) for model in models] == [
        ("mlx-community/Qwen3.8-27B-4bit", True, ""), ("acme/Chat-Only", False, "no-tools")]
    assert models[0].label == "Qwen3.8-27B-4bit" and models[0].size == 2048 and models[0].thinking


def test_ollama_models_read_capabilities_and_context() -> None:
    shows = {
        "blacksite-qwen3.8": {"capabilities": ["completion", "tools", "thinking"], "parameters": "num_ctx                        65536"},
        "gemma3:27b": {"capabilities": ["completion", "vision"]},
        "nomic-embed-text": {"capabilities": ["embedding"]},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "blacksite-qwen3.8:latest", "size": 17}, {"name": "gemma3:27b"},
                                                        {"name": "nomic-embed-text:latest"}]})
        return httpx.Response(200, json=shows[json.loads(request.content)["model"]])

    models = anyio.run(catalog.ollama_models, "http://ollama", httpx.MockTransport(handler))
    assert [(model.id, model.usable, model.note, model.context, model.thinking) for model in models] == [
        ("blacksite-qwen3.8", True, "", 65536, True), ("gemma3:27b", False, "no-tools", 0, False)]


def test_ollama_status_reports_a_context_too_small_for_the_agent(make_settings) -> None:
    model = make_settings("model.provider=ollama", "model.base_url=http://ollama/v1", "model.name=qwen").model

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/show":
            return httpx.Response(200, json={"details": {}})
        return httpx.Response(200, json={"models": [{"name": "qwen:latest", "context_length": 4096}]})

    result = anyio.run(status, model, httpx.MockTransport(handler))
    assert not result.loaded and not result.loading and "4096-token context" in result.detail and "llama.cpp" in result.detail


def test_serving_names_what_each_server_runs(make_settings) -> None:
    routes = {
        "/api/ps": {"models": [{"name": "qwen:latest", "model": "qwen:latest"}]},
        "/v1/models": {"data": [{"id": "Qwen3.8", "root": "/cache/models--org--Qwen3.8/snapshots/1"}]},
        "/props": {"model_path": "/models/qwen.gguf"},
    }
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=routes[request.url.path]))
    found = {provider: anyio.run(serving, make_settings(f"model.provider={provider}", "model.base_url=http://host/v1").model,
                                 transport) for provider in ("ollama", "llamacpp", "vllm")}
    assert found["ollama"] == [{"name": "qwen", "source": "qwen"}]
    assert found["llamacpp"] == [{"name": "Qwen3.8", "source": "/models/qwen.gguf"}]
    assert found["vllm"] == [{"name": "Qwen3.8", "source": "/cache/models--org--Qwen3.8/snapshots/1"}]


def test_supervisor_explains_a_server_that_exits(tmp_path: Path) -> None:
    supervisor = Supervisor(tmp_path / "server.log")
    code = "import sys; print('loading'); print('error: unknown model architecture'); sys.exit(1)"
    supervisor.start(Launch([sys.executable, "-c", code], dict(os.environ)), "llamacpp", "http://x/v1", "m")
    deadline = time.monotonic() + 20
    while supervisor.running and time.monotonic() < deadline:
        time.sleep(0.1)
    assert supervisor.failure() == "error: unknown model architecture"
    supervisor.stop()


# The page's model picker ---------------------------------------------------------------

GGUF = catalog.LocalModel(id="/models/qwen.gguf", label="qwen3.8:27b", size=10, source="Ollama")
BARE = catalog.LocalModel(id="/models/gemma4.gguf", label="gemma4", source="Ollama", usable=False, note="no-template")
OLLAMA = [catalog.LocalModel(id="blacksite-qwen3.8", label="blacksite-qwen3.8", source="Ollama", thinking=True, context=65536),
          catalog.LocalModel(id="plain:7b", label="plain:7b", source="Ollama", thinking=False)]


@pytest.fixture
def demo(tmp_path: Path, monkeypatch):
    config = tmp_path / "blacksite.toml"
    config.write_text('[model]\nprovider = "ollama"\nbase_url = "http://127.0.0.1:9/v1"\nname = "blacksite-qwen3.8"\n'
                      '[learning]\nstore_path = "learning.sqlite"\n', encoding="utf-8")
    incidents = tmp_path / "incidents"
    shutil.copytree(INCIDENT, incidents / "nginx-502-oom")
    servers: dict[str, list[dict[str, str]]] = {"ollama": [], "llamacpp": [], "vllm": []}
    launched: list[Launch] = []

    async def fake_ollama(root, transport=None):
        return OLLAMA

    async def fake_status(model, transport=None):
        up = model.provider == "ollama" or bool(servers[model.provider])
        return Status(up, up and model.provider == "ollama")

    async def fake_serving(model, transport=None):
        return servers[model.provider]

    async def nothing(*args, **kwargs):
        return None

    def fake_plan(settings, model=None, from_ollama=None, binary=None, offline=False, extra=()):
        launch = Launch([sys.executable, "-c", "import time; time.sleep(60)"], dict(os.environ))
        launched.append(launch)
        assert settings.model.provider == "llamacpp" and model == GGUF.id and offline
        return launch

    monkeypatch.setattr(catalog, "ollama_models", fake_ollama)
    monkeypatch.setattr(catalog, "gguf_models", lambda: [GGUF, BARE])
    monkeypatch.setattr(catalog, "hf_models", lambda: [])
    monkeypatch.setattr(app_module, "find_llama_server", lambda: "llama-server")
    monkeypatch.setattr(app_module, "find_vllm", lambda: (_ for _ in ()).throw(app_module.ModelServerError("vllm is not installed")))
    monkeypatch.setattr(app_module, "backend_status", fake_status)
    monkeypatch.setattr(app_module, "serving", fake_serving)
    monkeypatch.setattr(app_module, "plan", fake_plan)
    monkeypatch.setattr(app_module, "_unload_ollama", nothing)
    monkeypatch.setattr(app_module, "_warm_ollama", nothing)
    with TestClient(create_app(config, [], incidents), base_url=BASE_URL) as client:
        sign_in(client, "admin", "admin")
        client.servers, client.launched = servers, launched
        yield client


def test_picker_lists_each_server_and_its_models(demo) -> None:
    data = demo.get("/api/models").json()
    backends = {entry["id"]: entry for entry in data["backends"]}
    assert data["current"]["provider"] == "ollama" and data["context"] == 65536
    assert [model["in_use"] for model in backends["ollama"]["models"]] == [True, False]
    assert backends["llamacpp"]["base_url"] == "http://127.0.0.1:8080/v1" and not backends["llamacpp"]["running"]
    assert [(model["label"], model["usable"]) for model in backends["llamacpp"]["models"]] == [("qwen3.8:27b", True), ("gemma4", False)]
    assert not backends["vllm"]["installed"] and "not installed" in backends["vllm"]["detail"]


def test_picker_starts_and_stops_llama_cpp(demo) -> None:
    response = demo.post("/api/models", json={"provider": "llamacpp", "model": GGUF.id})
    assert response.status_code == 200, response.text
    state = demo.app.state.demo
    assert state.server.running and state.model == {"provider": "llamacpp", "base_url": "http://127.0.0.1:8080/v1",
                                                    "name": "qwen3.8-27b"}
    status = demo.get("/api/status").json()
    assert status["loading"] and status["detail"] == "starting llama.cpp with qwen3.8:27b"
    assert [model["in_use"] for model in response.json()["backends"][1]["models"]] == [True, False]
    demo.post("/api/models", json={"action": "stop"})
    assert not state.server.running
    # Back to Ollama: a model without thinking turns the thinking switch off.
    assert demo.post("/api/models", json={"provider": "ollama", "model": "plain:7b"}).status_code == 200
    assert state.model["name"] == "plain:7b" and state.switches["thinking"] == "none"


def test_picker_refuses_unknown_paths_busy_servers_and_running_investigations(demo) -> None:
    def error(body: dict) -> str:
        response = demo.post("/api/models", json=body)
        assert response.status_code == 400
        return response.json()["error"]

    assert error({"provider": "llamacpp", "model": "/etc/passwd"}) == "That model is not on this computer."
    assert "no chat template" in error({"provider": "llamacpp", "model": BARE.id})
    assert "not installed" in error({"provider": "vllm", "model": "x"})
    demo.servers["llamacpp"] = [{"name": "other", "source": "/models/other.gguf"}]
    assert "did not start it" in error({"provider": "llamacpp", "model": GGUF.id})
    demo.servers["llamacpp"] = [{"name": "qwen-external", "source": GGUF.id}]
    assert demo.post("/api/models", json={"provider": "llamacpp", "model": GGUF.id}).status_code == 200
    state = demo.app.state.demo
    assert state.model["name"] == "qwen-external" and not state.server.running and not demo.launched  # used as it is
    state.runs["nginx-502-oom"] = Run()
    assert "Wait for the running investigation" in error({"provider": "ollama", "model": "blacksite-qwen3.8"})


def test_models_command_lists_every_server(tmp_path: Path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    async def no_ollama(root, transport=None):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(catalog, "ollama_models", no_ollama)
    monkeypatch.setattr(catalog, "gguf_models", lambda: [GGUF, BARE])
    monkeypatch.setattr(catalog, "hf_models", lambda: [])
    assert main(["models"]) == 0
    out = capsys.readouterr().out
    assert "Ollama: not running at http://127.0.0.1:11434/v1" in out
    assert "llama.cpp (2 models)" in out and "no chat template in the file" in out and f"--model {GGUF.id}" in out
    assert "vLLM (0 models)" in out
    assert load_settings(environ={}, cwd=tmp_path).model.context == 65536
