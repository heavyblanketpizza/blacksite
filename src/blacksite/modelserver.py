"""`blacksite serve model`: start llama.cpp or vLLM with the flags Blacksite relies on.

Port, served name, and context length come from the same ``[model]`` settings the
agent uses, so the server and the agent always agree.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from . import catalog
from .config import Settings

# Tool calls and thinking for the Qwen3.5/3.6/3.8 family (hybrid attention, XML tool calls).
VLLM_TOOL_PARSER = "qwen3_xml"
VLLM_REASONING_PARSER = "qwen3"
DEFAULT_VLLM_MODEL = {"darwin": "mlx-community/Qwen3.8-27B-4bit"}
DEFAULT_VLLM_MODEL_CUDA = "Qwen/Qwen3.8-27B-FP8"
# KV cache and runtime room to reserve beside the weights on a Mac: a 64k-token
# Qwen3.8-27B request needs about 4.5 GiB of KV cache.
METAL_HEADROOM = 9 * 2**30


class ModelServerError(ValueError):
    """The server cannot be started as asked; the message says what to install or pass."""


@dataclass(frozen=True)
class Launch:
    command: list[str]
    env: dict[str, str]


def plan(settings: Settings, model: str | None = None, from_ollama: str | None = None,
         binary: str | None = None, offline: bool = False, extra: Sequence[str] = ()) -> Launch:
    """The command that starts the configured backend; ``extra`` goes to the server as is."""
    provider = settings.model.provider
    url = urlsplit(settings.model.base_url)
    host, port = url.hostname or "127.0.0.1", str(url.port or (8080 if provider == "llamacpp" else 8000))
    key = os.environ.get(settings.model.api_key_env, "")
    env = dict(os.environ)
    if provider == "llamacpp":
        path = model or (str(ollama_model_path(from_ollama)) if from_ollama else None)
        if not path:
            raise ModelServerError("Pass --model PATH.gguf, or --from-ollama NAME to reuse a model Ollama downloaded")
        if not Path(path).is_file():
            raise ModelServerError(f"No GGUF file at {path}")
        command = [binary or find_llama_server(), "-m", path, "--alias", settings.model.name,
                   "--host", host, "--port", port, "-c", str(settings.model.context),
                   # One slot gets the whole context; --jinja applies the model's chat template
                   # (tool calls), and deepseek returns thinking in reasoning_content.
                   "-np", "1", "--jinja", "--reasoning-format", "deepseek", "-ngl", "999", "-fa", "on"]
        if key:
            command += ["--api-key", key]
        return Launch([*command, *extra], env)
    if provider == "vllm":
        executable = binary or find_vllm()
        name = model or DEFAULT_VLLM_MODEL.get(sys.platform, DEFAULT_VLLM_MODEL_CUDA)
        command = [executable, "serve", name, "--served-model-name", settings.model.name,
                   "--host", host, "--port", port, "--max-model-len", str(settings.model.context),
                   "--enable-auto-tool-choice", "--tool-call-parser", VLLM_TOOL_PARSER,
                   "--reasoning-parser", VLLM_REASONING_PARSER, "--enable-prefix-caching"]
        if sys.platform != "darwin":
            # NVIDIA: FP8 KV cache and the model's multi-token-prediction head. The Apple
            # Silicon build supports neither for this hybrid model yet.
            command += ["--kv-cache-dtype", "fp8",
                        "--speculative-config", json.dumps({"method": "mtp", "num_speculative_tokens": 3})]
        elif not any(arg.startswith("--gpu-memory-utilization") for arg in extra):
            fraction = metal_memory_fraction(name)
            if fraction:
                command += ["--gpu-memory-utilization", f"{fraction:.2f}"]
        if key:
            command += ["--api-key", key]
        env.update({"VLLM_NO_USAGE_STATS": "1", "DO_NOT_TRACK": "1"})  # vLLM reports usage by default
        # vLLM's strict tool calling adds a grammar that fixes parameter order and never lets
        # Qwen3.8 stop after a tool call: in testing it kept calling tools until max_tokens.
        # The agent validates every tool call against its schema itself.
        env["VLLM_ENFORCE_STRICT_TOOL_CALLING"] = "0"
        if offline:
            env.update({"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"})
        return Launch([*command, *extra], env)
    raise ModelServerError(
        "Ollama runs its own server. Create the model once with: ollama create blacksite-qwen3.8 -f demo/Modelfile")


def run(launch: Launch) -> int:
    """Run in the foreground until stopped with Ctrl+C."""
    try:
        return subprocess.run(launch.command, env=launch.env, check=False).returncode
    except KeyboardInterrupt:
        return 130


def metal_memory_fraction(model: str) -> float | None:
    """A GPU memory share for vLLM on Apple Silicon that leaves the rest of the machine usable.

    vllm-metal fills 92% of the GPU working set (about three quarters of RAM) with KV
    cache by default; on a laptop that pushes everything else into swap and halves the
    token rate. Reserve the weights plus headroom instead; None when the weights are
    not on disk yet, which keeps vLLM's default.
    """
    weights = weights_bytes(model)
    if not weights:
        return None
    working_set = 0.75 * os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    return min(0.9, max(0.3, math.ceil((weights + METAL_HEADROOM) / working_set * 100) / 100))


def weights_bytes(model: str) -> int:
    """Size of a model's safetensors, from a local folder or the Hugging Face cache."""
    if Path(model).is_dir():
        return catalog.weights_bytes(Path(model))
    folder = catalog.snapshot(catalog.hub_cache() / f"models--{model.replace('/', '--')}") if "/" in model else None
    return catalog.weights_bytes(folder) if folder else 0


def find_vllm() -> str:
    executable = shutil.which("vllm")
    if not executable:
        raise ModelServerError(
            "vllm is not installed. On Linux with NVIDIA GPUs: pip install vllm. "
            "On Apple Silicon: brew tap vllm-project/vllm-metal https://github.com/vllm-project/vllm-metal "
            "&& brew install vllm-project/vllm-metal/vllm-metal")
    return executable


def find_llama_server() -> str:
    """llama-server from PATH or LLAMA_SERVER; failing that, the copy Ollama ships with."""
    for candidate in (os.environ.get("LLAMA_SERVER"), shutil.which("llama-server")):
        if candidate and Path(candidate).is_file():
            return candidate
    bundled = [
        Path("/Applications/Ollama.app/Contents/Resources/llama-server"),
        Path("/usr/local/lib/ollama/llama-server"),
        Path("/usr/lib/ollama/llama-server"),
    ]
    if os.environ.get("LOCALAPPDATA"):
        bundled.append(Path(os.environ["LOCALAPPDATA"], "Programs", "Ollama", "lib", "ollama", "llama-server.exe"))
    for path in bundled:
        if path.is_file():
            return str(path)
    raise ModelServerError(
        "llama-server is not installed. Install llama.cpp (brew install llama.cpp, winget install llama.cpp, "
        "or a release from github.com/ggml-org/llama.cpp), or set LLAMA_SERVER to its path.")


def ollama_model_path(name: str) -> Path:
    """The GGUF file behind an Ollama model name, so llama.cpp can use it without a new download."""
    found = catalog.ollama_blobs().get(name.removesuffix(":latest"))
    if found is None:
        raise ModelServerError(f"Ollama has no model named {name}. Check `ollama list`.")
    return found[0]


class Supervisor:
    """The one model server the web demo started, so it can be replaced or stopped.

    It never touches a server it did not start. Output goes to a log file, whose last
    lines explain a server that exits early.
    """

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.process: subprocess.Popen[bytes] | None = None
        self.provider = ""
        self.base_url = ""
        self.model = ""

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self, launch: Launch, provider: str, base_url: str, model: str) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("wb") as log:
            self.process = subprocess.Popen(launch.command, env=launch.env, stdout=log, stderr=subprocess.STDOUT,
                                            stdin=subprocess.DEVNULL)
        self.provider, self.base_url, self.model = provider, base_url, model

    def stop(self, timeout: float = 20) -> None:
        """Stop the server and wait for it, so its memory is free before the next one starts."""
        process, self.process = self.process, None
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def failure(self) -> str:
        """Why the server exited, from the end of its log; '' while it runs or was never started."""
        if self.process is None or self.process.poll() is None:
            return ""
        try:
            lines = self.log_path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        except OSError:
            lines = []
        important = [line for line in lines if re.search(r"error|failed|exception|not found|unsupported", line, re.I)]
        return (important or lines or [f"exited with code {self.process.returncode}"])[-1].strip()[:300]
