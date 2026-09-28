"""Models already on this computer, for each model server Blacksite can use.

Nothing here downloads anything. Ollama is asked what it has installed; llama.cpp can use
GGUF files from Ollama's store, the Hugging Face cache, LM Studio, and llama.cpp's own
cache; vLLM can use models in the Hugging Face cache. A model the agent cannot drive
(no tool calling) is listed with the reason instead of being hidden.
"""

from __future__ import annotations

import json
import os
import re
import struct
import sys
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

MODEL_LAYER = "application/vnd.ollama.image.model"
NOT_CHAT = re.compile(r"embed|rerank|bert|minilm|clip|whisper|mmproj", re.IGNORECASE)


@dataclass(frozen=True)
class LocalModel:
    id: str  # what the server loads: an Ollama name, a GGUF path, or a Hugging Face ID
    label: str  # the short name people see
    size: int = 0  # bytes on disk; 0 when unknown
    source: str = ""
    usable: bool = True
    note: str = ""  # why it cannot be used: "no-tools" (the agent needs tool calling) or "no-template"
    thinking: bool | None = None  # None when unknown
    # Ollama: num_ctx set on the model (0: Ollama's context-length setting applies).
    # GGUF: the longest context the model supports.
    context: int = 0

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


# Ollama ----------------------------------------------------------------------------------

async def ollama_models(root: str, transport: httpx.AsyncBaseTransport | None = None) -> list[LocalModel]:
    """Installed Ollama models, with what each can do. Raises httpx.HTTPError when Ollama is not running."""
    models = []
    async with httpx.AsyncClient(timeout=5, transport=transport) as client:
        tags = (await client.get(f"{root}/api/tags")).json().get("models", [])
        for tag in tags:
            name = str(tag.get("name", "")).removesuffix(":latest")
            show = (await client.post(f"{root}/api/show", json={"model": name})).json()
            capabilities = set(show.get("capabilities") or [])
            if "completion" not in capabilities:
                continue  # embedding models
            context = next((int(line.split()[1]) for line in str(show.get("parameters") or "").splitlines()
                            if line.split()[:1] == ["num_ctx"]), 0)
            usable = "tools" in capabilities
            models.append(LocalModel(
                id=name, label=name, size=int(tag.get("size") or 0), source="Ollama", usable=usable,
                note="" if usable else "no-tools", thinking="thinking" in capabilities, context=context))
    return sorted(models, key=lambda model: (not model.usable, model.label))


def ollama_roots() -> list[Path]:
    roots = [Path(os.environ["OLLAMA_MODELS"])] if os.environ.get("OLLAMA_MODELS") else []
    return [*roots, Path.home() / ".ollama" / "models", Path("/usr/share/ollama/.ollama/models")]


def ollama_blobs() -> dict[str, tuple[Path, str]]:
    """Ollama model names mapped to (GGUF blob, family), read from Ollama's store on disk."""
    found: dict[str, tuple[Path, str]] = {}
    for root in ollama_roots():
        registry = root / "manifests" / "registry.ollama.ai"
        for manifest in sorted(registry.glob("*/*/*")) if registry.is_dir() else []:
            namespace, model, tag = manifest.relative_to(registry).parts
            name = f"{'' if namespace == 'library' else namespace + '/'}{model}:{tag}".removesuffix(":latest")
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                digest = next(layer["digest"] for layer in data.get("layers", []) if layer.get("mediaType") == MODEL_LAYER)
                config = root / "blobs" / str(data.get("config", {}).get("digest", "")).replace(":", "-")
                family = json.loads(config.read_text(encoding="utf-8")).get("model_family", "") if config.is_file() else ""
            except (OSError, ValueError, KeyError, StopIteration):
                continue
            blob = root / "blobs" / digest.replace(":", "-")
            if blob.is_file() and name not in found:
                found[name] = (blob, str(family))
    return found


# llama.cpp ---------------------------------------------------------------------------------

# GGUF value types: fixed sizes by type number; 8 is a string and 9 an array.
_GGUF_SIZES = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
_GGUF_INTS = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 10: "<Q", 11: "<q"}


@lru_cache(maxsize=64)
def gguf_metadata(path: str, mtime: float = 0.0) -> dict[str, Any]:
    """String and integer metadata from a GGUF header (the chat template, context length).

    Reads only the header, skipping arrays such as the vocabulary; {} for anything that is
    not a readable GGUF file. ``mtime`` keys the cache.
    """
    found: dict[str, Any] = {}
    try:
        with open(path, "rb") as file:
            read = file.read
            if read(4) != b"GGUF" or struct.unpack("<I", read(4))[0] < 2:
                return {}
            _, count = struct.unpack("<QQ", read(16))

            def string() -> bytes:
                return read(struct.unpack("<Q", read(8))[0])

            def skip(kind: int) -> None:
                if kind == 8:
                    string()
                elif kind == 9:
                    inner, length = struct.unpack("<IQ", read(12))
                    if inner in _GGUF_SIZES:
                        file.seek(_GGUF_SIZES[inner] * length, os.SEEK_CUR)
                    else:
                        for _ in range(length):
                            skip(inner)
                elif kind in _GGUF_SIZES:
                    file.seek(_GGUF_SIZES[kind], os.SEEK_CUR)
                else:
                    raise ValueError(f"unknown GGUF value type {kind}")

            for _ in range(min(count, 100_000)):
                key = string().decode("utf-8", "replace")
                kind = struct.unpack("<I", read(4))[0]
                if kind == 8 and (key.endswith((".chat_template", ".name")) or key == "general.architecture"):
                    found[key] = string().decode("utf-8", "replace")
                elif kind in _GGUF_INTS and key.endswith(".context_length"):
                    found[key] = struct.unpack(_GGUF_INTS[kind], read(_GGUF_SIZES[kind]))[0]
                else:
                    skip(kind)
    except (OSError, ValueError, struct.error, MemoryError):
        return found
    return found


def gguf_model(path: Path, label: str, source: str) -> LocalModel:
    info = gguf_metadata(str(path), path.stat().st_mtime)
    template = str(info.get("tokenizer.chat_template", ""))
    usable = "tool" in template
    context = next((int(value) for key, value in info.items() if key.endswith(".context_length")), 0)
    # Ollama keeps some models' templates outside the file; llama.cpp then has none to use.
    note = "" if usable else "no-tools" if template else "no-template"
    return LocalModel(id=str(path), label=label, size=path.stat().st_size, source=source, usable=usable,
                      note=note, thinking="enable_thinking" in template or None, context=context)

def gguf_dirs() -> list[tuple[Path, str]]:
    cache = os.environ.get("LLAMA_CACHE") or (
        Path.home() / "Library" / "Caches" / "llama.cpp" if sys.platform == "darwin"
        else Path(os.environ.get("LOCALAPPDATA", Path.home())) / "llama.cpp" if os.name == "nt"
        else Path.home() / ".cache" / "llama.cpp")
    return [(hub_cache(), "Hugging Face cache"), (Path(cache), "llama.cpp cache"),
            (Path.home() / ".lmstudio" / "models", "LM Studio"), (Path.home() / ".cache" / "lm-studio" / "models", "LM Studio")]


def gguf_models() -> list[LocalModel]:
    """GGUF files llama.cpp can load, one entry per file, reusing Ollama's downloads when present."""
    models: dict[Path, LocalModel] = {}
    # Several Ollama names can share one blob (an alias with a larger context, for example).
    for name, (blob, family) in sorted(ollama_blobs().items(), key=lambda item: (item[0].startswith("blacksite-"), item[0])):
        if blob in models or NOT_CHAT.search(name) or NOT_CHAT.search(family):
            continue
        models[blob] = gguf_model(blob, name, "Ollama")
    for folder, source in gguf_dirs():
        for path in sorted(folder.rglob("*.gguf")) if folder.is_dir() else []:
            if NOT_CHAT.search(path.name) or re.search(r"-0000[2-9]-of-|-000[1-9]\d-of-", path.name):
                continue  # projectors, embedding models, and later shards of split files
            resolved = path.resolve()
            if resolved not in models and resolved.is_file():
                models[resolved] = gguf_model(path, path.stem, source)
    return sorted(models.values(), key=lambda model: (not model.usable, model.label))


# vLLM --------------------------------------------------------------------------------------

def hub_cache() -> Path:
    if os.environ.get("HF_HUB_CACHE"):
        return Path(os.environ["HF_HUB_CACHE"])
    return Path(os.environ.get("HF_HOME") or Path.home() / ".cache" / "huggingface") / "hub"


def snapshot(repo: Path) -> Path | None:
    """The snapshot folder that refs/main points to, or the newest one."""
    ref = repo / "refs" / "main"
    if ref.is_file():
        folder = repo / "snapshots" / ref.read_text(encoding="utf-8").strip()
        if folder.is_dir():
            return folder
    folders = sorted((repo / "snapshots").glob("*"), key=lambda path: path.stat().st_mtime) if (repo / "snapshots").is_dir() else []
    return folders[-1] if folders else None


def weights_bytes(folder: Path) -> int:
    return sum(path.stat().st_size for path in folder.glob("*.safetensors") if path.exists())


def chat_template(folder: Path) -> str | None:
    for name in ("chat_template.jinja", "chat_template.json"):
        if (folder / name).is_file():
            return (folder / name).read_text(encoding="utf-8", errors="replace")
    try:
        template = json.loads((folder / "tokenizer_config.json").read_text(encoding="utf-8")).get("chat_template")
    except (OSError, ValueError):
        return None
    if isinstance(template, list):  # named templates
        template = " ".join(str(item.get("template", "")) for item in template if isinstance(item, dict))
    return template if isinstance(template, str) else None


def hf_models() -> list[LocalModel]:
    """Chat models in the Hugging Face cache that vLLM can serve."""
    models = []
    for repo in sorted(hub_cache().glob("models--*")) if hub_cache().is_dir() else []:
        repo_id = repo.name.removeprefix("models--").replace("--", "/")
        folder = snapshot(repo)
        if folder is None or NOT_CHAT.search(repo_id):
            continue
        try:
            config = json.loads((folder / "config.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        architectures = config.get("architectures") or []
        size = weights_bytes(folder)
        template = chat_template(folder)
        if not size or template is None or not any(str(arch).endswith(("ForCausalLM", "ForConditionalGeneration"))
                                                   for arch in architectures):
            continue
        usable = "tool" in template
        models.append(LocalModel(id=repo_id, label=repo_id.split("/")[-1], size=size, source="Hugging Face cache",
                                 usable=usable, note="" if usable else "no-tools",
                                 thinking="enable_thinking" in template or None))
    return sorted(models, key=lambda model: (not model.usable, model.label))


def served_name(model: LocalModel) -> str:
    """The name llama.cpp or vLLM serves a model under, which is also what the demo shows."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", model.label).strip("-") or "model"

