"""Settings, including the switches for retrieval (RAG) and learning.

Precedence, lowest first: built-in defaults, a TOML file, ``BLACKSITE__SECTION__KEY``
environment variables, then ``--set section.key=value`` overrides. Retrieval and both
learning features default to off: each has to beat the plain baseline in evaluation
before a deployment turns it on, because extra context can also make an agent worse.
Relative paths resolve against the config file's directory, or the current directory
when no file is used.
"""

from __future__ import annotations

import dataclasses
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping, get_args, get_origin, get_type_hints

CONFIG_ENV = "BLACKSITE_CONFIG"
ENV_PREFIX = "BLACKSITE__"
DEFAULT_CONFIG_NAME = "blacksite.toml"

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


class ConfigError(ValueError):
    """A setting is unknown or has an invalid value."""


@dataclass(frozen=True)
class ModelSettings:
    """The OpenAI-compatible endpoint used by the agent and for reflection."""

    # vllm (GPU servers), llamacpp (llama-server, any hardware), or ollama. All speak the
    # OpenAI-compatible API; blacksite.backends handles their differences.
    provider: Literal["vllm", "llamacpp", "ollama"] = "vllm"
    base_url: str = "http://localhost:8000/v1"
    name: str = "blacksite"
    api_key_env: str = "VLLM_API_KEY"
    timeout: float = 600.0
    # Context length `blacksite serve model` gives llama.cpp and vLLM (Ollama: demo/Modelfile).
    context: int = 65_536


@dataclass(frozen=True)
class AgentSettings:
    # Reasoning effort per model call; "none" is fastest, "medium" most thorough.
    thinking: Literal["none", "low", "medium"] = "low"
    # Tool calls per turn before the agent must answer or ask the developer.
    max_tool_calls: int = 14
    # Language of the guide and questions: en (English) or ko (Korean).
    language: Literal["en", "ko"] = "en"


@dataclass(frozen=True)
class EvidenceSettings:
    max_output_chars: int = 12_000
    max_line_chars: int = 2_000
    redact: bool = True


@dataclass(frozen=True)
class RagSettings:
    enabled: bool = False
    # tool: the model searches when it decides to; inject: top hits are added up front.
    mode: Literal["tool", "inject"] = "tool"
    retriever: Literal["bm25", "hybrid"] = "bm25"
    rerank: bool = False
    top_k: int = 5
    candidates: int = 40
    docs_dir: Path = Path("knowledge")
    index_path: Path = Path("var/knowledge.sqlite")
    embedding_url: str = "http://localhost:8001/v1"
    embedding_model: str = "Qwen/Qwen3-Embedding-0.6B"
    rerank_url: str = "http://localhost:8002/v1"
    rerank_model: str = "Qwen/Qwen3-Reranker-0.6B"
    inject_chars: int = 6_000


@dataclass(frozen=True)
class CaseSettings:
    """Memory of past incidents and their confirmed outcomes."""

    enabled: bool = False
    mode: Literal["tool", "inject"] = "tool"
    top_k: int = 3


@dataclass(frozen=True)
class PlaybookSettings:
    """Approved lessons, added to the agent's instructions when enabled."""

    enabled: bool = False
    max_bullets: int = 40


@dataclass(frozen=True)
class LearningSettings:
    store_path: Path = Path("var/learning.sqlite")
    # New cases and playbook bullets wait for a person to approve them.
    require_approval: bool = True
    max_playbook_updates: int = 6
    cases: CaseSettings = field(default_factory=CaseSettings)
    playbook: PlaybookSettings = field(default_factory=PlaybookSettings)


@dataclass(frozen=True)
class UsbSettings:
    """Removable-drive intake: copy evidence into a sandbox, investigate, export, wipe."""

    enabled: bool = False
    # Only drives with this folder at their root are read.
    marker: str = "blacksite"
    # Directories whose subdirectories are mounted drives. Empty: this OS's usual places
    # (drive letters on Windows, /Volumes on macOS, /media, /run/media, /mnt on Linux).
    roots: tuple[str, ...] = ()
    sandbox_dir: Path = Path("var/sandbox")
    poll_seconds: float = 2.0
    max_bytes: int = 2_000_000_000
    max_files: int = 20_000
    auto_investigate: bool = True
    wipe_after_export: bool = True


@dataclass(frozen=True)
class AuthSettings:
    """Accounts and sessions for the web app. The web app always requires a login."""

    store_path: Path = Path("var/access.sqlite")
    # Master secret and signing key; readable only by the OS account that runs Blacksite.
    keys_dir: Path = Path("var/keys")
    # Pause authenticator enrollment, sign-in codes, and code confirmation for everyone.
    # Existing enrollments are retained so turning this back on restores two-step sign-in.
    totp_enabled: bool = False
    session_hours: float = 12.0
    idle_minutes: float = 30.0
    lockout_attempts: int = 5
    lockout_minutes: float = 15.0
    # How long a password (and code) re-confirmation lasts for sensitive admin actions.
    confirm_minutes: float = 5.0


@dataclass(frozen=True)
class AuditSettings:
    """The tamper-evident record of who did what."""

    store_path: Path = Path("var/audit.sqlite")
    # Sign the ledger head every this many records (and daily, and at shutdown).
    checkpoint_every: int = 100
    # Re-check new records in the background this often.
    verify_minutes: float = 60.0


@dataclass(frozen=True)
class Settings:
    model: ModelSettings = field(default_factory=ModelSettings)
    agent: AgentSettings = field(default_factory=AgentSettings)
    evidence: EvidenceSettings = field(default_factory=EvidenceSettings)
    rag: RagSettings = field(default_factory=RagSettings)
    learning: LearningSettings = field(default_factory=LearningSettings)
    usb: UsbSettings = field(default_factory=UsbSettings)
    auth: AuthSettings = field(default_factory=AuthSettings)
    audit: AuditSettings = field(default_factory=AuditSettings)


def load_settings(
    config_path: Path | str | None = None,
    overrides: Iterable[str] = (),
    environ: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> Settings:
    """Load settings from defaults, an optional TOML file, the environment, and overrides."""
    environ = os.environ if environ is None else environ
    cwd = Path.cwd() if cwd is None else cwd
    if config_path is None and environ.get(CONFIG_ENV):
        config_path = environ[CONFIG_ENV]
    if config_path is None and (cwd / DEFAULT_CONFIG_NAME).is_file():
        config_path = cwd / DEFAULT_CONFIG_NAME

    data: dict[str, Any] = {}
    base_dir = cwd
    if config_path is not None:
        path = Path(config_path).expanduser()
        if not path.is_absolute():
            path = cwd / path
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ConfigError(f"Config file not found: {path}") from None
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"Invalid TOML in {path}: {exc}") from None
        base_dir = path.parent

    for key, value in sorted(environ.items()):
        if key.startswith(ENV_PREFIX) and len(key) > len(ENV_PREFIX):
            _set_dotted(data, key[len(ENV_PREFIX):].lower().split("__"), value, key)
    for item in overrides:
        name, sep, value = item.partition("=")
        if not sep or not name.strip():
            raise ConfigError(f"Override must look like section.key=value; got {item!r}")
        _set_dotted(data, name.strip().split("."), value.strip(), name.strip())

    return _build(Settings, data, "", base_dir)


def feature_summary(settings: Settings) -> dict[str, str]:
    """Name each switchable feature and its state, for logs and experiment records."""

    def state(enabled: bool, detail: str) -> str:
        return f"on ({detail})" if enabled else "off"

    rag = settings.rag
    cases = settings.learning.cases
    return {
        "rag": state(rag.enabled, f"{rag.mode}, {rag.retriever}{', rerank' if rag.rerank else ''}"),
        "cases": state(cases.enabled, cases.mode),
        "playbook": state(settings.learning.playbook.enabled, "instructions"),
    }


def as_dict(settings: Any) -> dict[str, Any]:
    """Settings as plain TOML-compatible values."""
    result: dict[str, Any] = {}
    for item in dataclasses.fields(settings):
        value = getattr(settings, item.name)
        if dataclasses.is_dataclass(value):
            result[item.name] = as_dict(value)
        else:
            result[item.name] = str(value) if isinstance(value, Path) else value
    return result


def _set_dotted(data: dict[str, Any], parts: list[str], value: Any, source: str) -> None:
    if any(not part for part in parts):
        raise ConfigError(f"Invalid setting name: {source}")
    node = data
    for part in parts[:-1]:
        child = node.setdefault(part, {})
        if not isinstance(child, dict):
            raise ConfigError(f"{source}: {part} is a value, not a section")
        node = child
    node[parts[-1]] = value


def _build(cls: type, data: Mapping[str, Any], prefix: str, base_dir: Path) -> Any:
    if not isinstance(data, Mapping):
        raise ConfigError(f"{prefix.rstrip('.') or 'settings'} must be a table")
    hints = get_type_hints(cls)
    names = {item.name for item in dataclasses.fields(cls)}
    unknown = sorted(set(data) - names)
    if unknown:
        raise ConfigError(
            f"Unknown setting {prefix}{unknown[0]}. Valid keys here: {', '.join(sorted(names))}"
        )
    values: dict[str, Any] = {}
    for item in dataclasses.fields(cls):
        kind = hints[item.name]
        if item.name in data:
            values[item.name] = _coerce(kind, data[item.name], prefix + item.name, base_dir)
        elif dataclasses.is_dataclass(kind):
            values[item.name] = _build(kind, {}, f"{prefix}{item.name}.", base_dir)
        elif kind is Path:
            values[item.name] = base_dir / item.default
    return cls(**values)


def _coerce(kind: Any, value: Any, name: str, base_dir: Path) -> Any:
    if dataclasses.is_dataclass(kind):
        return _build(kind, value, name + ".", base_dir)
    if get_origin(kind) is Literal:
        choices = get_args(kind)
        if value not in choices:
            raise ConfigError(f"{name} must be one of {', '.join(choices)}; got {value!r}")
        return value
    if kind is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.lower() in _TRUE | _FALSE:
            return value.lower() in _TRUE
        raise ConfigError(f"{name} must be true or false; got {value!r}")
    if kind is int or kind is float:
        if isinstance(value, bool):
            raise ConfigError(f"{name} must be a number; got {value!r}")
        try:
            number = kind(value)
        except (TypeError, ValueError):
            raise ConfigError(f"{name} must be a number; got {value!r}") from None
        if number <= 0:
            raise ConfigError(f"{name} must be positive; got {value!r}")
        return number
    if kind is Path:
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{name} must be a path; got {value!r}")
        path = Path(value).expanduser()
        return path if path.is_absolute() else base_dir / path
    if kind is str:
        if not isinstance(value, str):
            raise ConfigError(f"{name} must be text; got {value!r}")
        return value
    if get_origin(kind) is tuple:
        # A TOML array, or comma-separated text from the environment or --set.
        items = [part.strip() for part in value.split(",")] if isinstance(value, str) else value
        if not isinstance(items, (list, tuple)) or not all(isinstance(item, str) for item in items):
            raise ConfigError(f"{name} must be a list of text; got {value!r}")
        return tuple(item for item in items if item)
    raise ConfigError(f"Unsupported setting type for {name}")  # pragma: no cover
