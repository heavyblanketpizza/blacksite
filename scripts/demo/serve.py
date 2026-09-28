"""Prepare a private sample workspace and run Blacksite against a real local model.

Only the input evidence and accounts are synthetic. This uses the production app,
model discovery, model calls, evidence tools, authentication, signing, and ledger.
It never seeds a conversation or supplies an investigation result.

Run from the repository with its virtual environment::

    .venv/bin/python scripts/demo/serve.py --data-dir var/video-real/run-001
    .venv/bin/python scripts/demo/serve.py --provider llamacpp --data-dir var/video-real/run-002

The data directory must not exist. Its private credentials.json is intended for
the recorder and must never be published with the resulting video.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time

import uvicorn

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from blacksite.auth import totp
from blacksite.config import load_settings
from blacksite.services import Services
from blacksite.web.app import create_app

INCIDENT_ID = "nginx-502-oom"
DEFAULT_MODEL = "blacksite-qwen3.8:latest"
DEFAULT_URL = "http://127.0.0.1:11434/v1"
BACKENDS = {
    "ollama": (DEFAULT_MODEL, DEFAULT_URL, "OLLAMA_API_KEY"),
    "llamacpp": ("blacksite-qwen3.8", "http://127.0.0.1:8080/v1", "LLAMA_API_KEY"),
}


def prepare_app(data_dir: Path, *, port: int = 18768,
                provider: str = "ollama", model: str | None = None, base_url: str | None = None):
    """Create a new workspace without invoking the model or opening a server."""
    if provider not in BACKENDS:
        raise ValueError(f"Unsupported demo provider: {provider}")
    default_model, default_url, api_key_env = BACKENDS[provider]
    model = default_model if model is None else model
    base_url = default_url if base_url is None else base_url
    if not model.strip() or not base_url.strip():
        raise ValueError("The model name and base URL must not be empty.")
    data_dir = data_dir.expanduser().resolve()
    if data_dir.is_relative_to(ROOT) and not data_dir.is_relative_to(ROOT / "var"):
        raise ValueError("Repository runtime data must be inside the ignored var/ directory.")
    # exist_ok=False prevents a recording from silently reusing an old answer,
    # replacing credentials, or destroying a previous investigation.
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(data_dir, 0o700)
    config = data_dir / "blacksite.toml"
    config.write_text(
        "\n".join([
            "[model]",
            f"provider = {json.dumps(provider)}",
            f"base_url = {json.dumps(base_url)}",
            f"name = {json.dumps(model)}",
            f"api_key_env = {json.dumps(api_key_env)}",
            "timeout = 1800.0",
            "context = 65536",
            "",
            "[agent]",
            'language = "en"',
            'thinking = "low"',
            "max_tool_calls = 12",
            "",
            "[rag]",
            f"docs_dir = {json.dumps(str(ROOT / 'demo' / 'knowledge'))}",
            'index_path = "knowledge.sqlite"',
            "",
            "[learning]",
            'store_path = "learning.sqlite"',
            "",
            "[auth]",
            "totp_enabled = false",
            'store_path = "access.sqlite"',
            'keys_dir = "keys"',
            "idle_minutes = 120.0",
            "confirm_minutes = 60.0",
            "",
            "[audit]",
            'store_path = "audit.sqlite"',
            "",
            "[usb]",
            "enabled = false",
            'sandbox_dir = "sandbox"',
            "",
        ]), encoding="utf-8",
    )
    incidents = data_dir / "incidents"
    incident_dir = incidents / INCIDENT_ID
    shutil.copytree(ROOT / "tests" / "fixtures" / "incidents" / INCIDENT_ID, incident_dir)
    metadata_path = incident_dir / "incident.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["title"] = "Demo: order API 502 errors since 02:14"
    metadata["description"] = (
        "Synthetic training logs. Version 2.14.0 was deployed at 01:50, and the order API "
        "started returning 502 errors at 02:14. nginx forwards requests to the app at "
        "127.0.0.1:8080."
    )
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    # Explicit config overrides keep unrelated BLACKSITE__ settings in the shell
    # from redirecting this isolated recording to another account or data store.
    settings = load_settings(config, environ={})
    overrides = [
        f"model.provider={settings.model.provider}",
        f"model.base_url={settings.model.base_url}",
        f"model.name={settings.model.name}",
        f"model.api_key_env={settings.model.api_key_env}",
        f"model.timeout={settings.model.timeout}",
        f"model.context={settings.model.context}",
        "agent.language=en", "agent.thinking=low", "agent.max_tool_calls=12",
        "rag.enabled=false", f"rag.docs_dir={settings.rag.docs_dir}",
        f"rag.index_path={settings.rag.index_path}",
        f"learning.store_path={settings.learning.store_path}",
        "learning.cases.enabled=false", "learning.playbook.enabled=false",
        f"auth.store_path={settings.auth.store_path}",
        f"auth.keys_dir={settings.auth.keys_dir}", "auth.totp_enabled=false",
        "auth.idle_minutes=120.0", "auth.confirm_minutes=60.0",
        f"audit.store_path={settings.audit.store_path}",
        "usb.enabled=false", f"usb.sandbox_dir={settings.usb.sandbox_dir}",
    ]
    services = Services.open(settings)
    admin, password = services.access.create_user(
        "demo", "Demo administrator", "admin", "demo.bootstrap", must_change=False,
    )
    for username, display_name in (
        ("minseo", "Minseo Kim · Engineering"),
        ("jiwon", "Jiwon Park · Operations"),
    ):
        services.access.create_user(username, display_name, "member", admin.actor())
    services.access.register_incident(INCIDENT_ID, admin.id)
    services.ledger.append("demo.prepared", actor="system", target=INCIDENT_ID, detail={
        "evidence_source": "tests/fixtures/incidents/nginx-502-oom",
        "synthetic_evidence": True,
        "model_provider": settings.model.provider,
        "model": settings.model.name,
    })
    credentials = data_dir / "credentials.json"
    credentials.write_text(json.dumps({
        "url": f"http://127.0.0.1:{port}",
        "username": admin.username,
        "password": password,
        "synthetic": True,
        "provider": settings.model.provider,
        "model": settings.model.name,
        "model_base_url": settings.model.base_url,
    }, indent=2) + "\n", encoding="utf-8")
    os.chmod(credentials, 0o600)
    return create_app(config, overrides, incidents, services=services)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, help="New private runtime directory")
    parser.add_argument("--port", type=int, default=18768)
    parser.add_argument("--provider", choices=tuple(BACKENDS), default="ollama")
    parser.add_argument("--model", help="Model ID served by the backend (defaults depend on --provider)")
    parser.add_argument("--base-url", help="OpenAI-compatible model URL (defaults depend on --provider)")
    parser.add_argument("--totp", type=Path, metavar="CREDENTIALS_JSON",
                        help="Print a current code for this disposable demo account")
    args = parser.parse_args()
    if args.totp:
        credentials = json.loads(args.totp.read_text(encoding="utf-8"))
        print(totp.code_at(credentials["totp_secret"], totp.step_of(time.time())))
        return
    if args.data_dir is None:
        parser.error("--data-dir is required when starting the app")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        app = prepare_app(args.data_dir, port=args.port, provider=args.provider,
                          model=args.model, base_url=args.base_url)
    except (FileExistsError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Real-model demo: http://127.0.0.1:{args.port}", flush=True)
    print(f"Private credentials: {args.data_dir.resolve() / 'credentials.json'}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
