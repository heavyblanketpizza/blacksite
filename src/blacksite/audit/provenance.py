"""Signed records of where each guide came from.

When a turn ends with a guide, its manifest names who ran it (a user id, never a name),
the SHA-256 of every evidence file, the model and switches, the hashes of the agent's
instructions and of the guide itself, and the ledger head at that moment, all signed
with the Ed25519 key. ``check`` re-hashes the evidence on disk, so the page can say
whether the files still match what the guide was written from.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .. import __version__
from ..config import Settings
from ..evidence.store import ARTIFACTS_DIR, artifact_files
from ..keys import Keys, canonical, group, load_public_key, public_key_id, sha256_hex, verify_signature

if TYPE_CHECKING:
    from ..services import Services

MANIFEST_DIR = "provenance"


class VerifyError(ValueError):
    """A manifest or key could not be read."""

VERSION = 1
_CHUNK = 1 << 20


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_files(incident_dir: Path) -> list[dict[str, Any]]:
    """Every evidence file the index reads, with its size and SHA-256, in path order."""
    return [{"file": relative, "bytes": path.stat().st_size, "sha256": file_sha256(path)}
            for path, relative in artifact_files(Path(incident_dir) / ARTIFACTS_DIR)]


def evidence_root(files: list[dict[str, Any]]) -> str:
    return sha256_hex(canonical(sorted(files, key=lambda item: item["file"])))


def instructions_sha256() -> str:
    from ..agent.investigator import INSTRUCTIONS

    return sha256_hex(INSTRUCTIONS.encode("utf-8"))


def manifest_hash(manifest: dict[str, Any]) -> str:
    return sha256_hex(canonical(manifest))


def _unsigned(manifest: dict[str, Any]) -> bytes:
    return canonical({key: value for key, value in manifest.items() if key != "signature"})


def sign(manifest: dict[str, Any], keys: Keys) -> dict[str, Any]:
    signed = {**manifest, "key_id": keys.key_id}
    signed["signature"] = keys.sign(_unsigned(signed))
    return signed


def path_for(incident_dir: Path, turn: int) -> Path:
    return Path(incident_dir) / MANIFEST_DIR / f"turn-{turn}.json"


def write(incident_dir: Path, manifest: dict[str, Any]) -> Path:
    path = path_for(incident_dir, manifest["turn"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def load(incident_dir: Path, turn: int) -> dict[str, Any] | None:
    try:
        data = json.loads(path_for(incident_dir, turn).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def check(manifest: dict[str, Any], public_pem: bytes, incident_dir: Path | None = None,
          guide: dict[str, Any] | None = None) -> dict[str, Any]:
    """Whether the signature holds, the guide matches, and the evidence on disk is unchanged."""
    public = load_public_key(public_pem)
    signature = (manifest.get("key_id") == public_key_id(public)
                 and verify_signature(public, _unsigned(manifest), str(manifest.get("signature", ""))))
    guide_ok = None if guide is None else sha256_hex(canonical(guide)) == manifest.get("guide_sha256")
    files: list[dict[str, Any]] = []
    evidence = "unknown"
    if incident_dir is not None and (Path(incident_dir) / ARTIFACTS_DIR).is_dir():
        current = {item["file"]: item for item in evidence_files(incident_dir)}
        for item in manifest.get("evidence", []):
            now = current.pop(item["file"], None)
            status = "missing" if now is None else "unchanged" if now["sha256"] == item["sha256"] else "changed"
            files.append({"file": item["file"], "bytes": item["bytes"], "sha256": item["sha256"], "status": status})
        files += [{"file": name, "bytes": item["bytes"], "sha256": item["sha256"], "status": "added"}
                  for name, item in current.items()]
        evidence = "unchanged" if all(item["status"] == "unchanged" for item in files) else "changed"
    return {"signature": signature, "guide": guide_ok, "evidence": evidence, "files": files,
            "key_fingerprint": group(public_key_id(public))}


def _guide_event(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((event for event in reversed(events) if event.get("type") == "guide"), None)


def summary(incident_dir: Path, turns: list[dict[str, Any]], public_pem: bytes) -> list[dict[str, Any] | None]:
    """For each turn: None without a guide; otherwise whether it is signed and the evidence still matches."""
    result: list[dict[str, Any] | None] = []
    for index, turn in enumerate(turns, 1):
        event = _guide_event(turn.get("events", []))
        if event is None:
            result.append(None)
            continue
        manifest = load(incident_dir, index)
        if manifest is None:
            result.append({"signed": False, "unsigned": True})
            continue
        checked = check(manifest, public_pem, incident_dir, event.get("guide"))
        result.append({"signed": checked["signature"] and checked["guide"] is not False,
                       "evidence": checked["evidence"], "files": len(manifest.get("evidence", []))})
    return result


def _citations(event: dict[str, Any]) -> tuple[int, int, int]:
    checks = event.get("checks", [])
    good = sum(int(check.get("params", {}).get("count", 0)) for check in checks if check.get("code") == "citations_ok")
    bad = sum(int(check.get("params", {}).get("count", 0)) for check in checks if check.get("code") == "citations_bad")
    if not good and not bad:
        good = len(event.get("guide", {}).get("evidence", []))
    warnings = sum(1 for check in checks if check.get("level") in ("warn", "error"))
    return good, good + bad, warnings


def record_turn(services: Services, settings: Settings, incident_dir: Path, turn: int, events: list[dict[str, Any]],
                *, actor: str, session: str | None, started_at: str) -> dict[str, Any] | None:
    """Store the turn's metrics, sign a manifest if it produced a guide, and add both to the ledger."""
    incident_dir = Path(incident_dir)
    finished_at = _now()
    done = next((event for event in reversed(events) if event.get("type") == "done"), {})
    start = next((event for event in events if event.get("type") == "start"), {})
    guide_event = _guide_event(events)
    good, total, warnings = _citations(guide_event) if guide_event else (0, 0, 0)
    model = settings.model
    services.access.record_run({
        "incident_id": incident_dir.name, "turn": turn, "actor": actor, "session": session,
        "started_at": started_at, "finished_at": finished_at, "seconds": float(done.get("seconds", 0) or 0),
        "requests": done.get("requests", 0) or 0, "tool_calls": done.get("tool_calls", 0) or 0,
        "input_tokens": done.get("input_tokens", 0) or 0, "output_tokens": done.get("output_tokens", 0) or 0,
        "model": start.get("model") or model.name, "provider": model.provider,
        "citations_ok": good, "citations_total": total, "guide": guide_event is not None})
    manifest = None
    detail: dict[str, Any] = {"turn": turn, "seconds": done.get("seconds"), "tool_calls": done.get("tool_calls"),
                              "guide": guide_event is not None, "error": any(e.get("type") == "error" for e in events)}
    if guide_event is not None:
        files = evidence_files(incident_dir)
        seq, head = services.ledger.head()
        manifest = sign({
            "v": VERSION, "incident": incident_dir.name, "turn": turn, "actor": actor, "session": session,
            "started_at": started_at, "finished_at": finished_at, "evidence": files,
            "evidence_root": evidence_root(files),
            "model": {"provider": model.provider, "name": start.get("model") or model.name, "base_url": model.base_url},
            "settings": {"rag": settings.rag.mode if settings.rag.enabled else "off",
                         "cases": settings.learning.cases.mode if settings.learning.cases.enabled else "off",
                         "playbook": "on" if settings.learning.playbook.enabled else "off",
                         "thinking": settings.agent.thinking, "language": settings.agent.language},
            "blacksite_version": __version__, "prompt_sha256": instructions_sha256(),
            "guide_sha256": sha256_hex(canonical(guide_event["guide"])),
            "checks": {"citations_ok": good, "citations_total": total, "warnings": warnings},
            "ledger_anchor": {"seq": seq, "hash": head},
        }, services.keys)
        write(incident_dir, manifest)
        detail.update({"manifest": manifest_hash(manifest), "files": len(files), "evidence_root": manifest["evidence_root"]})
    services.ledger.append("incident.turn_finished", actor=actor, session=session, target=incident_dir.name,
                           detail=detail)
    return manifest
