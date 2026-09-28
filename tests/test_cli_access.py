import json
import re
import sqlite3
from pathlib import Path

import pytest

from blacksite.audit import provenance
from blacksite.cli import main
from blacksite.config import load_settings
from blacksite.evidence.store import Evidence
from blacksite.report import build_solution
from blacksite.services import Services
from test_provenance import events


@pytest.fixture(autouse=True)
def in_tmp(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("BLACKSITE_CONFIG", raising=False)
    return tmp_path


def run(capsys, *argv: str) -> tuple[int, str, str]:
    status = main(list(argv))
    out, err = capsys.readouterr()
    return status, out, err


def test_users_add_list_and_manage(capsys, tmp_path: Path) -> None:
    status, out, _ = run(capsys, "users", "add", "Alice", "--admin", "--display-name", "앨리스")
    assert status == 0 and "alice" in out
    temporary = re.search(r"Temporary password \(shown once\): (\S+)", out).group(1)
    assert len(temporary) == 19
    assert run(capsys, "users", "add", "alice")[0] == 1
    assert run(capsys, "users", "add", "bob", "--display-name", "Bob")[0] == 0
    status, out, _ = run(capsys, "users", "list")
    assert status == 0 and re.search(r"alice\s+앨리스\s+admin\s+active", out) and re.search(r"bob\s+Bob\s+member", out)
    status, _, err = run(capsys, "users", "suspend", "alice")
    assert status == 1 and "last active admin" in err
    assert run(capsys, "users", "suspend", "bob")[0] == 0
    assert run(capsys, "users", "activate", "bob")[0] == 0
    assert run(capsys, "users", "set-role", "bob", "admin")[0] == 0
    status, out, _ = run(capsys, "users", "reset-password", "bob")
    assert status == 0 and "Temporary password (shown once)" in out
    assert run(capsys, "users", "reset-2fa", "bob")[0] == 0
    assert run(capsys, "users", "revoke-sessions", "bob")[0] == 0
    assert run(capsys, "users", "suspend", "nobody")[0] == 1
    services = Services.open(load_settings(environ={}, cwd=tmp_path))
    actions = [record.action for record in services.ledger.records(limit=50)]
    assert "admin.user_created" in actions and "admin.user_suspended" in actions and "admin.role_changed" in actions
    assert all(record.actor.startswith(("cli:", "system")) for record in services.ledger.records(limit=50))
    assert temporary not in json.dumps([record.to_json() for record in services.ledger.records(limit=50)])


def test_audit_verify_export_and_anchor(capsys, tmp_path: Path) -> None:
    run(capsys, "users", "add", "alice", "--admin")
    status, out, _ = run(capsys, "audit", "verify")
    assert status == 0 and "verified" in out
    status, out, _ = run(capsys, "audit", "anchor")
    assert status == 0 and re.search(r"[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}", out)
    anchor_file = tmp_path / "anchor.json"
    anchor_file.write_text(json.dumps(json.loads(out.split("\n", 1)[1])), encoding="utf-8")
    assert run(capsys, "audit", "export", "audit.jsonl")[0] == 0
    status, out, _ = run(capsys, "audit", "verify", "--export", "audit.jsonl", "--anchor", str(anchor_file))
    assert status == 0 and "verified" in out
    con = sqlite3.connect(tmp_path / "var" / "audit.sqlite")
    con.executescript("DROP TRIGGER ledger_no_update; UPDATE ledger SET detail = '{}' WHERE seq = 2;")
    con.commit()
    con.close()
    status, out, _ = run(capsys, "audit", "verify")
    assert status == 1 and "Record 2" in out


def test_verify_an_exported_guide(capsys, tmp_path: Path, incident_dir: Path) -> None:
    services = Services.open(load_settings(environ={}, cwd=tmp_path))
    manifest = provenance.record_turn(services, services.settings, incident_dir, 1, events(), actor="user:1",
                                      session="s", started_at="2027-01-15T08:00:00Z")
    with Evidence(incident_dir) as evidence:
        files = build_solution(evidence, events()[1], "en", None, "m", provenance=manifest,
                               public_pem=services.keys.public_pem(), anchor=services.ledger.anchor())
    folder = tmp_path / "SOLUTION-1"
    folder.mkdir()
    for name, content in files.items():
        (folder / name).write_text(content, encoding="utf-8")
    status, out, _ = run(capsys, "verify", str(folder))
    assert status == 0 and "Signature: valid" in out and services.keys.fingerprint in out
    assert "Guide: matches" in out
    (folder / "manifest.json").write_text(files["manifest.json"].replace("App OOM-killed", "Edited"), encoding="utf-8")
    status, out, _ = run(capsys, "verify", str(folder))
    assert status == 1 and "Guide: does not match" in out


def test_verify_a_manifest_in_an_incident(capsys, tmp_path: Path, incident_dir: Path) -> None:
    services = Services.open(load_settings(environ={}, cwd=tmp_path))
    provenance.record_turn(services, services.settings, incident_dir, 1, events(), actor="user:1", session="s",
                           started_at="2027-01-15T08:00:00Z")
    status, out, _ = run(capsys, "verify", str(incident_dir / "provenance" / "turn-1.json"))
    assert status == 0 and "Evidence: unchanged" in out
    (incident_dir / "artifacts" / "syslog").write_text("changed\n", encoding="utf-8")
    status, out, _ = run(capsys, "verify", str(incident_dir / "provenance" / "turn-1.json"))
    assert status == 1 and "Evidence: changed" in out and "syslog" in out
