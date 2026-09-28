import json
from pathlib import Path

import pytest

from blacksite.audit import provenance
from blacksite.config import load_settings
from blacksite.evidence.store import Evidence
from blacksite.keys import Keys
from blacksite.report import build_solution
from blacksite.services import Services

GUIDE = {"title": "App OOM-killed", "confidence": "high", "summary": "The cache grows.", "root_cause": "Cache.",
         "evidence": [{"ref": "kern.log:3", "shows": "OOM kill"}], "steps": [], "verify": [], "unknowns": [],
         "security_notes": []}


def events(guide: dict | None = GUIDE) -> list[dict]:
    items = [{"type": "start", "model": "test-model", "thinking": "low", "language": "en", "t": 0.0}]
    if guide is not None:
        items.append({"type": "guide", "guide": guide, "markdown": "# App OOM-killed\n", "t": 9.0,
                      "checks": [{"level": "ok", "text": "3 citations verified", "code": "citations_ok",
                                  "params": {"count": 3}},
                                 {"level": "warn", "text": "1 bad", "code": "citations_bad", "params": {"count": 1}}]})
    else:
        items.append({"type": "question", "request": {"reason": "more", "questions": [], "commands": []}, "t": 9.0})
    items.append({"type": "done", "seconds": 12.5, "requests": 3, "tool_calls": 4, "input_tokens": 100,
                  "output_tokens": 20, "t": 12.5})
    return items


@pytest.fixture
def services(tmp_path: Path, clock) -> Services:
    return Services.open(load_settings(environ={}, cwd=tmp_path), clock=clock)


def test_services_start_the_ledger(services: Services) -> None:
    first = services.ledger.records(limit=5)[-1]
    assert first.action == "ledger.created" and first.detail["key_id"] == services.keys.key_id
    again = Services.open(services.settings)
    assert len(again.ledger.records()) == 1  # opening again does not add another


def test_record_turn_signs_a_manifest(services: Services, incident_dir: Path) -> None:
    manifest = provenance.record_turn(services, services.settings, incident_dir, 1, events(), actor="user:7",
                                      session="abc", started_at="2027-01-15T08:00:00Z")
    assert (incident_dir / "provenance" / "turn-1.json").is_file()
    assert manifest["actor"] == "user:7" and manifest["turn"] == 1 and manifest["incident"] == incident_dir.name
    assert manifest["checks"] == {"citations_ok": 3, "citations_total": 4, "warnings": 1}
    assert {item["file"] for item in manifest["evidence"]} >= {"kern.log", "nginx/error.log"}
    assert manifest["model"]["name"] == "test-model"  # the model that ran the turn, not the default
    assert manifest["ledger_anchor"]["seq"] >= 1 and manifest["key_id"] == services.keys.key_id
    result = provenance.check(manifest, services.keys.public_pem(), incident_dir, GUIDE)
    assert result["signature"] and result["guide"] and result["evidence"] == "unchanged"
    assert result["key_fingerprint"] == services.keys.fingerprint
    run = services.access.runs({incident_dir.name})[0]
    assert run["guide"] and run["tool_calls"] == 4 and run["citations_ok"] == 3 and run["citations_total"] == 4
    finished = services.ledger.records(action="incident.turn_finished")[0]
    assert finished.target == incident_dir.name and finished.detail["manifest"] == provenance.manifest_hash(manifest)
    assert "App OOM" not in json.dumps(finished.to_json())  # no guide text in the ledger


def test_turns_without_a_guide_record_metrics_only(services: Services, incident_dir: Path) -> None:
    assert provenance.record_turn(services, services.settings, incident_dir, 1, events(None), actor="user:7",
                                  session=None, started_at="2027-01-15T08:00:00Z") is None
    assert not (incident_dir / "provenance").exists()
    assert services.access.runs({incident_dir.name})[0]["guide"] is False


def test_changed_evidence_and_guide_are_detected(services: Services, incident_dir: Path) -> None:
    manifest = provenance.record_turn(services, services.settings, incident_dir, 1, events(), actor="user:7",
                                      session="abc", started_at="2027-01-15T08:00:00Z")
    with (incident_dir / "artifacts" / "kern.log").open("a", encoding="utf-8") as stream:
        stream.write("one more line\n")
    result = provenance.check(manifest, services.keys.public_pem(), incident_dir, {**GUIDE, "title": "Edited"})
    assert result["signature"] and result["guide"] is False and result["evidence"] == "changed"
    assert {item["file"]: item["status"] for item in result["files"]}["kern.log"] == "changed"


def test_forged_manifests_fail(services: Services, incident_dir: Path, tmp_path: Path) -> None:
    manifest = provenance.record_turn(services, services.settings, incident_dir, 1, events(), actor="user:7",
                                      session="abc", started_at="2027-01-15T08:00:00Z")
    other = Keys(tmp_path / "other")
    assert not provenance.check(manifest, other.public_pem())["signature"]
    edited = {**manifest, "actor": "user:1"}
    assert not provenance.check(edited, services.keys.public_pem())["signature"]


def test_summary_per_turn(services: Services, incident_dir: Path) -> None:
    provenance.record_turn(services, services.settings, incident_dir, 2, events(), actor="user:7", session="abc",
                           started_at="2027-01-15T08:00:00Z")
    turns = [{"events": events(None)}, {"events": events()}, {"events": events()}]
    summary = provenance.summary(incident_dir, turns, services.keys.public_pem())
    assert summary[0] is None
    assert summary[1]["signed"] and summary[1]["evidence"] == "unchanged" and summary[1]["files"] >= 5
    assert summary[2] == {"signed": False, "unsigned": True}


def test_export_includes_verifiable_provenance(services: Services, incident_dir: Path) -> None:
    manifest = provenance.record_turn(services, services.settings, incident_dir, 1, events(), actor="user:7",
                                      session="abc", started_at="2027-01-15T08:00:00Z")
    with Evidence(incident_dir) as evidence:
        files = build_solution(evidence, events()[1], "en", None, "test-model", provenance=manifest,
                               public_pem=services.keys.public_pem(), anchor=services.ledger.anchor())
    assert json.loads(files["provenance.json"])["signature"] == manifest["signature"]
    assert files["blacksite-signing-key.pub"].startswith("-----BEGIN PUBLIC KEY-----")
    assert json.loads(files["ledger-anchor.json"])["seq"] >= 1
    assert services.keys.fingerprint in files["guide.html"]
    assert "user:7" not in files["guide.html"]
