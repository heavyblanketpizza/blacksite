import json
from pathlib import Path

import pytest

from blacksite import cli
from blacksite.agent.guide import parse_answer
from blacksite.evaluation import Expected, evaluate, find_incidents, report_markdown, score
from blacksite.evidence.store import EvidenceError

from conftest import FIXTURES, INCIDENT, scripted_agent, write_web_config
from test_agent import GUIDE

INCIDENTS = FIXTURES / "incidents"


def _events(text: str = GUIDE, checks: list[dict] | None = None) -> list[dict]:
    guide = parse_answer(text).model_dump()
    return [{"type": "start"}, {"type": "guide", "guide": guide, "checks": checks or []},
            {"type": "done", "seconds": 12.5, "tool_calls": 3, "input_tokens": 1000, "output_tokens": 200}]


def test_labels_load_from_incident_json(tmp_path: Path) -> None:
    expected = Expected.load(INCIDENT)
    assert expected and "kern.log" in expected.cited_files and expected.root_cause[0].search("the OOM killer")
    (tmp_path / "incident.json").write_text('{"id": "x"}', encoding="utf-8")
    assert Expected.load(tmp_path) is None
    (tmp_path / "incident.json").write_text('{"expected": {"steps": ["(unclosed"]}}', encoding="utf-8")
    with pytest.raises(EvidenceError, match="bad expected block"):
        Expected.load(tmp_path)


def test_find_incidents_accepts_incidents_and_their_parent(tmp_path: Path) -> None:
    found = find_incidents([INCIDENTS])
    assert INCIDENT in found and len(found) >= 15 and found == sorted(found)
    assert find_incidents([INCIDENT]) == [INCIDENT]
    with pytest.raises(EvidenceError, match="not an incident directory"):
        find_incidents([tmp_path / "missing"])


def test_score_passes_a_guide_that_meets_every_label() -> None:
    expected = Expected.load(INCIDENT)
    assert expected is not None
    result = score(expected, _events())
    assert result.passed and result.problems == []
    assert (result.guide, result.root_cause, result.files_cited, result.steps) == (True, True, True, True)
    assert (result.seconds, result.tool_calls, result.tokens) == (12.5, 3, 1200)


def test_score_names_what_a_guide_lacks() -> None:
    expected = Expected.load(INCIDENT)
    assert expected is not None
    wrong = GUIDE.replace("cache", "store").replace("- kern.log:3, 6: repeated OOM kills\n", "")
    wrong = wrong.replace("sudo systemctl restart app.service", "sudo systemctl stop nginx")
    checks = [{"level": "error", "text": "", "code": "citations_bad", "params": {"count": 2}},
              {"level": "warn", "text": "", "code": "citations_unsupported", "params": {"count": 1}},
              {"level": "error", "text": "", "code": "unsafe_command", "params": {"step": 2}}]
    result = score(expected, _events(wrong, checks))
    assert not result.passed and result.guide
    assert result.problems == ["root cause does not match: cache", "no citation of kern.log",
                               "forbidden command: sudo systemctl stop nginx", "2 bad citations", "1 unsafe command"]
    assert (result.forbidden, result.citations_bad, result.citations_unsupported, result.unsafe) == (1, 2, 1, 1)


def test_score_counts_questions_and_errors_as_no_guide() -> None:
    expected = Expected.load(INCIDENT)
    assert expected is not None
    request = {"reason": "Need the unit file", "questions": [], "commands": ["systemctl stop nginx"], "hypotheses": []}
    asked = score(expected, [{"type": "question", "request": request, "checks": []}])
    assert asked.problems == ["no guide: the agent asked for information", "forbidden command: systemctl stop nginx"]
    failed = score(expected, [{"type": "error", "message": "model server is down"}])
    assert failed.problems == ["no guide: model server is down"] and not failed.guide


def test_evaluate_runs_each_preset_over_a_fresh_copy(tmp_path: Path, monkeypatch) -> None:
    scripted_agent(monkeypatch)
    config = write_web_config(tmp_path)
    seen: list = []
    results = evaluate([INCIDENT], ["baseline", "playbook"], tmp_path / "work", config, progress=seen.append)
    assert [(r.preset, r.run, r.incident) for r in results] == [("baseline", 1, "nginx-502-oom"),
                                                                  ("playbook", 1, "nginx-502-oom")]
    assert all(result.score.passed for result in results) and seen == results
    copy = tmp_path / "work" / "playbook" / "1" / "nginx-502-oom"
    assert (copy / "guide.md").is_file() and (copy / "conversation.json").is_file()
    assert not (INCIDENT / "conversation.json").exists()
    report = report_markdown(results)
    assert "| baseline | 1/1 | 1/1 |" in report and "| nginx-502-oom | 1/1 | 1/1 |" in report
    assert "lacked" not in report
    line = json.loads(json.dumps(results[0].as_json()))
    assert line["passed"] and line["preset"] == "baseline" and line["problems"] == []


def test_evaluate_rejects_unknown_presets_and_unlabeled_incidents(tmp_path: Path) -> None:
    with pytest.raises(cli.ConfigError, match="Unknown preset nope"):
        evaluate([INCIDENT], ["nope"], tmp_path)
    unlabeled = tmp_path / "plain"
    unlabeled.mkdir()
    (unlabeled / "incident.json").write_text('{"id": "plain"}', encoding="utf-8")
    with pytest.raises(EvidenceError, match="No expected block.*plain"):
        evaluate([unlabeled], ["baseline"], tmp_path / "work")


def test_report_lists_what_failed_runs_lacked() -> None:
    expected = Expected.load(INCIDENT)
    assert expected is not None
    from blacksite.evaluation import Result

    good = Result("nginx-502-oom", "baseline", 1, score(expected, _events()))
    bad = Result("nginx-502-oom", "rag", 1, score(expected, [{"type": "error", "message": "timed out"}]))
    report = report_markdown([good, bad])
    assert "| rag | 0/1 | 0/1 |" in report and "| nginx-502-oom | 1/1 | 0/1 |" in report
    assert "- nginx-502-oom, rag, run 1: no guide: timed out" in report


def test_eval_command_writes_results_and_a_scorecard(tmp_path: Path, monkeypatch, capfd) -> None:
    scripted_agent(monkeypatch)
    config = write_web_config(tmp_path)
    out, report, work = tmp_path / "results.jsonl", tmp_path / "scorecard.md", tmp_path / "work"
    status = cli.main(["--config", str(config), "eval", str(INCIDENT), "--out", str(out), "--report", str(report),
                       "--work", str(work)])
    assert status == 0
    lines = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 1 and lines[0]["passed"] and lines[0]["incident"] == "nginx-502-oom"
    text = report.read_text(encoding="utf-8")
    assert text.startswith("# Evaluation scorecard") and "| baseline | 1/1 |" in text
    printed = capfd.readouterr().out
    assert "nginx-502-oom  baseline  run 1: pass" in printed and text in printed
    assert cli.main(["--config", str(config), "eval", str(INCIDENT), "--presets", "nope"]) == 1
    assert "Unknown preset nope" in capfd.readouterr().err
