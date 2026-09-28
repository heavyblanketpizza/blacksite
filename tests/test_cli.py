import json
import sys
from pathlib import Path

import anyio
import pytest
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

from blacksite.cli import main
from blacksite.learning.store import LearningStore
from conftest import INCIDENT, KNOWLEDGE


def test_config_prints_feature_states(tmp_path: Path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["--set", "rag.enabled=true", "config"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "rag       on (tool, bm25)"
    assert '"require_approval": true' in out


def test_bad_setting_is_reported_without_traceback(tmp_path: Path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["--set", "rag.mode=sometimes", "config"]) == 1
    assert capsys.readouterr().err.startswith("blacksite: rag.mode must be one of tool, inject")


def test_new_and_ingest_build_an_incident(tmp_path: Path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    logs = sorted((INCIDENT / "artifacts").iterdir())
    assert main(["new", "inc", *map(str, logs), "--title", "502s", "--year", "2026"]) == 0
    assert json.loads((tmp_path / "inc" / "incident.json").read_text(encoding="utf-8"))["year"] == 2026
    assert main(["ingest", "inc"]) == 0
    out = capsys.readouterr().out
    assert "Incident inc: 502s" in out and "nginx/error.log" in out
    assert main(["new", "inc", "--title", "again"]) == 1


def test_learning_review_cycle(tmp_path: Path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    store = LearningStore(tmp_path / "var" / "learning.sqlite")
    store.apply_playbook([{"op": "add", "section": "safety", "text": "Back up configs before editing them."}],
                         source="inc", approved=False)
    assert main(["learn", "review"]) == 0
    assert "pb-0001  safety: Back up configs" in capsys.readouterr().out
    assert main(["learn", "approve", "pb-0001", "pb-0002"]) == 0
    captured = capsys.readouterr()
    assert "Approved: pb-0001" in captured.out and "pb-0002" in captured.err
    assert main(["--set", "learning.playbook.enabled=true", "context"]) == 0
    assert "[pb-0001] Back up configs before editing them." in capsys.readouterr().out


def test_record_requires_an_incident_directory(tmp_path: Path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["learn", "record", "missing", "--outcome", "resolved"]) == 1
    assert "not an incident directory" in capsys.readouterr().err


def test_search_command_uses_the_library(tmp_path: Path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["--set", f"rag.docs_dir={KNOWLEDGE}", "search", "no space left on device"]) == 0
    assert "runbooks/disk-full.md" in capsys.readouterr().out


@pytest.mark.parametrize("server", ["evidence", "knowledge"])
def test_servers_run_over_stdio(tmp_path: Path, incident_dir: Path, server: str) -> None:
    """End to end: launch the real command and talk MCP over its stdin/stdout."""
    args = ["-m", "blacksite.cli", "--set", f"rag.docs_dir={KNOWLEDGE}", "--set", "rag.enabled=true",
            "--set", f"rag.index_path={tmp_path / 'index.sqlite'}", "serve", server]
    args += [str(incident_dir)] if server == "evidence" else ["--incident", str(incident_dir)]
    params = StdioServerParameters(command=sys.executable, args=args, cwd=str(tmp_path))

    async def run() -> tuple[set[str], str]:
        async with Client(params) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            tool, arguments = (("search_logs", {"pattern": "Killed process"}) if server == "evidence"
                               else ("search_docs", {"query": "OOM killer cgroup"}))
            result = await client.call_tool(tool, arguments)
            return names, result.content[0].text

    names, text = anyio.run(run)
    if server == "evidence":
        assert "timeline" in names and "kern.log:3" in text
    else:
        assert names == {"search_docs", "read_doc"} and "runbooks/oom-killer.md" in text
