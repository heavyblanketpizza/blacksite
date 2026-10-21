import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from blacksite import __version__, cli
from blacksite.bundle import BundleError, build
from blacksite.checksums import MANIFEST, sha256_file, verify


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname = "blacksite"\n', encoding="utf-8")
    (root / "uv.lock").write_text("", encoding="utf-8")
    (root / "blacksite.example.toml").write_text("[model]\n", encoding="utf-8")
    return root


def fake_tools(commands: list[list[str]]):
    """Stands in for uv and pip: records each command and writes the files it would have produced."""

    def run(command, cwd: Path) -> None:
        commands.append(list(command))
        if "export" in command:
            Path(command[command.index("--output-file") + 1]).write_text("duckdb==1.5.0\n", encoding="utf-8")
        elif "build" in command:
            (Path(command[command.index("--out-dir") + 1]) / "blacksite-0.1.0-py3-none-any.whl").write_bytes(b"us")
        else:
            wheels = Path(command[command.index("--dest") + 1])
            (wheels / "duckdb-1.5.0-cp312-cp312-linux_x86_64.whl").write_bytes(b"db")

    return run


def _build(tmp_path: Path, checkout: Path, models: tuple[Path, ...] = ()) -> tuple[Path, dict, list[list[str]]]:
    commands: list[list[str]] = []
    target = tmp_path / "bundle"
    return target, build(target, models, checkout, fake_tools(commands)), commands


def test_build_collects_wheels_lock_config_models_and_notes(tmp_path: Path, checkout: Path) -> None:
    weights = tmp_path / "q4.gguf"
    weights.write_bytes(b"GGUF")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "config.json").write_text("{}", encoding="utf-8")
    target, manifest, commands = _build(tmp_path, checkout, (weights, snapshot))
    assert [command[:2] for command in commands[:2]] == [["uv", "export"], ["uv", "build"]]
    assert {"--frozen", "--no-dev", "--all-extras", "--no-emit-project"} <= set(commands[0])
    assert {"download", "--no-deps", "--only-binary=:all:"} <= set(commands[2])
    assert sorted(manifest["files"]) == [
        "README.txt", "blacksite.example.toml", "models/q4.gguf", "models/snapshot/config.json",
        "requirements.txt", "verify.py", "wheels/blacksite-0.1.0-py3-none-any.whl",
        "wheels/duckdb-1.5.0-cp312-cp312-linux_x86_64.whl"]
    assert manifest["files"]["models/q4.gguf"] == {"bytes": 4, "sha256": sha256_file(weights)}
    assert manifest["blacksite"] == __version__ and manifest["python"].startswith("3.")
    notes = (target / "README.txt").read_text(encoding="utf-8")
    assert __version__ in notes and "models/q4.gguf" in notes and "pip install --no-index" in notes
    assert json.loads((target / MANIFEST).read_text(encoding="utf-8")) == manifest
    assert verify(target) == []


def test_build_refuses_a_used_directory_and_a_missing_checkout_or_model(tmp_path: Path, checkout: Path) -> None:
    used = tmp_path / "used"
    used.mkdir()
    (used / "old.txt").write_text("x", encoding="utf-8")
    with pytest.raises(BundleError, match="not empty"):
        build(used, [], checkout, fake_tools([]))
    with pytest.raises(BundleError, match="not a Blacksite checkout"):
        build(tmp_path / "new", [], tmp_path, fake_tools([]))
    with pytest.raises(BundleError, match="Model path not found"):
        build(tmp_path / "new", [tmp_path / "none.gguf"], checkout, fake_tools([]))
    assert not (tmp_path / "new").exists()


def test_verify_reports_missing_changed_and_unlisted_files(tmp_path: Path, checkout: Path) -> None:
    target, _, _ = _build(tmp_path, checkout)
    (target / "wheels" / "blacksite-0.1.0-py3-none-any.whl").write_bytes(b"tampered")
    (target / "requirements.txt").unlink()
    (target / "extra.txt").write_text("?", encoding="utf-8")
    assert verify(target) == ["missing: requirements.txt", "changed: wheels/blacksite-0.1.0-py3-none-any.whl",
                              "not listed: extra.txt"]
    assert verify(tmp_path)[0].startswith("cannot read")
    (target / MANIFEST).write_text('{"files": {}}', encoding="utf-8")
    assert verify(target) == [f"{target / MANIFEST} is not a blacksite-bundle/1 manifest"]


def test_bundled_verify_script_needs_only_the_standard_library(tmp_path: Path, checkout: Path) -> None:
    target, _, _ = _build(tmp_path, checkout)
    source = (target / "verify.py").read_text(encoding="utf-8")
    assert not re.search(r"^(from|import) (\.|blacksite)", source, re.M)
    run = subprocess.run([sys.executable, "-I", str(target / "verify.py"), str(target)], capture_output=True,
                         text=True)
    assert run.returncode == 0 and run.stdout.startswith("OK:")
    (target / "README.txt").write_text("edited", encoding="utf-8")
    run = subprocess.run([sys.executable, "-I", "verify.py"], cwd=target, capture_output=True, text=True)
    assert run.returncode == 1 and run.stdout.strip() == "changed: README.txt"


def test_bundle_command_builds_and_verifies(tmp_path: Path, monkeypatch, capsys) -> None:
    import blacksite.bundle

    monkeypatch.setattr(blacksite.bundle, "run_command", fake_tools([]))
    target = tmp_path / "bundle"
    assert cli.main(["bundle", str(target)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Wrote 6 files") and sha256_file(target / MANIFEST) in out
    assert cli.main(["bundle", str(target), "--verify"]) == 0
    assert capsys.readouterr().out.startswith("OK:")
    (target / "verify.py").unlink()
    assert cli.main(["bundle", str(target), "--verify"]) == 1
    assert capsys.readouterr().out == f"missing: verify.py\n1 problem(s) in {target}\n"
    assert cli.main(["bundle", str(target)]) == 1
    assert "not empty" in capsys.readouterr().err
