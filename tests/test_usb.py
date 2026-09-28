import io
import json
import os
import shutil
import tarfile
import time
import zipfile
from pathlib import Path

import anyio
import pytest
from pydantic_ai.models.function import AgentInfo, FunctionModel
from starlette.testclient import TestClient

from blacksite.agent import investigator as investigator_module
from blacksite.config import UsbSettings
from blacksite.evidence.store import Evidence
from blacksite.report import build_solution
from blacksite.usb import (
    UsbError, find_bundles, import_bundle, list_drives, locate_bundle, read_source, wipe, write_solution,
)
from blacksite.web.app import _scan_drives, create_app
from conftest import BASE_URL, sign_in
from conftest import INCIDENT, KNOWLEDGE
from test_agent import GUIDE


@pytest.fixture
def mounts(tmp_path: Path) -> Path:
    """A fake mount root with one drive carrying the sample incident."""
    root = tmp_path / "Volumes"
    bundle = root / "KINGSTON" / "BlackSite" / "api-502"
    shutil.copytree(INCIDENT / "artifacts", bundle)
    (bundle / "incident.txt").write_text("API returns 502 since 02:14\nDeployed 2.14.0 at 01:50.\n", encoding="utf-8")
    (bundle / ".DS_Store").write_bytes(b"junk")
    (root / "PHOTOS" / "DCIM").mkdir(parents=True)  # a drive without the marker folder
    return root


def test_drives_under_custom_roots(mounts: Path) -> None:
    drives = list_drives((str(mounts),))
    assert [drive.name for drive in drives] == ["KINGSTON", "PHOTOS"]


def test_only_marked_drives_have_bundles(mounts: Path) -> None:
    drives = {drive.name: drive for drive in list_drives((str(mounts),))}
    assert find_bundles(drives["PHOTOS"], "blacksite") == []
    bundles = find_bundles(drives["KINGSTON"], "blacksite")  # marker matched case-insensitively
    assert [(b.name, b.relative, b.solved) for b in bundles] == [("api-502", "BlackSite/api-502", False)]


def test_marker_folder_without_subfolders_is_one_incident(tmp_path: Path) -> None:
    drive_path = tmp_path / "mnt" / "SDCARD"
    (drive_path / "blacksite").mkdir(parents=True)
    (drive_path / "blacksite" / "app.log").write_text("2026-09-27T02:00:00Z ERROR boom\n", encoding="utf-8")
    [bundle] = find_bundles(list_drives((str(tmp_path / "mnt"),))[0], "blacksite")
    assert bundle.name == "SDCARD" and bundle.relative == "blacksite"


def test_import_copies_evidence_into_a_private_sandbox(mounts: Path, tmp_path: Path) -> None:
    drive = list_drives((str(mounts),))[0]
    [bundle] = find_bundles(drive, "blacksite")
    original = bundle.path / "kern.log"
    os.utime(original, (1_700_000_000, 1_700_000_000))
    path = import_bundle(bundle, tmp_path / "sandbox", UsbSettings())
    meta = json.loads((path / "incident.json").read_text(encoding="utf-8"))
    assert meta["title"] == "API returns 502 since 02:14" and meta["description"] == "Deployed 2.14.0 at 01:50."
    assert (path / "artifacts" / "nginx" / "error.log").is_file()
    assert not (path / "artifacts" / ".DS_Store").exists() and not (path / "artifacts" / "incident.txt").exists()
    assert (path / "artifacts" / "kern.log").stat().st_mtime == 1_700_000_000  # year-less syslog needs it
    source = read_source(path)
    assert source["drive_name"] == "KINGSTON" and source["bundle"] == "BlackSite/api-502"
    assert {item["path"] for item in source["files"]} >= {"kern.log", "nginx/error.log"}
    assert all(len(item["sha256"]) == 64 for item in source["files"])
    if os.name != "nt":
        assert oct(path.stat().st_mode & 0o777) == "0o700"


def test_import_respects_size_and_count_limits(mounts: Path, tmp_path: Path) -> None:
    [bundle] = find_bundles(list_drives((str(mounts),))[0], "blacksite")
    path = import_bundle(bundle, tmp_path / "sandbox", UsbSettings(max_files=2))
    source = read_source(path)
    assert len(source["files"]) == 2 and len(source["skipped"]) == 3
    with pytest.raises(UsbError, match="no readable evidence"):
        import_bundle(bundle, tmp_path / "sandbox", UsbSettings(max_bytes=10))


def test_archives_are_unpacked_without_escaping_the_sandbox(tmp_path: Path) -> None:
    bundle_dir = tmp_path / "mnt" / "USB" / "blacksite" / "db"
    bundle_dir.mkdir(parents=True)
    with zipfile.ZipFile(bundle_dir / "logs.zip", "w") as archive:
        archive.writestr("postgres/postgresql.log", "2026-09-27 03:40:11 UTC [1] ERROR: disk full\n")
        archive.writestr("../../escape.txt", "outside")
        archive.writestr("C:/Windows/evil.txt", "outside")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        data = b"Sep 27 03:42:32 db01 systemd[1]: postgresql failed\n"
        info = tarfile.TarInfo("var/log/syslog")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("var/log/passwd")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)
        evil = tarfile.TarInfo("/etc/cron.d/evil")
        evil.size = 1
        archive.addfile(evil, io.BytesIO(b"x"))
    (bundle_dir / "system.tar.gz").write_bytes(buffer.getvalue())

    [bundle] = find_bundles(list_drives((str(tmp_path / "mnt"),))[0], "blacksite")
    path = import_bundle(bundle, tmp_path / "sandbox", UsbSettings())
    files = sorted(item["path"] for item in read_source(path)["files"])
    # An absolute member lands inside the sandbox (leading "/" stripped, as GNU tar does);
    # "..", drive letters, and links are dropped.
    assert files == ["logs/postgres/postgresql.log", "system/etc/cron.d/evil", "system/var/log/syslog"]
    assert all((path / "artifacts" / name).resolve().is_relative_to(path.resolve()) for name in files)
    assert not (tmp_path / "escape.txt").exists() and not list(tmp_path.rglob("evil.txt"))
    assert not list(tmp_path.rglob("passwd"))


def test_solution_marks_the_bundle_solved_and_wipe_removes_the_sandbox(mounts: Path, tmp_path: Path) -> None:
    drive = list_drives((str(mounts),))[0]
    [bundle] = find_bundles(drive, "blacksite")
    path = import_bundle(bundle, tmp_path / "sandbox", UsbSettings())
    assert locate_bundle(read_source(path), (str(mounts),)) == bundle.path
    time.sleep(0.01)
    target = write_solution(bundle.path, {"guide.md": "# Guide\n"})
    assert target.name.startswith("SOLUTION-") and (target / "guide.md").read_text(encoding="utf-8") == "# Guide\n"
    assert find_bundles(drive, "blacksite")[0].solved
    wipe(path)
    assert not path.exists()


def test_report_quotes_cited_lines_and_escapes_log_text(incident_dir: Path) -> None:
    from blacksite.agent.guide import guide_markdown, parse_answer

    guide = parse_answer(GUIDE.replace("nginx/access.log:61 contains", "nginx/access.log:61 <script>alert(1)</script>"))
    event = {"guide": guide.model_dump(), "checks": [], "markdown": guide_markdown(guide)}
    with Evidence(incident_dir) as evidence:
        files = build_solution(evidence, event, "ko", None, "test-model")
    assert set(files) == {"guide.md", "guide.html", "manifest.json"}
    page = files["guide.html"]
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert "<code>journalctl -k</code>" in page  # inline code rendered, still escaped
    assert '<html lang="ko">' in page and "근본 원인" in page and "#1a1b26" in page  # Tokyo Night
    assert "Out of memory" in page or "oom-killer" in page  # kern.log:3 quoted
    assert "## Cited log lines" not in files["guide.md"] and "## 인용한 로그 줄" in files["guide.md"]
    assert json.loads(files["manifest.json"])["model"] == "test-model"


@pytest.fixture
def usb_client(tmp_path: Path, mounts: Path, monkeypatch):
    config = tmp_path / "blacksite.toml"
    config.write_text(
        '[model]\nprovider = "vllm"\nbase_url = "http://127.0.0.1:9/v1"\nname = "test"\n'
        f'[rag]\ndocs_dir = "{KNOWLEDGE.as_posix()}"\n'
        f'[usb]\nenabled = true\nroots = ["{mounts.as_posix()}"]\nsandbox_dir = "sandbox"\npoll_seconds = 60\n',
        encoding="utf-8",
    )

    async def stream(messages, info: AgentInfo):
        for start in range(0, len(GUIDE), 300):
            yield GUIDE[start:start + 300]

    monkeypatch.setattr(investigator_module, "agent_model", lambda settings: FunctionModel(stream_function=stream))
    app = create_app(config, [], tmp_path / "incidents")
    with TestClient(app, base_url=BASE_URL) as client:
        sign_in(client, "admin", "admin")
        yield client, app, tmp_path


def _wait_until_idle(client, incident: str) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        data = client.get(f"/api/incidents/{incident}").json()
        if not data["running"] and not data["queued"] and data["turns"]:
            return
        time.sleep(0.1)
    raise AssertionError("investigation did not finish")


def test_usb_flow_imports_investigates_exports_and_wipes(usb_client, mounts: Path) -> None:
    client, app, tmp_path = usb_client
    events = client.get("/api/usb").json()["events"]  # the watcher's first scan runs at startup
    deadline = time.time() + 10
    while not any(event["kind"] == "imported" for event in events) and time.time() < deadline:
        time.sleep(0.1)
        events = client.get("/api/usb").json()["events"]
    imported = next(event for event in events if event["kind"] == "imported")
    assert imported["drive"] == "KINGSTON" and imported["title"] == "API returns 502 since 02:14"
    incident = imported["incident"]
    listed = {item["id"]: item for item in client.get("/api/incidents").json()["incidents"]}
    assert listed[incident]["usb"] == {"drive": "KINGSTON"}

    _wait_until_idle(client, incident)
    overview = client.get(f"/api/incidents/{incident}").json()
    assert overview["usb"]["present"] and overview["usb"]["files"] == 5

    written_by = app.state.demo.settings().model.name
    app.state.demo.model = {"name": "picked-later"}  # switching models must not change who wrote the guide
    result = client.post(f"/api/incidents/{incident}/export", json={"language": "en"}).json()
    solution = Path(result["path"])
    assert result["wiped"] and solution.parent == mounts / "KINGSTON" / "BlackSite" / "api-502"
    assert {"guide.md", "guide.html", "manifest.json"} <= {p.name for p in solution.iterdir()}
    assert json.loads((solution / "manifest.json").read_text(encoding="utf-8"))["model"] == written_by
    assert not (tmp_path / "sandbox" / incident).exists()
    ledger = app.state.demo.services.ledger
    records = list(reversed(ledger.records(target=incident)))
    actions = [record.action for record in records]
    assert actions[0] == "usb.imported" and actions[-2:] == ["incident.exported", "incident.wiped"]
    assert "incident.turn_started" in actions and "incident.turn_finished" in actions
    assert records[0].actor == "system:usb" and records[0].detail["files"] == 5
    assert records[-1].actor == "user:1" and records[-1].session
    assert ledger.verify().ok
    assert {"provenance.json", "blacksite-signing-key.pub", "ledger-anchor.json"} <= {p.name for p in solution.iterdir()}

    anyio.run(_scan_drives, app.state.demo, set())  # reinsert the drive: its bundle is now solved
    assert incident not in {item["id"] for item in client.get("/api/incidents").json()["incidents"]}
    later = client.get("/api/usb").json()["events"]
    assert sum(event["kind"] == "imported" for event in later) == 1  # solved bundles are not imported again
    assert [e["kind"] for e in later].count("inserted") == 2


def test_export_needs_the_drive(usb_client, mounts: Path) -> None:
    client, app, tmp_path = usb_client
    deadline = time.time() + 10
    incident = None
    while incident is None and time.time() < deadline:
        imported = [e for e in client.get("/api/usb").json()["events"] if e["kind"] == "imported"]
        incident = imported[0]["incident"] if imported else None
        time.sleep(0.1)
    _wait_until_idle(client, incident)
    shutil.move(mounts / "KINGSTON", tmp_path / "unplugged")
    response = client.post(f"/api/incidents/{incident}/export", json={})
    assert response.status_code == 400 and "Insert the drive KINGSTON" in response.json()["error"]
    assert (tmp_path / "sandbox" / incident).exists()  # nothing is lost when the drive is gone
    assert client.post(f"/api/incidents/{incident}/wipe").json() == {"wiped": True}
    assert not (tmp_path / "sandbox" / incident).exists()
