import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from blacksite.audit.ledger import GENESIS, Ledger, LedgerError, verify_export
from blacksite.keys import Keys, canonical, sha256_hex

DAY = 86400.0


@pytest.fixture
def ledger(tmp_path: Path, keys, clock) -> Ledger:
    return Ledger(tmp_path / "audit.sqlite", keys, checkpoint_every=100, clock=clock)


def tamper(path: Path, sql: str, triggers: str = "ledger") -> None:
    con = sqlite3.connect(path)
    con.executescript(f"DROP TRIGGER {triggers}_no_update; DROP TRIGGER {triggers}_no_delete; {sql}")
    con.commit()
    con.close()


def fill(ledger: Ledger, count: int) -> None:
    for n in range(count):
        ledger.append("incident.created", actor="user:1", session="s1", target=f"inc-{n}", detail={"files": n})


def test_append_links_records_and_verifies(ledger: Ledger) -> None:
    first = ledger.append("auth.login", actor="user:1", session="abc", detail={"stage": "full"})
    second = ledger.append("incident.opened", actor="user:1", session="abc", target="inc-1")
    assert (first.seq, second.seq) == (1, 2) and first.prev == GENESIS and second.prev == first.hash
    assert first.at.endswith("Z") and ledger.head() == (2, second.hash)
    result = ledger.verify()
    assert result.ok and result.records == 2 and result.first_bad is None


def test_records_cannot_be_changed_through_sql(ledger: Ledger, tmp_path: Path) -> None:
    ledger.append("auth.login", actor="user:1")
    con = sqlite3.connect(tmp_path / "audit.sqlite")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        con.execute("UPDATE ledger SET actor = 'user:2'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        con.execute("DELETE FROM ledger")
    con.close()


@pytest.mark.parametrize("sql,first_bad,words", [
    ("UPDATE ledger SET detail = '{\"files\":9}' WHERE seq = 3", 3, "changed"),
    ("DELETE FROM ledger WHERE seq = 2", 2, "missing"),
    ("UPDATE ledger SET seq = 103 WHERE seq = 3; UPDATE ledger SET seq = 3 WHERE seq = 4;"
     " UPDATE ledger SET seq = 4 WHERE seq = 103", 3, "follow"),
])
def test_tampering_is_detected(ledger: Ledger, tmp_path: Path, sql: str, first_bad: int, words: str) -> None:
    fill(ledger, 6)
    tamper(tmp_path / "audit.sqlite", sql)
    result = ledger.verify()
    assert not result.ok and result.first_bad == first_bad and words in result.reason


def test_rewriting_the_chain_without_the_key_is_caught(ledger: Ledger, tmp_path: Path) -> None:
    fill(ledger, 4)
    con = sqlite3.connect(tmp_path / "audit.sqlite")
    con.executescript("DROP TRIGGER ledger_no_update; DROP TRIGGER ledger_no_delete;")
    rows = con.execute("SELECT seq, at, actor, session, action, target, detail FROM ledger ORDER BY seq").fetchall()
    prev = GENESIS
    for seq, at, actor, session, action, target, detail in rows:
        if seq == 2:
            detail = json.dumps({"files": 99})
        fields = {"seq": seq, "at": at, "actor": actor, "session": session, "action": action, "target": target,
                  "detail": json.loads(detail), "prev": prev}
        digest = sha256_hex(canonical(fields))
        con.execute("UPDATE ledger SET detail = ?, prev = ?, hash = ? WHERE seq = ?", (detail, prev, digest, seq))
        prev = digest
    con.commit()
    con.close()
    result = ledger.verify()
    assert not result.ok and result.first_bad == 2 and "key" in result.reason


def test_checkpoints_are_signed_and_truncation_is_detected(tmp_path: Path, keys, clock) -> None:
    ledger = Ledger(tmp_path / "audit.sqlite", keys, checkpoint_every=3, clock=clock)
    fill(ledger, 4)
    anchor = ledger.anchor()
    assert anchor["seq"] == 3 and len(anchor["fingerprint"]) == 19 and anchor["key_id"] == keys.key_id
    tamper(tmp_path / "audit.sqlite", "DELETE FROM ledger WHERE seq >= 3")
    result = ledger.verify()
    assert not result.ok and "truncated" in result.reason


def test_a_forged_checkpoint_is_detected(tmp_path: Path, keys, clock) -> None:
    ledger = Ledger(tmp_path / "audit.sqlite", keys, checkpoint_every=2, clock=clock)
    fill(ledger, 4)
    other = Keys(tmp_path / "other-keys")
    forged = other.sign(canonical({"seq": 2, "hash": ledger.head()[1], "at": "2027-01-01T00:00:00Z"}))
    tamper(tmp_path / "audit.sqlite", f"UPDATE checkpoints SET signature = '{forged}' WHERE seq = 2", "checkpoints")
    result = ledger.verify()
    assert not result.ok and result.first_bad == 2 and "signature" in result.reason


def test_daily_and_forced_checkpoints(ledger: Ledger, clock) -> None:
    ledger.append("a", actor="system")
    assert ledger.anchor()["seq"] == 1  # the first record of a day is signed
    ledger.append("b", actor="system")
    assert ledger.anchor()["seq"] == 1
    clock.advance(DAY)
    ledger.append("c", actor="system")
    assert ledger.anchor()["seq"] == 3
    ledger.append("d", actor="system")
    assert ledger.checkpoint()["seq"] == 4 and ledger.checkpoint() is None


def test_anchors_from_elsewhere_are_checked(ledger: Ledger, tmp_path: Path) -> None:
    fill(ledger, 3)
    anchor = ledger.checkpoint()
    assert ledger.verify(anchors=[anchor]).ok
    tamper(tmp_path / "audit.sqlite", "DELETE FROM ledger WHERE seq = 3", "ledger")
    tamper(tmp_path / "audit.sqlite", "DELETE FROM checkpoints WHERE seq = 3", "checkpoints")
    result = ledger.verify(anchors=[anchor])
    assert not result.ok and "truncated" in result.reason


def test_incremental_verification_remembers_progress(ledger: Ledger) -> None:
    fill(ledger, 3)
    assert ledger.verify_incremental().checked_from == 1
    fill(ledger, 2)
    result = ledger.verify_incremental()
    assert result.ok and result.checked_from == 4 and result.records == 5
    assert ledger.last_verification()["records"] == 5


def test_records_filter_newest_first(ledger: Ledger) -> None:
    ledger.append("auth.login", actor="user:1", session="a")
    ledger.append("incident.opened", actor="user:1", session="a", target="inc-1")
    ledger.append("auth.login", actor="user:2", session="b")
    assert [record.seq for record in ledger.records()] == [3, 2, 1]
    assert [record.seq for record in ledger.records(action="auth.")] == [3, 1]
    assert [record.seq for record in ledger.records(session="a")] == [2, 1]
    assert [record.seq for record in ledger.records(actor="user:2")] == [3]
    assert [record.seq for record in ledger.records(target="inc-1")] == [2]
    assert [record.seq for record in ledger.records(before=3, limit=1)] == [2]
    assert [record.seq for record in ledger.records(after=1)] == [3, 2]
    assert [record.seq for record in ledger.records(where=lambda record: record.actor == "user:1", limit=1)] == [2]


def test_export_verifies_without_the_secret(ledger: Ledger, tmp_path: Path) -> None:
    fill(ledger, 5)
    target = tmp_path / "audit-export.jsonl"
    assert ledger.export(target) == 5
    result = verify_export(target)
    assert result.ok and result.records == 5 and result.key_fingerprint == ledger.keys.fingerprint
    lines = target.read_text(encoding="utf-8").splitlines()
    edited = [json.loads(line) for line in lines]
    for item in edited:
        if item.get("type") == "record" and item["seq"] == 2:
            item["detail"] = {"files": 42}
    target.write_text("\n".join(json.dumps(item) for item in edited) + "\n", encoding="utf-8")
    assert not verify_export(target).ok


def test_a_failed_append_marks_the_ledger_broken(ledger: Ledger, tmp_path: Path) -> None:
    ledger.append("a", actor="system")
    with pytest.raises(LedgerError):
        ledger.append("b", actor="system", detail={"bad": object()})
    assert ledger.broken
    assert ledger.probe() and not ledger.broken


WORKER = """
import sys
from pathlib import Path
from blacksite.audit.ledger import Ledger
from blacksite.keys import Keys
root = Path(sys.argv[1])
ledger = Ledger(root / "audit.sqlite", Keys(root / "keys"), checkpoint_every=7)
for n in range(20):
    ledger.append("worker", actor="system", detail={"worker": sys.argv[2], "n": n})
"""


def test_two_processes_append_one_chain(tmp_path: Path, keys) -> None:
    Ledger(tmp_path / "audit.sqlite", keys)
    workers = [subprocess.Popen([sys.executable, "-c", WORKER, str(tmp_path), name]) for name in ("a", "b")]
    assert all(worker.wait(timeout=120) == 0 for worker in workers)
    result = Ledger(tmp_path / "audit.sqlite", keys).verify()
    assert result.ok and result.records == 40
