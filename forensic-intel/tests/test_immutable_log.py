"""ImmutableLog keeps a verifiable hash chain."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from storage.immutable_log import ImmutableLog, LogEntry  # type: ignore


@pytest.fixture
def tmp_log(tmp_path):
    path = tmp_path / "test_evidence.jsonl"
    log = ImmutableLog(path)
    yield log
    # cleanup handled by tmp_path


def test_empty_log_is_valid(tmp_log):
    assert len(tmp_log) == 0
    assert tmp_log.verify() is True


def test_append_and_verify(tmp_log):
    e1 = tmp_log.append("action", {"cmd": "ls"})
    e2 = tmp_log.append("action", {"cmd": "cat secrets"})

    assert len(tmp_log) == 2
    assert e1.index == 0
    assert e2.index == 1
    assert e2.prev_hash == e1.entry_hash
    assert tmp_log.verify() is True


def test_chain_survives_reload(tmp_path):
    path = tmp_path / "persist.jsonl"
    log1 = ImmutableLog(path)
    log1.append("login", {"user": "alice"})
    log1.append("file_read", {"path": "/etc/passwd"})

    log2 = ImmutableLog(path)
    assert len(log2) == 2
    assert log2.verify() is True
    assert log2.get(0).payload["user"] == "alice"


def test_tamper_is_detected(tmp_path):
    path = tmp_path / "tamper.jsonl"
    log = ImmutableLog(path)
    log.append("action", {"cmd": "whoami"})
    log.append("action", {"cmd": "id"})

    # Manually corrupt the file
    lines = path.read_text().strip().splitlines()
    data = json.loads(lines[0])
    data["payload"]["cmd"] = "TAMPERED"
    lines[0] = json.dumps(data)
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(ValueError, match="broken hash chain"):
        ImmutableLog(path)
