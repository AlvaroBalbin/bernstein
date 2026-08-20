import json
from pathlib import Path
from unittest.mock import patch

import pytest
from bernstein.core.models import Task

from bernstein.core.agents.spawner_core import AgentSpawner


class DummySpawner:
    """Minimal stand-in for AgentSpawner to test _render_mailbox_section."""

    def __init__(self, workdir: Path):
        self._workdir = workdir


def _create_task(task_id: str = "T-1") -> Task:
    return Task(
        id=task_id,
        title="Test Task",
        description="Test description",
        role="backend",
    )


def _write_message(journal: Path, task_id: str = "T-1", seq: int = 0) -> None:
    """Write a single valid mailbox message to the journal."""
    journal.parent.mkdir(parents=True, exist_ok=True)
    msg = {
        "seq": seq,
        "task_id": task_id,
        "sender": "test-sender",
        "sender_card_fingerprint": "unregistered",
        "kind": "finding",
        "body": "test body",
        "body_hash": "sha256:dummy",
        "redaction_count": 0,
        "timestamp": 1234567890.0,
        "prev_entry_hash": "genesis",
        "entry_hash": "hmac-sha256:dummy",
        "signer_public_key_pem": "",
        "signature": "",
        "schema_version": 1,
    }
    with journal.open("w", encoding="utf-8") as f:
        f.write(json.dumps(msg) + "\n")


def test_a_delivered_message_produces_a_consumption_chain_entry(tmp_path: Path) -> None:
    from bernstein.core.security.audit_chain import AuditChainStore

    workdir = tmp_path
    journal = workdir / ".sdd" / "runtime" / "mailbox.jsonl"
    _write_message(journal)

    spawner = DummySpawner(workdir)
    tasks = [_create_task()]

    AgentSpawner._render_mailbox_section(spawner, tasks)

    chain = AuditChainStore(workdir / ".sdd" / "audit")
    events = chain.query(event_type="task.mailbox_consumed")
    assert len(events) == 1
    assert events[0].details["seq"] == 0
    assert events[0].details["entry_hash"] == "hmac-sha256:dummy"


def test_missing_journal_produces_a_visible_record_not_silent_empty_string(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    spawner = DummySpawner(tmp_path)
    tasks = [_create_task()]

    with caplog.at_level("INFO"):
        result = AgentSpawner._render_mailbox_section(spawner, tasks)

    assert result == ""
    assert any("Mailbox journal missing" in rec.message for rec in caplog.records), (
        "Expected INFO log for missing journal"
    )


def test_an_exception_during_render_is_visible_at_default_log_level(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Create the journal file so the code tries to instantiate TaskMailbox
    journal = tmp_path / ".sdd" / "runtime" / "mailbox.jsonl"
    journal.parent.mkdir(parents=True, exist_ok=True)
    journal.touch()

    spawner = DummySpawner(tmp_path)
    tasks = [_create_task()]

    # Mock TaskMailbox to raise an exception to test the except block
    with patch("bernstein.core.communication.task_mailbox.TaskMailbox", side_effect=ValueError("Test exception")):
        with caplog.at_level("DEBUG"):
            result = AgentSpawner._render_mailbox_section(spawner, tasks)

    assert result == ""
    assert any("Mailbox section rendering skipped" in rec.message and rec.levelno >= 30 for rec in caplog.records), (
        "Expected WARNING log for render exception"
    )
