"""Orchestrator routes ACP-declared adapters through the ACP event channel.

Follow-up to the ACP transport (#2522): the transport, the content-addressed
client journal, and the goose/kilo strategy-matrix migration all landed, but the
orchestrator's monitoring loop never read the declared ``EventChannel``, so in a
real run an ACP-declared adapter still fell through the text-signal lifecycle
path. These tests pin the missing dispatch seam at two levels:

* the pure router (:mod:`bernstein.core.orchestration.event_channel_router`),
  which reads the declared channel and drives ACP adapters through
  ``run_acp_channel`` while returning ``None`` for text-signal adapters, and
* the orchestrator monitoring method that calls it for finished agents, proving
  an ACP-declared adapter is journaled end to end (content-addressed, terminal,
  byte-identically replayable) with no ``BERNSTEIN:`` text parsing involved.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import MethodType, SimpleNamespace
from typing import Any

from bernstein.core.models import AgentSession

from bernstein.core.orchestration.event_channel_router import (
    agent_uses_acp_channel,
    iter_journal_frames,
    route_agent_lifecycle,
)
from bernstein.core.orchestration.orchestrator import Orchestrator
from bernstein.core.protocols.acp.client import (
    compare_acp_journals,
    replay_acp_content_hashes,
)
from bernstein.core.replay.journal import EventJournal, load_events

# A well-formed ACP prompt turn: initialize response, one stream update, and the
# terminal prompt response carrying a non-error stopReason. No BERNSTEIN: text
# grammar anywhere - the lifecycle is driven purely from structured frames.
_SESSION_FRAMES: list[dict[str, Any]] = [
    {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-04-01"}},
    {"jsonrpc": "2.0", "method": "streamUpdate", "params": {"sessionId": "s", "delta": {"text": "hi"}}},
    {"jsonrpc": "2.0", "id": 2, "result": {"stopReason": "end_turn"}},
]


def _frame_lines(frames: list[dict[str, Any]]) -> list[bytes]:
    return [(json.dumps(f) + "\n").encode("utf-8") for f in frames]


def _acp_rows(journal: EventJournal) -> list[dict[str, Any]]:
    return [row for row in load_events(journal.path) if row.get("event") == "acp_event"]


# ---------------------------------------------------------------------------
# Router: declared-channel dispatch
# ---------------------------------------------------------------------------


def test_router_drives_acp_declared_adapter_through_acp_channel(tmp_path: Path) -> None:
    journal = EventJournal("kilo-run", tmp_path)
    result = route_agent_lifecycle(
        "kilo",
        _frame_lines(_SESSION_FRAMES),
        journal=journal,
        session_id="kilo-run",
    )

    assert result is not None  # kilo declares EventChannel.ACP -> routed, not None
    assert result.terminal is True
    assert result.ok is True
    assert result.stop_reason == "end_turn"
    assert result.event_count == len(_SESSION_FRAMES)
    # Every inbound frame is chained into the run journal content-addressed.
    assert len(_acp_rows(journal)) == len(_SESSION_FRAMES)
    assert result.journal_head == journal.head()
    assert journal.verify().ok
    # The lifecycle used structured frames only: no text grammar was emitted.
    assert not any(b"BERNSTEIN:" in line for line in _frame_lines(_SESSION_FRAMES))


def test_router_leaves_text_signal_adapter_on_existing_path(tmp_path: Path) -> None:
    journal = EventJournal("aider-run", tmp_path)
    result = route_agent_lifecycle(
        "aider",
        _frame_lines(_SESSION_FRAMES),
        journal=journal,
        session_id="aider-run",
    )

    # aider is a text-signal adapter: the router does not consume its stream and
    # records nothing, so the existing lifecycle path is left untouched.
    assert result is None
    assert _acp_rows(journal) == []


def test_agent_uses_acp_channel_predicate() -> None:
    assert agent_uses_acp_channel("kilo") is True
    assert agent_uses_acp_channel("goose") is True
    assert agent_uses_acp_channel("aider") is False
    assert agent_uses_acp_channel("") is False


def test_router_journal_replay_is_byte_identical(tmp_path: Path) -> None:
    frames = _frame_lines(_SESSION_FRAMES)
    first = EventJournal("kilo-a", tmp_path / "a")
    second = EventJournal("kilo-b", tmp_path / "b")
    route_agent_lifecycle("kilo", frames, journal=first, session_id="kilo-a")
    route_agent_lifecycle("kilo", frames, journal=second, session_id="kilo-b")

    # Byte-identical replay: the ordered content hashes are the ACP session's
    # replay-stable identity, so two faithful drives agree at every step.
    assert replay_acp_content_hashes(first.path) == replay_acp_content_hashes(second.path)
    assert compare_acp_journals(first.path, second.path) is None


# ---------------------------------------------------------------------------
# iter_journal_frames helper
# ---------------------------------------------------------------------------


def test_iter_journal_frames_yields_nonblank_lines(tmp_path: Path) -> None:
    log = tmp_path / "agent.log"
    log.write_bytes(b"".join(_frame_lines(_SESSION_FRAMES)) + b"\n   \n")
    assert list(iter_journal_frames(log)) == _frame_lines(_SESSION_FRAMES)


def test_iter_journal_frames_missing_file_is_empty(tmp_path: Path) -> None:
    assert list(iter_journal_frames(tmp_path / "absent.log")) == []


# ---------------------------------------------------------------------------
# Orchestrator monitoring loop: end-to-end dispatch for a finished agent
# ---------------------------------------------------------------------------


def _bind(stub: SimpleNamespace, name: str) -> None:
    setattr(stub, name, MethodType(getattr(Orchestrator, name), stub))


def _orch_stub(tmp_path: Path, *, adapter: str) -> SimpleNamespace:
    stub = SimpleNamespace(
        _agents={},
        _workdir=tmp_path,
        _recorder=EventJournal("run-1", tmp_path / ".sdd"),
        _acp_driven=set(),
        _spawner=SimpleNamespace(default_adapter_name=adapter, check_alive=lambda _s: False),
    )
    _bind(stub, "_drive_finished_acp_channels")
    _bind(stub, "_resolve_acp_log_path")
    return stub


def _finished_session(tmp_path: Path, session_id: str) -> AgentSession:
    log = tmp_path / f"{session_id}.log"
    log.write_bytes(b"".join(_frame_lines(_SESSION_FRAMES)))
    return AgentSession(id=session_id, role="impl", status="dead", log_path=str(log))


def test_monitoring_loop_drives_finished_acp_agent_end_to_end(tmp_path: Path) -> None:
    stub = _orch_stub(tmp_path, adapter="kilo")
    session = _finished_session(tmp_path, "agent-kilo")
    stub._agents[session.id] = session

    stub._drive_finished_acp_channels()

    rows = _acp_rows(stub._recorder)
    assert len(rows) == len(_SESSION_FRAMES)
    assert rows[-1]["terminal"] is True
    assert rows[-1]["stop_reason"] == "end_turn"
    assert stub._recorder.verify().ok
    assert session.id in stub._acp_driven


def test_monitoring_loop_skips_text_signal_adapter(tmp_path: Path) -> None:
    stub = _orch_stub(tmp_path, adapter="aider")
    session = _finished_session(tmp_path, "agent-aider")
    stub._agents[session.id] = session

    stub._drive_finished_acp_channels()

    # A text-signal run never routes through the ACP channel: nothing recorded.
    assert _acp_rows(stub._recorder) == []


def test_monitoring_loop_does_not_drive_live_agent(tmp_path: Path) -> None:
    stub = _orch_stub(tmp_path, adapter="kilo")
    stub._spawner.check_alive = lambda _s: True  # still running
    session = _finished_session(tmp_path, "agent-live")
    session.status = "working"
    stub._agents[session.id] = session

    stub._drive_finished_acp_channels()

    # The frame stream is only complete after the process exits.
    assert _acp_rows(stub._recorder) == []
    assert session.id not in stub._acp_driven


def test_monitoring_loop_acp_drive_is_idempotent(tmp_path: Path) -> None:
    stub = _orch_stub(tmp_path, adapter="kilo")
    session = _finished_session(tmp_path, "agent-kilo")
    stub._agents[session.id] = session

    stub._drive_finished_acp_channels()
    first = len(_acp_rows(stub._recorder))
    stub._drive_finished_acp_channels()
    second = len(_acp_rows(stub._recorder))

    # Each session is driven at most once: the second pass records nothing new.
    assert first == len(_SESSION_FRAMES)
    assert second == first
