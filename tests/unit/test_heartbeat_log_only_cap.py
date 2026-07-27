"""Regression for issue #3058: stderr merged into the agent log must not
sustain the reap heartbeat indefinitely via _refresh_heartbeat_from_signals.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bernstein.core.models import AgentSession

from bernstein.core.agents.agent_lifecycle import (
    _MAX_LOG_ONLY_HEARTBEAT_TICKS,
    _refresh_heartbeat_from_signals,
)


def _make_orch(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(_workdir=tmp_path)


def _touch(path: Path, mtime: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("line\n") if not path.exists() else path.write_text(path.read_text() + "line\n")
    os.utime(path, (mtime, mtime))


@patch("bernstein.core.agents.agent_lifecycle._is_process_alive", return_value=False)
def test_log_only_heartbeat_capped_after_max_ticks(_mock_alive, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """A dead-PID session whose log keeps getting fresh stderr writes (e.g. a
    retry loop or spinner, per issue #3058) may only ride that signal for
    _MAX_LOG_ONLY_HEARTBEAT_TICKS consecutive ticks, not indefinitely."""
    orch = _make_orch(tmp_path)
    session = AgentSession(id="sess-log", role="backend", pid=123)
    log_path = tmp_path / ".sdd" / "worktrees" / session.id / ".sdd" / "runtime" / f"{session.id}.log"

    for tick in range(_MAX_LOG_ONLY_HEARTBEAT_TICKS):
        now = time.time() + tick + 1
        _touch(log_path, now)
        _refresh_heartbeat_from_signals(orch, session, now)
        assert session.heartbeat_ts == now, f"tick {tick} should still refresh from the log"
        assert session.log_only_heartbeat_ticks == tick + 1

    # One more tick, log still fresh: the cap is now reached, so no refresh.
    stale_heartbeat_ts = session.heartbeat_ts
    now = time.time() + _MAX_LOG_ONLY_HEARTBEAT_TICKS + 1
    _touch(log_path, now)
    _refresh_heartbeat_from_signals(orch, session, now)
    assert session.heartbeat_ts == stale_heartbeat_ts, "capped tick must not refresh heartbeat_ts"


@patch("bernstein.core.agents.agent_lifecycle._is_process_alive", return_value=False)
def test_heartbeat_json_signal_is_never_capped(_mock_alive, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """The deliberate heartbeat protocol JSON is real evidence of progress
    (unlike the stderr-tainted log) and must keep refreshing the heartbeat
    past however many ticks the log-only cap would allow."""
    orch = _make_orch(tmp_path)
    session = AgentSession(id="sess-json", role="backend", pid=123)
    heartbeat_json = tmp_path / ".sdd" / "runtime" / "heartbeats" / f"{session.id}.json"

    for tick in range(_MAX_LOG_ONLY_HEARTBEAT_TICKS + 5):
        now = time.time() + tick + 1
        _touch(heartbeat_json, now)
        _refresh_heartbeat_from_signals(orch, session, now)
        assert session.heartbeat_ts == now
        assert session.log_only_heartbeat_ticks == 0


@patch("bernstein.core.agents.agent_lifecycle._is_process_alive")
def test_live_pid_resets_log_only_streak(mock_alive, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """A confirmed-live PID is real evidence of progress: it must reset the
    log-only streak so a later stall gets the full grace budget again,
    rather than inheriting an already-exhausted counter."""
    orch = _make_orch(tmp_path)
    session = AgentSession(id="sess-mixed", role="backend", pid=123)
    log_path = tmp_path / ".sdd" / "worktrees" / session.id / ".sdd" / "runtime" / f"{session.id}.log"

    mock_alive.return_value = False
    for tick in range(_MAX_LOG_ONLY_HEARTBEAT_TICKS):
        now = time.time() + tick + 1
        _touch(log_path, now)
        _refresh_heartbeat_from_signals(orch, session, now)
    assert session.log_only_heartbeat_ticks == _MAX_LOG_ONLY_HEARTBEAT_TICKS

    # PID confirmed alive on the next tick: real signal, resets the streak.
    mock_alive.return_value = True
    now = time.time() + _MAX_LOG_ONLY_HEARTBEAT_TICKS + 1
    _refresh_heartbeat_from_signals(orch, session, now)
    assert session.heartbeat_ts == now
    assert session.log_only_heartbeat_ticks == 0

    # Back to log-only: it gets the full budget again, not an exhausted one.
    mock_alive.return_value = False
    now = time.time() + _MAX_LOG_ONLY_HEARTBEAT_TICKS + 2
    _touch(log_path, now)
    _refresh_heartbeat_from_signals(orch, session, now)
    assert session.heartbeat_ts == now
    assert session.log_only_heartbeat_ticks == 1
