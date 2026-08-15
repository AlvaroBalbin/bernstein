"""First-run contracts for the two long-running surfaces (issue #3826).

``bernstein live`` and ``bernstein worker`` both run until something stops
them, so "did the documented first run work" needs a definition before it
can be tested. Each surface gets one named readiness signal, and that
signal is the contract the FEATURE_MATRIX row rests on:

| Surface            | Readiness signal |
|--------------------|------------------|
| ``bernstein live`` | the first rendered frame, identified by the ``AGENTS`` and ``TASKS`` pane headers |
| ``bernstein worker`` | the ``Registered as node <id>`` line, printed once the central server accepts the registration |

Neither is a sleep. A fixed sleep would pass on a process that starts and
immediately wedges, which is the failure these tests exist to catch.

The shutdown half asserts the process ends on the documented interrupt
without a traceback and leaves no pid file behind. Signal delivery is
POSIX-only here, matching ``test_worker_subprocess_signals.py``; the
readiness half runs everywhere.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_READY_TIMEOUT_S = 90.0
_EXIT_TIMEOUT_S = 30.0

_POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32",
    reason="SIGINT delivery to a child process group is POSIX-only",
)


def _spawn(workdir: Path, log: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.Popen[bytes]:
    """Start the CLI as the docs write it, with output captured to *log*."""
    process_env = os.environ.copy()
    process_env["PYTHONUTF8"] = "1"
    if env:
        process_env.update(env)
    handle = log.open("wb")
    return subprocess.Popen(
        [sys.executable, "-m", "bernstein", *args],
        cwd=workdir,
        env=process_env,
        stdout=handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def _flat(text: str) -> str:
    """Collapse whitespace so a match cannot be broken by line wrapping.

    These surfaces print through Rich, which wraps at the terminal width.
    That width differs between a developer's terminal and a CI runner, so
    a phrase that is contiguous locally can arrive split across a newline
    - matching on the raw text makes the assertion depend on console
    geometry rather than on what the command said.
    """
    return " ".join(text.split())


def _wait_for_signal(log: Path, *needles: str, timeout_s: float = _READY_TIMEOUT_S) -> str:
    """Block until every needle appears in *log*. Returns the text read.

    Polls the log rather than sleeping a fixed interval, so a surface that
    becomes ready quickly is not charged the full budget and one that never
    does fails with what it actually printed.
    """
    deadline = time.monotonic() + timeout_s
    text = ""
    while time.monotonic() < deadline:
        if log.exists():
            text = log.read_text(encoding="utf-8", errors="replace")
            if all(needle in _flat(text) for needle in needles):
                return text
        time.sleep(0.1)
    raise AssertionError(f"readiness signal {needles!r} never appeared within {timeout_s}s. Output was:\n{text}")


def _terminate(process: subprocess.Popen[bytes]) -> None:
    """Best-effort cleanup for a surface a test is done with."""
    if process.poll() is None:
        process.kill()
        process.wait(timeout=_EXIT_TIMEOUT_S)


def _git_workspace(path: Path) -> Path:
    """A clean git checkout - what the worker docs require of a workspace."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "."], cwd=path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "init"],
        cwd=path,
        check=True,
    )
    return path


class TestLiveFirstRun:
    """``bernstein live`` renders a dashboard from a clean workspace."""

    def test_renders_a_first_frame(self, tmp_path: Path) -> None:
        """Readiness: the first rendered frame, not merely a started process.

        Run from an empty directory with no session to attach to, which is
        the worst case for a dashboard that polls a task server.
        """
        log = tmp_path / "live.log"
        process = _spawn(tmp_path, log, "live", "--no-splash")
        try:
            _wait_for_signal(log, "AGENTS", "TASKS")
            assert process.poll() is None, "live exited instead of holding the dashboard open"
        finally:
            _terminate(process)

    @_POSIX_ONLY
    def test_exits_cleanly_on_interrupt(self, tmp_path: Path) -> None:
        """The docs say Ctrl+C to exit, so an interrupt must not traceback."""
        log = tmp_path / "live.log"
        process = _spawn(tmp_path, log, "live", "--no-splash")
        try:
            _wait_for_signal(log, "AGENTS", "TASKS")
            process.send_signal(signal.SIGINT)
            process.wait(timeout=_EXIT_TIMEOUT_S)
        finally:
            _terminate(process)

        output = log.read_text(encoding="utf-8", errors="replace")
        assert "Traceback (most recent call last)" not in _flat(output), output[-2000:]
        assert not (tmp_path / ".sdd" / "runtime" / "server.pid").exists()


class TestWorkerFirstRun:
    """``bernstein worker`` joins a cluster from a clean git workspace."""

    def test_refuses_a_workspace_that_is_not_a_git_checkout(self, tmp_path: Path) -> None:
        """The refusal names the reason and the fix, rather than failing late.

        Each task runs in a git worktree cut from the workspace, so a
        non-git workspace can never work; saying so at startup is the
        documented behaviour and the control for the happy path below.
        """
        log = tmp_path / "worker.log"
        process = _spawn(tmp_path, log, "worker", "--server", "http://127.0.0.1:8099", "--token", "SECRET")
        try:
            exit_code = process.wait(timeout=_EXIT_TIMEOUT_S)
        finally:
            _terminate(process)

        assert exit_code == 1
        output = log.read_text(encoding="utf-8", errors="replace")
        assert "is not a git repository" in _flat(output), output[-2000:]
        assert "Traceback (most recent call last)" not in _flat(output), output[-2000:]

    def test_registers_against_a_live_server(self, tmp_path: Path, unused_tcp_port: int) -> None:
        """Readiness: the server accepted the registration and named the node."""
        central = _git_workspace(tmp_path / "central")
        worker_dir = _git_workspace(tmp_path / "worker")
        server_log = tmp_path / "serve.log"
        worker_log = tmp_path / "worker.log"
        cluster_env = {"BERNSTEIN_CLUSTER_ENABLED": "1", "BERNSTEIN_AUTH_TOKEN": "TESTSECRET"}

        server = _spawn(central, server_log, "serve", "--port", str(unused_tcp_port), env=cluster_env)
        try:
            _wait_for_signal(server_log, "Application startup complete")
            worker = _spawn(
                worker_dir,
                worker_log,
                "worker",
                "--server",
                f"http://127.0.0.1:{unused_tcp_port}",
                "--token",
                "TESTSECRET",
                "--name",
                "testbox",
                env=cluster_env,
            )
            try:
                _wait_for_signal(worker_log, "Registered as node")
                assert worker.poll() is None, "worker exited instead of holding its registration"
            finally:
                _terminate(worker)
        finally:
            _terminate(server)

        worker_output = worker_log.read_text(encoding="utf-8", errors="replace")
        assert "Traceback (most recent call last)" not in _flat(worker_output), worker_output[-2000:]


@pytest.fixture
def unused_tcp_port() -> int:
    """A port the OS just confirmed is free, so parallel runs do not collide."""
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
