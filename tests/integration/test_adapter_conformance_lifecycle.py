"""Cross-platform adapter conformance: spawn / stop / restart (#2367).

Unlike ``test_adapter_e2e.py`` (which skips on Windows because a handful of its
cases lean on POSIX signal delivery), this module exercises the platform-neutral
conformance contract for the three primary adapters -- claude, codex, gemini --
against the cross-platform fake-CLI harness, so it runs on the Windows CI lane
too. It proves, against a real spawned subprocess (no ``Popen`` mock), that each
adapter can:

* **spawn** the upstream CLI and capture its output,
* **stop** a hung spawn through the platform process-tree reap (Job Object /
  ``taskkill`` on Windows, process-group signal on POSIX), and
* **restart** into a fresh session after a prior spawn has exited.

The harness installs ``claude``/``codex``/``gemini`` shims on ``PATH`` (a POSIX
``sh`` wrapper or a Windows ``.cmd`` batch shim); the adapter launch path
resolves and runs them exactly as it would the real CLI.
"""

from __future__ import annotations

import contextlib
import subprocess
from typing import TYPE_CHECKING

import pytest
from bernstein.core.models import ModelConfig

from bernstein.adapters.claude import ClaudeCodeAdapter
from bernstein.adapters.codex import CodexAdapter
from bernstein.adapters.gemini import GeminiAdapter
from bernstein.core.config.platform_compat import (
    IS_WINDOWS,
    process_alive,
    reap_process_group,
)

if TYPE_CHECKING:
    from pathlib import Path

    from bernstein.adapters.base import CLIAdapter

    from .fake_cli.conftest_adapters import FakeCLIHandle

pytestmark = [pytest.mark.integration]

# The three primary adapters the conformance suite must green on every OS.
_ADAPTERS: dict[str, tuple[type[CLIAdapter], ModelConfig]] = {
    "claude": (ClaudeCodeAdapter, ModelConfig(model="sonnet", effort="medium")),
    "codex": (CodexAdapter, ModelConfig(model="gpt-5.5-mini", effort="medium")),
    "gemini": (GeminiAdapter, ModelConfig(model="gemini-3-flash", effort="medium")),
}


def _git_workdir(tmp_path: Path) -> Path:
    """Initialise the minimal git workdir the adapters expect."""
    workdir = tmp_path / "work"
    workdir.mkdir()
    for args in (
        ["git", "init", "-b", "main"],
        ["git", "config", "user.email", "test@example.com"],
        ["git", "config", "user.name", "T"],
        ["git", "commit", "--allow-empty", "-m", "init"],
    ):
        subprocess.run(args, cwd=workdir, check=True, capture_output=True)
    return workdir


def _reap_via_proc(result: object, *, timeout_s: float = 8.0) -> int:
    """Wait for the spawned worker to exit (cross-platform ``proc.wait``)."""
    proc = getattr(result, "proc", None)
    if proc is not None and hasattr(proc, "wait"):
        return int(proc.wait(timeout=timeout_s))
    return 0


@pytest.mark.parametrize("adapter_name", sorted(_ADAPTERS))
def test_adapter_spawns_and_captures_output(
    adapter_name: str,
    tmp_path: Path,
    fake_cli_fixture: FakeCLIHandle,
) -> None:
    """Each primary adapter spawns the fake CLI and captures its output."""
    adapter_cls, model = _ADAPTERS[adapter_name]
    workdir = _git_workdir(tmp_path)
    result = adapter_cls().spawn(
        prompt=f"{adapter_name}-success",
        workdir=workdir,
        model_config=model,
        session_id=f"{adapter_name}-conf-spawn",
    )
    exit_code = _reap_via_proc(result, timeout_s=8.0)
    with contextlib.suppress(Exception):
        adapter_cls.cancel_timeout(result)
    assert exit_code == 0
    # The fake recorded the argv the adapter actually assembled.
    assert fake_cli_fixture.read_argv(), "adapter did not spawn the fake CLI"


@pytest.mark.parametrize("adapter_name", sorted(_ADAPTERS))
def test_adapter_stop_terminates_a_hung_spawn(
    adapter_name: str,
    tmp_path: Path,
    fake_cli_fixture: FakeCLIHandle,
) -> None:
    """A hung spawn is stopped through the platform process-tree reap.

    The guarantee under test is "the hung spawn is no longer running after
    stop", not "a stop signal was accepted", so it is checked against the
    process itself rather than against the receipt that would otherwise be
    marking its own homework.

    The Windows lane used to fail here on ``assert receipt.delivered``.  The
    cause was not an already-exited spawn: the old Windows stop returned
    True for a pid nothing held, because its fallback ended in a liveness
    re-probe that a missing pid satisfied.  It returned False only when the
    target was still *observed running* after the force kill, which is what
    an immediate liveness probe does when raced against an asynchronous
    ``TerminateProcess``.  The reap now terminates through a handle it
    already holds and waits on that handle, so the outcome is decided by
    evidence rather than by timing.

    The receipt assertions below are deliberately limited to what each
    platform can establish.  Windows can observe the exit directly, so the
    receipt must say so.  POSIX cannot: an unreaped group answers EPERM on
    macOS and answers successfully on Linux (both measured), and neither
    reply separates "exited but unreaped" from "running", so the reap
    records the stop it delivered and confirms nothing.
    """
    adapter_cls, model = _ADAPTERS[adapter_name]
    workdir = _git_workdir(tmp_path)
    fake_cli_fixture.configure(mode="hang")
    result = adapter_cls().spawn(
        prompt=f"{adapter_name}-hang",
        workdir=workdir,
        model_config=model,
        session_id=f"{adapter_name}-conf-stop",
    )
    pid = int(getattr(result, "pid", 0))
    assert pid > 0
    receipt = reap_process_group(pid, grace_seconds=3.0)

    # The guarantee, established against the process rather than the receipt.
    proc = getattr(result, "proc", None)
    if proc is not None and hasattr(proc, "wait"):
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=8.0)
        stopped = proc.poll() is not None
    else:
        stopped = not process_alive(pid)
    assert stopped, f"worker still alive after platform reap: {receipt}"

    # Either a stop was delivered, or the tree was observed already gone.
    # A receipt claiming neither means the reap declined to act and said so,
    # which is honest but is not a reap.
    assert receipt.delivered or receipt.already_gone, f"reap reported neither a stop nor an observed exit: {receipt}"
    if IS_WINDOWS:
        # The pinned handle leaves the system when the process does, so on
        # this platform the guarantee is observable and must be reported.
        assert receipt.confirmed_dead, f"reap left the spawn unconfirmed: {receipt}"
    with contextlib.suppress(Exception):
        adapter_cls.cancel_timeout(result)


@pytest.mark.parametrize("adapter_name", sorted(_ADAPTERS))
def test_adapter_restarts_after_prior_spawn_exits(
    adapter_name: str,
    tmp_path: Path,
    fake_cli_fixture: FakeCLIHandle,
) -> None:
    """After a spawn exits, the adapter restarts into a fresh session."""
    adapter_cls, model = _ADAPTERS[adapter_name]
    workdir = _git_workdir(tmp_path)
    adapter = adapter_cls()

    first = adapter.spawn(
        prompt=f"{adapter_name}-restart-1",
        workdir=workdir,
        model_config=model,
        session_id=f"{adapter_name}-conf-restart-1",
    )
    assert _reap_via_proc(first, timeout_s=8.0) == 0
    with contextlib.suppress(Exception):
        adapter_cls.cancel_timeout(first)

    second = adapter.spawn(
        prompt=f"{adapter_name}-restart-2",
        workdir=workdir,
        model_config=model,
        session_id=f"{adapter_name}-conf-restart-2",
    )
    assert _reap_via_proc(second, timeout_s=8.0) == 0
    with contextlib.suppress(Exception):
        adapter_cls.cancel_timeout(second)
    assert int(getattr(second, "pid", 0)) != int(getattr(first, "pid", -1))
