"""Windows-branch coverage for the process-lifecycle platform layer.

These tests exercise the Windows code paths of
``bernstein.core.config.platform_compat`` on any host by substituting a
mock ``kernel32`` / ``subprocess.run`` and flipping ``IS_WINDOWS``. They
carry no platform skip marker: the Windows branches are pure logic once
the kernel calls are mocked, so parity coverage no longer waits for a
Windows runner.

The reap-receipt cases assert the *verifiable artifact* itself: the
:class:`ProcessReapReceipt` is a deterministic projection of the platform
onto ``(os_name, method, delivered, already_gone, escalated,
confirmed_dead)``. On Windows the force tier must fall back to the numeric
``9`` code because ``SIGKILL`` does not exist, and the receipt must record
``windows_process_tree`` as the mechanism. Stripping that projection is
what a Windows regression looks like, so we pin it here rather than only on
a Windows host.

Two properties get dedicated coverage because Windows recycles pids fast
enough for both to matter in practice:

* a target that had already exited is a *satisfied* reap, not a failed one
  - nothing is left running, which is the whole point of the call, and
* no stop tier may ever act on a pid that might have been recycled into an
  unrelated process, so the reap pins the target with an open handle and
  refuses a process that started after the reap was requested.
"""

from __future__ import annotations

import ctypes
import signal
import subprocess
import time
from typing import Any

import bernstein.core.config.platform_compat as pc

# ---------------------------------------------------------------------------
# kill_process - Windows branch
# ---------------------------------------------------------------------------


class TestKillProcessWindowsBranch:
    """Windows dispatch of kill_process onto taskkill / os.kill."""

    def test_sigterm_routes_to_taskkill_no_force(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        calls: list[tuple[int, bool, bool]] = []

        def _fake(pid: int, *, force: bool = False, tree: bool = False) -> bool:
            calls.append((pid, force, tree))
            return True

        monkeypatch.setattr(pc, "_win_taskkill", _fake)
        assert pc.kill_process(4321, signal.SIGTERM) is True
        assert calls == [(4321, False, False)]

    def test_sigkill_code_routes_to_forced_taskkill(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        calls: list[tuple[int, bool, bool]] = []

        def _fake(pid: int, *, force: bool = False, tree: bool = False) -> bool:
            calls.append((pid, force, tree))
            return True

        monkeypatch.setattr(pc, "_win_taskkill", _fake)
        # 9 == SIGKILL numeric value; SIGKILL is not importable on Windows.
        assert pc.kill_process(4321, 9) is True
        assert calls == [(4321, True, False)]

    def test_other_signal_falls_back_to_os_kill(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        seen: list[tuple[int, int]] = []
        monkeypatch.setattr(pc.os, "kill", lambda pid, sig: seen.append((pid, sig)))
        # 2 is neither SIGTERM(15) nor the SIGKILL numeric (9).
        assert pc.kill_process(4321, 2) is True
        assert seen == [(4321, 2)]

    def test_other_signal_oserror_returns_false(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)

        def _boom(pid: int, sig: int) -> None:
            raise OSError("no such process")

        monkeypatch.setattr(pc.os, "kill", _boom)
        assert pc.kill_process(4321, 2) is False

    def test_nonpositive_pid_short_circuits(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        # Must return False without ever touching taskkill.
        monkeypatch.setattr(
            pc,
            "_win_taskkill",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("called")),
        )
        assert pc.kill_process(0) is False
        assert pc.kill_process(-1) is False


# ---------------------------------------------------------------------------
# kill_process_group - Windows branch
# ---------------------------------------------------------------------------


class TestKillProcessGroupWindowsBranch:
    """Windows kill_process_group maps onto a taskkill tree termination."""

    def test_term_kills_tree_without_force(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        calls: list[tuple[int, bool, bool]] = []

        def _fake(pid: int, *, force: bool = False, tree: bool = False) -> bool:
            calls.append((pid, force, tree))
            return True

        monkeypatch.setattr(pc, "_win_taskkill", _fake)
        assert pc.kill_process_group(777, signal.SIGTERM) is True
        assert calls == [(777, False, True)]

    def test_kill_code_forces_tree_termination(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        calls: list[tuple[int, bool, bool]] = []

        def _fake(pid: int, *, force: bool = False, tree: bool = False) -> bool:
            calls.append((pid, force, tree))
            return True

        monkeypatch.setattr(pc, "_win_taskkill", _fake)
        assert pc.kill_process_group(777, 9) is True
        assert calls == [(777, True, True)]

    def test_nonpositive_pgid_returns_false(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        assert pc.kill_process_group(0) is False
        assert pc.kill_process_group(-5) is False


# ---------------------------------------------------------------------------
# _win_taskkill - taskkill tree stop + pinned-handle terminate fallback
# ---------------------------------------------------------------------------


class _Result:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode
        self.stdout = ""
        self.stderr = ""


class _PinKernel32:
    """kernel32 stand-in with a one-process world model.

    Models the handle semantics the reap pin depends on: ``OpenProcess``
    only resolves a pid the world knows about, the handle keeps answering
    after the process exits, ``TerminateProcess`` flips it to exited, and
    ``WaitForSingleObject`` reports exited/timed-out rather than a raw
    liveness poll.
    """

    def __init__(
        self,
        *,
        pid: int = 123,
        exists: bool = True,
        running: bool = True,
        start_time: float = 0.0,
        openable: bool = True,
        terminable: bool = True,
    ) -> None:
        self.pid = pid
        self.exists = exists
        self.running = running
        self.start_time = start_time
        self.openable = openable
        self.terminable = terminable
        self.opened: list[tuple[int, int]] = []
        self.terminated: list[int] = []
        self.closed: list[int] = []
        self.waits: list[tuple[int, int]] = []

    _HANDLE = 4242

    def OpenProcess(self, access: int, _inherit: bool, pid: int) -> int:
        self.opened.append((access, pid))
        if pid != self.pid or not self.exists or not self.openable:
            return 0
        return self._HANDLE

    def GetExitCodeProcess(self, _handle: int, ptr: Any) -> int:
        ptr._obj.value = 259 if self.running else 0
        return 1

    def GetProcessTimes(self, _handle: int, creation: Any, *_rest: Any) -> int:
        ticks = int((self.start_time + 11644473600.0) * 10_000_000)
        creation._obj.dwLowDateTime = ticks & 0xFFFFFFFF
        creation._obj.dwHighDateTime = ticks >> 32
        return 1

    def TerminateProcess(self, handle: int, _code: int) -> int:
        self.terminated.append(handle)
        if not self.terminable:
            return 0
        self.running = False
        return 1

    def WaitForSingleObject(self, handle: int, timeout_ms: int) -> int:
        self.waits.append((handle, timeout_ms))
        return 0 if not self.running else 258  # WAIT_OBJECT_0 / WAIT_TIMEOUT

    def CloseHandle(self, handle: int) -> None:
        self.closed.append(handle)


def _install_kernel32(monkeypatch: Any, fake: _PinKernel32) -> None:
    monkeypatch.setattr(pc, "_win_kernel32", lambda: fake)


def _install_kernel32_everywhere(monkeypatch: Any, fake: _PinKernel32) -> None:
    """Route both kernel32 entry points at *fake*.

    ``_win_process_alive`` reaches ``ctypes.windll`` directly while the reap
    pin goes through ``_win_kernel32``; a whole-reap test has to serve both.
    """
    _install_kernel32(monkeypatch, fake)

    class _Windll:
        kernel32 = fake

    monkeypatch.setattr(ctypes, "windll", _Windll(), raising=False)


class TestWinTaskkill:
    """The taskkill tree stop plus the pinned-handle terminate fallback.

    The fallback deliberately does *not* re-resolve the pid. Windows
    recycles pids fast, and the old PowerShell fallback fired
    ``Stop-Process -Id <pid> -Force`` precisely in the situation where the
    pid was most likely to have been recycled (taskkill had just reported it
    missing), so it could force-kill an unrelated process. Everything below
    goes through the handle opened before any stop tier ran.
    """

    def test_taskkill_success_skips_fallback(self, monkeypatch: Any) -> None:
        fake = _PinKernel32()
        _install_kernel32(monkeypatch, fake)
        cmds: list[list[str]] = []

        def _run(cmd: list[str], **_kw: Any) -> _Result:
            cmds.append(cmd)
            fake.running = False  # taskkill did stop it
            return _Result(0)

        monkeypatch.setattr(pc.subprocess, "run", _run)
        assert pc._win_taskkill(123, force=True, tree=True) is True
        # Exactly one external invocation: taskkill, no interpreter fallback.
        assert len(cmds) == 1
        assert cmds[0][0] == "taskkill"
        assert "/F" in cmds[0] and "/T" in cmds[0]
        assert cmds[0][-2:] == ["/PID", "123"]
        assert fake.terminated == []
        assert fake.closed == [_PinKernel32._HANDLE]

    def test_taskkill_failure_terminates_through_the_pinned_handle(self, monkeypatch: Any) -> None:
        fake = _PinKernel32()
        _install_kernel32(monkeypatch, fake)
        cmds: list[list[str]] = []

        def _run(cmd: list[str], **_kw: Any) -> _Result:
            cmds.append(cmd)
            return _Result(1)  # taskkill refuses (console process, no /F)

        monkeypatch.setattr(pc.subprocess, "run", _run)
        assert pc._win_taskkill(123) is True
        # Only taskkill is ever spawned; the fallback is an in-process
        # kernel call on the handle, not a second command line naming the pid.
        assert [c[0] for c in cmds] == ["taskkill"]
        assert fake.terminated == [_PinKernel32._HANDLE]

    def test_unterminable_target_returns_false(self, monkeypatch: Any) -> None:
        fake = _PinKernel32(terminable=False)
        _install_kernel32(monkeypatch, fake)
        monkeypatch.setattr(pc.subprocess, "run", lambda cmd, **_kw: _Result(1))
        assert pc._win_taskkill(123) is False

    def test_taskkill_timeout_falls_through_to_the_handle(self, monkeypatch: Any) -> None:
        fake = _PinKernel32()
        _install_kernel32(monkeypatch, fake)

        def _run(cmd: list[str], **_kw: Any) -> _Result:
            raise subprocess.TimeoutExpired(cmd, 5)

        monkeypatch.setattr(pc.subprocess, "run", _run)
        assert pc._win_taskkill(123) is True
        assert fake.terminated == [_PinKernel32._HANDLE]

    def test_already_exited_target_is_never_signalled(self, monkeypatch: Any) -> None:
        """An exited pid gets no taskkill and no terminate - only a report."""
        fake = _PinKernel32(running=False)
        _install_kernel32(monkeypatch, fake)

        def _run(cmd: list[str], **_kw: Any) -> _Result:
            raise AssertionError("stopped an already-exited process")

        monkeypatch.setattr(pc.subprocess, "run", _run)
        assert pc._win_taskkill(123) is False
        assert fake.terminated == []

    def test_unknown_pid_is_never_signalled(self, monkeypatch: Any) -> None:
        """A pid that resolves to nothing must not be handed to taskkill."""
        fake = _PinKernel32(exists=False)
        _install_kernel32(monkeypatch, fake)

        def _run(cmd: list[str], **_kw: Any) -> _Result:
            raise AssertionError("stopped a pid that resolves to no process")

        monkeypatch.setattr(pc.subprocess, "run", _run)
        assert pc._win_taskkill(123) is False


class TestWinPidReuseGuard:
    """The pin refuses to act on a pid that was recycled under it."""

    def test_process_started_after_the_request_is_not_the_target(self, monkeypatch: Any) -> None:
        # Creation time in the future relative to the reap request: this
        # process cannot be the one the caller asked us to stop.
        fake = _PinKernel32(start_time=time.time() + 60.0)
        _install_kernel32(monkeypatch, fake)

        pin = pc._win_pin_process(123)

        assert pin is not None
        assert pin.already_gone is True
        # The impostor's handle was released and never terminated.
        assert fake.terminated == []
        assert fake.closed == [_PinKernel32._HANDLE]

    def test_recycled_pid_is_not_handed_to_taskkill(self, monkeypatch: Any) -> None:
        fake = _PinKernel32(start_time=time.time() + 60.0)
        _install_kernel32(monkeypatch, fake)

        def _run(cmd: list[str], **_kw: Any) -> _Result:
            raise AssertionError("signalled a recycled pid")

        monkeypatch.setattr(pc.subprocess, "run", _run)
        assert pc._win_taskkill(123, force=True, tree=True) is False

    def test_established_pin_keeps_the_handle_open_for_the_whole_reap(self, monkeypatch: Any) -> None:
        """The open handle is what stops Windows recycling the pid mid-reap."""
        fake = _PinKernel32(start_time=time.time() - 60.0)
        _install_kernel32(monkeypatch, fake)

        pin = pc._win_pin_process(123)

        assert pin is not None
        assert pin.already_gone is False
        assert fake.closed == []  # still pinned
        pin.close()
        assert fake.closed == [_PinKernel32._HANDLE]

    def test_unavailable_kernel_boundary_claims_nothing(self, monkeypatch: Any) -> None:
        """No kernel32 means "guard unavailable", never "target gone"."""

        def _boom() -> Any:
            raise AttributeError("no windll on this host")

        monkeypatch.setattr(pc, "_win_kernel32", _boom)
        assert pc._win_pin_process(123) is None


# ---------------------------------------------------------------------------
# _win_process_alive - kernel32 liveness probe
# ---------------------------------------------------------------------------


class _FakeKernel32:
    def __init__(self, handle: int, exit_code: int, get_ok: bool = True) -> None:
        self._handle = handle
        self._exit_code = exit_code
        self._get_ok = get_ok
        self.closed: list[int] = []
        self.opened: list[tuple[int, bool, int]] = []

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:
        self.opened.append((access, inherit, pid))
        return self._handle

    def GetExitCodeProcess(self, handle: int, ptr: Any) -> int:
        if self._get_ok:
            ptr._obj.value = self._exit_code
            return 1
        return 0

    def CloseHandle(self, handle: int) -> None:
        self.closed.append(handle)


def _install_windll(monkeypatch: Any, fake: _FakeKernel32) -> None:
    class _Windll:
        kernel32 = fake

    monkeypatch.setattr(ctypes, "windll", _Windll(), raising=False)


class TestWinProcessAlive:
    """kernel32 OpenProcess + GetExitCodeProcess liveness projection."""

    def test_null_handle_is_dead(self, monkeypatch: Any) -> None:
        fake = _FakeKernel32(handle=0, exit_code=0)
        _install_windll(monkeypatch, fake)
        assert pc._win_process_alive(4321) is False
        # No handle opened means nothing to close.
        assert fake.closed == []

    def test_still_active_is_alive(self, monkeypatch: Any) -> None:
        fake = _FakeKernel32(handle=99, exit_code=259)  # 259 == STILL_ACTIVE
        _install_windll(monkeypatch, fake)
        assert pc._win_process_alive(4321) is True
        assert fake.closed == [99]

    def test_exited_process_is_dead(self, monkeypatch: Any) -> None:
        fake = _FakeKernel32(handle=99, exit_code=0)
        _install_windll(monkeypatch, fake)
        assert pc._win_process_alive(4321) is False
        assert fake.closed == [99]

    def test_get_exit_code_failure_is_dead(self, monkeypatch: Any) -> None:
        fake = _FakeKernel32(handle=99, exit_code=259, get_ok=False)
        _install_windll(monkeypatch, fake)
        assert pc._win_process_alive(4321) is False
        # Handle still closed on the failure path.
        assert fake.closed == [99]

    def test_process_alive_delegates_on_windows(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        monkeypatch.setattr(pc, "_win_process_alive", lambda pid: True)
        assert pc.process_alive(4321) is True

    def test_process_alive_nonpositive_skips_probe(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        monkeypatch.setattr(
            pc,
            "_win_process_alive",
            lambda pid: (_ for _ in ()).throw(AssertionError("probed")),
        )
        assert pc.process_alive(0) is False
        assert pc.process_alive(-3) is False


# ---------------------------------------------------------------------------
# reap_process_group - Windows-branch receipt projection (the artifact)
# ---------------------------------------------------------------------------


class TestReapReceiptWindowsProjection:
    """The reap receipt is a deterministic projection of the Windows path."""

    def test_clean_exit_projects_windows_tree_method(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        monkeypatch.setattr(pc, "_detect_os_name", lambda: "windows")
        monkeypatch.setattr(pc, "kill_process_group", lambda pgid, sig=signal.SIGTERM: True)
        monkeypatch.setattr(pc, "process_alive", lambda pid: False)

        receipt = pc.reap_process_group(999, grace_seconds=0.05, poll_interval=0.01)

        assert receipt.os_name == "windows"
        assert receipt.method == "windows_process_tree"
        assert receipt.delivered is True
        assert receipt.escalated is False
        details = receipt.to_details()
        assert details["os_name"] == "windows"
        assert details["method"] == "windows_process_tree"

    def test_escalation_uses_numeric_kill_code(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        monkeypatch.setattr(pc, "_detect_os_name", lambda: "windows")
        sigs: list[int] = []

        def _kpg(pgid: int, sig: int = signal.SIGTERM) -> bool:
            sigs.append(sig)
            return True

        monkeypatch.setattr(pc, "kill_process_group", _kpg)
        # Never dies -> reap must escalate.
        monkeypatch.setattr(pc, "process_alive", lambda pid: True)

        receipt = pc.reap_process_group(999, grace_seconds=0.02, poll_interval=0.01)

        assert receipt.method == "windows_process_tree"
        assert receipt.escalated is True
        # First tier is SIGTERM; force tier degrades to numeric 9 because
        # SIGKILL is not importable when IS_WINDOWS is set.
        assert sigs[0] == signal.SIGTERM
        assert sigs[-1] == 9

    def test_undeliverable_term_projects_not_delivered(self, monkeypatch: Any) -> None:
        """An undeliverable stop against a *running* target is a failure."""
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        monkeypatch.setattr(pc, "_detect_os_name", lambda: "windows")
        monkeypatch.setattr(pc, "kill_process_group", lambda pgid, sig=signal.SIGTERM: False)
        monkeypatch.setattr(pc, "process_alive", lambda pid: True)

        receipt = pc.reap_process_group(999, grace_seconds=0.05, poll_interval=0.01)

        assert receipt.os_name == "windows"
        assert receipt.method == "windows_process_tree"
        assert receipt.delivered is False
        assert receipt.escalated is False
        # Still running and we could not stop it: no guarantee to report.
        assert receipt.confirmed_dead is False
        assert receipt.already_gone is False

    def test_undeliverable_term_against_an_exited_target_is_success(self, monkeypatch: Any) -> None:
        """An already-exited tree satisfies the guarantee the reap exists for.

        This is the case that turned a green Windows lane red: the spawn had
        already exited, so no stop could be delivered to it, and the receipt
        reported that as a failed reap. "Nothing left to stop" is the
        outcome the caller wanted, not a failure to produce it.
        """
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        monkeypatch.setattr(pc, "_detect_os_name", lambda: "windows")
        monkeypatch.setattr(pc, "kill_process_group", lambda pgid, sig=signal.SIGTERM: False)
        monkeypatch.setattr(pc, "process_alive", lambda pid: False)

        receipt = pc.reap_process_group(999, grace_seconds=0.05, poll_interval=0.01)

        assert receipt.delivered is False
        assert receipt.escalated is False
        assert receipt.already_gone is True
        assert receipt.confirmed_dead is True

    def test_pinned_exited_target_skips_every_stop_tier(self, monkeypatch: Any) -> None:
        """A pin that reports the target gone stops the reap before it signals."""
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        monkeypatch.setattr(pc, "_detect_os_name", lambda: "windows")
        fake = _PinKernel32(pid=999, running=False)
        _install_kernel32(monkeypatch, fake)
        monkeypatch.setattr(
            pc,
            "kill_process_group",
            lambda pgid, sig=signal.SIGTERM: (_ for _ in ()).throw(AssertionError("signalled")),
        )

        receipt = pc.reap_process_group(999, grace_seconds=0.05, poll_interval=0.01)

        assert receipt.already_gone is True
        assert receipt.confirmed_dead is True
        assert receipt.delivered is False
        assert fake.terminated == []
        # The pin is always released, even on the early-return path.
        assert fake.closed == [_PinKernel32._HANDLE]

    def test_hung_console_spawn_is_reaped_and_confirmed(self, monkeypatch: Any) -> None:
        """Whole-reap replay of the Windows conformance case.

        A hung console process is what the adapter conformance suite spawns.
        ``taskkill`` without ``/F`` refuses to stop a console process, which
        used to drop the reap into a fallback that shelled out to
        ``Stop-Process -Id <pid> -Force`` and then raced an immediate
        liveness probe against an asynchronous termination. The reap now
        terminates through the handle it already holds and waits on that
        handle, so the outcome is decided by evidence rather than timing.
        """
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        monkeypatch.setattr(pc, "_detect_os_name", lambda: "windows")
        fake = _PinKernel32(pid=6300, start_time=time.time() - 30.0)
        _install_kernel32_everywhere(monkeypatch, fake)
        cmds: list[list[str]] = []

        def _run(cmd: list[str], **_kw: Any) -> _Result:
            cmds.append(cmd)
            # "This process can only be terminated forcefully (with /F)".
            return _Result(1)

        monkeypatch.setattr(pc.subprocess, "run", _run)

        receipt = pc.reap_process_group(6300, grace_seconds=0.05, poll_interval=0.01)

        assert receipt.os_name == "windows"
        assert receipt.method == "windows_process_tree"
        assert receipt.delivered is True
        assert receipt.escalated is False
        assert receipt.confirmed_dead is True
        assert fake.running is False
        # Only taskkill was ever spawned - no interpreter was asked to
        # force-kill the bare pid.
        assert [c[0] for c in cmds] == ["taskkill"]

    def test_clean_exit_projects_confirmed_dead(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pc, "IS_WINDOWS", True)
        monkeypatch.setattr(pc, "_detect_os_name", lambda: "windows")
        monkeypatch.setattr(pc, "kill_process_group", lambda pgid, sig=signal.SIGTERM: True)
        monkeypatch.setattr(pc, "process_alive", lambda pid: False)

        receipt = pc.reap_process_group(999, grace_seconds=0.05, poll_interval=0.01)

        assert receipt.delivered is True
        assert receipt.confirmed_dead is True
        assert receipt.already_gone is False
