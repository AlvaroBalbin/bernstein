"""The chain transaction primitive, one test per axis it can fail on.

These are deliberately not a vector list over one mechanism. Each test varies a
different axis of the primitive - how the audit directory was spelled, which
concurrency model the caller runs under, which scope exits, how the section
unwinds, who else is holding the lock, and what a retention pass does
underneath a reader - because the ways this can be wrong are structurally
different from each other, not variations on one theme.

The multi-process end-to-end case lives in
``tests/integration/security/test_chain_transaction_race.py``; it needs real
subprocesses and is marked slow.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from bernstein.core.persistence.file_locks import os_try_lock_fd, os_unlock_fd
from bernstein.core.security.audit import (
    _CHAIN_LOCK_NAME,
    AuditLog,
    ChainLockMisuse,
    ChainLockUnavailable,
    _entry_for,
    _release_entry,
    chain_transaction,
)

KEY = b"k" * 32


def _owned_here(entry: object) -> bool:
    """Whether *entry* is owned by the scope that calls this.

    Ownership is thread-object identity plus a token the owning thread holds in
    its thread-local set, never a thread ident: idents are recycled.
    """
    from bernstein.core.security.audit import _current_task, _held_tokens

    return (
        entry.owner_thread is threading.current_thread()  # type: ignore[attr-defined]
        and entry.owner_task is _current_task()  # type: ignore[attr-defined]
        and entry.owner_token in _held_tokens()  # type: ignore[attr-defined]
    )


def _os_lock_is_free(audit_dir: Path) -> bool:
    """Whether a *fresh* descriptor can take the OS lock on *audit_dir*.

    A fresh descriptor is exactly what a second process has: ``flock`` state
    belongs to the open file description, not to the process. So this answers
    "would another process get in right now?" without spawning one.
    """
    fd = os.open(str(audit_dir / _CHAIN_LOCK_NAME), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os_try_lock_fd(fd):
            os_unlock_fd(fd)
            return True
        return False
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Axis: re-entrancy. The obvious fix for the underlying defect deadlocks.
# ---------------------------------------------------------------------------


class TestNestingCompletes:
    """A fresh-descriptor-per-call lock self-deadlocks; this one must not.

    ``flock`` attaches to the open file description, so a second acquisition
    from the same process on a new descriptor blocks on the process's own lock.
    That is why wrapping a read plus an append in the previous append lock hung
    instead of fixing anything. The inverse of that observation is the
    regression this guards: nesting must *complete*.
    """

    def test_transaction_nests_without_deadlocking(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        with chain_transaction(audit_dir, timeout=5), chain_transaction(audit_dir, timeout=5):
            pass
        assert _os_lock_is_free(audit_dir)

    def test_an_append_inside_a_caller_section_completes(self, tmp_path: Path) -> None:
        """The whole point: read, decide, and append inside one section."""
        audit_dir = tmp_path / "audit"
        log = AuditLog(audit_dir, key=KEY)
        with chain_transaction(audit_dir, timeout=5):
            before = log.query()
            event = log.log("t", "actor", "res", "id-1", {"seen": len(before)})
        assert event.details["seen"] == 0
        assert log.verify() == (True, [])
        assert _os_lock_is_free(audit_dir)

    def test_a_fresh_descriptor_really_cannot_re_enter(self, tmp_path: Path) -> None:
        """Negative control: the hazard the ownership layer exists to route around."""
        audit_dir = tmp_path / "audit"
        with chain_transaction(audit_dir, timeout=5):
            assert not _os_lock_is_free(audit_dir), (
                "a second descriptor took the lock this process holds; the OS primitive is not "
                "providing exclusion and every other test here is vacuous"
            )


# ---------------------------------------------------------------------------
# Axis: how the audit directory was spelled
# ---------------------------------------------------------------------------


class TestPathSpelling:
    def test_every_spelling_of_one_directory_shares_one_entry(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """One inode must map to one lock entry, however the caller reached it.

        Two entries for one inode is worse than none: each hands out its own
        in-process mutex while both contend for the same OS lock, so the process
        blocks on itself. The CLI reaches the audit dir relatively, services
        reach it absolutely, and checkouts get symlinked - all in one process.
        """
        from bernstein.core.security.audit import _CHAIN_TABLE

        real = tmp_path / "work" / ".sdd" / "audit"
        real.mkdir(parents=True)
        link = tmp_path / "linked"
        link.symlink_to(tmp_path / "work")
        monkeypatch.chdir(tmp_path / "work")

        spellings = [
            Path(".sdd/audit"),  # relative, as the CLI's --workdir default builds it
            real,  # absolute
            tmp_path / "work" / "." / ".sdd" / ".." / ".sdd" / "audit",  # dot-hop
            link / ".sdd" / "audit",  # through a symlink
        ]

        # Case-flipping only aliases on a case-insensitive filesystem. Probe
        # rather than assume: macOS defaults to insensitive, CI Linux does not.
        flipped = tmp_path / "work" / ".SDD" / "audit"
        if (tmp_path / "work" / ".SDD").exists():
            spellings.append(flipped)

        before = set(_CHAIN_TABLE)
        for spelling in spellings:
            # Each must complete; a second entry for the same inode would hang
            # here rather than fail an assertion.
            with chain_transaction(spelling, timeout=5):
                pass

        added = set(_CHAIN_TABLE) - before
        assert len(added) == 1, f"{len(spellings)} spellings of one audit dir produced {len(added)} lock entries"

    def test_case_variant_shares_the_entry_on_a_case_insensitive_filesystem(self, tmp_path: Path) -> None:
        """``Path.resolve()`` does not case-fold, so keying on it would split the entry."""
        from bernstein.core.security.audit import _CHAIN_TABLE

        real = tmp_path / "audit"
        real.mkdir()
        flipped = tmp_path / "AUDIT"
        if not flipped.exists():
            pytest.skip("filesystem is case-sensitive; the case-flip alias does not exist here")

        before = set(_CHAIN_TABLE)
        with chain_transaction(real, timeout=5):
            pass
        with chain_transaction(flipped, timeout=5):
            pass
        assert len(set(_CHAIN_TABLE) - before) == 1


# ---------------------------------------------------------------------------
# Axis: how many audit directories one process touches over its life
# ---------------------------------------------------------------------------


class TestTableDoesNotGrowWithoutBound:
    """One descriptor per audit directory, held while the entry is live.

    A process normally works against exactly one audit directory, so this never
    binds in production. It binds in anything that sweeps through many, where an
    unbounded table is an eventual ``EMFILE`` - which in a long-lived task
    server is an outage, not an inconvenience.
    """

    def test_idle_entries_are_reclaimed_above_the_cap(self, tmp_path: Path) -> None:
        from bernstein.core.security.audit import _CHAIN_TABLE, CHAIN_LOCK_TABLE_CAP

        for i in range(CHAIN_LOCK_TABLE_CAP + 50):
            with chain_transaction(tmp_path / f"audit-{i}", timeout=5):
                pass
        assert len(_CHAIN_TABLE) <= CHAIN_LOCK_TABLE_CAP

    def test_an_entry_in_use_is_never_reclaimed(self, tmp_path: Path) -> None:
        """Reclamation is gated on the user count, not on the owner field.

        A caller sits between the table lookup and its mutex acquisition with
        ``owner`` still unset. Closing its descriptor in that window would leave
        it locking a closed descriptor - so the guard has to be the user count.
        """
        from bernstein.core.security.audit import _CHAIN_TABLE, CHAIN_LOCK_TABLE_CAP

        held = tmp_path / "held"
        with chain_transaction(held, timeout=5):
            for i in range(CHAIN_LOCK_TABLE_CAP + 50):
                with chain_transaction(tmp_path / f"churn-{i}", timeout=5):
                    pass
            # The held entry survived the sweep, and is still the live one.
            assert not _os_lock_is_free(held)
            entry = _entry_for(held)
            assert entry is not None
            assert _owned_here(entry)
            assert any(e is entry for e in _CHAIN_TABLE.values())
            _release_entry(entry)

        assert _os_lock_is_free(held)

    def test_a_reclaimed_directory_still_locks_correctly_afterwards(self, tmp_path: Path) -> None:
        """Reclaiming is forgetting, not weakening: the next caller re-opens."""
        from bernstein.core.security.audit import CHAIN_LOCK_TABLE_CAP

        first = tmp_path / "first"
        with chain_transaction(first, timeout=5):
            pass
        for i in range(CHAIN_LOCK_TABLE_CAP + 50):
            with chain_transaction(tmp_path / f"churn-{i}", timeout=5):
                pass

        with chain_transaction(first, timeout=5):
            assert not _os_lock_is_free(first), "the re-opened entry is not taking the OS lock"
        assert _os_lock_is_free(first)

    def test_a_full_table_of_held_entries_still_serves_a_new_directory(self, tmp_path: Path) -> None:
        """The sweep must never evict the entry it is about to hand back.

        A brand-new entry is idle by definition. If the sweep runs before the
        caller's reference is recorded, and every older entry is in use, the
        only evictable entry is the new one - so the caller would be handed an
        entry that has just been dropped from the table with its descriptor
        closed, and would then lock a closed descriptor.
        """
        from bernstein.core.security.audit import _CHAIN_TABLE, CHAIN_LOCK_TABLE_CAP

        with contextlib.ExitStack() as stack:
            for i in range(CHAIN_LOCK_TABLE_CAP + 1):
                stack.enter_context(chain_transaction(tmp_path / f"held-{i}", timeout=10))

            # Every entry above is held, so nothing is evictable. The table is
            # over its cap and the newest directory must still work.
            newest = tmp_path / f"held-{CHAIN_LOCK_TABLE_CAP}"
            assert not _os_lock_is_free(newest), "the newest entry is not holding its OS lock"
            entry = _entry_for(newest)
            assert entry is not None
            assert any(e is entry for e in _CHAIN_TABLE.values()), "the entry in use was dropped from the table"
            _release_entry(entry)

        assert _os_lock_is_free(tmp_path / f"held-{CHAIN_LOCK_TABLE_CAP}")


# ---------------------------------------------------------------------------
# Axis: concurrency model (asyncio tasks share a thread ident)
# ---------------------------------------------------------------------------


class TestAsyncioTaskOwnership:
    def test_second_task_on_the_same_thread_is_refused_immediately(self, tmp_path: Path) -> None:
        """Two tasks on one loop share a thread ident but are two callers.

        Treating them as the same holder - which a bare ``RLock`` does - would
        grant task B re-entry into the section task A opened, reproducing the
        exact read-modify-append interleaving the transaction forbids.

        The refusal must also be *immediate*. Waiting is nonsense here: the
        context that has to run in order to release the lock is the one being
        blocked, so a wait burns the entire budget and then fails anyway, with
        the wrong error.
        """
        audit_dir = tmp_path / "audit"
        order: list[str] = []
        timings: dict[str, float] = {}

        async def scenario() -> None:
            entered = asyncio.Event()
            release = asyncio.Event()

            async def holder() -> None:
                with chain_transaction(audit_dir, timeout=30):
                    order.append("A-IN")
                    entered.set()
                    await release.wait()
                order.append("A-OUT")

            async def intruder() -> None:
                await entered.wait()
                started = time.monotonic()
                try:
                    with chain_transaction(audit_dir, timeout=30):
                        order.append("B-ENTERED")
                except ChainLockMisuse:
                    order.append("B-error")
                except ChainLockUnavailable:  # pragma: no cover - wrong error
                    order.append("B-timeout")
                timings["intruder"] = time.monotonic() - started
                release.set()

            await asyncio.gather(holder(), intruder())

        asyncio.run(scenario())

        assert order == ["A-IN", "B-error", "A-OUT"], order
        assert timings["intruder"] < 1.0, (
            f"the second task waited {timings['intruder']:.2f}s before failing; it must fail immediately, "
            "because the task that would release the lock cannot run while the loop is blocked"
        )
        assert _os_lock_is_free(audit_dir)


# ---------------------------------------------------------------------------
# Axis: which scope exits
# ---------------------------------------------------------------------------


class TestExitScope:
    def test_foreign_exit_raises_and_leaves_the_owner_able_to_release(self, tmp_path: Path) -> None:
        """Both halves, and the second half is the one that matters.

        A guard that raises on a foreign exit but has already released - or has
        poisoned the depth counter on the way to raising - converts a bounded
        window into a permanent process-wide wedge: every later transaction
        matches the stale owner, takes the re-entrant path, and decrements a
        depth that never reaches zero. Asserting only "the foreign exit raises"
        is what lets that through.
        """
        audit_dir = tmp_path / "audit"
        transaction = chain_transaction(audit_dir, timeout=5)
        transaction.__enter__()
        try:
            raised: list[BaseException] = []

            def _foreign_exit() -> None:
                try:
                    transaction.__exit__(None, None, None)
                except BaseException as exc:
                    raised.append(exc)

            thread = threading.Thread(target=_foreign_exit)
            thread.start()
            thread.join(timeout=10)

            assert raised and isinstance(raised[0], ChainLockMisuse), raised
            assert not _os_lock_is_free(audit_dir), "the foreign exit released a lock it did not own"
        finally:
            transaction.__exit__(None, None, None)

        assert _os_lock_is_free(audit_dir), (
            "the owner could not release the lock after a foreign exit was refused; the guard "
            "stranded the lock instead of protecting it"
        )
        # And the process is not poisoned: the next transaction still works.
        with chain_transaction(audit_dir, timeout=5):
            pass
        assert _os_lock_is_free(audit_dir)

    def test_reentering_one_live_instance_is_refused_rather_than_wedging_the_lock(self, tmp_path: Path) -> None:
        """Re-entry on the *same object* is misuse, not nesting.

        The instance carries the bookkeeping for exactly one acquisition. A
        second ``__enter__`` on a live instance overwrote it, so the inner
        ``__exit__`` cleared the instance and the outer ``__exit__`` became a
        no-op: the OS lock stayed held for the life of the process with nothing
        left able to release it. Nesting is done by opening a second instance.
        """
        audit_dir = tmp_path / "audit"
        transaction = chain_transaction(audit_dir, timeout=5)
        with transaction:
            with pytest.raises(ChainLockMisuse, match="already open on this instance"):
                transaction.__enter__()
            # Refusing must not have disturbed the live section.
            assert not _os_lock_is_free(audit_dir)

        assert _os_lock_is_free(audit_dir), "the refused re-entry left the lock wedged"
        # And a second instance still nests correctly.
        with chain_transaction(audit_dir, timeout=5), chain_transaction(audit_dir, timeout=5):
            assert not _os_lock_is_free(audit_dir)
        assert _os_lock_is_free(audit_dir)

    def test_one_instance_can_still_be_used_again_once_its_section_has_closed(self, tmp_path: Path) -> None:
        """Refusing live re-entry must not refuse sequential reuse."""
        audit_dir = tmp_path / "audit"
        transaction = chain_transaction(audit_dir, timeout=5)
        for _ in range(3):
            with transaction:
                assert not _os_lock_is_free(audit_dir)
            assert _os_lock_is_free(audit_dir)

    def test_exiting_out_of_order_is_refused_and_the_inner_scope_keeps_the_lock(self, tmp_path: Path) -> None:
        """Reachable through ``ExitStack`` or a generator that holds a transaction.

        The outer scope exiting first would release the lock while the inner
        section is still running against it, and drive the depth counter to -1.
        The thread/task check alone does not catch this: both scopes are the
        same thread and the same task.
        """
        audit_dir = tmp_path / "audit"
        entry = _entry_for(audit_dir)
        assert entry is not None

        outer = chain_transaction(audit_dir, timeout=5)
        inner = chain_transaction(audit_dir, timeout=5)
        outer.__enter__()
        inner.__enter__()
        try:
            with pytest.raises(ChainLockMisuse, match="inner section is still open"):
                outer.__exit__(None, None, None)
            assert entry.depth == 2, "the refused exit changed the depth anyway"
            assert not _os_lock_is_free(audit_dir), "the refused exit released the lock under the inner scope"
        finally:
            inner.__exit__(None, None, None)
            outer.__exit__(None, None, None)
        _release_entry(entry)

        assert entry.depth == 0
        assert _os_lock_is_free(audit_dir)


# ---------------------------------------------------------------------------
# Axis: a forked child inheriting the lock table
# ---------------------------------------------------------------------------


_FORK_SOURCE = textwrap.dedent(
    """
    import os, sys
    from pathlib import Path
    from bernstein.core.security.audit import chain_transaction, ChainLockUnavailable

    audit_dir = Path(sys.argv[1])
    # Warm the table in the parent, exactly as any prior append would.
    with chain_transaction(audit_dir, timeout=10):
        pass

    read_fd, write_fd = os.pipe()
    with chain_transaction(audit_dir, timeout=10):
        pid = os.fork()
        if pid == 0:
            try:
                with chain_transaction(audit_dir, timeout=0.4):
                    verdict = b"CHILD-GOT-IN"
            except ChainLockUnavailable:
                verdict = b"CHILD-REFUSED"
            except BaseException as exc:
                verdict = b"CHILD-ERROR:" + type(exc).__name__.encode()
            os.write(write_fd, verdict)
            os._exit(0)
        os.close(write_fd)
        out = os.read(read_fd, 64)
        os.waitpid(pid, 0)
    print(out.decode(), flush=True)
    """
).strip()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork() is POSIX-only")
class TestForkedChild:
    def test_a_child_forked_with_a_warm_table_cannot_take_the_parents_lock(self, tmp_path: Path) -> None:
        """``fork`` duplicates the open file description, not merely the descriptor.

        A POSIX ``flock`` belongs to the description, so ``LOCK_EX | LOCK_NB``
        against a descriptor whose description already holds the lock
        *succeeds*. A child that inherited a warm lock table therefore re-locked
        its parent's own descriptor and both believed they held it: two writers
        inside one read-modify-append section, which is the exact defect the
        transaction exists to prevent.

        Run out-of-process because the fork has to happen with the table warm
        and the parent inside a section, which is not a state to leave a pytest
        worker in.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(parents=True)
        script = tmp_path / "forker.py"
        script.write_text(_FORK_SOURCE, encoding="utf-8")

        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[3] / "src")
        proc = subprocess.run(
            [sys.executable, str(script), str(audit_dir)],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
            check=False,
        )

        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "CHILD-REFUSED", f"stdout={proc.stdout!r} stderr={proc.stderr!r}"


# ---------------------------------------------------------------------------
# Axis: a stranded owner whose thread ident is recycled
# ---------------------------------------------------------------------------


_IDENT_REUSE_SOURCE = textwrap.dedent(
    """
    import sys, threading
    from pathlib import Path
    from bernstein.core.security.audit import chain_transaction, ChainLockUnavailable

    audit_dir = Path(sys.argv[1])
    stranded = []

    def strand():
        stranded.append(threading.get_ident())
        chain_transaction(audit_dir, timeout=10).__enter__()  # entered, never exited

    stranding = threading.Thread(target=strand)
    stranding.start()
    stranding.join(10)

    # The successor lands on the dead holder's recycled ident. Presenting the
    # ident is the whole simulation: it is the only thing a recycled thread
    # shares with the dead one.
    real_get_ident = threading.get_ident
    threading.get_ident = lambda: stranded[0]

    verdict = []
    done = threading.Event()

    def successor():
        try:
            with chain_transaction(audit_dir, timeout=0.4):
                verdict.append("SUCCESSOR-GOT-IN")
        except ChainLockUnavailable:
            verdict.append("SUCCESSOR-REFUSED")
        except BaseException as exc:
            verdict.append("SUCCESSOR-ERROR:" + type(exc).__name__)
        finally:
            done.set()

    threading.Thread(target=successor).start()
    done.wait(60)
    threading.get_ident = real_get_ident
    print(verdict[0] if verdict else "SUCCESSOR-HUNG", flush=True)
    """
).strip()


class TestStrandedOwner:
    def test_a_thread_presenting_a_stranded_owners_ident_is_not_treated_as_the_owner(self, tmp_path: Path) -> None:
        """Thread idents are recycled, so ownership must not be keyed on one.

        A thread that entered and died without exiting leaves the entry owned
        and the mutex held. The operating system is free to hand its ident to
        the next thread, and an ownership check keyed on that ident then
        matches: the new thread takes the re-entrant path with neither the
        in-process mutex nor the OS lock, and appends inside a section it never
        acquired. It was reachable on the first attempt.

        Run out-of-process because presenting a recycled ident means replacing
        ``threading.get_ident`` process-wide, which is not a state to leave a
        pytest worker in - and because the stranded holder keeps its lock and
        its mutex for the life of the process by construction.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(parents=True)
        script = tmp_path / "ident_reuse.py"
        script.write_text(_IDENT_REUSE_SOURCE, encoding="utf-8")

        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[3] / "src")
        proc = subprocess.run(
            [sys.executable, str(script), str(audit_dir)],
            capture_output=True,
            text=True,
            env=env,
            timeout=180,
            check=False,
        )

        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "SUCCESSOR-REFUSED", (
            f"a thread presenting the stranded owner's ident was admitted on the re-entrant path; "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )


# ---------------------------------------------------------------------------
# Axis: how the section unwinds
# ---------------------------------------------------------------------------


class TestUnwind:
    def test_an_exception_inside_the_section_still_releases(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        entry = _entry_for(audit_dir)
        assert entry is not None

        with pytest.raises(RuntimeError, match="boom"), chain_transaction(audit_dir, timeout=5):
            raise RuntimeError("boom")

        assert entry.depth == 0
        assert entry.owner_thread is None
        assert _os_lock_is_free(audit_dir)

    def test_an_exception_inside_a_nested_section_leaves_the_outer_holding(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        entry = _entry_for(audit_dir)
        assert entry is not None

        with chain_transaction(audit_dir, timeout=5):
            with contextlib.suppress(RuntimeError), chain_transaction(audit_dir, timeout=5):
                raise RuntimeError("boom")
            assert entry.depth == 1
            assert _owned_here(entry)
            assert not _os_lock_is_free(audit_dir)

        assert entry.depth == 0
        assert _os_lock_is_free(audit_dir)


# ---------------------------------------------------------------------------
# Axis: a live foreign holder
# ---------------------------------------------------------------------------


_HOLDER_SOURCE = textwrap.dedent(
    """
    import sys, time
    from pathlib import Path
    from bernstein.core.security.audit import chain_transaction

    audit_dir = Path(sys.argv[1])
    with chain_transaction(audit_dir, timeout=30):
        print("HELD", flush=True)
        time.sleep(float(sys.argv[2]))
    """
).strip()


class TestHolderLiveness:
    def test_a_foreign_thread_holder_produces_a_bounded_named_error(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        held = threading.Event()
        release = threading.Event()

        def _holder() -> None:
            with chain_transaction(audit_dir, timeout=30):
                held.set()
                release.wait(timeout=30)

        thread = threading.Thread(target=_holder)
        thread.start()
        try:
            assert held.wait(timeout=10)
            started = time.monotonic()
            with pytest.raises(ChainLockUnavailable) as excinfo:
                with chain_transaction(audit_dir, timeout=0.3):
                    pass
            elapsed = time.monotonic() - started
            assert 0.2 <= elapsed < 5.0, elapsed
            assert str(audit_dir) in str(excinfo.value)
        finally:
            release.set()
            thread.join(timeout=10)

        assert _os_lock_is_free(audit_dir)

    @pytest.mark.timeout(120)
    def test_a_cross_process_holder_times_out_without_stranding_the_mutex(self, tmp_path: Path) -> None:
        """The failure path that strands the in-process mutex if it is written wrong.

        A cross-process timeout happens *after* the in-process mutex was taken.
        Without an explicit release on that path the mutex stays held forever,
        and the next caller in this process fails with ``ChainLockUnavailable``
        for a lock nobody holds - a self-inflicted permanent outage that looks
        exactly like the real one.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(parents=True)
        holder_py = tmp_path / "holder.py"
        holder_py.write_text(_HOLDER_SOURCE, encoding="utf-8")

        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[3] / "src")
        proc = subprocess.Popen(
            [sys.executable, str(holder_py), str(audit_dir), "3"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )
        try:
            assert proc.stdout is not None
            assert proc.stdout.readline().strip() == "HELD"

            with pytest.raises(ChainLockUnavailable):
                with chain_transaction(audit_dir, timeout=0.3):
                    pass
            proc.wait(timeout=60)
        finally:
            if proc.poll() is None:  # pragma: no cover - only on an unexpected hang
                proc.terminate()
                proc.wait(timeout=30)

        # The mutex was not stranded by the failed acquisition: the very next
        # caller in this process gets in.
        with chain_transaction(audit_dir, timeout=10):
            pass
        assert _os_lock_is_free(audit_dir)


# ---------------------------------------------------------------------------
# Axis: retention running underneath a reader
# ---------------------------------------------------------------------------


class TestArchiveWindow:
    """``archive()`` compresses then unlinks. Both intermediate states are wrong.

    Neither needs a concurrent writer. Retention alone opens them, so a charter
    can be misread on a completely idle installation.
    """

    @staticmethod
    def _seed_old_day(audit_dir: Path, count: int = 4) -> None:
        log = AuditLog(audit_dir, key=KEY)
        for i in range(count):
            log.log("charter", "alice", "tenant", "acme", {"seq": i})
        live = next(iter(sorted(audit_dir.glob("*.jsonl"))))
        live.rename(audit_dir / "2020-01-01.jsonl")

    def test_a_transactional_read_never_observes_the_archive_window(self, tmp_path: Path) -> None:
        from bernstein.core.security.audit import RetentionPolicy

        audit_dir = tmp_path / "audit"
        self._seed_old_day(audit_dir)
        log = AuditLog(audit_dir, key=KEY)

        window_open = threading.Event()
        observations: list[int] = []
        real_unlink = Path.unlink

        def _slow_unlink(self: Path, *args: object, **kwargs: object) -> None:
            # Widen the window between the ``.gz`` landing and the ``.jsonl``
            # disappearing, so a reader that could observe it, would.
            if self.suffix == ".jsonl":
                window_open.set()
                time.sleep(0.3)
            real_unlink(self, *args, **kwargs)  # type: ignore[arg-type]

        def _archiver() -> None:
            log.archive(RetentionPolicy(retention_days=1))

        with pytest.MonkeyPatch.context() as patcher:
            patcher.setattr(Path, "unlink", _slow_unlink)
            thread = threading.Thread(target=_archiver)
            thread.start()
            try:
                assert window_open.wait(timeout=30)
                reader = AuditLog(audit_dir, key=KEY)
                for _ in range(5):
                    with chain_transaction(audit_dir, timeout=30):
                        observations.append(len(reader.query(resource_id="acme", include_archived=True)))
            finally:
                thread.join(timeout=60)

        assert observations, "the reader never ran"
        assert all(n == 4 for n in observations), (
            f"a transactional read observed the archive window: counts {observations}. "
            "8 means every event of the archived day was visible twice; 0 means the day "
            "vanished, which reads as 'no charter exists' and lets a caller open a second one."
        )

    def test_negative_control_a_non_transactional_read_does_observe_it(self, tmp_path: Path) -> None:
        """The window is real, and the transaction is what closes it."""
        from bernstein.core.security.audit import RetentionPolicy

        audit_dir = tmp_path / "audit"
        self._seed_old_day(audit_dir)
        log = AuditLog(audit_dir, key=KEY)

        window_open = threading.Event()
        proceed = threading.Event()
        real_unlink = Path.unlink

        def _held_unlink(self: Path, *args: object, **kwargs: object) -> None:
            if self.suffix == ".jsonl":
                window_open.set()
                proceed.wait(timeout=30)
            real_unlink(self, *args, **kwargs)  # type: ignore[arg-type]

        with pytest.MonkeyPatch.context() as patcher:
            patcher.setattr(Path, "unlink", _held_unlink)
            thread = threading.Thread(target=lambda: log.archive(RetentionPolicy(retention_days=1)))
            thread.start()
            try:
                assert window_open.wait(timeout=30)
                reader = AuditLog(audit_dir, key=KEY)
                observed = len(reader.query(resource_id="acme", include_archived=True))
            finally:
                proceed.set()
                thread.join(timeout=60)

        assert observed == 8, (
            f"expected the unguarded read to see the archived day twice, saw {observed}; "
            "if this stops reproducing the guarded test above proves nothing"
        )


# ---------------------------------------------------------------------------
# Axis: a crash-truncated final line
# ---------------------------------------------------------------------------


class TestTornTail:
    def test_a_torn_final_line_does_not_swallow_the_next_record(self, tmp_path: Path) -> None:
        """Without the seal the next record fuses onto the fragment.

        The result is one unparseable line holding both, one real record gone,
        and a verifier reporting *fewer* errors than before - damage that hides
        by looking like less damage.
        """
        audit_dir = tmp_path / "audit"
        log = AuditLog(audit_dir, key=KEY)
        log.log("t", "actor", "res", "first")

        day_file = next(iter(sorted(audit_dir.glob("*.jsonl"))))
        with day_file.open("ab") as fh:
            fh.write(b'{"timestamp": "2026-01-01T00:00:00.0Z", "event_ty')  # crash mid-write

        fresh = AuditLog(audit_dir, key=KEY)
        fresh.log("t", "actor", "res", "second")

        lines = day_file.read_bytes().split(b"\n")
        payloads = [line for line in lines if line]
        # first, torn fragment, seal receipt, second
        assert len(payloads) == 4, payloads
        assert payloads[1].endswith(b'"event_ty'), "the torn fragment was rewritten; the log is append-only"
        assert b'"second"' in payloads[3]
        assert b'"chain.torn_record"' in payloads[2]

        # The real record survives as its own line, and the damage stays visible
        # as exactly one flagged line rather than silently eating a record.
        recovered = [e.resource_id for e in fresh.query(resource_id="second")]
        assert recovered == ["second"]
        ok, errors = fresh.verify()
        assert ok is False
        assert len(errors) == 1, errors
