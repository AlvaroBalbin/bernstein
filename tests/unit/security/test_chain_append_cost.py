"""What one steady-state audit append is allowed to cost in syscalls.

A throughput number is a moving target on a shared machine; the count of file
opens per append is not. This pins the shape instead of the wall clock, so a
future change that reintroduces a per-append probe fails here rather than
showing up months later as "the audit log got slower".

Two costs are pinned:

* **No read probe per append.** Checking whether the previous append left the
  segment terminated is only meaningful when the head is actually being
  rescanned. The writer already knows its own last append ended in ``b"\\n"``,
  so in the steady state the probe answers a question nobody asked - at the
  price of an extra ``open`` + ``seek`` + ``read`` on every record.
* **No lock-file reopen per append.** The lock table is keyed on the lock
  file's inode, and once an entry is registered a ``stat`` resolves the same
  inode that ``open`` would, through the same symlinks and the same case
  folding. Re-opening the descriptor per append bought nothing.
"""

from __future__ import annotations

import os
import pathlib
from collections import Counter
from pathlib import Path

import pytest

from bernstein.core.security.audit import AuditLog

KEY = b"k" * 32

#: Appends measured after the instance has warmed up. Large enough that a
#: per-append cost cannot hide in a rounding error, small enough to stay a unit
#: test.
STEADY_STATE_APPENDS = 100


class _OpenCounter:
    """Count ``Path.open`` calls by mode and ``os.open`` calls, while passing through."""

    def __init__(self) -> None:
        self.path_modes: Counter[str] = Counter()
        self.os_opens = 0

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_path_open = pathlib.Path.open
        real_os_open = os.open

        def counted_path_open(this: Path, mode: str = "r", *args: object, **kwargs: object) -> object:
            self.path_modes[mode] += 1
            return real_path_open(this, mode, *args, **kwargs)  # type: ignore[arg-type]

        def counted_os_open(*args: object, **kwargs: object) -> int:
            self.os_opens += 1
            return real_os_open(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(pathlib.Path, "open", counted_path_open)
        monkeypatch.setattr(os, "open", counted_os_open)


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLog:
    """An ``AuditLog`` already warmed up: table registered, head cached."""
    log = AuditLog(audit_dir=tmp_path / "audit", key=KEY)
    for i in range(3):
        log.log("warmup", "test", "resource", f"w-{i}", {})
    return log


def test_a_steady_state_append_does_not_probe_the_segment_for_a_torn_tail(
    audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One append, one open, and that open is the append itself.

    The torn-tail probe used to run unconditionally: ``open("rb")`` plus a seek
    to the last byte plus a one-byte read, on every record. The file-open census
    per 100 appends went from ``{append: 100}`` to ``{append: 100, read: 100}``,
    which measured as roughly a third of append throughput.
    """
    counter = _OpenCounter()
    counter.install(monkeypatch)

    for i in range(STEADY_STATE_APPENDS):
        audit_log.log("steady", "test", "resource", f"r-{i}", {"i": i})

    read_opens = sum(count for mode, count in counter.path_modes.items() if "r" in mode)
    assert read_opens == 0, (
        f"{read_opens} read-mode opens across {STEADY_STATE_APPENDS} steady-state appends; "
        f"census={dict(counter.path_modes)}. A per-append probe has come back."
    )


def test_a_steady_state_append_opens_the_segment_exactly_once(
    audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The census is exactly one append-mode open per record, and nothing else."""
    counter = _OpenCounter()
    counter.install(monkeypatch)

    for i in range(STEADY_STATE_APPENDS):
        audit_log.log("steady", "test", "resource", f"r-{i}", {"i": i})

    assert dict(counter.path_modes) == {"a": STEADY_STATE_APPENDS}, (
        f"expected exactly {STEADY_STATE_APPENDS} append-mode opens and nothing else, got {dict(counter.path_modes)}"
    )


def test_a_steady_state_append_does_not_reopen_the_lock_file(
    audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once the lock table knows the inode, the transaction costs one ``stat``.

    Registering an entry per append was ``mkdir`` + ``os.open`` + ``fstat`` +
    ``close`` on the hot path, purely to rediscover an inode the table already
    held a pinned descriptor for.
    """
    counter = _OpenCounter()
    counter.install(monkeypatch)

    for i in range(STEADY_STATE_APPENDS):
        audit_log.log("steady", "test", "resource", f"r-{i}", {"i": i})

    assert counter.os_opens == 0, (
        f"{counter.os_opens} lock-file opens across {STEADY_STATE_APPENDS} appends; "
        "the lock entry should be looked up, not re-registered, once the table is warm."
    )


def test_the_first_append_of_a_segment_still_checks_for_a_torn_tail(tmp_path: Path) -> None:
    """The probe is skipped, not deleted.

    A fresh instance has no idea what left the segment in the state it is in, so
    it must look. This is the guard against "fixed the throughput by removing
    the check": the seal still has to happen on the path where it matters.
    """
    audit_dir = tmp_path / "audit"
    first = AuditLog(audit_dir=audit_dir, key=KEY)
    first.log("seed", "test", "resource", "r-0", {})

    segment = next(audit_dir.glob("*.jsonl"))
    raw = segment.read_bytes()
    assert raw.endswith(b"\n")
    segment.write_bytes(raw[:-1])  # a crash between the payload and its terminator

    # A different instance, exactly as a second process would be.
    second = AuditLog(audit_dir=audit_dir, key=KEY)
    second.log("after-crash", "test", "resource", "r-1", {})

    lines = segment.read_bytes().split(b"\n")
    assert lines[-1] == b""
    assert len(lines) == 4, (
        f"expected the torn record, the seal event, and the new record as three separate lines, got {len(lines) - 1}"
    )
    assert b"chain.torn_record" in segment.read_bytes()
