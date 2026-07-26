"""Bounded tail re-sync for :meth:`AuditLog._sync_for_append`.

Under multi-process contention nearly every append sees a segment-stamp
mismatch and takes the slow re-sync path while holding the exclusive
cross-process flock. When that path read the entire day segment, the cost of a
contended append grew linearly with the day's size (roughly 1 s p99 on an
ordinary 24 MB day), and the total contended write cost over a day was
O(N^2) in events. The chain head only ever lives in the segment's final
records, so the re-sync reads a bounded, line-aligned tail window and falls
back to the whole segment only when the window cannot decide: no line boundary
inside it, or a non-verifying tail whose seal needs the segment's exact byte
offsets.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import bernstein.core.security.audit as audit_mod
from bernstein.core.security.audit import AuditLog

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

KEY = b"\x42" * 32


def _alternate_appends(a: AuditLog, b: AuditLog, count: int) -> None:
    """Interleave appends across two instances so every append re-syncs.

    Two instances of the same audit dir model two processes: each append by
    one invalidates the other's ``(path, stamp)`` fast path, which is exactly
    the shape multi-process contention produces.
    """
    for index in range(count):
        writer = a if index % 2 == 0 else b
        writer.log("sync.window", "writer", "task", f"t{index}", {"n": index, "pad": "x" * 200})


def _day_segment(audit_dir: Path) -> Path:
    return next(iter(sorted(audit_dir.glob("*.jsonl"))))


class TestBoundedResync:
    def test_contended_resync_never_rereads_the_whole_segment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A healthy contended append must not pay O(day-segment bytes).

        The whole-segment read is only legitimate on the fallback paths (no
        line boundary in the window, or a torn tail about to be sealed). On a
        healthy segment, alternating writers must sync from the bounded tail
        window alone.
        """
        audit_dir = tmp_path / "audit"
        a = AuditLog(audit_dir, key=KEY)
        b = AuditLog(audit_dir, key=KEY)
        _alternate_appends(a, b, 40)
        segment = _day_segment(audit_dir)

        from pathlib import Path as PathType

        whole_reads: list[str] = []
        real_read_bytes = PathType.read_bytes

        def spy(self: Path) -> bytes:
            if self.name == segment.name:
                whole_reads.append(self.name)
            return real_read_bytes(self)

        monkeypatch.setattr(PathType, "read_bytes", spy)
        _alternate_appends(a, b, 10)
        assert whole_reads == [], "contended appends re-read the entire day segment"

        monkeypatch.undo()
        ok, errors = a.verify()
        assert ok, errors

    def test_alternating_writers_chain_correctly_past_the_window(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Correctness on a segment much larger than the window.

        With the window forced far below the segment size, every re-sync sees
        only the final records. The chain must still verify end to end and
        hold every append.
        """
        monkeypatch.setattr(audit_mod, "_TAIL_SYNC_WINDOW", 4096)
        audit_dir = tmp_path / "audit"
        a = AuditLog(audit_dir, key=KEY)
        b = AuditLog(audit_dir, key=KEY)
        _alternate_appends(a, b, 120)  # ~40 KB of records, ~10x the window

        ok, errors = a.verify()
        assert ok, errors
        fresh = AuditLog(audit_dir, key=KEY)
        assert len(fresh.query(event_type="sync.window")) == 120

    def test_window_smaller_than_one_record_falls_back_and_still_chains(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A window that cannot hold one record must fall back, not misjudge.

        With no line boundary inside the window the tail cannot be aligned, so
        the re-sync must read the whole segment rather than adopt a head from
        a mid-record fragment.
        """
        monkeypatch.setattr(audit_mod, "_TAIL_SYNC_WINDOW", 64)
        audit_dir = tmp_path / "audit"
        a = AuditLog(audit_dir, key=KEY)
        b = AuditLog(audit_dir, key=KEY)
        _alternate_appends(a, b, 12)

        ok, errors = a.verify()
        assert ok, errors
        assert len(AuditLog(audit_dir, key=KEY).query(event_type="sync.window")) == 12

    def test_torn_tail_beyond_a_healthy_window_is_still_sealed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The tear gate survives the windowed read.

        A crash fragment at the tail must be sealed exactly as before: the
        windowed read may observe it first, but the seal must record offsets
        computed over the whole segment.
        """
        monkeypatch.setattr(audit_mod, "_TAIL_SYNC_WINDOW", 4096)
        audit_dir = tmp_path / "audit"
        a = AuditLog(audit_dir, key=KEY)
        b = AuditLog(audit_dir, key=KEY)
        _alternate_appends(a, b, 60)
        segment = _day_segment(audit_dir)
        intact = segment.stat().st_size

        with segment.open("ab") as fh:
            fh.write(b'{"partial-crash-fragment')

        # The other instance re-syncs (stamp mismatch), seals the tear, and
        # appends on top of the evidence record.
        b.log("sync.window", "writer", "task", "after-tear", {})

        report = AuditLog(audit_dir, key=KEY).verify_detailed()
        assert not report.hard_errors, report.hard_errors
        tears = report.unacknowledged_tears
        assert len(tears) == 1
        assert tears[0].sealed is True
        assert tears[0].verified_prefix_offset == intact
        events = AuditLog(audit_dir, key=KEY).query(event_type="sync.window")
        assert any(e.resource_id == "after-tear" for e in events)
