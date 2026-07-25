"""How long the chain's readers and retention may hold the chain lock.

The chain transaction is exclusive across processes and has a fixed budget
(:data:`CHAIN_LOCK_TIMEOUT_S`, 30s) that every other caller fails against rather
than waiting past. So any holder whose hold grows with history size eventually
denies unrelated writers: a scheduled ``bernstein audit verify`` in flight, and
an ordinary ``bernstein tenant create`` alongside it exits non-zero with nothing
created.

Holders that had that shape:

* the charter pillar re-read the whole chain once per charter *inside* one
  transaction, so the hold was O(charters x history);
* ``AuditLog.archive`` gzipped every expired segment inside the transaction, so
  the hold was O(bytes in the retention window);
* ``AuditChainStore.verify_and_query``, ``bernstein tenant verify`` and the two
  new ``audit verify`` pillars held the transaction across a full-history walk,
  measured at roughly 30 seconds of exclusive hold per gigabyte of chain.

All of them are now snapshot-then-work: the exclusive section covers the
segment pin (or the two renames), and the expensive part runs outside it.

Every hold test is paired with a verdict test, because the cheap way to pass a
hold budget is to stop doing the work.

**Budget shape.** The assertions are calibrated against the cost of the one
chain read the work genuinely needs, measured on the same machine in the same
run, rather than against a wall-clock constant that means different things on a
laptop and a shared runner. The property under test is that the hold is a small
multiple of *one* pass over history, not a multiple of the number of tenants.
That is exactly the property that failed: the reported crossover was ~300
charters at 50k events, and the shape is linear in tenants, so a seed one order
of magnitude smaller reproduces the same ratio in seconds instead of minutes.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

from bernstein.cli.commands import audit_cmd
from bernstein.core.security.audit import (
    CHAIN_LOCK_TIMEOUT_S,
    AuditLog,
    ChainLockUnavailable,
    chain_transaction,
)
from bernstein.core.security.audit_chain import EVENT_TENANT_CHARTER, AuditChainStore
from bernstein.core.security.tenant_charter import (
    CHARTER_MEMBER_ADD,
    CHARTER_OPEN,
    next_event,
    record_charter_event,
)

KEY = b"k" * 32

#: Tenants in the seeded directory. The old fold re-read the chain once per
#: tenant, so the hold scaled with this number directly.
SEEDED_TENANTS = 80

#: Unrelated events padding the chain, so one read is not free and the
#: per-tenant multiplier is measurable.
SEEDED_FILLER_EVENTS = 8000

#: How much longer than one honest chain read the exclusive hold may last.
#: Generous on purpose: the failure being guarded against is a multiplier of
#: ``SEEDED_TENANTS``, not of three.
HOLD_BUDGET_READS = 3.0

#: Floor under the calibrated budget, so a machine fast enough to read the
#: seeded chain in microseconds does not turn scheduler noise into a failure.
HOLD_BUDGET_FLOOR_S = 0.30

#: What fraction of an ``archive()`` call the exclusive lock may be held for.
#: Measured at 0.3-1.0% with the compression outside; compressing under the
#: lock puts it at 25% (once per segment) to 100% (once around the loop).
ARCHIVE_HOLD_FRACTION = 0.12

#: Floor for the archive budget, so probe granularity and scheduler noise on a
#: fast machine cannot fail the test on their own.
ARCHIVE_HOLD_FLOOR_S = 0.08

#: Filler events for the reader-hold tests. Large enough that one full-history
#: walk costs several hundred milliseconds, which is what separates "held the
#: lock across the walk" from probe granularity.
READER_FILLER_EVENTS = 25000

#: What fraction of a reader's own wall time the exclusive lock may cover. The
#: honest locked work is a directory listing plus one ``stat`` per segment, so
#: the measured fraction is near zero; holding the lock across the walk puts it
#: at ~100%. Calibrated as a fraction rather than against one chain read,
#: because the read these callers make is a filtered query - far cheaper than
#: the HMAC walk that was being held.
READER_HOLD_FRACTION = 0.35

#: Floor for the reader budgets, so probe granularity and scheduler noise on a
#: fast machine cannot fail the test on their own.
READER_HOLD_FLOOR_S = 0.08


@pytest.fixture(autouse=True)
def _pin_audit_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("bernstein.core.security.audit.load_or_create_audit_key", lambda *a, **k: KEY)


class _HoldProbe:
    """Measure the longest window in which the chain lock was not obtainable.

    A second *thread* is a faithful stand-in for a second process here: the
    in-process mutex is taken for exactly as long as the OS lock is, and a
    non-owning thread is refused by the same check a foreign process is. What
    this measures is therefore the operator-visible quantity - how long an
    unrelated writer would be turned away.
    """

    def __init__(self, audit_dir: Path, poll_s: float = 0.002) -> None:
        self._audit_dir = audit_dir
        self._poll_s = poll_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.longest_denial_s = 0.0

    def _run(self) -> None:
        last_success = time.monotonic()
        while not self._stop.is_set():
            try:
                with chain_transaction(self._audit_dir, timeout=0):
                    pass
            except ChainLockUnavailable:
                time.sleep(self._poll_s)
                continue
            now = time.monotonic()
            self.longest_denial_s = max(self.longest_denial_s, now - last_success)
            last_success = now
            time.sleep(self._poll_s)

    def __enter__(self) -> _HoldProbe:
        self._thread.start()
        time.sleep(0.05)  # let the probe establish a baseline before the work starts
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=10)


def _seed(audit_dir: Path, *, tenants: int, filler: int) -> None:
    """Write *tenants* two-event charters interleaved with *filler* other events."""
    chain = AuditChainStore(audit_dir)
    log = AuditLog(audit_dir=audit_dir, key=KEY)
    for index in range(tenants):
        tenant_id = f"tenant-{index:03d}"
        opened = next_event(None, tenant_id=tenant_id, kind=CHARTER_OPEN, principal="ops")
        record_charter_event(chain, opened)
        added = next_event(
            opened,
            tenant_id=tenant_id,
            kind=CHARTER_MEMBER_ADD,
            principal="ops",
            body={"principal": "alice"},
        )
        record_charter_event(chain, added)
        for pad in range(filler // max(tenants, 1)):
            log.log("filler", "test", "resource", f"{tenant_id}-{pad}", {})


def _os_lock_is_free(audit_dir: Path) -> bool:
    """Whether a *foreign* descriptor can take the chain lock right now.

    ``flock`` state belongs to the open file description, not to the process, so
    a fresh descriptor is refused by exactly the same check a second process is.
    """
    from bernstein.core.persistence.file_locks import os_try_lock_fd, os_unlock_fd
    from bernstein.core.security.audit import _CHAIN_LOCK_NAME

    fd = os.open(str(audit_dir / _CHAIN_LOCK_NAME), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os_try_lock_fd(fd):
            os_unlock_fd(fd)
            return True
        return False
    finally:
        os.close(fd)


def _spy_on_queries(monkeypatch: pytest.MonkeyPatch, audit_dir: Path) -> list[bool]:
    """Record, per ``AuditChainStore.query`` call, whether the chain lock was free."""
    observed: list[bool] = []
    real_query = AuditChainStore.query

    def _query(self: AuditChainStore, **kwargs: object) -> object:
        observed.append(_os_lock_is_free(audit_dir))
        return real_query(self, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(AuditChainStore, "query", _query)
    return observed


def _one_snapshot_read_s(audit_dir: Path) -> float:
    """Time the single chain read the charter pillar genuinely needs."""
    chain = AuditChainStore(audit_dir)
    start = time.monotonic()
    with chain.transaction():
        chain.query(event_type=EVENT_TENANT_CHARTER, include_archived=True)
    return time.monotonic() - start


class TestCharterPillarHold:
    def test_folding_every_charter_does_not_hold_the_lock_per_charter(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The verdict needs one consistent snapshot, not one transaction per tenant.

        Folding inside the transaction re-read the whole chain once per charter.
        The fold is pure CPU over data already in hand, so nothing about the
        verdict required the lock to still be held while it ran.
        """
        audit_dir = tmp_path / "audit"
        monkeypatch.setattr(audit_cmd, "AUDIT_DIR", audit_dir)
        _seed(audit_dir, tenants=SEEDED_TENANTS, filler=SEEDED_FILLER_EVENTS)

        one_read = _one_snapshot_read_s(audit_dir)
        budget = max(HOLD_BUDGET_FLOOR_S, one_read * HOLD_BUDGET_READS)

        with _HoldProbe(audit_dir) as probe:
            assert audit_cmd._verify_tenant_charters() is True
        held = probe.longest_denial_s

        assert held <= budget, (
            f"the charter pillar held the exclusive chain lock for {held:.3f}s across "
            f"{SEEDED_TENANTS} charters; one honest chain read costs {one_read:.3f}s, so the "
            f"budget is {budget:.3f}s. A hold proportional to the number of charters denies every "
            f"other writer for that long, against a primitive budget of {CHAIN_LOCK_TIMEOUT_S}s."
        )

    def test_the_verdict_is_unchanged_by_folding_outside_the_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A damaged charter must still fail the pillar.

        Guards the cheap way to pass the budget test: stop folding.
        """
        audit_dir = tmp_path / "audit"
        monkeypatch.setattr(audit_cmd, "AUDIT_DIR", audit_dir)
        _seed(audit_dir, tenants=2, filler=0)

        segment = next(iter(sorted(audit_dir.glob("*.jsonl"))))
        raw = segment.read_text(encoding="utf-8")
        # Break one charter body's own hash linkage without touching the HMAC
        # framing: the fold must catch what the byte-level verifier cannot.
        segment.write_text(raw.replace('"seq": 1', '"seq": 7', 1), encoding="utf-8")

        assert audit_cmd._verify_tenant_charters() is False


class TestArchiveHold:
    def test_compressing_the_retention_window_happens_outside_the_lock(self, tmp_path: Path) -> None:
        """The hold covers the two renames, not the gzip.

        Compression is proportional to the bytes in the expired window, and an
        operator with a year of retention has a lot of them. Only expired
        segments are compressed and appends only ever touch the current day, so
        nothing is written while a segment compresses; the source is re-checked
        under the lock before the swap so a segment that moved is skipped rather
        than published from a stale copy.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(parents=True)
        # Random hex, not repeated filler: real records carry HMAC digests, which
        # do not compress, and a payload that gzips 50x would not exercise the
        # cost this test is about.
        payload = "".join(f'{{"hmac": "{os.urandom(256).hex()}"}}\n' for _ in range(12000))
        for day in ("2020-01-01", "2020-01-02", "2020-01-03", "2020-01-04"):
            (audit_dir / f"{day}.jsonl").write_text(payload, encoding="utf-8")

        log = AuditLog(audit_dir=audit_dir, key=KEY)

        with _HoldProbe(audit_dir) as probe:
            started = time.monotonic()
            result = log.archive()
            total = time.monotonic() - started
        held = probe.longest_denial_s

        assert sorted(result.archived) == [
            "2020-01-01.jsonl",
            "2020-01-02.jsonl",
            "2020-01-03.jsonl",
            "2020-01-04.jsonl",
        ]

        # Calibrated against archive's own cost, not against a chain read: the
        # honest locked work here is two renames per segment, which is
        # microseconds, while the call as a whole is dominated by gzip. So the
        # question is what *fraction* of the call the lock was held for.
        # Compressing under the lock, whether once around the loop or once per
        # segment, puts that fraction at 25-100%; keeping it outside measures
        # under 1%.
        budget = max(ARCHIVE_HOLD_FLOOR_S, total * ARCHIVE_HOLD_FRACTION)
        assert held <= budget, (
            f"archive() held the exclusive chain lock for {held:.3f}s of a {total:.3f}s call "
            f"({held / total:.1%}); the budget is {budget:.3f}s. Compression must run outside "
            "the transaction."
        )

    def test_a_segment_that_changed_under_the_compress_is_not_published(self, tmp_path: Path) -> None:
        """Moving the gzip outside the lock must not publish a stale copy.

        The compress reads the segment without the lock, so the segment could in
        principle have grown by the time the swap runs. The publish step
        re-checks ``(size, mtime_ns)`` under the lock and skips rather than
        replacing a live segment with a copy that is missing its tail.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(parents=True)
        stale = audit_dir / "2020-01-01.jsonl"
        stale.write_text('{"a": 1}\n', encoding="utf-8")

        log = AuditLog(audit_dir=audit_dir, key=KEY)
        real_publish = log._publish_archived_segment

        def grow_then_publish(log_path: Path, gz_path: Path, tmp_path_: Path, before: object) -> bool:
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write('{"a": 2}\n')
            return real_publish(log_path, gz_path, tmp_path_, before)  # type: ignore[arg-type]

        log._publish_archived_segment = grow_then_publish  # type: ignore[method-assign]
        result = log.archive()

        assert result.archived == []
        assert "2020-01-01.jsonl" in result.skipped
        assert stale.exists(), "a segment that grew under the compress was unlinked anyway"
        assert not (audit_dir / "archive" / "2020-01-01.jsonl.gz").exists()
        assert not list((audit_dir / "archive").glob("*.tmp")), "the discarded temp file was left behind"


class TestReaderHoldsAreBoundedByThePin:
    """Readers whose own cost is O(history) must not hold the lock across it.

    Each of these pins the segment set under the transaction - a listing plus
    one ``stat`` per segment - and then walks the pinned bytes with no lock
    held. The budget is calibrated against one honest chain read on the same
    machine in the same run; a walk held under the lock costs at least that.
    """

    def test_verify_and_query_does_not_hold_the_lock_across_the_walk(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        _seed(audit_dir, tenants=4, filler=READER_FILLER_EVENTS)
        chain = AuditChainStore(audit_dir, key=KEY)

        with _HoldProbe(audit_dir) as probe:
            started = time.monotonic()
            ok, errors, events = chain.verify_and_query(event_type="filler")
            total = time.monotonic() - started
        held = probe.longest_denial_s
        budget = max(READER_HOLD_FLOOR_S, total * READER_HOLD_FRACTION)

        assert ok, errors
        assert events, "the projection came back empty, so the budget proves nothing"
        assert held <= budget, (
            f"verify_and_query held the exclusive chain lock for {held:.3f}s of a {total:.3f}s "
            f"call ({held / total:.1%}); the budget is {budget:.3f}s. The HMAC recomputation is a "
            "pure walk over pinned bytes and needs no exclusion of its own."
        )

    def test_verify_and_query_still_reports_a_broken_chain(self, tmp_path: Path) -> None:
        """Guards the cheap way to pass the budget above: stop verifying."""
        audit_dir = tmp_path / "audit"
        _seed(audit_dir, tenants=1, filler=4)
        segment = next(iter(sorted(audit_dir.glob("*.jsonl"))))
        raw = segment.read_text(encoding="utf-8")
        segment.write_text(raw.replace('"actor": "test"', '"actor": "mallory"', 1), encoding="utf-8")

        ok, errors, _ = AuditChainStore(audit_dir, key=KEY).verify_and_query(event_type="filler")
        assert ok is False
        assert errors

    def test_the_tear_pillar_reads_with_no_lock_held(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Structural, not timed: the reads themselves must be outside the section.

        The pillar runs two full-history reads. Their cost grows with the chain,
        so whether *this* chain makes them slow enough to measure is beside the
        point - what must hold is that a second process can take the lock while
        they run.
        """
        audit_dir = tmp_path / "audit"
        monkeypatch.setattr(audit_cmd, "AUDIT_DIR", audit_dir)
        _seed(audit_dir, tenants=2, filler=200)

        observed = _spy_on_queries(monkeypatch, audit_dir)
        assert audit_cmd._verify_chain_tears() is True
        monkeypatch.undo()

        assert len(observed) == 2, f"the tear pillar made {len(observed)} reads, expected 2"
        assert all(observed), "the tear pillar read the chain with the exclusive lock held"
        assert _os_lock_is_free(audit_dir) is True

    def test_the_charter_pillar_reads_with_no_lock_held(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        audit_dir = tmp_path / "audit"
        monkeypatch.setattr(audit_cmd, "AUDIT_DIR", audit_dir)
        _seed(audit_dir, tenants=2, filler=200)

        observed = _spy_on_queries(monkeypatch, audit_dir)
        assert audit_cmd._verify_tenant_charters() is True
        monkeypatch.undo()

        assert observed, "the charter pillar made no chain read at all"
        assert all(observed), "the charter pillar read the chain with the exclusive lock held"

    def test_the_tear_pillar_still_reports_an_unacknowledged_tear(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Guards the cheap way to pass the budget above: stop looking for tears."""
        audit_dir = tmp_path / "audit"
        monkeypatch.setattr(audit_cmd, "AUDIT_DIR", audit_dir)
        log = AuditLog(audit_dir=audit_dir, key=KEY)
        log.log("filler", "test", "resource", "r0", {})

        segment = next(iter(sorted(audit_dir.glob("*.jsonl"))))
        os.truncate(segment, segment.stat().st_size - 1)
        AuditLog(audit_dir=audit_dir, key=KEY).log("filler", "test", "resource", "r1", {})

        assert audit_cmd._verify_chain_tears() is False

    def test_tenant_verify_does_not_hold_the_lock_across_the_chain_verify(self, tmp_path: Path) -> None:
        """``bernstein tenant verify`` is a read; it must not deny writers for a full walk."""
        from click.testing import CliRunner

        from bernstein.cli.commands.tenant_cmd import tenant_group

        workdir = tmp_path / "project"
        audit_dir = workdir / ".sdd" / "audit"
        _seed(audit_dir, tenants=2, filler=READER_FILLER_EVENTS)

        runner = CliRunner()
        with _HoldProbe(audit_dir) as probe:
            started = time.monotonic()
            result = runner.invoke(tenant_group, ["verify", "tenant-000", "--workdir", str(workdir), "--json"])
            total = time.monotonic() - started
        held = probe.longest_denial_s
        budget = max(READER_HOLD_FLOOR_S, total * READER_HOLD_FRACTION)

        assert result.exit_code == 0, result.output
        assert held <= budget, (
            f"'tenant verify' held the exclusive chain lock for {held:.3f}s of a {total:.3f}s "
            f"command ({held / total:.1%}); the budget is {budget:.3f}s. chain.verify() is a walk "
            "over pinned bytes and belongs outside the exclusive section."
        )

    def test_tenant_verify_still_fails_on_a_broken_chain(self, tmp_path: Path) -> None:
        """Guards the cheap way to pass the budget above: stop calling chain.verify()."""
        import json as _json

        from click.testing import CliRunner

        from bernstein.cli.commands.tenant_cmd import tenant_group

        workdir = tmp_path / "project"
        audit_dir = workdir / ".sdd" / "audit"
        _seed(audit_dir, tenants=1, filler=4)
        segment = next(iter(sorted(audit_dir.glob("*.jsonl"))))
        raw = segment.read_text(encoding="utf-8")
        segment.write_text(raw.replace('"actor": "test"', '"actor": "mallory"', 1), encoding="utf-8")

        result = CliRunner().invoke(tenant_group, ["verify", "tenant-000", "--workdir", str(workdir), "--json"])
        assert result.exit_code == 1
        assert _json.loads(result.output)["audit_chain_ok"] is False
