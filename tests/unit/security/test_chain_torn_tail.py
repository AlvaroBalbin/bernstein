"""A sealed tear must not lie about the chain, and must not stop being reportable.

Sealing a crash-truncated segment is the one repair a writer performs on an
append-only log. It is the right repair - the alternative lets the next record
fuse onto the fragment and swallow a real one - but it is a write, and a write
has two consequences the rest of the system has to survive:

* **It moves the chain head.** Anything that read the head before the seal and
  embedded that value in a record now claims a position its record does not
  occupy, under a valid HMAC. The verifier structurally cannot catch it: the
  embedded digest is opaque payload to the HMAC, so a false claim signs exactly
  as cleanly as a true one.
* **It can make the segment verify clean again.** When the crash removed only
  the terminator of an otherwise complete record, putting the byte back leaves
  a segment with nothing wrong in it. A verifier that only checks bytes flips
  from FAILED to Passed with no operator having looked.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bernstein.cli.commands import audit_cmd
from bernstein.core.security.audit import (
    EVENT_CHAIN_TEAR_ACKNOWLEDGED,
    EVENT_CHAIN_TORN_RECORD,
    AuditLog,
)
from bernstein.core.security.audit_chain import AuditChainStore

KEY = b"k" * 32


@pytest.fixture(autouse=True)
def _pin_audit_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The chain store and the verify pillars both load the install key directly."""
    monkeypatch.setattr("bernstein.core.security.audit.load_or_create_audit_key", lambda *a, **k: KEY)


def _segment(audit_dir: Path) -> Path:
    """The single live segment in *audit_dir*."""
    segments = sorted(audit_dir.glob("*.jsonl"))
    assert len(segments) == 1, f"expected one live segment, found {[p.name for p in segments]}"
    return segments[0]


def _records(segment: Path) -> list[dict]:
    """Every parseable record in *segment*, in file order."""
    out: list[dict] = []
    for line in segment.read_bytes().split(b"\n"):
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _is_json_object(line: bytes) -> bool:
    """Whether *line* is one complete JSON object."""
    try:
        return isinstance(json.loads(line), dict)
    except ValueError:
        return False


def _tear_terminator_only(segment: Path) -> None:
    """Remove the final newline: a crash between the payload and its terminator.

    This is the case that heals. Every byte of every record is present and
    authentic; only the last byte of the file is missing.
    """
    raw = segment.read_bytes()
    assert raw.endswith(b"\n")
    segment.write_bytes(raw[:-1])


def _tear_mid_record(segment: Path) -> None:
    """Truncate inside the last record: a crash part-way through the payload.

    This is the case that must stay broken. Half a record is on disk and the
    other half never will be.
    """
    raw = segment.read_bytes()
    body, _, _ = raw.rstrip(b"\n").rpartition(b"\n")
    torn = raw[: len(body) + 1 + 40]
    assert not torn.endswith(b"\n")
    segment.write_bytes(torn)


# ---------------------------------------------------------------------------
# The embedded digest must name the head the record actually chained onto
# ---------------------------------------------------------------------------


class TestEmbeddedDigestAfterASeal:
    def test_a_record_written_over_a_torn_tail_names_its_real_predecessor(self, tmp_path: Path) -> None:
        """The seal happens before the head is read, not after it.

        Reading the head first and sealing afterwards produced a record whose
        embedded ``prev_chain_digest`` named the pre-seal head while the record
        itself chained onto the post-seal head. Both values are real chain
        digests, so nothing downstream can tell which one is the lie.
        """
        audit_dir = tmp_path / "audit"
        seed = AuditChainStore(audit_dir)
        seed.log(event_type="seed", actor="test", resource_type="resource", resource_id="r-0", details={})
        segment = _segment(audit_dir)
        _tear_terminator_only(segment)

        # A different store instance, exactly as a second process would be.
        store = AuditChainStore(audit_dir)
        event = store.log_with_prev_digest(
            event_type="decision",
            actor="test",
            resource_type="resource",
            resource_id="r-1",
            details={},
        )

        claimed = event.details["prev_chain_digest"]
        records = _records(segment)
        assert records[-1]["hmac"] == event.hmac, "the decision record is not the last record in the segment"
        actual = records[-2]["hmac"]

        assert claimed == actual, (
            f"the record claims to have chained onto {claimed[:8]}... but actually chained onto "
            f"{actual[:8]}...; the seal moved the head after the claim was read"
        )
        assert claimed == event.prev_hmac, "the embedded digest disagrees with the record's own prev_hmac"

    def test_the_seal_event_is_the_predecessor_that_gets_named(self, tmp_path: Path) -> None:
        """Names the mechanism, so a future regression is diagnosable, not just red."""
        audit_dir = tmp_path / "audit"
        AuditChainStore(audit_dir).log(
            event_type="seed", actor="test", resource_type="resource", resource_id="r-0", details={}
        )
        _tear_terminator_only(_segment(audit_dir))

        event = AuditChainStore(audit_dir).log_with_prev_digest(
            event_type="decision", actor="test", resource_type="resource", resource_id="r-1", details={}
        )

        seals = [r for r in _records(_segment(audit_dir)) if r["event_type"] == EVENT_CHAIN_TORN_RECORD]
        assert len(seals) == 1
        assert event.details["prev_chain_digest"] == seals[0]["hmac"]

    def test_an_untorn_chain_is_unaffected(self, tmp_path: Path) -> None:
        """The ordering change must not disturb the ordinary path."""
        audit_dir = tmp_path / "audit"
        store = AuditChainStore(audit_dir)
        store.log(event_type="seed", actor="test", resource_type="resource", resource_id="r-0", details={})
        event = AuditChainStore(audit_dir).log_with_prev_digest(
            event_type="decision", actor="test", resource_type="resource", resource_id="r-1", details={}
        )

        records = _records(_segment(audit_dir))
        assert event.details["prev_chain_digest"] == records[-2]["hmac"]
        assert event.details["prev_chain_digest"] == event.prev_hmac


# ---------------------------------------------------------------------------
# Damage stays reportable, in both tear shapes
# ---------------------------------------------------------------------------


class TestDamageStaysReportable:
    """Both directions are pinned here on purpose.

    The two cases pull against each other: sealing is what keeps the mid-record
    tear detectable, and sealing is what makes the terminator-only tear heal. A
    change that fixes either one by removing the seal breaks the other, so
    neither may be asserted alone.
    """

    def test_a_terminator_only_tear_keeps_failing_verify_after_an_ordinary_append(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The case that used to heal itself.

        Before the seal the HMAC pillar fails on "missing trailing newline".
        After any append the bytes are whole again and that pillar passes - so
        the damage has to be recorded as its own durable fact, or a monitoring
        job watching the exit code stops alerting with nobody having looked.
        """
        audit_dir = tmp_path / "audit"
        monkeypatch.setattr(audit_cmd, "AUDIT_DIR", audit_dir)
        AuditLog(audit_dir=audit_dir, key=KEY).log("seed", "test", "resource", "r-0", {})
        _tear_terminator_only(_segment(audit_dir))

        before_valid, before_errors = AuditLog(audit_dir=audit_dir, key=KEY).verify()
        assert before_valid is False, "the tear is not detected at all"
        assert any("newline" in e for e in before_errors), before_errors

        # Anything at all appending is enough to restore the missing byte.
        AuditLog(audit_dir=audit_dir, key=KEY).log("ordinary", "test", "resource", "r-1", {})

        after_valid, after_errors = AuditLog(audit_dir=audit_dir, key=KEY).verify()
        assert after_valid is True, (
            "precondition changed: the byte-level verifier is expected to pass once the seal "
            f"restored the terminator, which is exactly why the damage needs its own pillar: {after_errors}"
        )
        assert audit_cmd._verify_chain_tears() is False, (
            "'audit verify' went back to passing after an ordinary append sealed the tear"
        )

    def test_a_mid_record_tear_stays_two_lines_and_stays_failing(self, tmp_path: Path) -> None:
        """The gain the seal exists for, pinned so a future change cannot trade it away.

        Without the seal the next record concatenates onto the fragment, making
        one unparseable line that holds both - and the verifier then reports
        *fewer* errors, because a real record has been swallowed.
        """
        audit_dir = tmp_path / "audit"
        log = AuditLog(audit_dir=audit_dir, key=KEY)
        log.log("seed", "test", "resource", "r-0", {})
        log.log("seed", "test", "resource", "r-1", {})
        segment = _segment(audit_dir)
        _tear_mid_record(segment)
        fragment = segment.read_bytes().rpartition(b"\n")[2]

        AuditLog(audit_dir=audit_dir, key=KEY).log("after-crash", "test", "resource", "r-2", {})

        lines = [line for line in segment.read_bytes().split(b"\n") if line]
        assert fragment in lines, "the fragment was fused into another line instead of being sealed off"

        parseable = [line for line in lines if _is_json_object(line)]
        assert len(lines) == 4, (
            "expected four lines - the intact first record, the fragment, the seal event, and the "
            f"new record - got {len(lines)}: a fused fragment leaves two"
        )
        assert len(parseable) == 3, (
            f"expected three parseable records beside the fragment, got {len(parseable)}: a record "
            "was swallowed into the unparseable line"
        )

        valid, errors = AuditLog(audit_dir=audit_dir, key=KEY).verify()
        assert valid is False, "a half-written record must keep failing verification forever"
        assert errors

    def test_an_acknowledgement_clears_the_alert_and_nothing_else_does(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only an operator record clears it, and clearing it is itself a chain record.

        Nothing is deleted or rewritten to stop the alerting: who signed the
        damage off, when, and why is as tamper-evident as the damage.
        """
        audit_dir = tmp_path / "audit"
        monkeypatch.setattr(audit_cmd, "AUDIT_DIR", audit_dir)
        AuditLog(audit_dir=audit_dir, key=KEY).log("seed", "test", "resource", "r-0", {})
        _tear_terminator_only(_segment(audit_dir))
        AuditLog(audit_dir=audit_dir, key=KEY).log("ordinary", "test", "resource", "r-1", {})

        outstanding = audit_cmd._unacknowledged_tears()
        assert len(outstanding) == 1
        segment_name, offset, _recorded_at = outstanding[0]

        # More ordinary appends do not clear it.
        AuditLog(audit_dir=audit_dir, key=KEY).log("ordinary", "test", "resource", "r-2", {})
        assert audit_cmd._verify_chain_tears() is False

        AuditChainStore(audit_dir).log_with_prev_digest(
            event_type=EVENT_CHAIN_TEAR_ACKNOWLEDGED,
            actor="operator",
            resource_type="audit_segment",
            resource_id=segment_name,
            details={"segment": segment_name, "byte_offset": offset, "reason": "restart after power loss"},
        )

        assert audit_cmd._verify_chain_tears() is True
        assert audit_cmd._unacknowledged_tears() == []

    def test_an_acknowledgement_for_a_different_tear_does_not_clear_this_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The acknowledgement is keyed on ``(segment, byte_offset)``, not on the segment."""
        audit_dir = tmp_path / "audit"
        monkeypatch.setattr(audit_cmd, "AUDIT_DIR", audit_dir)
        AuditLog(audit_dir=audit_dir, key=KEY).log("seed", "test", "resource", "r-0", {})
        _tear_terminator_only(_segment(audit_dir))
        AuditLog(audit_dir=audit_dir, key=KEY).log("ordinary", "test", "resource", "r-1", {})

        segment_name, offset, _ = audit_cmd._unacknowledged_tears()[0]
        AuditChainStore(audit_dir).log_with_prev_digest(
            event_type=EVENT_CHAIN_TEAR_ACKNOWLEDGED,
            actor="operator",
            resource_type="audit_segment",
            resource_id=segment_name,
            details={"segment": segment_name, "byte_offset": offset + 1, "reason": "wrong offset"},
        )

        assert audit_cmd._verify_chain_tears() is False

    def test_a_clean_chain_reports_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The pillar is a silent no-op when nothing is torn."""
        audit_dir = tmp_path / "audit"
        monkeypatch.setattr(audit_cmd, "AUDIT_DIR", audit_dir)
        AuditLog(audit_dir=audit_dir, key=KEY).log("seed", "test", "resource", "r-0", {})
        assert audit_cmd._verify_chain_tears() is True


# ---------------------------------------------------------------------------
# The repair and its evidence are one write
# ---------------------------------------------------------------------------


class _WriteInterceptor:
    """A segment handle that records every write, and can fail or truncate one.

    Selects by payload rather than by call order, so the same test exercises the
    same *event* whether the seal emits it in one write or in two.
    """

    def __init__(
        self,
        inner: object,
        *,
        marker: bytes | None = None,
        fail: bool = False,
        partial: int | None = None,
    ) -> None:
        self._inner = inner
        self._marker = marker
        self._fail = fail
        self._partial = partial
        self.writes: list[bytes] = []

    def __enter__(self) -> _WriteInterceptor:
        return self

    def __exit__(self, *exc: object) -> None:
        self._inner.__exit__(*exc)  # type: ignore[attr-defined]

    def write(self, data: bytes | str) -> int:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        self.writes.append(raw)
        if self._marker is not None and self._marker not in raw:
            return self._inner.write(data)  # type: ignore[attr-defined]
        if self._fail:
            raise OSError(28, "No space left on device")
        if self._partial is None:
            return self._inner.write(data)  # type: ignore[attr-defined]
        return self._inner.write(data[: self._partial])  # type: ignore[attr-defined]


def _intercept_appends(monkeypatch: pytest.MonkeyPatch, **kwargs: object) -> list[_WriteInterceptor]:
    """Route every append to a live segment through an interceptor."""
    taken: list[_WriteInterceptor] = []
    real_open = Path.open

    def _patched(self: Path, mode: str = "r", *args: object, **kw: object) -> object:
        handle = real_open(self, mode, *args, **kw)  # type: ignore[arg-type]
        if not mode.startswith("a") or self.suffix != ".jsonl":
            return handle
        interceptor = _WriteInterceptor(handle.__enter__(), **kwargs)  # type: ignore[arg-type]
        taken.append(interceptor)
        return interceptor

    monkeypatch.setattr(Path, "open", _patched)
    return taken


class TestTheSealAndItsEvidenceAreOneWrite:
    """A crash during the seal must not leave the damage unreported.

    Writing the terminator first and the ``chain.torn_record`` second leaves a
    state in which the segment is healed and nothing on the chain says it was
    ever damaged: ``bernstein audit verify`` goes exit 1 -> exit 0 with no
    operator action, and a monitoring job watching the exit code stops alerting
    by itself. The state is reachable by a crash, a ``SIGKILL``, or a full
    volume - and a full volume is one of the two classic causes of the tear.
    """

    def _torn(self, tmp_path: Path) -> tuple[Path, Path]:
        audit_dir = tmp_path / "audit"
        log = AuditLog(audit_dir=audit_dir, key=KEY)
        for index in range(3):
            log.log("probe.seed", "test", "resource", f"r{index}", {})
        segment = _segment(audit_dir)
        _tear_terminator_only(segment)
        assert AuditLog(audit_dir=audit_dir, key=KEY).verify()[0] is False
        return audit_dir, segment

    def test_the_seal_emits_the_terminator_and_the_record_in_one_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        audit_dir, _ = self._torn(tmp_path)

        taken = _intercept_appends(monkeypatch)
        AuditLog(audit_dir=audit_dir, key=KEY).log("probe.after", "test", "resource", "r9", {})
        monkeypatch.undo()

        sealing = [w for handle in taken for w in handle.writes if EVENT_CHAIN_TORN_RECORD.encode() in w]
        assert len(sealing) == 1, f"the evidence was written {len(sealing)} times"
        assert sealing[0].startswith(b"\n"), "the terminator was not in the same write as the evidence"
        assert sealing[0].endswith(b"\n")
        # Nothing else was written to the segment before it: the repair does not
        # exist as a separate, earlier write.
        assert taken[0].writes[0] is sealing[0], "the repair was written before its evidence"

    def test_a_seal_write_that_fails_leaves_the_damage_reportable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ENOSPC on the seal: the volume that caused the tear is still full."""
        audit_dir, segment = self._torn(tmp_path)
        before = segment.read_bytes()

        _intercept_appends(monkeypatch, marker=EVENT_CHAIN_TORN_RECORD.encode(), fail=True)
        with pytest.raises(OSError, match="No space left"):
            AuditLog(audit_dir=audit_dir, key=KEY).log("probe.after", "test", "resource", "r9", {})
        monkeypatch.undo()

        assert segment.read_bytes() == before, "the segment changed despite the failed write"
        ok, errors = AuditLog(audit_dir=audit_dir, key=KEY).verify()
        assert ok is False, "a failed seal healed the segment"
        assert any("newline" in err for err in errors)

    def test_a_partial_seal_write_leaves_the_damage_reportable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A torn write of the combined buffer must not read as a healed segment.

        The caller is refused rather than allowed to append onto the fragment
        the short write left: fusing its record onto that fragment would produce
        one unparseable line and swallow a real record.
        """
        audit_dir, segment = self._torn(tmp_path)

        _intercept_appends(monkeypatch, marker=EVENT_CHAIN_TORN_RECORD.encode(), partial=12)
        with pytest.raises(OSError, match="could not seal the torn tail"):
            AuditLog(audit_dir=audit_dir, key=KEY).log("probe.after", "test", "resource", "r9", {})
        monkeypatch.undo()

        assert not segment.read_bytes().endswith(b"\n"), "a partial seal left a terminated segment"
        assert AuditLog(audit_dir=audit_dir, key=KEY).verify()[0] is False

        # And the next ordinary append seals and reports the fresh fragment,
        # so the damage stays on the chain rather than being written away.
        AuditLog(audit_dir=audit_dir, key=KEY).log("probe.later", "test", "resource", "r10", {})
        tears = AuditChainStore(audit_dir, key=KEY).query(event_type=EVENT_CHAIN_TORN_RECORD)
        assert tears, "no tear was recorded for the fragment the partial write left"

    def test_the_evidence_lands_in_the_segment_it_describes(self, tmp_path: Path) -> None:
        """The tear and its record are in the same file, whatever day it is now."""
        audit_dir, segment = self._torn(tmp_path)
        AuditLog(audit_dir=audit_dir, key=KEY).log("probe.after", "test", "resource", "r9", {})

        recorded = [row for row in _records(segment) if row.get("event_type") == EVENT_CHAIN_TORN_RECORD]
        assert len(recorded) == 1
        assert recorded[0]["details"]["segment"] == segment.name
