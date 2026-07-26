"""Durable appends: a decision record must survive the host, not the process.

An ordinary append returns once its bytes are in the page cache. A host crash
can drop a group of acknowledged records off the tail of the newest segment,
and a chain walk cannot see that loss: the surviving prefix is intact and
correctly linked, so every verifier reports the chain as healthy. For most
telemetry that trade is right. For a record someone *acts on* - a charter
revocation above all - it silently reverts the decision, so those callers pass
``durable=True`` and pay one ``fsync``.

These tests pin the contract, not the platter: ``os.fsync`` is spied, never
relied on, so they run identically on any filesystem.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

import pytest

from bernstein.core.security import audit as audit_module
from bernstein.core.security.audit import AuditLog
from bernstein.core.security.audit_chain import AuditChainStore
from bernstein.core.security.tenant_charter import open_event, record_charter_event

if TYPE_CHECKING:
    from pathlib import Path

KEY = b"\x11" * 32


@pytest.fixture
def fsync_calls(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Spy on ``os.fsync``, recording the descriptors it was asked to flush."""
    calls: list[int] = []

    def _spy(fd: int) -> None:
        calls.append(fd)

    monkeypatch.setattr(os, "fsync", _spy)
    return calls


class TestDurableAppend:
    def test_a_plain_append_does_not_fsync(self, tmp_path: Path, fsync_calls: list[int]) -> None:
        """The hot path must not pay for a guarantee nobody asked it for."""
        log = AuditLog(audit_dir=tmp_path / "audit", key=KEY)
        log.log("test.event", "actor", "resource", "r1", {"n": 1})
        assert fsync_calls == []

    def test_a_durable_append_flushes_the_segment(self, tmp_path: Path, fsync_calls: list[int]) -> None:
        log = AuditLog(audit_dir=tmp_path / "audit", key=KEY)
        log.log("test.event", "actor", "resource", "r1", {"n": 1}, durable=True)
        assert len(fsync_calls) >= 1

    def test_a_durable_append_into_a_fresh_segment_publishes_the_directory_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A durable record in a file nothing points at is not durable.

        The segment's own bytes reaching the platter is not enough when the
        append *created* the segment: the directory entry naming it has to
        survive too. Only the first durable append into a day file pays this;
        the second one appends to a segment whose entry already exists.
        """
        published: list[Path] = []
        monkeypatch.setattr(audit_module, "_fsync_directory", published.append)
        monkeypatch.setattr(os, "fsync", lambda fd: None)

        audit_dir = tmp_path / "audit"
        log = AuditLog(audit_dir=audit_dir, key=KEY)
        log.log("test.event", "actor", "resource", "r1", {"n": 1}, durable=True)
        assert published == [audit_dir]

        log.log("test.event", "actor", "resource", "r2", {"n": 2}, durable=True)
        assert published == [audit_dir]

    def test_the_durable_record_verifies_like_any_other(self, tmp_path: Path) -> None:
        """Durability changes when ``log`` returns, never what it writes."""
        log = AuditLog(audit_dir=tmp_path / "audit", key=KEY)
        log.log("test.event", "actor", "resource", "r1", {"n": 1}, durable=True)
        log.log("test.event", "actor", "resource", "r2", {"n": 2})
        ok, errors = log.verify()
        assert ok, errors


class TestDurablePassThrough:
    def test_log_with_prev_digest_forwards_durable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[bool] = []
        real_log = AuditLog.log

        def _recording(self: AuditLog, *args: Any, durable: bool = False, **kwargs: Any) -> Any:
            seen.append(durable)
            return real_log(self, *args, durable=durable, **kwargs)

        monkeypatch.setattr(AuditLog, "log", _recording)
        chain = AuditChainStore(tmp_path / "audit", key=KEY)
        chain.log_with_prev_digest(
            event_type="test.event",
            actor="actor",
            resource_type="resource",
            resource_id="r1",
            details={"n": 1},
            durable=True,
        )
        assert seen == [True]

    def test_a_charter_event_is_recorded_durably(self, tmp_path: Path, fsync_calls: list[int]) -> None:
        """A charter event is a decision someone acts on; it must not revert."""
        chain = AuditChainStore(tmp_path / "audit", key=KEY)
        record_charter_event(chain, open_event(tenant_id="acme", principal="alice"))
        assert len(fsync_calls) >= 1
