"""Durable charter head pins: tail loss of charter events must not fold away.

The charter fold and the HMAC walk are both internal to the recorded bytes:
cutting whole records off the tail leaves a shorter history that still folds
and still verifies, and a Merkle seal only binds bytes it already sealed. A
charter event lost after the last seal (or before any seal existed) therefore
reverted silently, and a plain ``bernstein audit seal`` re-pinned the shrunk
history.

Every charter append now also records a signed head pin - ``(tenant_id, seq,
event_hash)`` under ``<audit_dir>/checkpoints/charter-heads.jsonl`` - written
under the same append section, fsynced, and validated with the same discipline
as chain checkpoints. A history whose fold is behind its pinned head conflicts
until an operator acknowledges it; sealing refuses over the conflict rather
than adopting it.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from bernstein.core.persistence.chain_checkpoint import (
    ACK_CHARTER_HEAD_KEY,
    CharterHeadRegressionError,
    CheckpointFileError,
    charter_heads_path,
    check_charter_heads,
    load_charter_heads,
    unacknowledged_charter_head_conflicts,
)
from bernstein.core.security.audit import EVENT_CHAIN_TEAR_ACKNOWLEDGED, AuditLog
from bernstein.core.security.audit_chain import AuditChainStore
from bernstein.core.security.tenant_charter import (
    CHARTER_MEMBER_ADD,
    CHARTER_MEMBER_REMOVE,
    next_event,
    open_event,
    read_charter_events,
    record_charter_event,
)

if TYPE_CHECKING:
    from pathlib import Path

KEY = b"\x24" * 32
TENANT = "acme"


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    return tmp_path / ".sdd" / "audit"


def _chain(audit_dir: Path) -> AuditChainStore:
    return AuditChainStore(audit_dir, key=KEY)


def _build_charter(chain: AuditChainStore, *, revoke: bool = True) -> None:
    """Open a charter and enrol/revoke members: seq 0..2 (or 0..1)."""
    opened = open_event(tenant_id=TENANT, principal="alice", role="owner")
    record_charter_event(chain, opened)
    grant = next_event(
        opened,
        tenant_id=TENANT,
        kind=CHARTER_MEMBER_ADD,
        principal="alice",
        body={"principal": "bob", "role": "member"},
    )
    record_charter_event(chain, grant)
    if revoke:
        removal = next_event(
            grant,
            tenant_id=TENANT,
            kind=CHARTER_MEMBER_REMOVE,
            principal="alice",
            body={"principal": "bob"},
        )
        record_charter_event(chain, removal)


def _drop_last_records(audit_dir: Path, count: int) -> None:
    """Cut whole records off the newest segment - host-level tail loss."""
    segment = max(audit_dir.glob("*.jsonl"))
    records = segment.read_bytes().split(b"\n")[:-1]
    assert len(records) > count
    segment.write_bytes(b"\n".join(records[:-count]) + b"\n")


class TestPinsFollowCharterWrites:
    def test_every_charter_append_pins_the_new_head(self, audit_dir: Path) -> None:
        chain = _chain(audit_dir)
        _build_charter(chain)
        pins = load_charter_heads(audit_dir, KEY)
        assert set(pins) == {TENANT}
        events = read_charter_events(chain, TENANT)
        assert pins[TENANT].seq == 2
        assert pins[TENANT].event_hash == events[-1].event_hash()
        assert check_charter_heads(audit_dir, KEY) == []

    def test_pin_signature_tamper_is_refused(self, audit_dir: Path) -> None:
        _build_charter(_chain(audit_dir))
        path = charter_heads_path(audit_dir)
        lines = path.read_bytes().decode("utf-8").splitlines()
        doc = json.loads(lines[-1])
        doc["payload"]["seq"] = 99
        lines[-1] = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with pytest.raises(CheckpointFileError):
            load_charter_heads(audit_dir, KEY)

    def test_a_torn_pin_append_keeps_the_previous_pin(self, audit_dir: Path) -> None:
        _build_charter(_chain(audit_dir))
        path = charter_heads_path(audit_dir)
        with path.open("ab") as fh:
            fh.write(b'{"payload": {"tenant')
        pins = load_charter_heads(audit_dir, KEY)
        assert pins[TENANT].seq == 2


class TestTailLossDetection:
    def test_losing_the_newest_charter_event_conflicts_with_the_pin(self, audit_dir: Path) -> None:
        """The one detector that does not need a seal covering the event.

        The revocation is the newest chain record; dropping it leaves an HMAC
        chain that still verifies and a charter that still folds - one version
        behind. Only the head pin can see it, sealed or not.
        """
        chain = _chain(audit_dir)
        _build_charter(chain)
        _drop_last_records(audit_dir, 1)

        ok, errors = AuditLog(audit_dir, key=KEY).verify()
        assert ok, f"tail loss must be invisible to the HMAC walk for this test to mean anything: {errors}"
        assert not charter_heads_path(audit_dir).parent.joinpath("checkpoints.jsonl").exists()

        conflicts = check_charter_heads(audit_dir, KEY)
        assert len(conflicts) == 1
        assert conflicts[0].kind == "charter_head_behind"
        assert conflicts[0].segment == f"charter:{TENANT}"
        assert conflicts[0].offset == 2
        assert unacknowledged_charter_head_conflicts(audit_dir, KEY) == conflicts

    def test_an_acknowledgement_record_authorises_the_regression(self, audit_dir: Path) -> None:
        chain = _chain(audit_dir)
        _build_charter(chain)
        pin = load_charter_heads(audit_dir, KEY)[TENANT]
        _drop_last_records(audit_dir, 1)

        AuditLog(audit_dir, key=KEY).log(
            EVENT_CHAIN_TEAR_ACKNOWLEDGED,
            "operator",
            "audit_segment",
            f"charter:{TENANT}",
            {
                "segment": f"charter:{TENANT}",
                "byte_offset": pin.seq,
                "reason": "investigated",
                ACK_CHARTER_HEAD_KEY: pin.event_hash,
            },
        )
        # The evidence stays; only the refusals stand down.
        assert len(check_charter_heads(audit_dir, KEY)) == 1
        assert unacknowledged_charter_head_conflicts(audit_dir, KEY) == []

    def test_a_later_charter_write_supersedes_the_pin(self, audit_dir: Path) -> None:
        chain = _chain(audit_dir)
        _build_charter(chain)
        _drop_last_records(audit_dir, 1)
        assert check_charter_heads(audit_dir, KEY)

        events = read_charter_events(chain, TENANT)
        follow_up = next_event(
            events[-1],
            tenant_id=TENANT,
            kind=CHARTER_MEMBER_ADD,
            principal="alice",
            body={"principal": "carol", "role": "member"},
        )
        record_charter_event(chain, follow_up)
        assert load_charter_heads(audit_dir, KEY)[TENANT].seq == follow_up.seq
        assert check_charter_heads(audit_dir, KEY) == []


class TestSealGate:
    def test_seal_refuses_while_a_charter_head_regressed(self, audit_dir: Path) -> None:
        """A plain re-seal must not launder post-seal charter loss."""
        from bernstein.core.persistence.merkle import compute_seal

        chain = _chain(audit_dir)
        _build_charter(chain, revoke=False)
        _tree, seal = compute_seal(audit_dir, key=KEY)
        from bernstein.core.persistence.chain_checkpoint import record_checkpoint

        record_checkpoint(audit_dir, seal, key=KEY)

        events = read_charter_events(chain, TENANT)
        removal = next_event(
            events[-1],
            tenant_id=TENANT,
            kind=CHARTER_MEMBER_REMOVE,
            principal="alice",
            body={"principal": "bob"},
        )
        record_charter_event(chain, removal)
        _drop_last_records(audit_dir, 1)

        with pytest.raises(CharterHeadRegressionError):
            compute_seal(audit_dir, key=KEY)

    def test_seal_proceeds_after_the_regression_is_acknowledged(self, audit_dir: Path) -> None:
        from bernstein.core.persistence.merkle import compute_seal

        chain = _chain(audit_dir)
        _build_charter(chain)
        pin = load_charter_heads(audit_dir, KEY)[TENANT]
        _drop_last_records(audit_dir, 1)
        AuditLog(audit_dir, key=KEY).log(
            EVENT_CHAIN_TEAR_ACKNOWLEDGED,
            "operator",
            "audit_segment",
            f"charter:{TENANT}",
            {
                "segment": f"charter:{TENANT}",
                "byte_offset": pin.seq,
                "reason": "investigated",
                ACK_CHARTER_HEAD_KEY: pin.event_hash,
            },
        )
        _tree, seal = compute_seal(audit_dir, key=KEY)
        assert seal["entry_count"]
