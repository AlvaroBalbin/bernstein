"""Charter fold, backdating refusal, and duty refusals (#2554 AC1, AC4, AC5).

The tests that matter here are the ones that construct a *bad* input and assert
it is caught: a check that cannot fail on crafted input is not implemented.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from bernstein.core.cost.showback_canonical import NonCanonicalTextError
from bernstein.core.security.audit_chain import (
    EVENT_TENANT_CHARTER,
    EVENT_TENANT_DUTY_REFUSAL,
    AuditChainStore,
)
from bernstein.core.security.tenant_certificate import (
    REFUSAL_CERTIFICATE_EXPIRED,
    REFUSAL_CHARTER_CLOSED,
    REFUSAL_CHARTER_DRIFT,
    REFUSAL_DUTY_NOT_GRANTED,
    REFUSAL_NOT_A_MEMBER,
    REFUSAL_SELF_APPROVAL,
    DutyNotGranted,
    authorize_duty,
    mint_certificate,
    read_duty_refusals,
    record_duty_refusal,
    require_duty,
)
from bernstein.core.security.tenant_charter import (
    CHARTER_BUDGET_SET,
    CHARTER_CLOSE,
    CHARTER_GENESIS,
    CHARTER_MEMBER_ADD,
    CHARTER_MEMBER_REMOVE,
    CHARTER_OPEN,
    CHARTER_QUOTA_SET,
    CHARTER_ROLE_SET,
    CharterChainError,
    CharterEvent,
    canonical_instant,
    dump_charter_segment,
    fold_charter,
    load_charter,
    load_charter_segment,
    next_event,
    read_charter_events,
    record_charter_event,
    verify_charter,
    verify_charter_events,
)

KEY = b"\x11" * 32


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _segment(
    tenant: str = "acme",
    *,
    members: tuple[tuple[str, str], ...] = (("alice", "owner"), ("bob", "member")),
    budget_usd: str | None = "250.000000000",
) -> list[CharterEvent]:
    """Build a well-formed charter segment with monotonically advancing stamps."""
    stamps = [f"2026-07-2{d // 10}T0{d % 10}:00:00.000000Z" for d in range(1, 9)]
    events = [next_event(None, tenant_id=tenant, kind=CHARTER_OPEN, principal="alice", recorded_at=stamps[0])]
    for index, (principal, role) in enumerate(members, start=1):
        events.append(
            next_event(
                events[-1],
                tenant_id=tenant,
                kind=CHARTER_MEMBER_ADD,
                principal="alice",
                body={"principal": principal, "role": role},
                recorded_at=stamps[index],
            )
        )
    if budget_usd is not None:
        events.append(
            next_event(
                events[-1],
                tenant_id=tenant,
                kind=CHARTER_BUDGET_SET,
                principal="alice",
                body={"budget_usd": budget_usd},
                recorded_at=stamps[len(members) + 1],
            )
        )
    return events


# ---------------------------------------------------------------------------
# AC1 - the fold is deterministic and byte-identical
# ---------------------------------------------------------------------------


class TestCharterFold:
    def test_fold_reaches_expected_state(self) -> None:
        state = fold_charter(_segment())
        assert state.tenant_id == "acme"
        assert state.members == (("alice", "owner"), ("bob", "member"))
        assert state.principals == frozenset({"alice", "bob"})
        assert state.role_of("alice") == "owner"
        assert state.role_of("carol") is None
        assert state.budget_nano_usd == 250_000_000_000
        assert state.version == 4
        assert not state.closed

    def test_charter_hash_is_stable_across_repeated_folds(self) -> None:
        events = _segment()
        assert fold_charter(events).charter_hash() == fold_charter(events).charter_hash()

    def test_enrolment_order_does_not_change_the_membership(self) -> None:
        """Membership is a set: who was enrolled first must not reorder it."""
        forward = fold_charter(_segment(members=(("alice", "owner"), ("bob", "member"))))
        reverse = fold_charter(_segment(members=(("bob", "member"), ("alice", "owner"))))
        assert forward.members == reverse.members == (("alice", "owner"), ("bob", "member"))

        forward_body = forward.to_body()
        reverse_body = reverse.to_body()
        del forward_body["head_event_hash"], reverse_body["head_event_hash"]
        assert forward_body == reverse_body

    def test_the_charter_hash_binds_the_history_that_produced_it(self) -> None:
        """Two histories reaching the same membership are still distinct charters.

        The hash covers ``head_event_hash``, so "which charter was in force"
        names one exact event segment. Without that, two different histories
        could both claim a decision that was only ever taken under one of them.
        """
        forward = fold_charter(_segment(members=(("alice", "owner"), ("bob", "member"))))
        reverse = fold_charter(_segment(members=(("bob", "member"), ("alice", "owner"))))
        assert forward.head_event_hash != reverse.head_event_hash
        assert forward.charter_hash() != reverse.charter_hash()

    def test_a_membership_change_moves_the_hash(self) -> None:
        base = _segment()
        state = fold_charter(base)
        extended = [
            *base,
            next_event(
                base[-1],
                tenant_id="acme",
                kind=CHARTER_MEMBER_ADD,
                principal="alice",
                body={"principal": "carol", "role": "member"},
                recorded_at="2026-07-28T09:00:00.000000Z",
            ),
        ]
        assert fold_charter(extended).charter_hash() != state.charter_hash()

    def test_role_set_and_removal_fold(self) -> None:
        base = _segment()
        promoted = next_event(
            base[-1],
            tenant_id="acme",
            kind=CHARTER_ROLE_SET,
            principal="alice",
            body={"principal": "bob", "role": "approver"},
            recorded_at="2026-07-28T09:00:00.000000Z",
        )
        state = fold_charter([*base, promoted])
        assert state.role_of("bob") == "approver"

        removed = next_event(
            promoted,
            tenant_id="acme",
            kind=CHARTER_MEMBER_REMOVE,
            principal="alice",
            body={"principal": "bob"},
            recorded_at="2026-07-28T10:00:00.000000Z",
        )
        assert not fold_charter([*base, promoted, removed]).is_member("bob")

    def test_quota_and_close_fold(self) -> None:
        base = _segment()
        quota = next_event(
            base[-1],
            tenant_id="acme",
            kind=CHARTER_QUOTA_SET,
            principal="alice",
            body={"max_concurrent_tasks": 4},
            recorded_at="2026-07-28T09:00:00.000000Z",
        )
        closed = next_event(
            quota,
            tenant_id="acme",
            kind=CHARTER_CLOSE,
            principal="alice",
            recorded_at="2026-07-28T10:00:00.000000Z",
        )
        state = fold_charter([*base, quota, closed])
        assert state.quota_max_concurrent == 4
        assert state.closed

    def test_binding_is_minted_from_the_charter(self) -> None:
        """Receipts cite the charter's own hash, not a second invented identity."""
        state = fold_charter(_segment())
        binding = state.binding(certificate_hash="sha256:cafe", certificate_version="1")
        assert binding.charter_hash == state.charter_hash()
        assert binding.to_body()["certificate_hash"] == "sha256:cafe"

    def test_segment_round_trips_through_bytes(self) -> None:
        events = _segment()
        restored = load_charter_segment(dump_charter_segment(events))
        assert fold_charter(restored).charter_hash() == fold_charter(events).charter_hash()

    def test_fold_is_byte_identical_in_a_fresh_interpreter(self, tmp_path: Path) -> None:
        """AC1: two verifiers on the same segment reach identical bytes.

        A separate interpreter with a different ``PYTHONHASHSEED`` stands in for
        the second machine: it is the cheapest way to prove the fold does not
        inherit ordering from this process's set/dict iteration.
        """
        events = _segment()
        segment_path = tmp_path / "segment.jsonl"
        segment_path.write_bytes(dump_charter_segment(events))
        expected = fold_charter(events)

        script = (
            "import json,sys;"
            "from bernstein.core.security.tenant_charter import fold_charter, load_charter_segment;"
            "s=fold_charter(load_charter_segment(open(sys.argv[1],'rb').read()));"
            "print(json.dumps({'hash':s.charter_hash(),'bytes':s.canonical_bytes().decode()}))"
        )
        for seed in ("0", "1", "12345"):
            proc = subprocess.run(
                [sys.executable, "-c", script, str(segment_path)],
                check=True,
                capture_output=True,
                text=True,
                env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
            )
            out = json.loads(proc.stdout)
            assert out["hash"] == expected.charter_hash()
            assert out["bytes"].encode() == expected.canonical_bytes()


# ---------------------------------------------------------------------------
# AC5 - backdating breaks verification
# ---------------------------------------------------------------------------


class TestBackdatingIsRefused:
    def test_appending_a_backdated_event_is_refused(self) -> None:
        """Minting an event dated before its predecessor fails at the boundary."""
        events = _segment()
        with pytest.raises(CharterChainError) as excinfo:
            next_event(
                events[-1],
                tenant_id="acme",
                kind=CHARTER_MEMBER_ADD,
                principal="alice",
                body={"principal": "mallory", "role": "owner"},
                recorded_at="2020-01-01T00:00:00.000000Z",
            )
        assert excinfo.value.reason == "backdated"

    def test_a_backdated_event_forced_into_the_segment_fails_the_fold(self) -> None:
        """Bypassing ``next_event`` does not help: the fold rejects it too."""
        events = _segment()
        forced = CharterEvent(
            tenant_id="acme",
            kind=CHARTER_MEMBER_ADD,
            seq=events[-1].seq + 1,
            recorded_at="2020-01-01T00:00:00.000000Z",
            principal="alice",
            prev_event_hash=events[-1].event_hash(),
            body={"principal": "mallory", "role": "owner"},
        )
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter([*events, forced])
        assert excinfo.value.reason == "backdated"
        assert excinfo.value.seq == forced.seq

    def test_editing_a_recorded_events_timestamp_orphans_its_successor(self) -> None:
        """AC5: rewriting history breaks the chain instead of changing the fold."""
        events = _segment()
        clean_hash = fold_charter(events).charter_hash()

        # Backdate the membership event that enrolled bob, in place.
        tampered = list(events)
        tampered[2] = replace(tampered[2], recorded_at="2026-07-21T00:30:00.000000Z")

        with pytest.raises(CharterChainError) as excinfo:
            fold_charter(tampered)
        assert excinfo.value.reason == "broken_link"
        assert excinfo.value.seq == 3
        # And the attacker gained nothing: the clean fold is unreachable from
        # the tampered segment.
        assert fold_charter(events).charter_hash() == clean_hash

    def test_backdating_on_disk_breaks_both_the_charter_and_the_audit_chain(self, tmp_path: Path) -> None:
        """AC5, end to end: the HMAC chain is the second, independent detector."""
        audit_dir = tmp_path / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        events = _segment()
        for event in events:
            record_charter_event(chain, event)

        assert chain.verify()[0] is True
        assert load_charter(chain, "acme").charter_hash() == fold_charter(events).charter_hash()

        # Rewrite the recorded membership event's timestamp directly in the log.
        log_path = next(iter(sorted(audit_dir.glob("*.jsonl"))))
        lines = log_path.read_text(encoding="utf-8").splitlines()
        patched: list[str] = []
        for line in lines:
            row = json.loads(line)
            body = (row.get("details") or {}).get("charter") or {}
            if row.get("event_type") == EVENT_TENANT_CHARTER and body.get("seq") == 2:
                body["recorded_at"] = "2026-07-21T00:30:00.000000Z"
            patched.append(json.dumps(row))
        log_path.write_text("\n".join(patched) + "\n", encoding="utf-8")

        # Detector 1: the HMAC chain no longer verifies.
        ok, errors = chain.verify()
        assert ok is False
        assert errors

        # Detector 2: the charter fold refuses, naming the orphaned successor.
        reread = AuditChainStore(audit_dir, key=KEY)
        result = verify_charter_events(read_charter_events(reread, "acme"), tenant_id="acme")
        assert result.ok is False
        assert result.reason == "broken_link"
        assert result.seq == 3

    def test_reordering_two_events_is_caught(self) -> None:
        events = _segment()
        swapped = [events[0], events[2], events[1], events[3]]
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter(swapped)
        assert excinfo.value.reason in {"gap", "broken_link"}

    def test_deleting_a_middle_event_is_caught(self) -> None:
        events = _segment()
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter([events[0], events[1], events[3]])
        assert excinfo.value.reason == "gap"

    def test_splicing_a_foreign_tenant_is_caught(self) -> None:
        events = _segment("acme")
        foreign = CharterEvent(
            tenant_id="globex",
            kind=CHARTER_MEMBER_ADD,
            seq=events[-1].seq + 1,
            recorded_at="2026-07-29T00:00:00.000000Z",
            principal="alice",
            prev_event_hash=events[-1].event_hash(),
            body={"principal": "mallory", "role": "owner"},
        )
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter([*events, foreign])
        assert excinfo.value.reason == "tenant_mismatch"


class TestFoldRejections:
    def test_empty_segment(self) -> None:
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter([])
        assert excinfo.value.reason == "empty"

    def test_segment_not_starting_at_open(self) -> None:
        events = _segment()
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter(events[1:])
        assert excinfo.value.reason == "not_opened"

    def test_opening_event_must_point_at_genesis(self) -> None:
        bad = CharterEvent(
            tenant_id="acme",
            kind=CHARTER_OPEN,
            seq=0,
            recorded_at=canonical_instant(),
            principal="alice",
            prev_event_hash="sha256:" + "0" * 64,
        )
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter([bad])
        assert excinfo.value.reason == "broken_link"

    def test_reopening_is_refused(self) -> None:
        events = _segment()
        reopen = next_event(
            events[-1],
            tenant_id="acme",
            kind=CHARTER_OPEN,
            principal="alice",
            recorded_at="2026-07-29T00:00:00.000000Z",
        )
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter([*events, reopen])
        assert excinfo.value.reason == "reopened"

    def test_duplicate_member_is_refused(self) -> None:
        events = _segment()
        dupe = next_event(
            events[-1],
            tenant_id="acme",
            kind=CHARTER_MEMBER_ADD,
            principal="alice",
            body={"principal": "bob", "role": "member"},
            recorded_at="2026-07-29T00:00:00.000000Z",
        )
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter([*events, dupe])
        assert excinfo.value.reason == "duplicate_member"

    def test_removing_a_non_member_is_refused(self) -> None:
        events = _segment()
        ghost = next_event(
            events[-1],
            tenant_id="acme",
            kind=CHARTER_MEMBER_REMOVE,
            principal="alice",
            body={"principal": "nobody"},
            recorded_at="2026-07-29T00:00:00.000000Z",
        )
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter([*events, ghost])
        assert excinfo.value.reason == "unknown_member"

    def test_events_after_close_are_refused(self) -> None:
        events = _segment()
        closed = next_event(
            events[-1],
            tenant_id="acme",
            kind=CHARTER_CLOSE,
            principal="alice",
            recorded_at="2026-07-29T00:00:00.000000Z",
        )
        after = next_event(
            closed,
            tenant_id="acme",
            kind=CHARTER_MEMBER_ADD,
            principal="alice",
            body={"principal": "carol", "role": "member"},
            recorded_at="2026-07-30T00:00:00.000000Z",
        )
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter([*events, closed, after])
        assert excinfo.value.reason == "closed"

    def test_unknown_event_kind_is_refused(self) -> None:
        with pytest.raises(CharterChainError) as excinfo:
            CharterEvent(
                tenant_id="acme",
                kind="charter.pay_bonus",
                seq=0,
                recorded_at=canonical_instant(),
                principal="alice",
                prev_event_hash=CHARTER_GENESIS,
            )
        assert excinfo.value.reason == "unknown_kind"

    def test_non_canonical_instant_is_refused(self) -> None:
        with pytest.raises(CharterChainError) as excinfo:
            CharterEvent(
                tenant_id="acme",
                kind=CHARTER_OPEN,
                seq=0,
                recorded_at="2026-07-24T00:00:00Z",
                principal="alice",
                prev_event_hash=CHARTER_GENESIS,
            )
        assert excinfo.value.reason == "bad_instant"

    def test_non_nfc_principal_is_rejected_not_normalized(self) -> None:
        """Reject rather than repair: a verifier hashes what it was handed."""
        with pytest.raises(NonCanonicalTextError):
            CharterEvent(
                tenant_id="acme",
                kind=CHARTER_OPEN,
                seq=0,
                recorded_at=canonical_instant(),
                principal="alicé",  # 'e' + combining acute; NFC is U+00E9
                prev_event_hash=CHARTER_GENESIS,
            )

    def test_identifier_with_a_path_separator_is_refused(self) -> None:
        with pytest.raises(CharterChainError) as excinfo:
            CharterEvent(
                tenant_id="../../etc",
                kind=CHARTER_OPEN,
                seq=0,
                recorded_at=canonical_instant(),
                principal="alice",
                prev_event_hash=CHARTER_GENESIS,
            )
        assert excinfo.value.reason == "bad_identifier"

    def test_recorded_event_hash_is_recomputed_not_trusted(self) -> None:
        """A hand-edited body cannot smuggle a stale ``event_hash`` past the fold."""
        events = _segment()
        body = events[1].to_body()
        body["body"] = {"principal": "mallory", "role": "owner"}
        forged = CharterEvent.from_body(body)
        assert forged.event_hash() != events[1].event_hash()
        with pytest.raises(CharterChainError) as excinfo:
            fold_charter([events[0], forged, events[2], events[3]])
        assert excinfo.value.reason == "broken_link"


# ---------------------------------------------------------------------------
# AC4 - a spawn-only certificate cannot approve its own gate
# ---------------------------------------------------------------------------


class TestDutyRefusal:
    @staticmethod
    def _charter():
        return fold_charter(_segment())

    def test_spawn_only_certificate_cannot_approve(self) -> None:
        """AC4: the refusal names the certificate hash and the missing scope."""
        charter = self._charter()
        cert = mint_certificate(charter, version="1", duties=frozenset({"spawn"}))

        refusal = authorize_duty(
            cert,
            charter,
            principal="bob",
            duty="approve",
            resource_id="task-17",
            spawned_by="bob",
        )
        assert refusal is not None
        assert refusal.reason == REFUSAL_DUTY_NOT_GRANTED
        assert refusal.certificate_hash == cert.certificate_hash()
        assert refusal.charter_hash == charter.charter_hash()
        assert refusal.missing_scope == ("approve",)
        assert cert.certificate_hash() in str(refusal)

    def test_the_same_certificate_still_grants_spawn(self) -> None:
        """The refusal is scoped, not a blanket denial."""
        charter = self._charter()
        cert = mint_certificate(charter, version="1", duties=frozenset({"spawn"}))
        assert authorize_duty(cert, charter, principal="bob", duty="spawn", resource_id="task-17") is None

    def test_an_approve_certificate_still_cannot_approve_its_own_work(self) -> None:
        """Separation of duties is a distinct check from narrowing."""
        charter = self._charter()
        cert = mint_certificate(charter, version="1", duties=frozenset({"spawn", "approve"}))

        own = authorize_duty(cert, charter, principal="bob", duty="approve", resource_id="task-17", spawned_by="bob")
        assert own is not None
        assert own.reason == REFUSAL_SELF_APPROVAL
        assert own.certificate_hash == cert.certificate_hash()

        other = authorize_duty(
            cert, charter, principal="bob", duty="approve", resource_id="task-17", spawned_by="alice"
        )
        assert other is None

    def test_non_member_is_refused(self) -> None:
        charter = self._charter()
        cert = mint_certificate(charter, version="1", duties=frozenset({"spawn", "approve"}))
        refusal = authorize_duty(cert, charter, principal="mallory", duty="spawn", resource_id="task-17")
        assert refusal is not None
        assert refusal.reason == REFUSAL_NOT_A_MEMBER

    def test_expired_certificate_is_refused(self) -> None:
        charter = self._charter()
        cert = mint_certificate(charter, version="1", duties=frozenset({"spawn"}), not_after=1000.0)
        refusal = authorize_duty(cert, charter, principal="bob", duty="spawn", resource_id="t", now=1001.0)
        assert refusal is not None
        assert refusal.reason == REFUSAL_CERTIFICATE_EXPIRED

    def test_certificate_for_a_different_charter_version_is_refused(self) -> None:
        """A membership change cannot silently re-authorize an old certificate."""
        base = _segment()
        charter = fold_charter(base)
        cert = mint_certificate(charter, version="1", duties=frozenset({"spawn"}))

        grown = fold_charter(
            [
                *base,
                next_event(
                    base[-1],
                    tenant_id="acme",
                    kind=CHARTER_MEMBER_ADD,
                    principal="alice",
                    body={"principal": "carol", "role": "member"},
                    recorded_at="2026-07-29T00:00:00.000000Z",
                ),
            ]
        )
        refusal = authorize_duty(cert, grown, principal="bob", duty="spawn", resource_id="t")
        assert refusal is not None
        assert refusal.reason == REFUSAL_CHARTER_DRIFT

    def test_closed_charter_refuses_everything(self) -> None:
        base = _segment()
        closed = fold_charter(
            [
                *base,
                next_event(
                    base[-1],
                    tenant_id="acme",
                    kind=CHARTER_CLOSE,
                    principal="alice",
                    recorded_at="2026-07-29T00:00:00.000000Z",
                ),
            ]
        )
        cert = mint_certificate(closed, version="1", duties=frozenset({"spawn"}))
        refusal = authorize_duty(cert, closed, principal="bob", duty="spawn", resource_id="t")
        assert refusal is not None
        assert refusal.reason == REFUSAL_CHARTER_CLOSED

    def test_certificate_hash_moves_with_every_field(self) -> None:
        charter = self._charter()
        base = mint_certificate(
            charter, version="1", duties=frozenset({"spawn"}), issued_at="2026-07-24T00:00:00.000000Z"
        )
        variants = [
            mint_certificate(charter, version="2", duties=frozenset({"spawn"}), issued_at=base.issued_at),
            mint_certificate(charter, version="1", duties=frozenset({"approve"}), issued_at=base.issued_at),
            mint_certificate(charter, version="1", duties=frozenset({"spawn"}), issued_at=base.issued_at, max_depth=2),
            mint_certificate(
                charter, version="1", duties=frozenset({"spawn"}), issued_at="2026-07-25T00:00:00.000000Z"
            ),
        ]
        hashes = {base.certificate_hash(), *(v.certificate_hash() for v in variants)}
        assert len(hashes) == len(variants) + 1

    def test_refusal_is_recorded_on_the_chain(self, tmp_path: Path) -> None:
        """AC4: the refusal is a chain event, not a silent denial."""
        charter = self._charter()
        cert = mint_certificate(charter, version="1", duties=frozenset({"spawn"}))
        chain = AuditChainStore(tmp_path / "audit", key=KEY)

        with pytest.raises(DutyNotGranted) as excinfo:
            require_duty(
                cert,
                charter,
                principal="bob",
                duty="approve",
                resource_id="gate-9",
                spawned_by="bob",
                chain=chain,
            )
        assert excinfo.value.refusal.certificate_hash == cert.certificate_hash()

        recorded = read_duty_refusals(chain, "acme")
        assert len(recorded) == 1
        assert recorded[0].certificate_hash == cert.certificate_hash()
        assert recorded[0].reason == REFUSAL_DUTY_NOT_GRANTED
        assert recorded[0].missing_scope == ("approve",)
        assert chain.verify()[0] is True

        rows = chain.query(event_type=EVENT_TENANT_DUTY_REFUSAL)
        assert rows and rows[0].details["refusal"]["certificate_hash"] == cert.certificate_hash()

    def test_a_granted_duty_records_nothing(self, tmp_path: Path) -> None:
        charter = self._charter()
        cert = mint_certificate(charter, version="1", duties=frozenset({"spawn"}))
        chain = AuditChainStore(tmp_path / "audit", key=KEY)
        require_duty(cert, charter, principal="bob", duty="spawn", resource_id="t", chain=chain)
        assert read_duty_refusals(chain, "acme") == []

    def test_refusal_hash_covers_the_reason(self) -> None:
        charter = self._charter()
        cert = mint_certificate(charter, version="1", duties=frozenset({"spawn", "approve"}))
        not_granted = authorize_duty(cert, charter, principal="mallory", duty="approve", resource_id="g")
        self_approval = authorize_duty(
            cert, charter, principal="bob", duty="approve", resource_id="g", spawned_by="bob"
        )
        assert not_granted is not None
        assert self_approval is not None
        assert not_granted.refusal_hash() != self_approval.refusal_hash()


# ---------------------------------------------------------------------------
# Chain round-trip
# ---------------------------------------------------------------------------


class TestChainRoundTrip:
    def test_charter_events_survive_a_chain_round_trip(self, tmp_path: Path) -> None:
        chain = AuditChainStore(tmp_path / "audit", key=KEY)
        events = _segment()
        for event in events:
            record_charter_event(chain, event)

        reread = read_charter_events(AuditChainStore(tmp_path / "audit", key=KEY), "acme")
        assert [e.event_hash() for e in reread] == [e.event_hash() for e in events]
        assert fold_charter(reread).charter_hash() == fold_charter(events).charter_hash()

    def test_sibling_charters_do_not_bleed_into_each_other(self, tmp_path: Path) -> None:
        chain = AuditChainStore(tmp_path / "audit", key=KEY)
        for event in _segment("acme"):
            record_charter_event(chain, event)
        for event in _segment("globex", members=(("carol", "owner"),), budget_usd=None):
            record_charter_event(chain, event)

        acme = load_charter(chain, "acme")
        globex = load_charter(chain, "globex")
        assert acme.principals == frozenset({"alice", "bob"})
        assert globex.principals == frozenset({"carol"})
        assert acme.charter_hash() != globex.charter_hash()

    def test_missing_charter_is_a_named_error(self, tmp_path: Path) -> None:
        chain = AuditChainStore(tmp_path / "audit", key=KEY)
        with pytest.raises(CharterChainError) as excinfo:
            load_charter(chain, "nope")
        assert excinfo.value.reason == "no_charter"


# ---------------------------------------------------------------------------
# Retention: the charter readers must see archived segments
# ---------------------------------------------------------------------------


def _age_and_archive(audit_dir: Path, *, key: bytes = KEY) -> list[str]:
    """Age the live segment and run ordinary retention over it.

    Retention archives by the date in the filename, so renaming the live
    segment to an old date and archiving is exactly what happens to a charter
    that has simply been open for a while.
    """
    from bernstein.core.security.audit import AuditLog, RetentionPolicy

    for path in sorted(audit_dir.glob("*.jsonl")):
        path.rename(audit_dir / "2020-01-01.jsonl")
    return list(AuditLog(audit_dir=audit_dir, key=key).archive(RetentionPolicy(retention_days=1)).archived)


class TestCharterSurvivesRetention:
    """A charter is a linkage structure, so its oldest event is archived first.

    Reading only the live segment would make an intact charter look like it
    never existed - and would let a second ``tenant create`` take the tenant.
    """

    def test_charter_still_folds_after_its_opening_segment_is_archived(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        events = _segment()
        for event in events:
            record_charter_event(chain, event)
        expected = fold_charter(events).charter_hash()

        assert _age_and_archive(audit_dir) == ["2020-01-01.jsonl"]
        assert not list(audit_dir.glob("*.jsonl")), "the live segment should be gone"

        reread = AuditChainStore(audit_dir, key=KEY)
        assert len(read_charter_events(reread, "acme")) == len(events)
        assert load_charter(reread, "acme").charter_hash() == expected
        assert verify_charter(reread, "acme").ok is True
        assert reread.verify()[0] is True

    def test_negative_control_a_live_only_read_loses_the_archived_charter(self, tmp_path: Path) -> None:
        """The archived read is load-bearing, not defensive decoration."""
        from bernstein.core.security.audit_chain import EVENT_TENANT_CHARTER

        audit_dir = tmp_path / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        for event in _segment():
            record_charter_event(chain, event)
        _age_and_archive(audit_dir)

        reread = AuditChainStore(audit_dir, key=KEY)
        live_only = reread.query(event_type=EVENT_TENANT_CHARTER, resource_id="acme")
        archived = reread.query(event_type=EVENT_TENANT_CHARTER, resource_id="acme", include_archived=True)
        assert live_only == []
        assert len(archived) == 4
        # ...and the reader we ship uses the second one.
        assert len(read_charter_events(reread, "acme")) == 4

    def test_duty_refusals_survive_retention_too(self, tmp_path: Path) -> None:
        charter = fold_charter(_segment())
        cert = mint_certificate(charter, version="1", duties=frozenset({"spawn"}))
        audit_dir = tmp_path / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        refusal = authorize_duty(cert, charter, principal="bob", duty="approve", resource_id="gate-9")
        assert refusal is not None
        record_duty_refusal(chain, refusal)

        _age_and_archive(audit_dir)
        reread = AuditChainStore(audit_dir, key=KEY)
        recorded = read_duty_refusals(reread, "acme")
        assert len(recorded) == 1
        assert recorded[0].certificate_hash == cert.certificate_hash()


# ---------------------------------------------------------------------------
# The verifier reports damage instead of crashing on it
# ---------------------------------------------------------------------------


class TestMalformedBodiesAreReportedNotRaised:
    """Every recorded body is attacker-controlled, so every parse of one is a
    place the verifier could crash. A crash is indistinguishable from a broken
    tool, which is precisely the outcome a tamperer wants."""

    @staticmethod
    def _record(tmp_path: Path, mutate) -> AuditChainStore:  # type: ignore[no-untyped-def]
        audit_dir = tmp_path / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        for event in _segment():
            record_charter_event(chain, event)
        log_path = next(iter(sorted(audit_dir.glob("*.jsonl"))))
        patched: list[str] = []
        for line in log_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            body = (row.get("details") or {}).get("charter") or {}
            if row.get("event_type") == EVENT_TENANT_CHARTER:
                mutate(body)
            patched.append(json.dumps(row))
        log_path.write_text("\n".join(patched) + "\n", encoding="utf-8")
        return AuditChainStore(audit_dir, key=KEY)

    def test_a_rewritten_budget_yields_a_fail_verdict(self, tmp_path: Path) -> None:
        def mutate(body: dict) -> None:  # type: ignore[type-arg]
            if body.get("kind") == CHARTER_BUDGET_SET:
                body["body"]["budget_usd"] = "1e9"

        result = verify_charter(self._record(tmp_path, mutate), "acme")
        assert result.ok is False
        assert result.reason in {"malformed_body", "broken_link"}
        assert result.detail

    def test_a_rewritten_quota_yields_a_fail_verdict(self, tmp_path: Path) -> None:
        def mutate(body: dict) -> None:  # type: ignore[type-arg]
            if body.get("kind") == CHARTER_BUDGET_SET:
                body["kind"] = CHARTER_QUOTA_SET
                body["body"] = {"max_concurrent_tasks": "not-a-number"}

        result = verify_charter(self._record(tmp_path, mutate), "acme")
        assert result.ok is False
        assert result.reason in {"malformed_body", "broken_link"}

    def test_a_non_nfc_principal_yields_a_fail_verdict(self, tmp_path: Path) -> None:
        def mutate(body: dict) -> None:  # type: ignore[type-arg]
            if body.get("kind") == CHARTER_MEMBER_ADD:
                body["body"]["principal"] = "alicé"

        result = verify_charter(self._record(tmp_path, mutate), "acme")
        assert result.ok is False
        assert result.reason in {"malformed_body", "broken_link"}

    def test_a_mapping_where_a_scalar_belongs_yields_a_fail_verdict(self, tmp_path: Path) -> None:
        def mutate(body: dict) -> None:  # type: ignore[type-arg]
            if body.get("kind") == CHARTER_MEMBER_ADD:
                body["body"]["role"] = {"nested": "mapping"}

        result = verify_charter(self._record(tmp_path, mutate), "acme")
        assert result.ok is False

    def test_a_corrupt_recorded_principal_is_reported_by_the_reader(self, tmp_path: Path) -> None:
        """Damage to the event envelope is caught on read, still as a verdict."""

        def mutate(body: dict) -> None:  # type: ignore[type-arg]
            body["principal"] = "alicé"

        result = verify_charter(self._record(tmp_path, mutate), "acme")
        assert result.ok is False
        assert result.reason == "malformed_event"

    def test_fold_never_raises_a_bare_value_error_on_a_damaged_body(self, tmp_path: Path) -> None:
        """The exception family the fold may raise is exactly CharterChainError."""

        def mutate(body: dict) -> None:  # type: ignore[type-arg]
            if body.get("kind") == CHARTER_BUDGET_SET:
                body["body"]["budget_usd"] = "1e9"

        chain = self._record(tmp_path, mutate)
        try:
            events = read_charter_events(chain, "acme")
            fold_charter(events)
        except CharterChainError:
            pass  # the only acceptable failure
        else:
            pytest.fail("expected the damaged segment to be rejected")

    def test_verify_charter_reports_a_missing_charter(self, tmp_path: Path) -> None:
        result = verify_charter(AuditChainStore(tmp_path / "audit", key=KEY), "ghost")
        assert result.ok is False
        assert result.reason == "no_charter"
