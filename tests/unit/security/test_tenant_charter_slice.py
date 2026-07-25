"""Charter-keyed audit slices carry no sibling events (#2554 AC3).

The property test is the point: an example-based test proves one chain has no
leak, a property test over generated multi-tenant chains proves the *filter* has
no leak. Both the tenant-id key and the membership key are exercised, because a
free-form string is exactly what a sibling can forge.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from bernstein.core.security.audit_chain import AuditChainStore
from bernstein.core.security.audit_multitenant import export_tenant_slice, verify_tenant_slice
from bernstein.core.security.tenant_charter import (
    CHARTER_MEMBER_ADD,
    CHARTER_OPEN,
    fold_charter,
    next_event,
    record_charter_event,
)
from bernstein.core.security.tenant_charter_slice import (
    charter_slice_members,
    event_belongs_to_charter,
    export_charter_slice,
)

KEY = b"\x22" * 32
SINCE = "2000-01-01"
UNTIL = "2999-01-01"

TENANTS = ("acme", "globex", "initech")
PRINCIPALS = ("alice", "bob", "carol", "dave", "mallory")


def _charter(chain: AuditChainStore, tenant: str, members: tuple[str, ...]):
    """Open a charter for *tenant* enrolling *members*, recording it on *chain*."""
    stamps = [f"2026-07-01T00:{index:02d}:00.000000Z" for index in range(len(members) + 1)]
    events = [next_event(None, tenant_id=tenant, kind=CHARTER_OPEN, principal=members[0], recorded_at=stamps[0])]
    for index, principal in enumerate(members, start=1):
        events.append(
            next_event(
                events[-1],
                tenant_id=tenant,
                kind=CHARTER_MEMBER_ADD,
                principal=members[0],
                body={"principal": principal, "role": "member"},
                recorded_at=stamps[index],
            )
        )
    for event in events:
        record_charter_event(chain, event)
    return fold_charter(events)


def _work_event(chain: AuditChainStore, *, tenant: str, principal: str, index: int) -> None:
    """Append one tenant-attributed work event."""
    chain.log_with_prev_digest(
        event_type="task.transition",
        actor="orchestrator",
        resource_type="task",
        resource_id=f"task-{index}",
        details={"principal": principal, "state": "done", "tenant_id": tenant},
    )


class TestCharterSlicePurity:
    def test_slice_contains_only_charter_events(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        acme = _charter(chain, "acme", ("alice", "bob"))
        _charter(chain, "globex", ("carol",))

        _work_event(chain, tenant="acme", principal="alice", index=1)
        _work_event(chain, tenant="globex", principal="carol", index=2)
        _work_event(chain, tenant="acme", principal="bob", index=3)

        result = export_charter_slice(audit_dir, acme, since=SINCE, until=UNTIL, key=KEY, write=False)
        bundle = json.loads(result.export.bundle_bytes)

        assert bundle["tenant_id"] == "acme"
        assert {e["details"]["tenant_id"] for e in bundle["events"]} == {"acme"}
        assert all(e["details"].get("principal", e["actor"]) in {"alice", "bob"} for e in bundle["events"])
        assert result.charter_hash == acme.charter_hash()

    def test_a_forged_tenant_id_from_a_non_member_is_excluded_and_reported(self, tmp_path: Path) -> None:
        """A sibling writing our tenant id does not get into our slice."""
        audit_dir = tmp_path / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        acme = _charter(chain, "acme", ("alice",))

        _work_event(chain, tenant="acme", principal="alice", index=1)
        _work_event(chain, tenant="acme", principal="mallory", index=2)  # forged claim

        result = export_charter_slice(audit_dir, acme, since=SINCE, until=UNTIL, key=KEY, write=False)
        bundle = json.loads(result.export.bundle_bytes)

        principals = {e["details"].get("principal", e["actor"]) for e in bundle["events"]}
        assert "mallory" not in principals
        # Excluded, not silently dropped.
        assert result.excluded_principals == (("mallory", 1),)

    def test_negative_control_the_unkeyed_export_does_admit_the_forgery(self, tmp_path: Path) -> None:
        """The membership key is doing work, not decorating a filter that already passed.

        Without it, the same forged event lands in the slice - which is exactly
        the gap a free-form ``tenant_id`` leaves open.
        """
        audit_dir = tmp_path / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        acme = _charter(chain, "acme", ("alice",))
        _work_event(chain, tenant="acme", principal="mallory", index=2)

        unkeyed = export_tenant_slice(audit_dir, "acme", since=SINCE, until=UNTIL, key=KEY, write=False)
        principals = {e["details"].get("principal", e["actor"]) for e in json.loads(unkeyed.bundle_bytes)["events"]}
        assert "mallory" in principals

        keyed = export_charter_slice(audit_dir, acme, since=SINCE, until=UNTIL, key=KEY, write=False)
        keyed_principals = {
            e["details"].get("principal", e["actor"]) for e in json.loads(keyed.export.bundle_bytes)["events"]
        }
        assert "mallory" not in keyed_principals

    def test_the_slice_still_verifies_against_the_shared_head(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        acme = _charter(chain, "acme", ("alice", "bob"))
        for index in range(5):
            _work_event(chain, tenant="acme", principal="alice", index=index)
            _work_event(chain, tenant="globex", principal="carol", index=index)

        out = export_charter_slice(audit_dir, acme, since=SINCE, until=UNTIL, key=KEY, output_dir=tmp_path / "ev")
        assert out.export.bundle_path is not None
        verification = verify_tenant_slice(out.export.bundle_path, key=KEY)
        assert verification.ok, verification.errors
        assert chain.verify()[0] is True

    def test_slice_bytes_are_deterministic(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        acme = _charter(chain, "acme", ("alice",))
        for index in range(3):
            _work_event(chain, tenant="acme", principal="alice", index=index)

        first = export_charter_slice(audit_dir, acme, since=SINCE, until=UNTIL, key=KEY, write=False)
        second = export_charter_slice(audit_dir, acme, since=SINCE, until=UNTIL, key=KEY, write=False)
        assert first.export.bundle_bytes == second.export.bundle_bytes

    def test_summary_serializes(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        acme = _charter(chain, "acme", ("alice",))
        _work_event(chain, tenant="acme", principal="alice", index=1)
        summary = export_charter_slice(audit_dir, acme, since=SINCE, until=UNTIL, key=KEY, write=False).to_dict()
        json.dumps(summary)
        assert summary["members"] == ["alice"]


class TestCharterSlicePurityProperty:
    """AC3: over generated multi-tenant chains, a slice never carries a sibling."""

    @settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(
        rows=st.lists(
            st.tuples(st.sampled_from(TENANTS), st.sampled_from(PRINCIPALS)),
            min_size=1,
            max_size=25,
        ),
        member_flags=st.lists(st.booleans(), min_size=len(PRINCIPALS), max_size=len(PRINCIPALS)),
    )
    def test_no_sibling_events_in_a_charter_slice(
        self,
        tmp_path: Path,
        rows: list[tuple[str, str]],
        member_flags: list[bool],
    ) -> None:
        members = tuple(p for p, keep in zip(PRINCIPALS, member_flags, strict=True) if keep) or ("alice",)
        # Hypothesis reuses the function-scoped tmp_path across examples (and
        # replays cached ones), so each example needs its own chain rather than
        # appending to the previous example's log.
        audit_dir = Path(tempfile.mkdtemp(dir=tmp_path)) / "audit"
        chain = AuditChainStore(audit_dir, key=KEY)
        acme = _charter(chain, "acme", members)
        for index, (tenant, principal) in enumerate(rows):
            _work_event(chain, tenant=tenant, principal=principal, index=index)

        result = export_charter_slice(audit_dir, acme, since=SINCE, until=UNTIL, key=KEY, write=False)
        bundle = json.loads(result.export.bundle_bytes)
        allowed = charter_slice_members(acme)

        for event in bundle["events"]:
            assert event["details"]["tenant_id"] == "acme"
            assert event["details"].get("principal", event["actor"]) in allowed

        # Nothing that belonged was lost either: the admitted count equals the
        # work events the predicate accepts, plus the charter's own events
        # (all recorded by members[0], who is a member by construction).
        admitted_work = sum(
            1
            for tenant, principal in rows
            if event_belongs_to_charter(
                {"actor": "orchestrator", "details": {"principal": principal, "tenant_id": tenant}},
                acme,
            )
        )
        charter_rows = len(members) + 1
        assert bundle["event_count"] == admitted_work + charter_rows
