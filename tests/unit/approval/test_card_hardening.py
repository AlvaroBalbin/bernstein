"""Hardening regressions for approval card v2 (issue #2651).

Every test here pins one defect that made a privileged approval replayable,
forgeable, or unverifiable:

* resolution was non-terminal, so one issued card could be settled repeatedly
  and a restart reopened an already-resolved card (the replay hole),
* the decision value was never validated against the allowed set,
* a pinned card could be settled from a foreign worktree or conversation,
* the issued card was exposed in memory before its event reached the chain,
* ``request_id`` was not bound to ``card_hash`` before the gate ran,
* the offline verifier accepted absent / zero / negative / NaN ``resolved_at``
  and a resolve recorded before its issue,
* non-finite timestamps defeated chain-side expiry and emitted invalid JSON,
* ``render_card_text`` dropped hashed fields, so the displayed text was not a
  faithful projection of what the operator's echo committed to.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest

from bernstein.core.approval.card import (
    ApprovalCardV2,
    build_card,
    canonical_card_bytes,
    card_hash,
    render_card_text,
)
from bernstein.core.approval.card_gate import (
    REFUSAL_REASON_ALREADY_SETTLED,
    REFUSAL_REASON_CROSS_CONVERSATION,
    REFUSAL_REASON_CROSS_WORKTREE,
    REFUSAL_REASON_INVALID_DECISION,
    ApprovalCardAlreadySettled,
    ApprovalCardBindingMismatch,
    ApprovalCardGate,
    ApprovalCardHashMismatch,
    ApprovalCardInvalidDecision,
)
from bernstein.core.approval.card_verify import verify_approval_cards
from bernstein.core.security.audit_chain import (
    EVENT_APPROVAL_CARD_REFUSED,
    EVENT_APPROVAL_CARD_RESOLVED,
    AuditChainStore,
)

_KEY = b"deterministic-test-key-2651"


def _chain(tmp_path: Path) -> AuditChainStore:
    return AuditChainStore(tmp_path / "audit", key=_KEY)


def _card(*, approval_id: str = "ap-1", created_at: float = 1_000.0, ttl: float = 600.0) -> ApprovalCardV2:
    return build_card(
        approval_id=approval_id,
        tool_name="Edit",
        tool_args={"file_path": "src/app.py", "new_string": "x = 1"},
        reasoning="Add a constant used by the new endpoint.",
        created_at=created_at,
        ttl_seconds=ttl,
    )


def _reasons(chain: AuditChainStore) -> list[str]:
    return [str(e.details.get("reason", "")) for e in chain.query(event_type=EVENT_APPROVAL_CARD_REFUSED)]


# ---------------------------------------------------------------------------
# Terminality: one issued card settles exactly once (critical)
# ---------------------------------------------------------------------------


def test_second_resolve_of_same_hash_is_refused(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card())

    gate.resolve(card_hash=issued.card_hash, decision="approve", approver="U7", now=1_100.0)

    with pytest.raises(ApprovalCardAlreadySettled):
        gate.resolve(card_hash=issued.card_hash, decision="approve", approver="U7", now=1_200.0)

    # Exactly one settlement reached the chain; the replay is recorded as a refusal.
    assert len(chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED)) == 1
    assert _reasons(chain) == [REFUSAL_REASON_ALREADY_SETTLED]


def test_resolved_card_is_not_reopened_after_restart(tmp_path: Path) -> None:
    """The replay proof: a fresh process must replay RESOLVED, not only ISSUED."""
    chain1 = _chain(tmp_path)
    gate1 = ApprovalCardGate(chain1)
    issued = gate1.issue(_card(created_at=1_000.0, ttl=600.0))
    gate1.resolve(card_hash=issued.card_hash, decision="approve", approver="U7", now=1_100.0)

    # A fresh gate over a fresh store on the same audit dir models a restart:
    # it holds no in-memory state and must rebuild the settled set from the chain.
    chain2 = _chain(tmp_path)
    gate2 = ApprovalCardGate(chain2)
    with pytest.raises(ApprovalCardAlreadySettled):
        gate2.resolve(card_hash=issued.card_hash, decision="approve", approver="U7", now=1_200.0)

    # Still exactly one settlement across both processes.
    assert len(chain2.query(event_type=EVENT_APPROVAL_CARD_RESOLVED)) == 1
    assert REFUSAL_REASON_ALREADY_SETTLED in _reasons(chain2)


def test_expired_refusal_is_terminal_across_restart(tmp_path: Path) -> None:
    chain1 = _chain(tmp_path)
    gate1 = ApprovalCardGate(chain1)
    issued = gate1.issue(_card(created_at=1_000.0, ttl=600.0))
    with pytest.raises(Exception, match="expired"):
        gate1.resolve(card_hash=issued.card_hash, decision="approve", now=1_700.0)

    chain2 = _chain(tmp_path)
    gate2 = ApprovalCardGate(chain2)
    # Even rewinding the injected clock cannot revive a card the chain saw expire.
    with pytest.raises(ApprovalCardAlreadySettled):
        gate2.resolve(card_hash=issued.card_hash, decision="approve", now=1_100.0)
    assert chain2.query(event_type=EVENT_APPROVAL_CARD_RESOLVED) == []


def test_rejected_attempt_does_not_burn_a_pending_card(tmp_path: Path) -> None:
    """A refused *attempt* must not deny the legitimate operator their decision."""
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card(), worktree_id="wt-a")

    with pytest.raises(ApprovalCardBindingMismatch):
        gate.resolve(card_hash=issued.card_hash, decision="approve", worktree_id="wt-evil", now=1_100.0)

    # The card is still settleable from its own worktree.
    resolved = gate.resolve(card_hash=issued.card_hash, decision="approve", worktree_id="wt-a", now=1_150.0)
    assert resolved.card_hash == issued.card_hash


# ---------------------------------------------------------------------------
# Decision validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("decision", ["", "APPROVE", "approve_all", "yes", "maybe", "reject "])
def test_invalid_decision_is_refused(tmp_path: Path, decision: str) -> None:
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card())

    with pytest.raises(ApprovalCardInvalidDecision):
        gate.resolve(card_hash=issued.card_hash, decision=decision, now=1_100.0)

    assert chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED) == []
    assert _reasons(chain) == [REFUSAL_REASON_INVALID_DECISION]


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_allowed_decisions_settle(tmp_path: Path, decision: str) -> None:
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card())
    gate.resolve(card_hash=issued.card_hash, decision=decision, now=1_100.0)
    events = chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED)
    assert [e.details["decision"] for e in events] == [decision]


# ---------------------------------------------------------------------------
# Binding: worktree and conversation pinning
# ---------------------------------------------------------------------------


def test_cross_worktree_resolve_is_refused(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card(), worktree_id="wt-a")

    with pytest.raises(ApprovalCardBindingMismatch):
        gate.resolve(card_hash=issued.card_hash, decision="approve", worktree_id="wt-b", now=1_100.0)

    assert chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED) == []
    assert _reasons(chain) == [REFUSAL_REASON_CROSS_WORKTREE]


def test_cross_conversation_resolve_is_refused(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card(), thread_id="C42")

    with pytest.raises(ApprovalCardBindingMismatch):
        gate.resolve(card_hash=issued.card_hash, decision="approve", thread_id="C99", now=1_100.0)

    assert chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED) == []
    assert _reasons(chain) == [REFUSAL_REASON_CROSS_CONVERSATION]


def test_matching_conversation_resolves(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card(), worktree_id="wt-a", thread_id="C42")
    resolved = gate.resolve(
        card_hash=issued.card_hash,
        decision="approve",
        worktree_id="wt-a",
        thread_id="C42",
        now=1_100.0,
    )
    assert resolved.thread_id == "C42"


def test_binding_survives_restart(tmp_path: Path) -> None:
    chain1 = _chain(tmp_path)
    issued = ApprovalCardGate(chain1).issue(_card(), worktree_id="wt-a", thread_id="C42")

    chain2 = _chain(tmp_path)
    gate2 = ApprovalCardGate(chain2)
    with pytest.raises(ApprovalCardBindingMismatch):
        gate2.resolve(card_hash=issued.card_hash, decision="approve", thread_id="C99", now=1_100.0)


# ---------------------------------------------------------------------------
# Issue ordering: chain first, memory second
# ---------------------------------------------------------------------------


class _FailingChain:
    """A chain store whose append always fails, modelling a durability fault."""

    def __init__(self, real: AuditChainStore) -> None:
        self._real = real
        self.attempts = 0

    def log_with_prev_digest(self, **kwargs: Any) -> Any:
        self.attempts += 1
        msg = "chain append failed"
        raise OSError(msg)

    def query(self, **kwargs: Any) -> Any:
        return self._real.query(**kwargs)


def test_card_is_not_exposed_when_the_issued_event_fails_to_persist(tmp_path: Path) -> None:
    chain = _FailingChain(_chain(tmp_path))
    gate = ApprovalCardGate(chain)  # type: ignore[arg-type]
    card = _card()

    with pytest.raises(OSError, match="chain append failed"):
        gate.issue(card)

    # The card never became resolvable: an approval that is not on the chain
    # must not be settleable from memory.
    with pytest.raises((ApprovalCardHashMismatch, OSError)):
        gate.resolve(card_hash=card_hash(card), decision="approve", now=1_100.0)


# ---------------------------------------------------------------------------
# Non-finite timestamps and TTLs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_build_card_rejects_non_finite_ttl(bad: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        build_card(
            approval_id="ap-1",
            tool_name="Edit",
            tool_args={"file_path": "a.py"},
            reasoning="r",
            created_at=1_000.0,
            ttl_seconds=bad,
        )


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_build_card_rejects_non_finite_created_at(bad: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        build_card(
            approval_id="ap-1",
            tool_name="Edit",
            tool_args={"file_path": "a.py"},
            reasoning="r",
            created_at=bad,
            ttl_seconds=600.0,
        )


def test_build_card_rejects_negative_ttl() -> None:
    with pytest.raises(ValueError, match="ttl_seconds"):
        build_card(
            approval_id="ap-1",
            tool_name="Edit",
            tool_args={"file_path": "a.py"},
            reasoning="r",
            created_at=1_000.0,
            ttl_seconds=-1.0,
        )


@pytest.mark.parametrize("field", ["created_at", "not_after"])
def test_from_dict_rejects_non_finite_timestamps(field: str) -> None:
    payload = _card().to_dict()
    payload[field] = math.nan
    with pytest.raises(ValueError, match="finite"):
        ApprovalCardV2.from_dict(payload)


def test_canonical_bytes_reject_non_finite_values() -> None:
    """A NaN anywhere in the envelope must not emit invalid JSON."""
    card = _card()
    poisoned = ApprovalCardV2(
        approval_id=card.approval_id,
        action=card.action,
        reasoning=card.reasoning,
        impact=type(card.impact)(
            score=math.nan,
            hard_one_way=card.impact.hard_one_way,
            rationale=card.impact.rationale,
            fired_detectors=card.impact.fired_detectors,
        ),
        rollback=card.rollback,
        created_at=card.created_at,
        not_after=card.not_after,
    )
    with pytest.raises(ValueError, match="[Nn]a[Nn]|finite|not JSON compliant"):
        canonical_card_bytes(poisoned)


def test_nan_not_after_cannot_defeat_chain_side_expiry() -> None:
    """``now >= nan`` is False, so a NaN not_after would make a card immortal."""
    payload = _card().to_dict()
    payload["not_after"] = math.nan
    with pytest.raises(ValueError, match="finite"):
        ApprovalCardV2.from_dict(payload)


# ---------------------------------------------------------------------------
# Verbatim rendering: no lossy projection of hashed fields
# ---------------------------------------------------------------------------


def test_render_includes_the_canonical_envelope_that_rehashes_to_the_card_hash() -> None:
    card = build_card(
        approval_id="ap-precision",
        tool_name="Edit",
        tool_args={"file_path": "src/app.py"},
        reasoning="Precision matters.",
        created_at=1_000.123_456_789,
        ttl_seconds=600.987_654_321,
    )
    text = render_card_text(card)

    envelope_line = next(line for line in text.splitlines() if line.startswith("Canonical envelope:"))
    payload = json.loads(envelope_line.split(": ", 1)[1])
    # The displayed envelope re-hashes to the displayed hash: the operator can
    # verify the message equals the committed record without trusting the client.
    assert card_hash(ApprovalCardV2.from_dict(payload)) == card_hash(card)
    assert f"Card hash: {card_hash(card)}" in text


def test_render_does_not_round_away_hashed_precision() -> None:
    card = build_card(
        approval_id="ap-precision",
        tool_name="Edit",
        tool_args={"file_path": "src/app.py"},
        reasoning="Precision matters.",
        created_at=1_000.123_456_789,
        ttl_seconds=600.987_654_321,
    )
    text = render_card_text(card)
    assert repr(card.not_after) in text
    assert repr(card.created_at) in text
    assert repr(card.impact.score) in text


def test_render_surfaces_every_hashed_field() -> None:
    card = _card(approval_id="ap-visible")
    text = render_card_text(card)
    assert card.approval_id in text
    assert card.card_version in text
    assert card.action.tool_name in text
    assert card.action.args_digest in text
    assert card.reasoning in text
    assert card.impact.rationale in text
    assert card.rollback.procedure in text


# ---------------------------------------------------------------------------
# Offline verifier
# ---------------------------------------------------------------------------


def _issue_via_gate(chain: AuditChainStore, card: ApprovalCardV2) -> str:
    return ApprovalCardGate(chain).issue(card).card_hash


def _raw_resolve(chain: AuditChainStore, digest: str, resolved_at: Any) -> None:
    chain.log_with_prev_digest(
        event_type=EVENT_APPROVAL_CARD_RESOLVED,
        actor="operator",
        resource_type="approval_card",
        resource_id=digest,
        details={"card_hash": digest, "decision": "approve", "resolved_at": resolved_at},
    )


@pytest.mark.parametrize("bad", [0.0, -1.0, -1e18])
def test_verifier_rejects_non_positive_resolved_at(tmp_path: Path, bad: float) -> None:
    chain = _chain(tmp_path)
    digest = _issue_via_gate(chain, _card())
    _raw_resolve(chain, digest, bad)

    result = verify_approval_cards(tmp_path / "audit", key=_KEY)
    assert not result.ok
    assert any("resolved_at" in e for e in result.errors)


def test_verifier_rejects_missing_resolved_at(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    digest = _issue_via_gate(chain, _card())
    chain.log_with_prev_digest(
        event_type=EVENT_APPROVAL_CARD_RESOLVED,
        actor="operator",
        resource_type="approval_card",
        resource_id=digest,
        details={"card_hash": digest, "decision": "approve"},
    )

    result = verify_approval_cards(tmp_path / "audit", key=_KEY)
    assert not result.ok
    assert any("resolved_at" in e for e in result.errors)


def test_verifier_rejects_non_finite_resolved_at(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    digest = _issue_via_gate(chain, _card())
    # NaN survives a JSON round-trip through python's tolerant decoder.
    _raw_resolve(chain, digest, float("nan"))

    result = verify_approval_cards(tmp_path / "audit", key=_KEY)
    assert not result.ok
    assert any("resolved_at" in e for e in result.errors)


def test_verifier_rejects_resolve_recorded_before_its_issue(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    card = _card()
    digest = card_hash(card)
    # The resolve lands on the chain first; the issue is backfilled after.
    _raw_resolve(chain, digest, 1_100.0)
    _issue_via_gate(chain, card)

    result = verify_approval_cards(tmp_path / "audit", key=_KEY)
    assert not result.ok
    assert any("before" in e or "no matching issued" in e for e in result.errors)


def test_verifier_rejects_resolved_at_before_created_at(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    digest = _issue_via_gate(chain, _card(created_at=1_000.0, ttl=600.0))
    _raw_resolve(chain, digest, 900.0)

    result = verify_approval_cards(tmp_path / "audit", key=_KEY)
    assert not result.ok
    assert any("created_at" in e for e in result.errors)


def test_verifier_accepts_a_well_formed_pair(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card(created_at=1_000.0, ttl=600.0))
    gate.resolve(card_hash=issued.card_hash, decision="approve", now=1_100.0)

    result = verify_approval_cards(tmp_path / "audit", key=_KEY)
    assert result.ok, result.errors
    assert result.reconstructed_count == 1
