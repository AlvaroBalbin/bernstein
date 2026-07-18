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
    ActionRef,
    ApprovalCardV2,
    ImpactEstimate,
    RollbackPlan,
    build_card,
    canonical_card_bytes,
    card_hash,
    render_card_envelope,
    render_card_text,
)
from bernstein.core.approval.card_gate import (
    REFUSAL_REASON_ALREADY_SETTLED,
    REFUSAL_REASON_BEFORE_ISSUE,
    REFUSAL_REASON_CROSS_CONVERSATION,
    REFUSAL_REASON_CROSS_WORKTREE,
    REFUSAL_REASON_HASH_MISMATCH,
    REFUSAL_REASON_INVALID_DECISION,
    ApprovalCardAlreadySettled,
    ApprovalCardBindingMismatch,
    ApprovalCardClockSkew,
    ApprovalCardGate,
    ApprovalCardHashMismatch,
    ApprovalCardInvalidDecision,
)
from bernstein.core.approval.card_verify import verify_approval_cards
from bernstein.core.security.audit_chain import (
    EVENT_APPROVAL_CARD_ISSUED,
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


@pytest.mark.parametrize(
    ("pins", "resolve_kwargs", "reason"),
    [
        ({"worktree_id": "wt-a"}, {"worktree_id": ""}, REFUSAL_REASON_CROSS_WORKTREE),
        ({"thread_id": "C42"}, {"thread_id": ""}, REFUSAL_REASON_CROSS_CONVERSATION),
    ],
)
def test_empty_origin_cannot_bypass_a_pin(
    tmp_path: Path,
    pins: dict[str, str],
    resolve_kwargs: dict[str, str],
    reason: str,
) -> None:
    """Revert-checked: fails if the guard regains its ``and worktree_id`` clause.

    An absent origin must not disable the guard. The value the check exists to
    distrust is exactly the value that would switch it off.
    """
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card(), **pins)

    with pytest.raises(ApprovalCardBindingMismatch):
        gate.resolve(card_hash=issued.card_hash, decision="approve", now=1_100.0, **resolve_kwargs)

    assert chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED) == []
    assert _reasons(chain) == [reason]


def test_settlement_records_the_resolving_origin_not_the_issuing_one(tmp_path: Path) -> None:
    """Revert-checked: fails if the event records ``issued.worktree_id`` again.

    The chain must attribute a decision to where it came from. Recording the
    issuing origin would make the chain attest that the legitimate worktree and
    conversation decided something they did not.
    """
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    # Unpinned card, so a foreign origin is allowed through and must be recorded.
    issued = gate.issue(_card())
    gate.resolve(
        card_hash=issued.card_hash,
        decision="approve",
        worktree_id="wt-EVIL",
        thread_id="C-EVIL",
        now=1_100.0,
    )

    details = chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED)[0].details
    assert details["worktree_id"] == "wt-EVIL"
    assert details["thread_id"] == "C-EVIL"
    # The issuing origin is preserved under its own keys, not conflated.
    assert details["issued_worktree_id"] == ""
    assert details["issued_thread_id"] == ""


def test_settlement_keeps_issuing_origin_alongside_the_resolver(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card(), worktree_id="wt-a", thread_id="C42")
    gate.resolve(
        card_hash=issued.card_hash,
        decision="approve",
        worktree_id="wt-a",
        thread_id="C42",
        now=1_100.0,
    )

    details = chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED)[0].details
    assert details["worktree_id"] == "wt-a"
    assert details["issued_worktree_id"] == "wt-a"
    assert details["thread_id"] == "C42"
    assert details["issued_thread_id"] == "C42"


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


class _FailFirstAppendChain:
    """A chain store whose *first* append fails, modelling a durability fault.

    Only the first append fails so the later refusal path still works. That
    matters: a chain that fails every append would let the test pass on an
    ``OSError`` raised from the refusal write, which is also what the
    *unhardened* ordering raises, and the assertion would no longer
    discriminate between the two.
    """

    def __init__(self, real: AuditChainStore) -> None:
        self._real = real
        self.attempts = 0

    def log_with_prev_digest(self, **kwargs: Any) -> Any:
        self.attempts += 1
        if self.attempts == 1:
            msg = "chain append failed"
            raise OSError(msg)
        return self._real.log_with_prev_digest(**kwargs)

    def query(self, **kwargs: Any) -> Any:
        return self._real.query(**kwargs)


def test_card_is_not_exposed_when_the_issued_event_fails_to_persist(tmp_path: Path) -> None:
    """Revert-checked: fails if the chain append is moved back after the memory insert.

    Under the unhardened ordering the card is in ``_issued`` before the failing
    append, so the resolve below finds it, passes every guard and settles a card
    that never reached the chain: no ``ApprovalCardHashMismatch`` is raised and
    a resolved event appears.
    """
    real = _chain(tmp_path)
    chain = _FailFirstAppendChain(real)
    gate = ApprovalCardGate(chain)  # type: ignore[arg-type]
    card = _card()

    with pytest.raises(OSError, match="chain append failed"):
        gate.issue(card)

    # An approval that is not on the chain must not be settleable from memory.
    # The refusal itself is chain-recorded, so this asserts the specific
    # unknown-card refusal rather than tolerating any error.
    with pytest.raises(ApprovalCardHashMismatch):
        gate.resolve(card_hash=card_hash(card), decision="approve", now=1_100.0)

    assert real.query(event_type=EVENT_APPROVAL_CARD_RESOLVED) == []
    assert _reasons(real) == [REFUSAL_REASON_HASH_MISMATCH]


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


def test_integer_timestamps_widen_so_the_hash_stays_stable() -> None:
    """An int timestamp must not produce different canonical bytes than a float.

    ``json.dumps`` emits ``1000`` for an int and ``1000.0`` for a float, so
    without widening, the same instant would hash to two different cards.
    """
    as_int = build_card(
        approval_id="ap-1",
        tool_name="Edit",
        tool_args={"file_path": "a.py"},
        reasoning="r",
        created_at=1_000,
        ttl_seconds=600,
    )
    as_float = build_card(
        approval_id="ap-1",
        tool_name="Edit",
        tool_args={"file_path": "a.py"},
        reasoning="r",
        created_at=1_000.0,
        ttl_seconds=600.0,
    )
    assert canonical_card_bytes(as_int) == canonical_card_bytes(as_float)
    assert card_hash(as_int) == card_hash(as_float)


@pytest.mark.parametrize("bad", ["1000.0", None, True, {"v": 1}, []])
def test_from_dict_rejects_non_numeric_timestamps(bad: object) -> None:
    """A stored envelope with a non-numeric timestamp is rejected, not coerced."""
    payload = _card().to_dict()
    payload["created_at"] = bad
    with pytest.raises(ValueError, match="finite number"):
        ApprovalCardV2.from_dict(payload)


def test_verifier_rejects_non_numeric_resolved_at(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    digest = _issue_via_gate(chain, _card())
    _raw_resolve(chain, digest, "1100.0")

    result = verify_approval_cards(tmp_path / "audit", key=_KEY)
    assert not result.ok
    assert any("resolved_at" in e for e in result.errors)


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


def test_render_card_envelope_rehashes_to_the_card_hash() -> None:
    card = build_card(
        approval_id="ap-precision",
        tool_name="Edit",
        tool_args={"file_path": "src/app.py"},
        reasoning="Precision matters.",
        created_at=1_000.123_456_789,
        ttl_seconds=600.987_654_321,
    )
    rendered = render_card_envelope(card)
    payload = json.loads(rendered.splitlines()[0])
    # The canonical envelope re-hashes to the committed hash, so a verifier can
    # confirm it without trusting the chat client.
    assert card_hash(ApprovalCardV2.from_dict(payload)) == card_hash(card)
    assert f"Card hash: {card_hash(card)}" in rendered


#: Shortest body cap across the chat drivers. Discord rejects `content` over
#: 2000 characters and Slack caps a Block Kit section's text at 3000; neither
#: driver chunks, so the card body has to fit as-is. Drivers prepend a title
#: (``f"{title}\n\n{body}"``), so the body is held to a margin below the cap.
_DISCORD_BODY_CAP = 2000
_TITLE_ALLOWANCE = 200


@pytest.mark.parametrize("depth", [1, 40, 160, 1_000])
def test_chat_body_stays_within_the_tightest_driver_cap(depth: int) -> None:
    """Revert-checked: fails if the canonical envelope is inlined, or the path unbounded.

    The card that matters most is the one with the widest blast radius, which is
    also the longest. An oversized body is not truncated by any driver, it fails
    to deliver, so the operator never sees the approval at all. The bound must
    therefore hold for adversarial input, not just typical input.
    """
    worst = build_card(
        approval_id="ap-worst",
        tool_name="Write",
        tool_args={"file_path": "/srv/" + "deeply/" * depth + "file.py", "content": "y" * 200},
        reasoning="q" * 700,
        created_at=1_000.0,
        ttl_seconds=600.0,
    )
    body = render_card_text(worst)
    assert len(body.encode("utf-8")) < _DISCORD_BODY_CAP - _TITLE_ALLOWANCE
    # Completeness is not traded away for size: every hashed field is still
    # present and round-trippable in the delivered body.
    assert worst.approval_id in body
    assert repr(worst.not_after) in body
    assert card_hash(worst) in body


def test_render_size_does_not_grow_with_unbounded_arguments() -> None:
    """A card's rendered size must not scale with attacker-controlled argument length."""

    def render_len(path_depth: int, command_len: int) -> int:
        card = build_card(
            approval_id="ap",
            tool_name="Write",
            tool_args={"file_path": "/srv/" + "deeply/" * path_depth + "f.py", "content": "y" * command_len},
            reasoning="q" * 700,
            created_at=1_000.0,
            ttl_seconds=600.0,
        )
        return len(render_card_text(card).encode("utf-8"))

    assert render_len(40, 200) == render_len(4_000, 20_000)


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


def test_verifier_rejects_two_settlements_of_one_card(tmp_path: Path) -> None:
    """Revert-checked: fails without the ``settled`` set in the verifier pass.

    Exactly-once is the headline invariant, so it has to be reconstructable from
    the chain and not merely enforced live by the gate. A chain written by an
    unpatched build or a second writer carries the double settlement as
    evidence.
    """
    chain = _chain(tmp_path)
    digest = _issue_via_gate(chain, _card())
    _raw_resolve(chain, digest, 1_100.0)
    _raw_resolve(chain, digest, 1_200.0)

    result = verify_approval_cards(tmp_path / "audit", key=_KEY)
    assert not result.ok
    assert any("more than once" in e for e in result.errors)
    assert result.reconstructed_count == 1


def test_gate_never_writes_a_settlement_its_own_verifier_rejects(tmp_path: Path) -> None:
    """Revert-checked: fails without ``_guard_clock``.

    The verifier requires ``created_at <= resolved_at``. The audit log is
    append-only, so a settlement below that bound would fail verification
    permanently with no remediation. The gate must refuse instead of writing it.
    """
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card(created_at=1_000.0, ttl=600.0))

    with pytest.raises(ApprovalCardClockSkew):
        gate.resolve(card_hash=issued.card_hash, decision="approve", now=900.0)

    assert chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED) == []
    assert _reasons(chain) == [REFUSAL_REASON_BEFORE_ISSUE]
    # The chain the gate did write still verifies clean.
    assert verify_approval_cards(tmp_path / "audit", key=_KEY).ok


def test_resolve_at_exactly_created_at_is_allowed(tmp_path: Path) -> None:
    """The lower bound is inclusive, matching the verifier's ``created_at <=``."""
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card(created_at=1_000.0, ttl=600.0))
    gate.resolve(card_hash=issued.card_hash, decision="approve", now=1_000.0)

    assert len(chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED)) == 1
    assert verify_approval_cards(tmp_path / "audit", key=_KEY).ok


# ---------------------------------------------------------------------------
# Storage round-trip: the hash must commit to what is persisted
# ---------------------------------------------------------------------------


def _variant(**overrides: Any) -> ApprovalCardV2:
    """Return a card with one field replaced by an off-normal-form value."""
    base = _card()
    fields: dict[str, Any] = {
        "approval_id": base.approval_id,
        "action": base.action,
        "reasoning": base.reasoning,
        "impact": base.impact,
        "rollback": base.rollback,
        "created_at": base.created_at,
        "not_after": base.not_after,
    }
    fields.update(overrides)
    return ApprovalCardV2(**fields)


def _off_normal_cards() -> list[tuple[str, ApprovalCardV2]]:
    """Cards whose in-memory field types differ from their persisted types.

    Every one of these is constructible today. ``score`` is the live case:
    :func:`score_change` computes ``min(1.0, soft + files)``, which returns a
    plain ``int`` when both components are ``0``, and ``round(0, 4)`` keeps it
    an ``int``.
    """
    return [
        ("int score", _variant(impact=ImpactEstimate(0, False, "r", ()))),
        ("negative zero score", _variant(impact=ImpactEstimate(-0.0, False, "r", ()))),
        ("int approval_id", _variant(approval_id=123)),  # type: ignore[arg-type]
        ("list fired_detectors", _variant(impact=ImpactEstimate(0.5, False, "r", ["a"]))),  # type: ignore[arg-type]
        ("non-string fired_detectors", _variant(impact=ImpactEstimate(0.5, False, "r", (1, 2)))),  # type: ignore[arg-type]
        ("int timestamps", _variant(created_at=1_000, not_after=1_600)),  # type: ignore[arg-type]
        ("non-string rollback fields", _variant(rollback=RollbackPlan(procedure=7, irreversible=1))),  # type: ignore[arg-type]
        ("non-string action fields", _variant(action=ActionRef(tool_name=5, args_digest=9))),  # type: ignore[arg-type]
    ]


@pytest.mark.parametrize(("label", "card"), _off_normal_cards(), ids=lambda v: v if isinstance(v, str) else "")
def test_hash_survives_the_real_storage_round_trip(tmp_path: Path, label: str, card: ApprovalCardV2) -> None:
    """Revert-checked: fails if ``to_dict`` stops emitting the persisted normal form.

    Deliberately drives the production writer and reader rather than hashing an
    in-memory object, because an in-memory comparison cannot see a lossy step
    between the object and the stored bytes. JSON does not preserve Python's
    numeric types, so a hash taken over un-normalised in-memory values does not
    match one recomputed from storage, and an honest card becomes unresolvable
    after a restart and fails ``audit verify`` forever on an append-only chain.
    """
    del label
    chain = _chain(tmp_path)
    issued = ApprovalCardGate(chain).issue(card, worktree_id="wt-a", thread_id="C42")

    # Recompute from the bytes actually on disk, not from the object above.
    stored = [e.details for e in chain.query(event_type=EVENT_APPROVAL_CARD_ISSUED) if e.details.get("card_hash")][-1]
    persisted: dict[str, Any] = dict(stored["envelope"])
    assert card_hash(ApprovalCardV2.from_dict(persisted)) == str(stored["card_hash"])

    # The reader path a restart takes must still rehydrate and settle the card.
    restarted = ApprovalCardGate(_chain(tmp_path))
    restarted.resolve(
        card_hash=issued.card_hash,
        decision="approve",
        worktree_id="wt-a",
        thread_id="C42",
        now=card.created_at + 1.0,
    )
    assert verify_approval_cards(tmp_path / "audit", key=_KEY).ok


@pytest.mark.parametrize(("label", "card"), _off_normal_cards(), ids=lambda v: v if isinstance(v, str) else "")
def test_to_dict_is_a_fixed_point_of_the_round_trip(label: str, card: ApprovalCardV2) -> None:
    """``to_dict`` must already be in the form ``from_dict`` rebuilds."""
    del label
    once = card.to_dict()
    twice = ApprovalCardV2.from_dict(json.loads(json.dumps(once))).to_dict()
    assert once == twice
    assert canonical_card_bytes(card) == canonical_card_bytes(ApprovalCardV2.from_dict(once))


def test_verifier_accepts_a_well_formed_pair(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    gate = ApprovalCardGate(chain)
    issued = gate.issue(_card(created_at=1_000.0, ttl=600.0))
    gate.resolve(card_hash=issued.card_hash, decision="approve", now=1_100.0)

    result = verify_approval_cards(tmp_path / "audit", key=_KEY)
    assert result.ok, result.errors
    assert result.reconstructed_count == 1
