"""request_id / card_hash binding for routed elicitations (issue #2651).

The router previously forwarded whatever ``(request_id, card_hash)`` pair the
caller supplied: the gate checked the hash and the handler checked the request
id, but nothing checked that the two named the *same* prompt. An operator
approving card A could therefore answer elicitation B, and a gate settlement
could commit while the handler leg silently did nothing.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from bernstein.core.approval.card_gate import ApprovalCardGate
from bernstein.core.approval.card_inbound import (
    ApprovalCardRequestMismatch,
    ElicitationApprovalRouter,
)
from bernstein.core.protocols.mcp.mcp_elicitation import (
    ElicitationHandler,
    ElicitationRequest,
    ElicitationStatus,
)
from bernstein.core.security.audit_chain import (
    EVENT_APPROVAL_CARD_RESOLVED,
    AuditChainStore,
)

if TYPE_CHECKING:
    from pathlib import Path

_KEY = b"deterministic-test-key-2651"


def _chain(tmp_path: Path) -> AuditChainStore:
    return AuditChainStore(tmp_path / "audit", key=_KEY)


def _router(tmp_path: Path) -> tuple[ElicitationApprovalRouter, ElicitationHandler, AuditChainStore]:
    chain = _chain(tmp_path)
    handler = ElicitationHandler()
    router = ElicitationApprovalRouter(
        handler=handler,
        gate=ApprovalCardGate(chain),
        thread_id="C42",
        worktree_id="wt-a",
    )
    return router, handler, chain


def _request(request_id: str) -> ElicitationRequest:
    return ElicitationRequest(
        id=request_id,
        server_name="github",
        message=f"Provide a value for {request_id}",
        request_type="input",
    )


def test_mismatched_request_id_and_card_hash_is_refused(tmp_path: Path) -> None:
    router, handler, chain = _router(tmp_path)
    first = asyncio.run(router.route(_request("e1"), now=1_000.0))
    second = asyncio.run(router.route(_request("e2"), now=1_000.0))
    assert first is not None
    assert second is not None
    assert first.card_hash != second.card_hash

    # Approving card e2 while naming request e1 must not settle either.
    with pytest.raises(ApprovalCardRequestMismatch):
        router.resolve(request_id="e1", card_hash=second.card_hash, decision="approve", now=1_100.0)

    assert chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED) == []
    assert {r.id for r in handler.get_pending()} == {"e1", "e2"}


def test_unknown_request_id_is_refused_before_the_gate_commits(tmp_path: Path) -> None:
    router, _handler, chain = _router(tmp_path)
    issued = asyncio.run(router.route(_request("e1"), now=1_000.0))
    assert issued is not None

    with pytest.raises(ApprovalCardRequestMismatch):
        router.resolve(request_id="never-issued", card_hash=issued.card_hash, decision="approve", now=1_100.0)

    # The gate leg must not have committed for a pair it could not bind.
    assert chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED) == []


def test_handler_leg_is_prechecked_so_both_legs_commit_together(tmp_path: Path) -> None:
    router, handler, chain = _router(tmp_path)
    issued = asyncio.run(router.route(_request("e1"), now=1_000.0))
    assert issued is not None

    # Drain the handler behind the router's back: the handler leg can no longer
    # commit, so the gate leg must not commit either.
    assert handler.resolve("e1", "approve") is not None

    with pytest.raises(ApprovalCardRequestMismatch):
        router.resolve(request_id="e1", card_hash=issued.card_hash, decision="approve", now=1_100.0)

    assert chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED) == []


def test_matching_pair_settles_both_legs(tmp_path: Path) -> None:
    router, _handler, chain = _router(tmp_path)
    issued = asyncio.run(router.route(_request("e1"), now=1_000.0))
    assert issued is not None

    settled, resolved = router.resolve(request_id="e1", card_hash=issued.card_hash, decision="approve", now=1_100.0)
    assert settled.card_hash == issued.card_hash
    assert resolved is not None
    assert resolved.status is ElicitationStatus.USER_RESOLVED
    assert len(chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED)) == 1


def test_binding_is_consumed_so_a_replayed_pair_is_refused(tmp_path: Path) -> None:
    router, _handler, chain = _router(tmp_path)
    issued = asyncio.run(router.route(_request("e1"), now=1_000.0))
    assert issued is not None

    router.resolve(request_id="e1", card_hash=issued.card_hash, decision="approve", now=1_100.0)

    with pytest.raises(ApprovalCardRequestMismatch):
        router.resolve(request_id="e1", card_hash=issued.card_hash, decision="approve", now=1_200.0)

    assert len(chain.query(event_type=EVENT_APPROVAL_CARD_RESOLVED)) == 1
