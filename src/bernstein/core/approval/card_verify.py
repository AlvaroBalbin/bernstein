"""Offline verification of resolved approval cards (issue #2511).

A resolved approval must be re-checkable offline from the audit chain alone.
:func:`verify_approval_cards` walks the ``chat.approval_card.issued`` and
``chat.approval_card.resolved`` events and proves, for every resolved card:

* the stored envelope still hashes to the recorded ``card_hash`` -- any
  post-hoc mutation of the stored envelope is detected, because a mutated
  envelope no longer hashes to the committed value,
* the decision echoed the issued envelope's ``card_hash`` (the operator
  decided against the fields that were hashed, not a divergent view),
* the issue event was recorded *before* the resolution that settles it, so a
  settlement cannot be legitimised by an issue backfilled afterwards,
* the decision carries a usable timestamp and landed inside the envelope's
  window: ``created_at <= resolved_at < not_after``, with ``resolved_at``
  required to be finite and strictly positive. Expiry is reconstructable, not
  merely enforced live.

This is orthogonal to the HMAC chain check: the HMAC chain proves the event
bytes were not altered; this check proves the *card semantics* hold across the
issue/resolve pair. Together they make the card a decision record whose whole
context is verifiable after the fact.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from bernstein.core.approval.card import ApprovalCardV2, card_hash
from bernstein.core.security.audit import AuditLog
from bernstein.core.security.audit_chain import (
    EVENT_APPROVAL_CARD_ISSUED,
    EVENT_APPROVAL_CARD_RESOLVED,
)

if TYPE_CHECKING:
    from pathlib import Path

    from bernstein.core.security.audit import AuditEvent

__all__ = ["ApprovalCardVerifyResult", "verify_approval_cards"]


@dataclass(frozen=True)
class ApprovalCardVerifyResult:
    """Outcome of :func:`verify_approval_cards`."""

    ok: bool
    errors: list[str]
    issued_count: int = 0
    resolved_count: int = 0
    reconstructed_count: int = 0


def _admit_issue(event: AuditEvent, issued: dict[str, ApprovalCardV2], errors: list[str]) -> None:
    """Admit one issue event into *issued*, flagging mutation or a bad envelope."""
    details: dict[str, Any] = event.details
    stored_hash = str(details.get("card_hash", ""))
    envelope_any: Any = details.get("envelope")
    if not stored_hash or not isinstance(envelope_any, dict):
        errors.append(f"approval card issue event {event.resource_id!r} is missing card_hash or envelope")
        return
    try:
        card = ApprovalCardV2.from_dict(cast("dict[str, Any]", envelope_any))
    except (TypeError, ValueError) as exc:
        errors.append(f"approval card {stored_hash!r} issue envelope is not a valid card ({exc})")
        return
    recomputed = card_hash(card)
    if recomputed != stored_hash:
        errors.append(
            f"approval card {stored_hash!r} envelope was mutated after issue "
            f"(stored hash {stored_hash[:16]}, envelope hashes to {recomputed[:16]})",
        )
        return
    issued[stored_hash] = card


def _resolved_at(details: dict[str, Any]) -> float | None:
    """Return a finite, strictly positive ``resolved_at``, or ``None``.

    Anything else -- absent, non-numeric, zero, negative, or non-finite -- is
    rejected by the caller. Zero and negative readings are not merely odd: the
    previous check short-circuited on a falsy ``resolved_at``, so a resolution
    recorded with ``0`` skipped the expiry comparison entirely, and ``NaN``
    made every ordering comparison false.
    """
    raw: Any = details.get("resolved_at")
    if raw is None or isinstance(raw, bool):
        return None
    try:
        value = float(cast("float", raw))
    except (TypeError, ValueError):
        return None
    if not math.isfinite(value) or value <= 0.0:
        return None
    return value


def _check_resolution(
    event: AuditEvent,
    issued: dict[str, ApprovalCardV2],
    errors: list[str],
) -> bool:
    """Validate one resolve event against the issues seen earlier in the chain.

    Returns ``True`` when the resolution is fully reconstructable.
    """
    details: dict[str, Any] = event.details
    echoed = str(details.get("card_hash", ""))
    card = issued.get(echoed)
    if card is None:
        # Either the hash names no issued envelope at all, or the issue event
        # is recorded *after* this resolution. Both are rejected: a settlement
        # cannot legitimately precede the issue it settles.
        errors.append(
            f"resolved approval card {echoed!r} has no matching issued envelope with an intact hash "
            f"recorded before it in the chain",
        )
        return False
    resolved_at = _resolved_at(details)
    if resolved_at is None:
        errors.append(
            f"resolved approval card {echoed!r} carries a missing or invalid resolved_at "
            f"({details.get('resolved_at')!r}); a settlement with no usable timestamp cannot be "
            f"checked against the envelope's window",
        )
        return False
    if resolved_at < card.created_at:
        errors.append(
            f"resolved approval card {echoed!r} was decided at {resolved_at:.0f}, "
            f"before its envelope's created_at {card.created_at:.0f}",
        )
        return False
    if resolved_at >= card.not_after:
        errors.append(
            f"resolved approval card {echoed!r} was decided at {resolved_at:.0f} "
            f"at or after its not_after {card.not_after:.0f}",
        )
        return False
    return True


def verify_approval_cards(audit_dir: Path, *, key: bytes | None = None) -> ApprovalCardVerifyResult:
    """Verify every resolved approval card in *audit_dir* offline.

    Args:
        audit_dir: Directory holding the HMAC-chained audit JSONL files.
        key: Optional HMAC key. Only used to read the events; the semantic
            checks here do not depend on the key (the HMAC chain check does).

    Returns:
        An :class:`ApprovalCardVerifyResult`. ``ok`` is ``True`` when no
        resolved card references a mutated envelope, an unknown ``card_hash``,
        or a decision made after expiry (and when there are no cards at all).
    """
    log = AuditLog(audit_dir=audit_dir, key=key) if key is not None else AuditLog(audit_dir=audit_dir)

    # One ordered pass over the chain rather than two independent queries. The
    # order is the evidence: reading issues and resolutions separately loses the
    # happens-before relation between them, which is exactly what lets a
    # backfilled issue event legitimise a resolution that was recorded first.
    events = [
        event for event in log.query() if event.event_type in {EVENT_APPROVAL_CARD_ISSUED, EVENT_APPROVAL_CARD_RESOLVED}
    ]

    errors: list[str] = []
    issued: dict[str, ApprovalCardV2] = {}
    issued_count = 0
    resolved_count = 0
    reconstructed = 0

    for event in events:
        if event.event_type == EVENT_APPROVAL_CARD_ISSUED:
            issued_count += 1
            _admit_issue(event, issued, errors)
            continue
        resolved_count += 1
        if _check_resolution(event, issued, errors):
            reconstructed += 1

    return ApprovalCardVerifyResult(
        ok=not errors,
        errors=errors,
        issued_count=issued_count,
        resolved_count=resolved_count,
        reconstructed_count=reconstructed,
    )
