"""Chain-governed tenant charters: the boundary is a fold, not a config file (#2554).

A tenant today is a free-form ``tenant_id`` string any caller may set. Nothing
says who belongs to it, so a per-tenant audit slice or a cost statement rests on
a mutable field rather than on a governed record. This module makes the boundary
itself a chain object.

A **charter** is not stored state. It is the deterministic fold of an
append-only sequence of :class:`CharterEvent` records:

.. code-block:: text

    open -> member_add -> member_add -> budget_set -> member_remove -> ...
                                   |
                                   v
                            CharterState (members, roles, quota, budget)

Two properties follow from that shape, and both are the point:

**The fold is byte-identical everywhere.** :meth:`CharterState.charter_hash`
digests the RFC 8785 canonical bytes of the folded state through the shipped
canonical core (:mod:`bernstein.core.cost.showback_canonical`), which rejects
floats and non-NFC text rather than repairing them. Two verifiers holding the
same event segment therefore reach the same hash on any machine, and that hash
is what admission, halt, approval, and merge receipts cite as their
:class:`~bernstein.core.identity.delegation_scope.DecisionBinding`.

**Backdating breaks verification instead of rewriting history.** Every event
carries ``prev_event_hash``, so the events form their own Merkle chain *inside*
the HMAC audit chain. That gives two independent detectors:

* Appending an event dated before its predecessor is refused at fold time
  (``recorded_at`` must be non-decreasing in ``seq`` order).
* Editing a recorded event's timestamp after the fact changes its
  ``event_hash``, so its successor's ``prev_event_hash`` no longer matches and
  the fold raises :class:`CharterChainError` naming the broken link - while the
  surrounding HMAC chain independently fails ``bernstein audit verify``.

A membership change can therefore never silently reinterpret a historical
decision: the decision cites the charter hash in force when it was taken, and
the only way to alter the events behind that hash is to break a chain.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from bernstein.core.cost.showback_canonical import (
    canonical_statement_bytes,
    nano_usd_from_decimal_str,
    nano_usd_to_decimal_str,
    require_nfc,
)
from bernstein.core.identity.delegation_scope import DecisionBinding

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

    from bernstein.core.security.audit import AuditEvent
    from bernstein.core.security.audit_chain import AuditChainStore

__all__ = [
    "CHARTER_BUDGET_SET",
    "CHARTER_CLOSE",
    "CHARTER_EVENT_KINDS",
    "CHARTER_GENESIS",
    "CHARTER_MEMBER_ADD",
    "CHARTER_MEMBER_REMOVE",
    "CHARTER_OPEN",
    "CHARTER_QUOTA_SET",
    "CHARTER_ROLE_SET",
    "CHARTER_SCHEMA",
    "CharterChainError",
    "CharterEvent",
    "CharterState",
    "CharterVerification",
    "canonical_instant",
    "charter_events_from_entries",
    "dump_charter_segment",
    "fold_charter",
    "load_charter",
    "load_charter_segment",
    "next_event",
    "open_event",
    "read_charter_entries",
    "read_charter_events",
    "record_charter_event",
    "refreshed_charter_events",
    "verify_charter",
    "verify_charter_events",
    "verify_charter_from_entries",
]

#: Schema tag carried by every charter event body.
CHARTER_SCHEMA: str = "tenant-charter-v1"

#: Domain-separated genesis sentinel for the per-charter event chain. A charter
#: whose first event does not point here is a fragment, not a charter.
CHARTER_GENESIS: str = "sha256:" + hashlib.sha256(b"bernstein/tenant-charter-v1/genesis").hexdigest()

CHARTER_OPEN: str = "charter.open"
CHARTER_MEMBER_ADD: str = "charter.member_add"
CHARTER_MEMBER_REMOVE: str = "charter.member_remove"
CHARTER_ROLE_SET: str = "charter.role_set"
CHARTER_QUOTA_SET: str = "charter.quota_set"
CHARTER_BUDGET_SET: str = "charter.budget_set"
CHARTER_CLOSE: str = "charter.close"

#: Every kind the fold understands. An unknown kind is a hard error rather than
#: a skipped row: two verifiers on different versions must not disagree about
#: what a segment means.
CHARTER_EVENT_KINDS: frozenset[str] = frozenset(
    {
        CHARTER_OPEN,
        CHARTER_MEMBER_ADD,
        CHARTER_MEMBER_REMOVE,
        CHARTER_ROLE_SET,
        CHARTER_QUOTA_SET,
        CHARTER_BUDGET_SET,
        CHARTER_CLOSE,
    }
)

#: Fixed-width UTC instant. Fixed width is load-bearing: lexical comparison
#: equals chronological comparison, so the monotonicity check that catches
#: backdating needs no date parsing and cannot drift with locale or tz database.
_INSTANT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", re.ASCII)

#: Principal and tenant identifiers. Deliberately narrow so an id can never
#: carry path separators, whitespace, or anything that changes under
#: normalization.
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}", re.ASCII)


class CharterChainError(ValueError):
    """A charter event segment is not a well-formed, unbroken chain.

    Attributes:
        reason: Stable machine-readable cause (e.g. ``"backdated"``).
        seq: Sequence number of the offending event, when known.
    """

    def __init__(self, reason: str, message: str, *, seq: int | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.seq = seq


def canonical_instant(moment: datetime | None = None) -> str:
    """Render *moment* (default: now) as the canonical fixed-width UTC instant."""
    value = (moment or datetime.now(tz=UTC)).astimezone(UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


@contextlib.contextmanager
def _as_chain_error(seq: int | None, what: str, *, reason: str = "malformed_body") -> Iterator[None]:
    """Convert value-level failures inside the fold into :class:`CharterChainError`.

    A recorded event body is attacker-controlled input: a rewritten
    ``budget_usd`` reaches :func:`nano_usd_from_decimal_str`, a rewritten quota
    reaches :func:`int`, and a rewritten principal reaches
    :func:`~bernstein.core.cost.showback_canonical.require_nfc`. Those raise
    :class:`MoneyFormatError`, :class:`ValueError`, and
    :class:`NonCanonicalTextError` respectively - none of which derive from
    :class:`CharterChainError`.

    Letting them escape would make the *verifier for a tamper-detection
    feature* crash on tampering, which an operator cannot tell apart from a
    tool bug. Every such failure is therefore reported as a chain error naming
    the offending event, exactly like a broken hash link.
    """
    try:
        yield
    except CharterChainError:
        raise
    except (ValueError, TypeError) as exc:
        raise CharterChainError(reason, f"{what}: {type(exc).__name__}: {exc}", seq=seq) from exc


def _require_id(value: str, *, what: str) -> str:
    """Return *value* if it is a canonical identifier; raise otherwise."""
    require_nfc(value)
    if not _ID_RE.fullmatch(value):
        raise CharterChainError("bad_identifier", f"{what} is not a canonical identifier: {value!r}")
    return value


def _require_instant(value: str, *, seq: int | None = None) -> str:
    if not _INSTANT_RE.fullmatch(value):
        raise CharterChainError(
            "bad_instant",
            f"recorded_at must be a fixed-width UTC instant (YYYY-MM-DDTHH:MM:SS.ffffffZ), got {value!r}",
            seq=seq,
        )
    return value


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CharterEvent:
    """One lifecycle change, hash-linked to the change before it.

    The event's identity (:meth:`event_hash`) covers ``prev_event_hash``, so
    the sequence is a Merkle chain: no field of a recorded event can move
    without orphaning every event after it.
    """

    tenant_id: str
    kind: str
    seq: int
    recorded_at: str
    principal: str
    prev_event_hash: str
    body: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_id(self.tenant_id, what="tenant_id")
        _require_id(self.principal, what="principal")
        _require_instant(self.recorded_at, seq=self.seq)
        if self.kind not in CHARTER_EVENT_KINDS:
            raise CharterChainError("unknown_kind", f"unknown charter event kind: {self.kind!r}", seq=self.seq)
        if self.seq < 0:
            raise CharterChainError("bad_seq", f"seq must be non-negative, got {self.seq}", seq=self.seq)

    # -- identity -----------------------------------------------------------

    def payload(self) -> dict[str, Any]:
        """Return the hashed body (everything the event commits to)."""
        return {
            "body": self.body,
            "kind": self.kind,
            "prev_event_hash": self.prev_event_hash,
            "principal": self.principal,
            "recorded_at": self.recorded_at,
            "schema": CHARTER_SCHEMA,
            "seq": self.seq,
            "tenant_id": self.tenant_id,
        }

    def event_hash(self) -> str:
        """Return this event's content address (``sha256:<hex>``)."""
        return "sha256:" + hashlib.sha256(canonical_statement_bytes(self.payload())).hexdigest()

    # -- serialization ------------------------------------------------------

    def to_body(self) -> dict[str, Any]:
        """Return the JSON body written into the audit-chain event details."""
        payload = self.payload()
        payload["event_hash"] = self.event_hash()
        return payload

    @classmethod
    def from_body(cls, body: dict[str, Any]) -> CharterEvent:
        """Rebuild an event from its recorded body.

        The recorded ``event_hash`` is deliberately *not* trusted: it is
        recomputed on read, so a hand-edited body cannot smuggle a stale hash
        past the fold.
        """
        raw_body = body.get("body")
        return cls(
            tenant_id=str(body.get("tenant_id", "")),
            kind=str(body.get("kind", "")),
            seq=int(body.get("seq", -1)),
            recorded_at=str(body.get("recorded_at", "")),
            principal=str(body.get("principal", "")),
            prev_event_hash=str(body.get("prev_event_hash", "")),
            body=dict(raw_body) if isinstance(raw_body, dict) else {},
        )


def next_event(
    previous: CharterEvent | None,
    *,
    tenant_id: str,
    kind: str,
    principal: str,
    body: dict[str, Any] | None = None,
    recorded_at: str | None = None,
) -> CharterEvent:
    """Mint the event that follows *previous*, refusing to backdate it.

    Passing ``previous=None`` opens a new chain at the genesis sentinel. A
    ``recorded_at`` earlier than the predecessor's is rejected here rather than
    accepted and folded later, so the refusal names the attempt instead of
    surfacing as a mismatched hash three events downstream.
    """
    stamp = _require_instant(recorded_at or canonical_instant())
    if previous is None:
        return CharterEvent(
            tenant_id=tenant_id,
            kind=kind,
            seq=0,
            recorded_at=stamp,
            principal=principal,
            prev_event_hash=CHARTER_GENESIS,
            body=dict(body or {}),
        )
    if stamp < previous.recorded_at:
        raise CharterChainError(
            "backdated",
            f"refusing to append a charter event dated {stamp} before its predecessor "
            f"{previous.recorded_at} (seq {previous.seq}); charter history is append-only",
            seq=previous.seq + 1,
        )
    return CharterEvent(
        tenant_id=tenant_id,
        kind=kind,
        seq=previous.seq + 1,
        recorded_at=stamp,
        principal=principal,
        prev_event_hash=previous.event_hash(),
        body=dict(body or {}),
    )


# ---------------------------------------------------------------------------
# Folded state
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CharterState:
    """The deterministic fold of a charter event segment.

    Every collection is stored sorted so the state has exactly one encoding
    regardless of the order members happened to be enrolled in.
    """

    tenant_id: str
    version: int
    members: tuple[tuple[str, str], ...] = ()
    quota_max_concurrent: int | None = None
    budget_nano_usd: int | None = None
    closed: bool = False
    head_event_hash: str = CHARTER_GENESIS

    # -- membership ---------------------------------------------------------

    @property
    def principals(self) -> frozenset[str]:
        """Return the set of member principals."""
        return frozenset(principal for principal, _ in self.members)

    def role_of(self, principal: str) -> str | None:
        """Return *principal*'s role in this charter, or ``None`` if not a member."""
        for member, role in self.members:
            if member == principal:
                return role
        return None

    def is_member(self, principal: str) -> bool:
        """Return whether *principal* belongs to this charter."""
        return self.role_of(principal) is not None

    # -- identity -----------------------------------------------------------

    def to_body(self) -> dict[str, Any]:
        """Return the canonical-safe body the charter hash is taken over.

        The budget is string-encoded: a nano-USD budget above ~9M USD leaves
        the I-JSON safe integer range, and one encoding rule for the field
        beats a rule that changes at a magnitude threshold.
        """
        return {
            "budget_usd": None if self.budget_nano_usd is None else nano_usd_to_decimal_str(self.budget_nano_usd),
            "closed": self.closed,
            "head_event_hash": self.head_event_hash,
            "members": [{"principal": principal, "role": role} for principal, role in self.members],
            "quota_max_concurrent": self.quota_max_concurrent,
            "schema": CHARTER_SCHEMA,
            "tenant_id": self.tenant_id,
            "version": self.version,
        }

    def canonical_bytes(self) -> bytes:
        """Return the RFC 8785 canonical bytes of :meth:`to_body`."""
        return canonical_statement_bytes(self.to_body())

    def charter_hash(self) -> str:
        """Return the content address of this charter version (``sha256:<hex>``)."""
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()

    def binding(
        self,
        *,
        certificate_hash: str | None = None,
        certificate_version: str | None = None,
    ) -> DecisionBinding:
        """Mint the decision-time binding a receipt cites.

        Decisions bind to the charter that produced them rather than to a
        second identity invented alongside it, so "which charter was in force"
        and "which state did the fold reach" are the same question.
        """
        return DecisionBinding(
            charter_hash=self.charter_hash(),
            certificate_hash=certificate_hash,
            certificate_version=certificate_version,
        )


# ---------------------------------------------------------------------------
# The fold
# ---------------------------------------------------------------------------


def _apply(
    state: CharterState,
    event: CharterEvent,
    members: dict[str, str],
) -> CharterState:
    """Apply one event to the running state (members mutated in place)."""
    kind = event.kind
    quota = state.quota_max_concurrent
    budget = state.budget_nano_usd
    closed = state.closed

    if kind == CHARTER_OPEN:
        raise CharterChainError(
            "reopened", f"charter {event.tenant_id!r} opened twice at seq {event.seq}", seq=event.seq
        )
    if kind in (CHARTER_MEMBER_ADD, CHARTER_ROLE_SET):
        principal = _require_id(str(event.body.get("principal", "")), what="member principal")
        role = _require_id(str(event.body.get("role", "member")), what="member role")
        if kind == CHARTER_MEMBER_ADD and principal in members:
            raise CharterChainError(
                "duplicate_member",
                f"{principal!r} is already a member of {event.tenant_id!r} at seq {event.seq}",
                seq=event.seq,
            )
        if kind == CHARTER_ROLE_SET and principal not in members:
            raise CharterChainError(
                "unknown_member",
                f"cannot set a role for non-member {principal!r} at seq {event.seq}",
                seq=event.seq,
            )
        members[principal] = role
    elif kind == CHARTER_MEMBER_REMOVE:
        principal = _require_id(str(event.body.get("principal", "")), what="member principal")
        if principal not in members:
            raise CharterChainError(
                "unknown_member",
                f"cannot remove non-member {principal!r} from {event.tenant_id!r} at seq {event.seq}",
                seq=event.seq,
            )
        del members[principal]
    elif kind == CHARTER_QUOTA_SET:
        raw = event.body.get("max_concurrent_tasks")
        quota = None if raw is None else int(raw)
        if quota is not None and quota < 0:
            raise CharterChainError("bad_quota", f"quota must be non-negative at seq {event.seq}", seq=event.seq)
    elif kind == CHARTER_BUDGET_SET:
        raw_budget = event.body.get("budget_usd")
        budget = None if raw_budget is None else nano_usd_from_decimal_str(str(raw_budget))
        if budget is not None and budget < 0:
            raise CharterChainError("bad_budget", f"budget must be non-negative at seq {event.seq}", seq=event.seq)
    elif kind == CHARTER_CLOSE:
        closed = True

    return CharterState(
        tenant_id=state.tenant_id,
        version=event.seq + 1,
        members=tuple(sorted(members.items())),
        quota_max_concurrent=quota,
        budget_nano_usd=budget,
        closed=closed,
        head_event_hash=event.event_hash(),
    )


def _apply_opening_body(
    state: CharterState,
    event: CharterEvent,
    members: dict[str, str],
) -> CharterState:
    """Apply the opening event's own body: the first member, and the budget.

    Kept separate from :func:`_apply`, which refuses ``charter.open`` outright
    so a second opening event can never be folded as an ordinary one.
    """
    principal = event.body.get("principal")
    if principal is not None:
        members[_require_id(str(principal), what="member principal")] = _require_id(
            str(event.body.get("role", "owner")), what="member role"
        )

    raw_budget = event.body.get("budget_usd")
    budget = None if raw_budget is None else nano_usd_from_decimal_str(str(raw_budget))
    if budget is not None and budget < 0:
        raise CharterChainError("bad_budget", f"budget must be non-negative at seq {event.seq}", seq=event.seq)

    return CharterState(
        tenant_id=state.tenant_id,
        version=state.version,
        members=tuple(sorted(members.items())),
        quota_max_concurrent=state.quota_max_concurrent,
        budget_nano_usd=budget,
        closed=state.closed,
        head_event_hash=state.head_event_hash,
    )


def open_event(
    *,
    tenant_id: str,
    principal: str,
    role: str = "owner",
    budget_usd: str | None = None,
    recorded_at: str | None = None,
) -> CharterEvent:
    """Mint the single event that opens a charter with its first member.

    One event, therefore one chain append, therefore one ``write``. Opening a
    charter as a *batch* - open, then member_add, then optionally budget_set -
    put a reachable partial state on the chain: the transaction around the batch
    is exclusion, not atomicity, so a Ctrl-C between two appends committed the
    prefix already written. What that left was an opened charter with nobody in
    it, which every verifier folded as healthy, which nothing could complete
    because the tenant id was taken, and which an append-only log cannot undo.
    Carrying the opening's whole meaning in one record removes the prefix rather
    than diagnosing it.

    Args:
        tenant_id: The tenant to open.
        principal: The first member, enrolled by this same event.
        role: That member's role.
        budget_usd: Optional budget envelope, as a decimal string.
        recorded_at: Optional explicit instant (defaults to now).

    Returns:
        The opening event, pointing at the genesis sentinel at ``seq`` 0.
    """
    body: dict[str, Any] = {"principal": principal, "role": role}
    if budget_usd is not None:
        body["budget_usd"] = budget_usd
    return next_event(
        None,
        tenant_id=tenant_id,
        kind=CHARTER_OPEN,
        principal=principal,
        body=body,
        recorded_at=recorded_at,
    )


def fold_charter(events: Sequence[CharterEvent]) -> CharterState:
    """Fold a charter event segment into its state, or refuse.

    The fold is total on well-formed segments and raises on every ill-formed
    one; it never repairs, skips, or reorders. Rejections that matter:

    * ``empty`` / ``not_opened`` - a segment that does not start at ``open``.
    * ``broken_link`` - ``prev_event_hash`` does not equal the predecessor's
      recomputed ``event_hash``. This is the detector that fires when a
      recorded event is edited after the fact.
    * ``backdated`` - ``recorded_at`` moves backwards in ``seq`` order.
    * ``gap`` - ``seq`` is not contiguous from zero.
    * ``tenant_mismatch`` - two tenants' events were spliced together.
    * ``malformed_body`` - a recorded body could not be interpreted at all (a
      rewritten budget, quota, principal, or role). Reported as a chain error
      naming the event rather than raised as a bare value error, so a verifier
      never crashes on the tampering it exists to detect.

    The opening event may carry the charter's first member and its budget in
    its own body (``principal`` / ``role`` / ``budget_usd``), which is what lets
    a charter be opened by a single append; see :func:`open_event`. An opening
    event without them opens an empty charter, as before.

    Raises:
        CharterChainError: on any of the above, and only that.
    """
    if not events:
        raise CharterChainError("empty", "cannot fold an empty charter event segment")
    first = events[0]
    if first.kind != CHARTER_OPEN:
        raise CharterChainError(
            "not_opened",
            f"a charter segment must begin with {CHARTER_OPEN!r}, got {first.kind!r}",
            seq=first.seq,
        )
    if first.seq != 0:
        raise CharterChainError("gap", f"a charter segment must begin at seq 0, got {first.seq}", seq=first.seq)
    if first.prev_event_hash != CHARTER_GENESIS:
        raise CharterChainError(
            "broken_link",
            f"the opening event must point at the genesis sentinel, got {first.prev_event_hash!r}",
            seq=first.seq,
        )

    tenant_id = first.tenant_id
    members: dict[str, str] = {}
    with _as_chain_error(first.seq, f"opening event of {tenant_id!r} cannot be hashed"):
        state = CharterState(tenant_id=tenant_id, version=1, head_event_hash=first.event_hash())
    with _as_chain_error(first.seq, f"opening event of {tenant_id!r} has an unusable body"):
        state = _apply_opening_body(state, first, members)
    previous = first

    for event in events[1:]:
        if event.tenant_id != tenant_id:
            raise CharterChainError(
                "tenant_mismatch",
                f"event at seq {event.seq} belongs to {event.tenant_id!r}, not {tenant_id!r}",
                seq=event.seq,
            )
        if event.seq != previous.seq + 1:
            raise CharterChainError(
                "gap",
                f"charter events must be contiguous: seq {previous.seq} is followed by {event.seq}",
                seq=event.seq,
            )
        with _as_chain_error(previous.seq, f"event at seq {previous.seq} cannot be hashed"):
            previous_hash = previous.event_hash()
        if event.prev_event_hash != previous_hash:
            raise CharterChainError(
                "broken_link",
                f"event at seq {event.seq} points at {event.prev_event_hash} but its predecessor hashes to "
                f"{previous_hash}; the recorded history was altered after the fact",
                seq=event.seq,
            )
        if event.recorded_at < previous.recorded_at:
            raise CharterChainError(
                "backdated",
                f"event at seq {event.seq} is dated {event.recorded_at}, before its predecessor "
                f"{previous.recorded_at}; charter history is append-only",
                seq=event.seq,
            )
        if state.closed:
            raise CharterChainError(
                "closed",
                f"charter {tenant_id!r} was closed at seq {previous.seq}; seq {event.seq} follows it",
                seq=event.seq,
            )
        with _as_chain_error(event.seq, f"event at seq {event.seq} ({event.kind}) has an unusable body"):
            state = _apply(state, event, members)
        previous = event

    return state


@dataclass(frozen=True)
class CharterVerification:
    """Non-raising outcome of :func:`verify_charter_events`."""

    ok: bool
    tenant_id: str
    reason: str | None = None
    detail: str | None = None
    seq: int | None = None
    state: CharterState | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict for CLI / machine consumption."""
        return {
            "detail": self.detail,
            "ok": self.ok,
            "reason": self.reason,
            "seq": self.seq,
            "state": None if self.state is None else self.state.to_body(),
            "tenant_id": self.tenant_id,
        }


def verify_charter_events(events: Sequence[CharterEvent], *, tenant_id: str = "") -> CharterVerification:
    """Fold *events* and report the outcome instead of raising.

    This is the surface an operator's verifier calls, so it must return a
    verdict for *every* input, including a deliberately malformed one. The fold
    already reports body-level damage as :class:`CharterChainError`; the second
    handler is a backstop so a path that was missed still yields a FAIL verdict
    rather than a traceback an operator would read as a broken tool.
    """
    fallback_tenant = tenant_id or (events[0].tenant_id if events else "")
    try:
        state = fold_charter(events)
    except CharterChainError as exc:
        return CharterVerification(
            ok=False,
            tenant_id=fallback_tenant,
            reason=exc.reason,
            detail=str(exc),
            seq=exc.seq,
        )
    except (ValueError, TypeError) as exc:  # pragma: no cover - backstop
        return CharterVerification(
            ok=False,
            tenant_id=fallback_tenant,
            reason="malformed_body",
            detail=f"{type(exc).__name__}: {exc}",
        )
    return CharterVerification(ok=True, tenant_id=state.tenant_id, state=state)


def verify_charter(
    chain: AuditChainStore,
    tenant_id: str,
) -> CharterVerification:
    """Read *tenant_id*'s charter from the chain and fold it, reporting either way.

    Reading is inside the guarded path deliberately: rebuilding a
    :class:`CharterEvent` from a tampered body is itself a place that can fail,
    so a caller that read first and folded inside a ``try`` would still crash on
    exactly the input this is meant to diagnose.

    Takes no lock: the read is exactly :func:`read_charter_events`, so this
    works on a read-only copy of the audit directory.

    Args:
        chain: The store to read from.
        tenant_id: The tenant to verify.
    """
    try:
        events = read_charter_events(chain, tenant_id)
    except CharterChainError as exc:
        return CharterVerification(ok=False, tenant_id=tenant_id, reason=exc.reason, detail=str(exc), seq=exc.seq)
    return _verdict_for(events, tenant_id)


def verify_charter_from_entries(entries: Sequence[AuditEvent], tenant_id: str) -> CharterVerification:
    """Fold one tenant's charter out of a chain snapshot already taken.

    Returns the same verdict as :func:`verify_charter` without reading the
    chain: *entries* is a snapshot of the charter events taken once, under one
    transaction, covering every tenant at once. That is what lets a verifier
    fold N tenants without holding the exclusive chain lock for N reads.

    Args:
        entries: Charter events read from the chain, in chain order.
        tenant_id: The tenant to fold.
    """
    try:
        events = charter_events_from_entries(entries, tenant_id)
    except CharterChainError as exc:
        return CharterVerification(ok=False, tenant_id=tenant_id, reason=exc.reason, detail=str(exc), seq=exc.seq)
    return _verdict_for(events, tenant_id)


def _verdict_for(events: Sequence[CharterEvent], tenant_id: str) -> CharterVerification:
    """Turn a tenant's rebuilt event list into a verdict."""
    if not events:
        return CharterVerification(
            ok=False,
            tenant_id=tenant_id,
            reason="no_charter",
            detail=f"no charter events recorded for tenant {tenant_id!r}",
        )
    return verify_charter_events(events, tenant_id=tenant_id)


# ---------------------------------------------------------------------------
# Audit-chain binding
# ---------------------------------------------------------------------------


def _require_current_predecessor(
    chain: AuditChainStore,
    event: CharterEvent,
    prior_entries: Sequence[AuditEvent] | None = None,
) -> None:
    """Refuse *event* unless the recorded tail is exactly the predecessor it claims.

    A lock only protects the callers that take it, so the invariant is asserted
    by the record rather than left to lock discipline. A caller that forgets
    :meth:`AuditChainStore.chain_transaction` gets a loud, deterministic
    refusal instead of a silently bricked charter.

    The precondition and the section compose: the section provides liveness (a
    second writer waits on the flock rather than spinning on refusals), the
    precondition provides safety (a writer that skipped the section cannot
    corrupt the fold).

    The caller must already hold :meth:`AuditChainStore.chain_transaction`,
    otherwise the tail this reads can move before the append lands. With
    *prior_entries* supplied, only live segments are read here (see
    :func:`refreshed_charter_events`), which is what keeps the exclusive
    section from holding an archive-wide decompression; without it the full
    history is re-read, which is exact but costs the section O(total history
    bytes) once retention has archived anything.

    Args:
        chain: The store to check against.
        event: The event about to be appended.
        prior_entries: Optional full-history charter read (see
            :func:`read_charter_entries`) taken before the section.

    Raises:
        CharterChainError: with reason ``"stale_predecessor"`` when the recorded
            tail is not the event's declared predecessor.
    """
    recorded = (
        refreshed_charter_events(chain, event.tenant_id, prior_entries)
        if prior_entries is not None
        else read_charter_events(chain, event.tenant_id)
    )
    if not recorded:
        if event.seq != 0 or event.prev_event_hash != CHARTER_GENESIS:
            raise CharterChainError(
                "stale_predecessor",
                f"refusing to append charter event seq {event.seq} for {event.tenant_id!r}: no charter "
                f"is recorded, so the only appendable event is seq 0 pointing at the genesis sentinel",
                seq=event.seq,
            )
        return

    tail = recorded[-1]
    tail_hash = tail.event_hash()
    if event.prev_event_hash != tail_hash or event.seq != tail.seq + 1:
        raise CharterChainError(
            "stale_predecessor",
            f"refusing to append charter event seq {event.seq} for {event.tenant_id!r}: it was minted "
            f"against predecessor {event.prev_event_hash} (expecting seq {tail.seq + 1}), but the "
            f"recorded tail is seq {tail.seq} with hash {tail_hash}. Re-read the charter and mint again.",
            seq=event.seq,
        )


def record_charter_event(
    chain: AuditChainStore,
    event: CharterEvent,
    *,
    prior_entries: Sequence[AuditEvent] | None = None,
) -> str:
    """Append *event* to the HMAC audit chain and return its content address.

    The event body travels inside ``details``, which the chain HMAC covers, so
    the charter history inherits the audit chain's tamper evidence on top of
    its own hash linkage. ``details.tenant_id`` is set so the existing
    tenant-scoped export finds charter events without a special case.

    The read of the recorded history, the check of its tail against the event's
    declared predecessor, and the append run inside one
    :meth:`AuditChainStore.chain_transaction` - the same cross-process append
    section every chained write holds, so a concurrent writer waits rather
    than interleaving. Appending an event whose predecessor is no longer the
    tail is refused rather than written: the log is append-only, so a duplicate
    ``seq`` can never be removed and the fold would stay unreadable forever.

    Pass *prior_entries* - a full-history charter read taken with
    :func:`read_charter_entries` at any earlier moment - to keep the in-section
    read bounded: only live segments are re-read under the lock and merged
    onto the pre-read history (see :func:`refreshed_charter_events`). Without
    it the section holds a full-history read, whose cost is O(total history
    bytes) once retention has archived anything - every archived segment is
    decompressed while every other audit writer in every process waits.

    The record is written durably: a charter event is a decision someone acts
    on, and an append that returns from the page cache can be dropped off the
    tail of the newest segment by a host crash, silently reverting the change
    with every verifier still reporting the chain as healthy. The append also
    advances the tenant's durable head pin
    (:func:`bernstein.core.persistence.chain_checkpoint.record_charter_head`)
    under the same section: the pin is the detector for whole-record tail loss
    the chain walk, the fold, and a not-yet-taken seal cannot see. Pin first
    would pin an event that may never land, so the chain append goes first; a
    crash between the two leaves the pin one event behind, which is never a
    conflict.

    Args:
        chain: The store to append to.
        event: The charter event to record.
        prior_entries: Optional full-history charter read (see above).

    Raises:
        CharterChainError: with reason ``"stale_predecessor"`` when the recorded
            tail is not the predecessor *event* was minted against.
    """
    from bernstein.core.persistence.chain_checkpoint import record_charter_head
    from bernstein.core.security.audit_chain import EVENT_TENANT_CHARTER

    details: dict[str, Any] = {"charter": event.to_body(), "tenant_id": event.tenant_id}
    with chain.chain_transaction():
        _require_current_predecessor(chain, event, prior_entries)
        chain.log_with_prev_digest(
            event_type=EVENT_TENANT_CHARTER,
            actor=event.principal,
            resource_type="tenant",
            resource_id=event.tenant_id,
            details=details,
            durable=True,
        )
        record_charter_head(
            chain.audit_dir,
            chain.hmac_key,
            tenant_id=event.tenant_id,
            seq=event.seq,
            event_hash=event.event_hash(),
        )
    return event.event_hash()


def read_charter_events(
    chain: AuditChainStore,
    tenant_id: str,
) -> list[CharterEvent]:
    """Read one tenant's charter events back from the chain, in chain order.

    ``include_archived=True`` is not an optimisation knob here, it is a
    correctness requirement. A charter is a *linkage* structure: every event
    points at its predecessor, and the opening event is by definition the
    oldest, so it is the first thing ordinary retention moves into
    ``archive/``. A live-only read of an archived charter returns nothing,
    which would make an intact charter look like it never existed - and would
    let ``tenant create`` reopen a tenant that already has an owner.

    Takes no lock of its own, so it works on a read-only copy of the audit
    directory, where opening the lock sentinel for writing would fail. A caller
    that *decides and then appends* on what this returns uses the two-phase
    shape instead of calling this inside the section: take the full-history
    entries with :func:`read_charter_entries` before the section, then rebuild
    inside it with :func:`refreshed_charter_events`, which re-reads live
    segments only - holding the exclusive section across an archive-wide
    decompression stalls every audit writer in every process. A read-only
    caller needs no section: a genuinely read-only snapshot has no concurrent
    archiver, so the unlocked read is exact there.

    Args:
        chain: The store to read from.
        tenant_id: The tenant whose charter to read.

    Raises:
        CharterChainError: if a recorded event body cannot be rebuilt.
    """
    return charter_events_from_entries(read_charter_entries(chain, tenant_id), tenant_id)


def read_charter_entries(
    chain: AuditChainStore,
    tenant_id: str,
) -> list[AuditEvent]:
    """Read one tenant's raw charter chain entries, full history, no lock.

    This is the expensive half of the two-phase write read: it decompresses
    every archived segment, so a write command runs it *before* entering the
    append section and hands the result to :func:`refreshed_charter_events`
    inside it. Holding the exclusive cross-process section across this read
    would stall every audit writer in every process for a duration that grows
    with total history size.

    Args:
        chain: The store to read from.
        tenant_id: The tenant whose charter entries to read.
    """
    from bernstein.core.security.audit_chain import EVENT_TENANT_CHARTER

    return chain.query(event_type=EVENT_TENANT_CHARTER, resource_id=tenant_id, include_archived=True)


def refreshed_charter_events(
    chain: AuditChainStore,
    tenant_id: str,
    prior_entries: Sequence[AuditEvent],
) -> list[CharterEvent]:
    """Bring a pre-section full-history read up to date, reading live segments only.

    The caller holds :meth:`AuditChainStore.chain_transaction` and took
    *prior_entries* with :func:`read_charter_entries` before entering it. The
    merge is exact rather than heuristic: every charter append lands in the
    current day's live segment, and retention never archives the current day,
    so any event recorded after *prior_entries* was taken is present in the
    live re-read. Entries are identified by their chain ``hmac`` (unique by
    construction: it covers the predecessor digest), so the overlap between
    the two reads - segments live at both moments, or a day observed both
    live and archived while retention published it - deduplicates without
    dropping anything the fold needs to see.

    Staleness of *prior_entries* is therefore safe; an *incomplete* list is
    not - it must be a genuine full-history read, or archived events would be
    invisible to the fold and the duplicate/predecessor guards.

    Args:
        chain: The store to read from (inside its transaction).
        tenant_id: The tenant whose charter to rebuild.
        prior_entries: Full-history charter entries read before the section.

    Raises:
        CharterChainError: if a recorded event body cannot be rebuilt.
    """
    from bernstein.core.security.audit_chain import EVENT_TENANT_CHARTER

    live = chain.query(event_type=EVENT_TENANT_CHARTER, resource_id=tenant_id, include_archived=False)
    merged: list[AuditEvent] = []
    seen: set[str] = set()
    for entry in [*prior_entries, *live]:
        if entry.hmac in seen:
            continue
        seen.add(entry.hmac)
        merged.append(entry)
    return charter_events_from_entries(merged, tenant_id)


def charter_events_from_entries(entries: Sequence[AuditEvent], tenant_id: str) -> list[CharterEvent]:
    """Rebuild one tenant's charter events from chain entries already read.

    Split out of :func:`read_charter_events` so a caller that must fold many
    tenants pays for one chain read rather than one per tenant, and so the
    folding - pure CPU over data already in hand - happens after the chain
    transaction has been released. Folding per tenant *inside* the transaction
    makes the exclusive hold proportional to (tenants x history), which denies
    every other writer for as long as that takes.

    Args:
        entries: Charter events read from the chain, in chain order. May cover
            several tenants; entries for other tenants are ignored.
        tenant_id: The tenant whose events to keep.

    Raises:
        CharterChainError: if a recorded event body cannot be rebuilt.
    """
    out: list[CharterEvent] = []
    for entry in entries:
        body = (entry.details or {}).get("charter")
        if not isinstance(body, dict):
            continue
        if str(body.get("tenant_id", "")) != tenant_id:
            continue
        raw_seq = body.get("seq")
        seq = raw_seq if isinstance(raw_seq, int) else None
        with _as_chain_error(seq, f"recorded charter event for {tenant_id!r} is unreadable", reason="malformed_event"):
            out.append(CharterEvent.from_body(body))
    return out


def load_charter(
    chain: AuditChainStore,
    tenant_id: str,
) -> CharterState:
    """Read and fold one tenant's charter from the chain.

    Takes no lock (see :func:`read_charter_events`); a caller that appends on
    what this returns calls it inside
    :meth:`AuditChainStore.chain_transaction`.

    Args:
        chain: The store to read from.
        tenant_id: The tenant whose charter to load.

    Raises:
        CharterChainError: if no charter exists for *tenant_id*, or its event
            segment does not fold.
    """
    events = read_charter_events(chain, tenant_id)
    if not events:
        raise CharterChainError("no_charter", f"no charter events recorded for tenant {tenant_id!r}")
    return fold_charter(events)


# ---------------------------------------------------------------------------
# Offline segment exchange
# ---------------------------------------------------------------------------


def dump_charter_segment(events: Iterable[CharterEvent]) -> bytes:
    """Serialize an event segment for offline exchange (one JSON per line)."""
    return b"".join(json.dumps(e.to_body(), sort_keys=True, separators=(",", ":")).encode() + b"\n" for e in events)


def load_charter_segment(raw: bytes) -> list[CharterEvent]:
    """Inverse of :func:`dump_charter_segment`."""
    events: list[CharterEvent] = []
    for line in raw.decode("utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise CharterChainError("bad_segment", f"charter segment line is not an object: {text[:80]!r}")
        events.append(CharterEvent.from_body(parsed))
    return events
