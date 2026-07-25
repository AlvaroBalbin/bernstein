"""Receipt-grade tenant showback statements (#2554).

A CSV built from a mutable ledger settles no billing dispute: the disputing
side has to trust the exporter. A **statement** is the opposite shape - a pure
function from a chain segment to canonical bytes, where every line item carries
the links that let a reader resolve it without the live install:

.. code-block:: text

    line item ---> spend id      (which ledger row)
              |--> task id       (which unit of work)
              |--> lineage id    (which artefact record)
              '--> audit hmac    (which chain entry)

The statement then binds those items three ways, so *any* single-field flip is
detected by recomputation alone:

``receipt_hash`` per item
    The content address of the item body. Catches a changed amount, task id,
    model, or link.

``line_items_root``
    A sequential fold ``H(prev || receipt_hash)`` over the items in chain
    order. Catches reordering and insertion/removal, which per-item hashes
    alone cannot see.

``statement_hash``
    The content address of the whole payload, including the charter hash,
    window, totals, and head anchor. Catches everything else.

Money never round-trips through a float here. Amounts are rounded exactly once,
where a line item is built from the ledger's float
(:func:`~bernstein.core.cost.showback_canonical.nano_usd_from_float`), and every
total is an exact integer sum taken in chain order - so aggregation order cannot
change a digit, and two parties recomputing over the same window get identical
bytes rather than amounts that agree to within a rounding step.

Verification is offline by construction: :func:`verify_statement` needs the
statement bytes and nothing else. Passing the shared chain head additionally
proves the statement was cut against the segment the auditor holds.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bernstein.core.cost.showback_canonical import (
    canonical_statement_bytes,
    nano_usd_from_float,
    nano_usd_to_decimal_str,
    require_nfc,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from bernstein.core.cost.spend_ledger import LedgerEntry
    from bernstein.core.security.tenant_charter import CharterState

__all__ = [
    "STATEMENT_SCHEMA",
    "ShowbackLineItem",
    "StatementVerification",
    "build_statement",
    "line_items_root",
    "statement_bytes",
    "statement_hash",
    "verify_statement",
]

#: Schema tag carried by every statement payload.
STATEMENT_SCHEMA: str = "tenant-showback-statement-v1"

#: Domain-separated seed for the line-item fold, so an empty statement's root
#: is a defined value rather than a special case.
_ROOT_GENESIS: str = "sha256:" + hashlib.sha256(b"bernstein/tenant-showback-statement-v1/root").hexdigest()


@dataclass(frozen=True)
class ShowbackLineItem:
    """One attributable charge, with its four resolution links.

    ``amount_nano_usd`` is already an exact integer: the single rounding step
    happened when the item was built. Nothing downstream rounds again.
    """

    line_id: str
    tenant_id: str
    task_id: str
    run_id: str
    model: str
    occurred_at: str
    amount_nano_usd: int
    lineage_record_id: str = ""
    audit_entry_hmac: str = ""

    @classmethod
    def from_ledger_entry(
        cls,
        entry: LedgerEntry,
        *,
        tenant_id: str,
        line_id: str | None = None,
        lineage_record_id: str = "",
        audit_entry_hmac: str = "",
    ) -> ShowbackLineItem:
        """Build a line item from a ledger row, rounding its float exactly once.

        This is the only place a showback amount is derived from a float. The
        conversion goes through the ledger value's shortest round-trip decimal
        and banker's rounding, so it is reproducible from the stored row alone.
        """
        return cls(
            line_id=line_id or _derive_line_id(entry),
            tenant_id=tenant_id,
            task_id=entry.task_id,
            run_id=entry.run_id,
            model=entry.model,
            occurred_at=entry.ts_iso,
            amount_nano_usd=nano_usd_from_float(entry.cost_usd),
            lineage_record_id=lineage_record_id,
            audit_entry_hmac=audit_entry_hmac,
        )

    def to_body(self) -> dict[str, Any]:
        """Return the canonical-safe item body (amount string-encoded)."""
        return {
            "amount_nano_usd": str(self.amount_nano_usd),
            "amount_usd": nano_usd_to_decimal_str(self.amount_nano_usd),
            "audit_entry_hmac": self.audit_entry_hmac,
            "lineage_record_id": self.lineage_record_id,
            "line_id": self.line_id,
            "model": self.model,
            "occurred_at": self.occurred_at,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
        }

    def receipt_hash(self) -> str:
        """Return the content address of this line item (``sha256:<hex>``)."""
        return "sha256:" + hashlib.sha256(canonical_statement_bytes(self.to_body())).hexdigest()

    @classmethod
    def from_body(cls, body: dict[str, Any]) -> ShowbackLineItem:
        """Rebuild a line item from a statement payload.

        The string-encoded ``amount_nano_usd`` is authoritative; ``amount_usd``
        is the human-readable rendering and is re-derived on verification, so a
        reader who edits only the pretty field is still caught.
        """
        return cls(
            line_id=str(body.get("line_id", "")),
            tenant_id=str(body.get("tenant_id", "")),
            task_id=str(body.get("task_id", "")),
            run_id=str(body.get("run_id", "")),
            model=str(body.get("model", "")),
            occurred_at=str(body.get("occurred_at", "")),
            amount_nano_usd=int(str(body.get("amount_nano_usd", "0"))),
            lineage_record_id=str(body.get("lineage_record_id", "")),
            audit_entry_hmac=str(body.get("audit_entry_hmac", "")),
        )


def _derive_line_id(entry: LedgerEntry) -> str:
    """Derive a stable line id from a ledger row's identifying fields."""
    seed = canonical_statement_bytes(
        {
            "agent_id": require_nfc(entry.agent_id),
            "model": require_nfc(entry.model),
            "run_id": require_nfc(entry.run_id),
            "task_id": require_nfc(entry.task_id),
            "ts_iso": require_nfc(entry.ts_iso),
        }
    )
    return "line:" + hashlib.sha256(seed).hexdigest()[:32]


def line_items_root(items: Sequence[ShowbackLineItem]) -> str:
    """Fold line-item receipts into one root in chain order.

    Sequential rather than a balanced Merkle tree on purpose: order is part of
    what the statement asserts (totals are summed in chain order), so the fold
    must be order-sensitive, and a linear fold has no tree-shape ambiguity to
    agree on across implementations.
    """
    acc = _ROOT_GENESIS
    for item in items:
        acc = "sha256:" + hashlib.sha256((acc + "|" + item.receipt_hash()).encode("utf-8")).hexdigest()
    return acc


def build_statement(
    *,
    charter: CharterState,
    line_items: Iterable[ShowbackLineItem],
    since: str,
    until: str,
    head_sha256: str,
    certificate_hash: str | None = None,
    certificate_version: str | None = None,
) -> dict[str, Any]:
    """Project a chain window into a canonical showback statement.

    Pure function: same charter state, same items, same window, same bytes -
    no clock read, no filesystem access, no ordering that depends on dict
    iteration. Items are emitted in the order given, which is chain order.

    Raises:
        ValueError: if any item does not belong to *charter*'s tenant, or the
            window is empty.
    """
    if since >= until:
        raise ValueError(f"since={since!r} must be < until={until!r}")
    items = list(line_items)
    stray = sorted({item.tenant_id for item in items if item.tenant_id != charter.tenant_id})
    if stray:
        raise ValueError(f"line items for foreign tenants in a {charter.tenant_id!r} statement: {stray}")

    total_nanos = 0
    for item in items:
        total_nanos += item.amount_nano_usd

    payload: dict[str, Any] = {
        "binding": {
            "certificate_hash": certificate_hash,
            "certificate_version": certificate_version,
            "charter_hash": charter.charter_hash(),
            "charter_version": charter.version,
        },
        "head_anchor": {"head_sha256": head_sha256},
        "line_items": [item.to_body() for item in items],
        "line_items_root": line_items_root(items),
        "schema": STATEMENT_SCHEMA,
        "tenant_id": charter.tenant_id,
        "totals": {
            "amount_nano_usd": str(total_nanos),
            "amount_usd": nano_usd_to_decimal_str(total_nanos),
            "line_item_count": len(items),
        },
        "window": {"since": since, "until": until},
    }
    payload["statement_hash"] = "sha256:" + hashlib.sha256(canonical_statement_bytes(payload)).hexdigest()
    return payload


def statement_bytes(statement: dict[str, Any]) -> bytes:
    """Return the RFC 8785 canonical bytes of a full statement payload."""
    return canonical_statement_bytes(statement)


def statement_hash(statement: dict[str, Any]) -> str:
    """Recompute the statement hash over everything but the hash field itself."""
    body = {key: value for key, value in statement.items() if key != "statement_hash"}
    return "sha256:" + hashlib.sha256(canonical_statement_bytes(body)).hexdigest()


@dataclass(frozen=True)
class StatementVerification:
    """Outcome of :func:`verify_statement`."""

    ok: bool
    tenant_id: str
    errors: tuple[str, ...] = ()
    line_item_count: int = 0
    total_nano_usd: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict for CLI / machine consumption."""
        return {
            "errors": list(self.errors),
            "line_item_count": self.line_item_count,
            "ok": self.ok,
            "tenant_id": self.tenant_id,
            "total_nano_usd": str(self.total_nano_usd),
            "total_usd": nano_usd_to_decimal_str(self.total_nano_usd),
        }


def verify_statement(
    statement: dict[str, Any],
    *,
    expected_head_sha256: str | None = None,
    expected_charter_hash: str | None = None,
) -> StatementVerification:
    """Recompute every binding in a statement and report what disagrees.

    Needs the statement and nothing else: no ledger, no chain, no network.
    Supplying ``expected_head_sha256`` or ``expected_charter_hash`` adds the
    two external equalities an auditor can check against material they already
    hold.
    """
    errors: list[str] = []
    tenant_id = str(statement.get("tenant_id", ""))

    if str(statement.get("schema", "")) != STATEMENT_SCHEMA:
        errors.append(f"schema is {statement.get('schema')!r}, expected {STATEMENT_SCHEMA!r}")

    raw_items = statement.get("line_items")
    if not isinstance(raw_items, list):
        errors.append("line_items is missing or not a list")
        return StatementVerification(ok=False, tenant_id=tenant_id, errors=tuple(errors))

    items: list[ShowbackLineItem] = []
    running_total = 0
    for index, raw in enumerate(raw_items):
        if not isinstance(raw, dict):
            errors.append(f"line_items[{index}] is not an object")
            continue
        try:
            item = ShowbackLineItem.from_body(raw)
        except (TypeError, ValueError) as exc:
            errors.append(f"line_items[{index}] is unreadable: {exc}")
            continue
        # Recomputing the receipt hash over the *rebuilt* item catches an edit
        # to any field the item is made of, including the display-only
        # ``amount_usd``, which is re-derived rather than trusted.
        if item.to_body() != raw:
            errors.append(f"line_items[{index}] ({item.line_id}) does not re-derive: a field was altered")
        if item.tenant_id != tenant_id:
            errors.append(
                f"line_items[{index}] ({item.line_id}) belongs to tenant {item.tenant_id!r}, not {tenant_id!r}"
            )
        items.append(item)
        running_total += item.amount_nano_usd

    recomputed_root = line_items_root(items)
    if str(statement.get("line_items_root", "")) != recomputed_root:
        errors.append(
            f"line_items_root is {statement.get('line_items_root')!r} but the items fold to {recomputed_root!r}; "
            "an item was reordered, inserted, or removed"
        )

    totals = statement.get("totals")
    if not isinstance(totals, dict):
        errors.append("totals is missing or not an object")
    else:
        declared_nanos = _parse_declared_nanos(totals.get("amount_nano_usd"), errors)
        if declared_nanos is not None and declared_nanos != running_total:
            errors.append(
                f"totals.amount_nano_usd is {declared_nanos} but the line items sum to {running_total} nano-USD"
            )
        declared_usd = totals.get("amount_usd")
        if declared_usd is not None and str(declared_usd) != nano_usd_to_decimal_str(running_total):
            rendered = nano_usd_to_decimal_str(running_total)
            errors.append(f"totals.amount_usd is {declared_usd!r} but the line items render as {rendered!r}")
        declared_count = totals.get("line_item_count")
        if declared_count is not None and int(declared_count) != len(items):
            errors.append(f"totals.line_item_count is {declared_count} but the statement carries {len(items)} items")

    recomputed_statement_hash = statement_hash(statement)
    if str(statement.get("statement_hash", "")) != recomputed_statement_hash:
        errors.append(
            f"statement_hash is {statement.get('statement_hash')!r} but the payload hashes to "
            f"{recomputed_statement_hash!r}"
        )

    if expected_head_sha256 is not None:
        anchor = statement.get("head_anchor")
        actual = str(anchor.get("head_sha256", "")) if isinstance(anchor, dict) else ""
        if actual != expected_head_sha256:
            errors.append(f"head anchor is {actual!r} but the shared chain head is {expected_head_sha256!r}")

    if expected_charter_hash is not None:
        binding = statement.get("binding")
        actual_charter = str(binding.get("charter_hash", "")) if isinstance(binding, dict) else ""
        if actual_charter != expected_charter_hash:
            errors.append(
                f"statement cites charter {actual_charter!r} but the expected charter is {expected_charter_hash!r}"
            )

    return StatementVerification(
        ok=not errors,
        tenant_id=tenant_id,
        errors=tuple(errors),
        line_item_count=len(items),
        total_nano_usd=running_total,
    )


def _parse_declared_nanos(raw: Any, errors: list[str]) -> int | None:
    """Parse a string-encoded nano-USD total, recording a readable error."""
    if raw is None:
        errors.append("totals.amount_nano_usd is missing")
        return None
    try:
        return int(str(raw))
    except ValueError:
        errors.append(f"totals.amount_nano_usd is not an integer: {raw!r}")
        return None
