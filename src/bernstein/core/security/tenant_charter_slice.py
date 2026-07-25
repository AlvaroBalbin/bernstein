"""Charter-keyed audit slices: membership decides the boundary (#2554).

:func:`~bernstein.core.security.audit_multitenant.export_tenant_slice` already
produces an offline-verifiable, re-chained per-tenant bundle. What it could not
do is say *what a tenant is*: it keys on ``details.tenant_id``, a free-form
string any caller may write, so a slice's boundary rested on a field rather than
on a governed record.

This module supplies the governed record. The export is keyed on a folded
:class:`~bernstein.core.security.tenant_charter.CharterState`, which contributes
two things the string alone cannot:

* the tenant id must belong to a charter that actually exists on the chain, and
* an event must be attributed to a principal the charter enrolled.

The second is the interesting one. An event that merely *claims* a tenant id -
written by a principal that charter never enrolled - is excluded, so a forged
string cannot inject rows into someone else's slice. Excluded rows are reported
rather than dropped silently (:attr:`CharterSlice.excluded_principals`), because
a slice that quietly loses events is as bad for an audit as one that leaks them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bernstein.core.security.audit_multitenant import (
    event_principal,
    event_tenant_id,
    export_tenant_slice,
    read_audit_events,
)

if TYPE_CHECKING:
    from pathlib import Path

    from bernstein.core.security.audit_multitenant import SignatureKind, TenantScopedExport
    from bernstein.core.security.lineage_kms import KMSAdapter
    from bernstein.core.security.tenant_charter import CharterState

__all__ = [
    "CharterSlice",
    "charter_slice_members",
    "event_belongs_to_charter",
    "export_charter_slice",
]


def charter_slice_members(charter: CharterState) -> frozenset[str]:
    """Return the principal set a charter's slice admits.

    Exactly the charter's members. Service identities that act for a tenant
    must be enrolled like any other principal - there is no implicit
    allowlist, because an implicit allowlist is how a boundary stops being a
    boundary.
    """
    return charter.principals


def event_belongs_to_charter(event: dict[str, Any], charter: CharterState) -> bool:
    """Return whether one raw audit event belongs to *charter*'s slice."""
    if event_tenant_id(event) != charter.tenant_id:
        return False
    return event_principal(event) in charter.principals


@dataclass(frozen=True)
class CharterSlice:
    """A charter-keyed export plus the accounting of what it left out."""

    export: TenantScopedExport
    charter_hash: str
    members: tuple[str, ...]
    #: Principals that claimed this tenant id but are not charter members,
    #: together with how many events each contributed. Surfaced so an operator
    #: sees a mis-enrolled service identity instead of a short slice.
    excluded_principals: tuple[tuple[str, int], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable summary for CLI / machine consumption."""
        return {
            "bundle_path": None if self.export.bundle_path is None else str(self.export.bundle_path),
            "charter_hash": self.charter_hash,
            "event_count": self.export.event_count,
            "excluded_principals": [{"events": count, "principal": name} for name, count in self.excluded_principals],
            "head_sha256": self.export.head_sha256,
            "members": list(self.members),
            "tenant_id": self.export.tenant_id,
            "window": {"since": self.export.since, "until": self.export.until},
        }


def export_charter_slice(
    audit_dir: Path,
    charter: CharterState,
    *,
    since: str,
    until: str,
    key: bytes,
    output_dir: Path | None = None,
    signature_kind: SignatureKind = "hmac-chain-only",
    head_kms_adapter: KMSAdapter | None = None,
    write: bool = True,
) -> CharterSlice:
    """Export the audit slice a charter governs.

    Delegates the re-chaining, anchoring, and signing to
    :func:`~bernstein.core.security.audit_multitenant.export_tenant_slice` -
    the slice is still a v2 bundle that verifies against the shared head with
    the existing verifier - and contributes only the membership key.

    Args:
        audit_dir: Directory of HMAC-chained ``YYYY-MM-DD.jsonl`` files.
        charter: Folded charter state whose membership keys the slice.
        since: ISO-8601 inclusive lower bound.
        until: ISO-8601 exclusive upper bound.
        key: Operator HMAC key for the slice-local chain.
        output_dir: Where to write the bundle (defaults per the wrapped export).
        signature_kind: Which verifier path the bundle declares.
        head_kms_adapter: Required for the ``pubkey`` signature kinds.
        write: When False, build in memory and skip the disk write.
    """
    members = charter_slice_members(charter)
    export = export_tenant_slice(
        audit_dir,
        charter.tenant_id,
        since=since,
        until=until,
        key=key,
        output_dir=output_dir,
        signature_kind=signature_kind,
        head_kms_adapter=head_kms_adapter,
        write=write,
        principals=members,
    )

    excluded: dict[str, int] = {}
    for event in read_audit_events(audit_dir):
        if event_tenant_id(event) != charter.tenant_id:
            continue
        timestamp = str(event.get("timestamp", ""))
        if not (since <= timestamp < until):
            continue
        principal = event_principal(event)
        if principal not in members:
            excluded[principal] = excluded.get(principal, 0) + 1

    return CharterSlice(
        export=export,
        charter_hash=charter.charter_hash(),
        members=tuple(sorted(members)),
        excluded_principals=tuple(sorted(excluded.items())),
    )
