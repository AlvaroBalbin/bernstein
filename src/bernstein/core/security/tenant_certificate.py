"""Scoped tenant certificates and the duty refusals they produce (#2554).

A charter says who belongs to a tenant. A **certificate** says what a run
working for that tenant is allowed to do. It is minted from a folded
:class:`~bernstein.core.security.tenant_charter.CharterState`, so it carries
that charter's hash rather than a second, independently-mutable identity: the
authority a run holds and the membership it holds it under are one record, and
changing the membership mints a new certificate instead of quietly reinterpreting
the old one.

The surface is deliberately small and negative-path first:

* :class:`TenantCertificate` - a content-addressed grant (charter hash, version,
  and a :class:`~bernstein.core.identity.delegation_scope.DelegationScope`).
* :func:`authorize_duty` - the one gate. Returns ``None`` when the duty is
  granted, and a :class:`DutyRefusal` naming the certificate hash and the
  missing scope when it is not.
* :func:`record_duty_refusal` - mirrors a refusal into the HMAC audit chain, so
  a denial leaves evidence rather than a gap.

Two refusals matter most, and they are distinct on purpose:

``duty_not_granted``
    The certificate's scope does not carry the duty at all. A run spawned under
    a spawn-only certificate asking to approve lands here.

``self_approval``
    The certificate *does* carry the duty, but the principal exercising it is
    the one that spawned the resource being decided. Maker-checker; a chain can
    narrow perfectly and still let one worker bless its own work, which is why
    this is a separate check rather than a scope axis.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bernstein.core.cost.showback_canonical import canonical_statement_bytes
from bernstein.core.identity.delegation_scope import (
    DUTY_SPAWN,
    GATED_DUTIES,
    DecisionBinding,
    DelegationScope,
)
from bernstein.core.security.tenant_charter import CHARTER_SCHEMA, CharterState, canonical_instant

if TYPE_CHECKING:
    from bernstein.core.security.audit_chain import AuditChainStore

__all__ = [
    "CERTIFICATE_SCHEMA",
    "REFUSAL_CERTIFICATE_EXPIRED",
    "REFUSAL_CHARTER_CLOSED",
    "REFUSAL_CHARTER_DRIFT",
    "REFUSAL_DUTY_NOT_GRANTED",
    "REFUSAL_NOT_A_MEMBER",
    "REFUSAL_SELF_APPROVAL",
    "DutyNotGranted",
    "DutyRefusal",
    "TenantCertificate",
    "authorize_duty",
    "mint_certificate",
    "read_duty_refusals",
    "record_duty_refusal",
    "require_duty",
]

#: Schema tag carried by every certificate body.
CERTIFICATE_SCHEMA: str = "tenant-certificate-v1"

REFUSAL_DUTY_NOT_GRANTED: str = "duty_not_granted"
REFUSAL_SELF_APPROVAL: str = "self_approval"
REFUSAL_NOT_A_MEMBER: str = "principal_not_a_member"
REFUSAL_CERTIFICATE_EXPIRED: str = "certificate_expired"
REFUSAL_CHARTER_DRIFT: str = "charter_drift"
REFUSAL_CHARTER_CLOSED: str = "charter_closed"


class DutyNotGranted(PermissionError):
    """Raised by :func:`require_duty` when a duty is refused.

    Attributes:
        refusal: The structured refusal, already suitable for the chain.
    """

    def __init__(self, refusal: DutyRefusal) -> None:
        super().__init__(str(refusal))
        self.refusal = refusal


@dataclass(frozen=True)
class TenantCertificate:
    """A scoped grant anchored to one charter version.

    ``not_after`` is a POSIX timestamp (seconds), matching the convention the
    capability-token and delegation-scope surfaces already use for expiry.
    """

    tenant_id: str
    charter_hash: str
    version: str
    scope: DelegationScope
    issued_at: str
    not_after: float | None = None

    def to_body(self) -> dict[str, Any]:
        """Return the canonical-safe body the certificate hash is taken over.

        ``not_after`` is string-encoded because the canonical core rejects
        floats outright: a fixed textual form has one encoding, whereas an
        IEEE-754 double has several spellings that hash differently.
        """
        return {
            "charter_hash": self.charter_hash,
            "charter_schema": CHARTER_SCHEMA,
            "issued_at": self.issued_at,
            "not_after": None if self.not_after is None else repr(float(self.not_after)),
            "schema": CERTIFICATE_SCHEMA,
            "scope": _scope_body(self.scope),
            "tenant_id": self.tenant_id,
            "version": self.version,
        }

    def canonical_bytes(self) -> bytes:
        """Return the RFC 8785 canonical bytes of :meth:`to_body`."""
        return canonical_statement_bytes(self.to_body())

    def certificate_hash(self) -> str:
        """Return the content address of this certificate (``sha256:<hex>``)."""
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()

    def binding(self) -> DecisionBinding:
        """Return the decision-time binding a receipt cites for this certificate."""
        return DecisionBinding(
            charter_hash=self.charter_hash,
            certificate_hash=self.certificate_hash(),
            certificate_version=self.version,
        )

    def grants(self, duty: str) -> bool:
        """Return whether this certificate's scope carries *duty*."""
        return duty in self.scope.duties


def _scope_body(scope: DelegationScope) -> dict[str, Any]:
    """Return a canonical-core-safe rendering of a delegation scope.

    :meth:`DelegationScope.to_body` emits ``not_after`` as a float, which the
    canonical core rejects by design. The certificate therefore string-encodes
    that one axis; every other axis passes through unchanged so the scope means
    the same thing on both surfaces.
    """
    body = dict(scope.to_body())
    raw = body.get("not_after")
    body["not_after"] = None if raw is None else repr(float(raw))
    return body


def mint_certificate(
    charter: CharterState,
    *,
    version: str,
    duties: frozenset[str] | set[str] | tuple[str, ...],
    permissions: frozenset[str] | set[str] | tuple[str, ...] = (),
    task_ids: frozenset[str] | None = None,
    path_prefixes: frozenset[str] | None = None,
    not_after: float | None = None,
    max_depth: int | None = None,
    issued_at: str | None = None,
) -> TenantCertificate:
    """Mint a certificate for *charter*, binding it to that charter's hash.

    The charter hash is read from the folded state rather than supplied by the
    caller, so a certificate cannot claim a charter version that never existed.
    """
    scope = DelegationScope(
        permissions=frozenset(permissions),
        duties=frozenset(duties),
        task_ids=task_ids,
        path_prefixes=path_prefixes,
        not_after=not_after,
        max_depth=max_depth,
    )
    return TenantCertificate(
        tenant_id=charter.tenant_id,
        charter_hash=charter.charter_hash(),
        version=version,
        scope=scope,
        issued_at=issued_at or canonical_instant(),
        not_after=not_after,
    )


@dataclass(frozen=True)
class DutyRefusal:
    """A denied duty exercise, with everything needed to audit it offline."""

    tenant_id: str
    charter_hash: str
    certificate_hash: str
    certificate_version: str
    principal: str
    duty: str
    resource_id: str
    reason: str
    missing_scope: tuple[str, ...] = ()

    def to_body(self) -> dict[str, Any]:
        """Return the canonical-safe refusal body."""
        return {
            "certificate_hash": self.certificate_hash,
            "certificate_version": self.certificate_version,
            "charter_hash": self.charter_hash,
            "duty": self.duty,
            "missing_scope": list(self.missing_scope),
            "principal": self.principal,
            "reason": self.reason,
            "resource_id": self.resource_id,
            "schema": CERTIFICATE_SCHEMA,
            "tenant_id": self.tenant_id,
        }

    def refusal_hash(self) -> str:
        """Return the content address of this refusal (``sha256:<hex>``)."""
        return "sha256:" + hashlib.sha256(canonical_statement_bytes(self.to_body())).hexdigest()

    def binding(self) -> DecisionBinding:
        """Return the binding the refusal was decided under."""
        return DecisionBinding(
            charter_hash=self.charter_hash,
            certificate_hash=self.certificate_hash,
            certificate_version=self.certificate_version,
        )

    def __str__(self) -> str:
        missing = ", ".join(self.missing_scope) or "-"
        return (
            f"{self.reason}: principal {self.principal!r} may not exercise {self.duty!r} on "
            f"{self.resource_id!r} for tenant {self.tenant_id!r}; certificate {self.certificate_hash} "
            f"(version {self.certificate_version}) is missing scope [{missing}]"
        )


def authorize_duty(
    certificate: TenantCertificate,
    charter: CharterState,
    *,
    principal: str,
    duty: str,
    resource_id: str,
    spawned_by: str | None = None,
    now: float | None = None,
) -> DutyRefusal | None:
    """Decide whether *principal* may exercise *duty* on *resource_id*.

    Returns ``None`` when the duty is granted, otherwise a :class:`DutyRefusal`
    citing the certificate hash and the missing scope.

    Checks run in a fixed order so the reported reason is deterministic: the
    charter binding is validated before membership, membership before expiry,
    expiry before the scope grant, and self-approval last (it only applies to a
    duty the certificate actually carries).

    Args:
        certificate: The grant the run is operating under.
        charter: The folded charter state in force at decision time.
        principal: Who is exercising the duty.
        duty: One of ``spawn`` / ``approve`` / ``merge``.
        resource_id: What is being decided (a task id, gate id, or run id).
        spawned_by: The principal that spawned *resource_id*, when known.
            Supplying it is what turns "approve" into "approve **its own**
            gate"; leaving it ``None`` means the maker is unknown and the
            self-approval check cannot fire.
        now: POSIX timestamp override for expiry checks (tests).
    """

    def refuse(reason: str, missing: tuple[str, ...] = ()) -> DutyRefusal:
        return DutyRefusal(
            tenant_id=certificate.tenant_id,
            charter_hash=certificate.charter_hash,
            certificate_hash=certificate.certificate_hash(),
            certificate_version=certificate.version,
            principal=principal,
            duty=duty,
            resource_id=resource_id,
            reason=reason,
            missing_scope=missing,
        )

    if certificate.charter_hash != charter.charter_hash():
        return refuse(REFUSAL_CHARTER_DRIFT, (duty,))
    if charter.closed:
        return refuse(REFUSAL_CHARTER_CLOSED, (duty,))
    if not charter.is_member(principal):
        return refuse(REFUSAL_NOT_A_MEMBER, (duty,))
    if certificate.not_after is not None:
        import time

        current = time.time() if now is None else now
        if current > certificate.not_after:
            return refuse(REFUSAL_CERTIFICATE_EXPIRED, (duty,))
    if not certificate.grants(duty):
        return refuse(REFUSAL_DUTY_NOT_GRANTED, (duty,))
    if duty in GATED_DUTIES and spawned_by is not None and spawned_by == principal:
        # Separation of duties, not narrowing: the grant is intact, the
        # principal is simply not allowed to be both maker and checker.
        return refuse(REFUSAL_SELF_APPROVAL, (f"{DUTY_SPAWN}/{duty}",))
    return None


def require_duty(
    certificate: TenantCertificate,
    charter: CharterState,
    *,
    principal: str,
    duty: str,
    resource_id: str,
    spawned_by: str | None = None,
    now: float | None = None,
    chain: AuditChainStore | None = None,
) -> None:
    """Enforce :func:`authorize_duty`, recording and raising on refusal.

    Raises:
        DutyNotGranted: carrying the structured refusal.
    """
    refusal = authorize_duty(
        certificate,
        charter,
        principal=principal,
        duty=duty,
        resource_id=resource_id,
        spawned_by=spawned_by,
        now=now,
    )
    if refusal is None:
        return
    if chain is not None:
        record_duty_refusal(chain, refusal)
    raise DutyNotGranted(refusal)


def record_duty_refusal(chain: AuditChainStore, refusal: DutyRefusal) -> str:
    """Append *refusal* to the HMAC audit chain and return its content address."""
    from bernstein.core.security.audit_chain import EVENT_TENANT_DUTY_REFUSAL

    body = refusal.to_body()
    body["refusal_hash"] = refusal.refusal_hash()
    chain.log_with_prev_digest(
        event_type=EVENT_TENANT_DUTY_REFUSAL,
        actor=refusal.principal,
        resource_type="tenant",
        resource_id=refusal.tenant_id,
        details={"refusal": body, "tenant_id": refusal.tenant_id},
    )
    return refusal.refusal_hash()


def read_duty_refusals(chain: AuditChainStore, tenant_id: str) -> list[DutyRefusal]:
    """Read one tenant's recorded duty refusals back from the chain.

    Archived segments are included: a refusal is evidence, and evidence that
    disappears when retention runs is not evidence.
    """
    from bernstein.core.security.audit_chain import EVENT_TENANT_DUTY_REFUSAL

    out: list[DutyRefusal] = []
    for entry in chain.query(event_type=EVENT_TENANT_DUTY_REFUSAL, resource_id=tenant_id, include_archived=True):
        body = (entry.details or {}).get("refusal")
        if not isinstance(body, dict):
            continue
        raw_missing = body.get("missing_scope") or []
        out.append(
            DutyRefusal(
                tenant_id=str(body.get("tenant_id", "")),
                charter_hash=str(body.get("charter_hash", "")),
                certificate_hash=str(body.get("certificate_hash", "")),
                certificate_version=str(body.get("certificate_version", "")),
                principal=str(body.get("principal", "")),
                duty=str(body.get("duty", "")),
                resource_id=str(body.get("resource_id", "")),
                reason=str(body.get("reason", "")),
                missing_scope=tuple(str(x) for x in raw_missing),
            )
        )
    return out
