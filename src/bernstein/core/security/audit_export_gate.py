"""One damage verdict for every surface that mints a chain-derived export.

``bernstein audit verify`` runs a set of pillars; the export surfaces
(``tenant slice``, ``tenant showback``) must refuse to mint when that command
would report the chain state as damaged. Gating exports on the HMAC walk alone
proved strictly weaker: a truncation back to a record boundary keeps the walk
green while the checkpoint pillar reports divergence, and post-seal charter
tail loss is visible only to the charter head pins - both states used to mint
signed bundles that laundered the damage.

This module is the single callable both the exports and any future surface
gate on, so a new damage-detecting pillar has one place to be added and
cannot be added to the verifier without the exports inheriting it.

Scope - damage, not staleness. The gate runs the pillars whose failure means
the recorded history is wrong: the HMAC walk with its tear model, checkpoint
extension, charter head pins, and the exporting tenant's own charter fold. It
deliberately does not compare current whole-file hashes against the last
Merkle seal: any legitimate append after a seal changes every file hash, so
that comparison separates "sealed just now" from "sealed a while ago", and the
damage half of what it would catch (a rewrite of sealed bytes) is already the
checkpoint pillar's prefix check. Every read here is lock-free, so the gate
works on a read-only snapshot of the audit directory.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["export_gate_errors"]


def export_gate_errors(audit_dir: Path, key: bytes, *, tenant_id: str | None = None) -> list[str]:
    """Return every damage verdict for *audit_dir*, empty when exports may mint.

    Args:
        audit_dir: The audit directory (typically ``<workdir>/.sdd/audit``).
        key: Audit HMAC key (the same key the chain was written with).
        tenant_id: When given, the exporting tenant's own charter fold is
            included in the verdict; a tenant with no charter at all is left
            to the caller's own not-found handling.

    Returns:
        Human-readable errors, in pillar order: HMAC walk and unacknowledged
        tears, checkpoint file validity and extension of the last pin,
        charter head pins, then the tenant's charter fold.
    """
    from bernstein.core.persistence.chain_checkpoint import (
        CheckpointFileError,
        authorize_divergence,
        check_extension,
        find_divergence_acks,
        load_checkpoints,
        unacknowledged_charter_head_conflicts,
    )
    from bernstein.core.security.audit import AuditLog

    errors: list[str] = []

    chain_ok, chain_errors = AuditLog(audit_dir, key=key).verify()
    if not chain_ok:
        errors.extend(chain_errors)

    try:
        state = load_checkpoints(audit_dir, key)
    except CheckpointFileError as exc:
        errors.extend(exc.errors)
    else:
        last = state.last
        if last is not None:
            conflicts = check_extension(audit_dir, last)
            if conflicts:
                acks = find_divergence_acks(audit_dir, key, str(last.get("root_hash", "")))
                if authorize_divergence(conflicts, acks) is None:
                    errors.extend(f"checkpoint: {c.segment or c.kind}: {c.detail}" for c in conflicts)

    try:
        errors.extend(f"{c.segment}: {c.detail}" for c in unacknowledged_charter_head_conflicts(audit_dir, key))
    except CheckpointFileError as exc:
        errors.extend(exc.errors)

    if tenant_id is not None:
        from bernstein.core.security.audit_chain import AuditChainStore
        from bernstein.core.security.tenant_charter import verify_charter

        verdict = verify_charter(AuditChainStore(audit_dir, key=key), tenant_id)
        if not verdict.ok and verdict.reason != "no_charter":
            errors.append(f"charter {tenant_id}: {verdict.reason}: {verdict.detail}")

    return errors
