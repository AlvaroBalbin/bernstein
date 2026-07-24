"""Programmatic entry point for endpoint certification (issue #2889).

``bernstein endpoints certify`` (and ``doctor --endpoint``) drive the CLI
surface through :func:`bernstein.cli.commands.doctor_cmd._run_endpoint_certification`.
This module exposes the same sealing path as a plain function so callers --
tests, embedders, notebooks -- can certify an endpoint and get the signed
receipt back as a value instead of a process exit code.

There is exactly one certification implementation: :func:`certify_endpoint`
runs the deterministic conformance subset
(:func:`~bernstein.core.endpoints.conformance.run_conformance`) and seals the
transcript plus per-role verdicts with
:func:`~bernstein.core.endpoints.certification.build_endpoint_certification`.
The receipt is Ed25519-signed, anchored in the lineage spine, and mirrored
into the HMAC audit chain -- the same artifact the CLI produces, so the two
surfaces can never diverge.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from bernstein.core.endpoints.certification import (
    build_endpoint_certification,
    load_or_create_endpoint_identity,
)
from bernstein.core.endpoints.conformance import (
    discover_default_model,
    evaluate_roles,
    run_conformance,
)
from bernstein.core.security.audit import load_or_create_audit_key
from bernstein.core.security.audit_chain import AuditChainStore

if TYPE_CHECKING:
    from collections.abc import Sequence

    from bernstein.core.endpoints.certification import EndpointCertification

__all__ = ["certify_endpoint"]

#: Default roles for a non-strict certification: a base-tier role that needs
#: only reachability + chat + timeout + context. ``strict`` adds the tooling
#: role, which additionally requires tool calling and patch fidelity.
_DEFAULT_ROLE = "linter"
_STRICT_ROLE = "test_writer"


def _record(sealed: EndpointCertification) -> dict[str, Any]:
    """Return the sealed receipt as a dict, enriched with derived views.

    ``probes`` mirrors the transcript's per-probe results and ``passed``
    reports whether every evaluated role certified, so a caller does not
    have to re-derive them from ``verdicts``.
    """
    record = dict(sealed.to_dict())
    results = sealed.transcript.get("results", [])
    record["probes"] = [dict(r) for r in results]
    record["fingerprint"] = sealed.fingerprint()
    record["passed"] = bool(sealed.verdicts) and all(v.get("certified") for v in sealed.verdicts)
    return record


def certify_endpoint(
    *,
    base_url: str,
    out_dir: str | Path,
    model: str | None = None,
    token: str = "",
    engine: str = "",
    strict: bool = False,
    timeout: float = 60.0,
    roles: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Probe ``base_url`` and seal a signed certification receipt.

    Args:
        base_url: OpenAI-compatible base URL (e.g. ``http://127.0.0.1:11434/v1``).
        out_dir: Directory that receives the sealed receipt (``<fingerprint>.json``);
            its ``.sdd`` subtree holds the lineage spine, audit chain, and
            endpoint identity so the call is fully self-contained.
        model: Model id to certify; falls back to the endpoint's ``/models``
            listing when omitted.
        token: Optional bearer token value (never logged).
        engine: Runtime label recorded in the receipt (``vllm``, ``ollama``, ...).
        strict: When true, evaluate a tooling role that also requires tool
            calling and patch fidelity to certify; otherwise evaluate a
            base-tier role.
        timeout: Per-probe response budget in seconds.
        roles: Explicit role set to evaluate; overrides the ``strict`` default.

    Returns:
        The sealed receipt as a dict (see :func:`_record`).

    Raises:
        ValueError: When no model can be resolved for the endpoint.
    """
    api_key = token or None
    resolved_model = model or discover_default_model(base_url=base_url, api_key=api_key, timeout=timeout)
    if not resolved_model:
        raise ValueError(
            f"cannot resolve a model for {base_url!r}: the /models listing is unavailable; pass model= explicitly."
        )

    evaluated_roles = tuple(roles) if roles is not None else ((_STRICT_ROLE,) if strict else (_DEFAULT_ROLE,))

    transcript = run_conformance(
        base_url=base_url,
        model=resolved_model,
        api_key=api_key,
        timeout=timeout,
    )
    verdicts = evaluate_roles(transcript, evaluated_roles)

    workdir = Path(out_dir)
    workdir.mkdir(parents=True, exist_ok=True)
    hmac_key = load_or_create_audit_key(workdir / ".sdd" / "audit.key")
    private_pem, public_pem = load_or_create_endpoint_identity(workdir / ".sdd" / "identity")
    chain = AuditChainStore(workdir / ".sdd" / "audit", key=hmac_key)

    sealed = build_endpoint_certification(
        workdir=workdir,
        lineage_root=workdir / ".sdd" / "lineage",
        hmac_key=hmac_key,
        private_key_pem=private_pem,
        public_key_pem=public_pem,
        transcript=transcript,
        verdicts=verdicts,
        engine=engine,
        timestamp=int(time.time()),
        chain=chain,
    )

    # build_endpoint_certification persists the canonical receipt under
    # ``.sdd/endpoints/certifications``; also drop a top-level copy in
    # out_dir so callers get the receipt as a single addressable file.
    receipt_file = workdir / f"{sealed.fingerprint()}.json"
    receipt_file.write_text(
        json.dumps(sealed.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    return _record(sealed)
