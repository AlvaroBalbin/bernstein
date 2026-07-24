"""Offline verification of a sealed endpoint certification receipt (issue #2889).

``bernstein endpoints verify`` checks a stored receipt by ``(base_url, model)``
against the certification spine. This module offers the file-oriented
counterpart: :func:`verify_cert` takes a receipt path and checks the
Ed25519 signature over its canonical binding using only the public key
embedded in the receipt -- no network, no key material, no spine required.
Editing any signed field (``base_url``, ``model``, a verdict, a probe hash)
breaks the signature, so a tampered receipt fails closed exactly like a
tampered audit-chain entry.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bernstein.core.endpoints.certification import EndpointCertification
from bernstein.core.endpoints.conformance import normalize_base_url
from bernstein.core.skills.catalog.signature import verify_payload

__all__ = ["verify_cert"]


def _signature_verifies(certification: EndpointCertification) -> bool:
    """True iff the receipt's Ed25519 signature covers its canonical binding."""
    outcome = verify_payload(
        certification.to_canonical_bytes(),
        certification.signature or None,
        certification.signer_public_key_pem or None,
        allow_unverified=True,
    )
    return outcome.verified


def _record(certification: EndpointCertification) -> dict[str, Any]:
    """Return the receipt as a dict, enriched with ``probes`` and ``passed``."""
    record = dict(certification.to_dict())
    results = certification.transcript.get("results", [])
    record["probes"] = [dict(r) for r in results]
    record["fingerprint"] = certification.fingerprint()
    record["passed"] = bool(certification.verdicts) and all(v.get("certified") for v in certification.verdicts)
    return record


def verify_cert(
    *,
    cert_path: str | Path,
    base_url: str | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    """Verify the sealed receipt at ``cert_path`` fully offline.

    Args:
        cert_path: Path to a sealed ``<fingerprint>.json`` receipt.
        base_url: Optional expected endpoint URL; when supplied together with
            ``model`` the receipt's endpoint identity must match.
        model: Optional expected model id (see ``base_url``).

    Returns:
        ``{"valid": bool, "record": dict}``. ``valid`` is false for a
        malformed receipt, a broken signature, or an endpoint-identity
        mismatch; ``record`` is the parsed receipt (raw dict when it could
        not be reconstructed).
    """
    raw = json.loads(Path(cert_path).read_text(encoding="utf-8"))
    try:
        certification = EndpointCertification.from_dict(raw)
    except (KeyError, TypeError, ValueError):
        return {"valid": False, "record": raw}

    ok = _signature_verifies(certification)
    if (
        ok
        and base_url is not None
        and model is not None
        and (normalize_base_url(base_url) != certification.base_url or model != certification.model)
    ):
        ok = False

    return {"valid": ok, "record": _record(certification)}
