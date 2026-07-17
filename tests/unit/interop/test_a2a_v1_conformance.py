"""A2A v1.0 agent-card conformance profile over the golden vector corpus (#2525).

The corpus under ``tests/fixtures/a2a/v1_agent_card/`` is a deterministic set:
a valid card that passes every check, plus one deliberately-broken variant per
named check (bad canonicalization, wrong typ, expired, unknown kid, tampered
signatures). This proves the card we emit verifies the way a peer checks it and
that each invalid vector is rejected by a *named* check.
"""

from __future__ import annotations

import json
from pathlib import Path

from bernstein.core.interop.a2a_conformance import (
    canonical_report_bytes,
    check_agent_card_v1_conformance,
    report_hash,
)

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "a2a" / "v1_agent_card"

# A fixed evaluation timestamp after the corpus ``createdAt`` but before the
# far-future expiry, so the valid card is inside its window and the expired
# vector is out of it.
_NOW = 1_700_000_100.0


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_bytes())


def _jwks() -> dict:
    return _load("jwks.json")


def _check(name: str) -> tuple[bool, dict[str, bool]]:
    report = check_agent_card_v1_conformance(_load(name), jwks=_jwks(), now=_NOW)
    by_name = {c.name: c.passed for c in report.checks}
    return report.ok, by_name


# ---------------------------------------------------------------------------
# Emit side: our own card passes every v1.0 profile check.
# ---------------------------------------------------------------------------


def test_valid_card_passes_every_check() -> None:
    ok, checks = _check("valid.json")
    assert ok is True, checks
    assert set(checks) == {
        "required_v1_fields",
        "signatures_present",
        "jcs_canonical",
        "jws_header",
        "kid_resolves",
        "signature",
        "expiry",
    }
    assert all(checks.values())


def test_valid_card_reports_resolved_fingerprint() -> None:
    report = check_agent_card_v1_conformance(_load("valid.json"), jwks=_jwks(), now=_NOW)
    assert report.fingerprint.startswith("sha256:")
    assert report.kid == "agent-golden-orchestrator"
    assert report.issuer == "bernstein"


# ---------------------------------------------------------------------------
# Each invalid vector is rejected by a named check.
# ---------------------------------------------------------------------------


def test_bad_canonicalization_fails_signature_only() -> None:
    ok, checks = _check("bad_canonicalization.json")
    assert ok is False
    # The body still canonicalises; the JWS was computed over non-JCS bytes,
    # so only the signature check fails.
    assert checks["jcs_canonical"] is True
    assert checks["signature"] is False


def test_wrong_typ_fails_header() -> None:
    ok, checks = _check("wrong_typ.json")
    assert ok is False
    assert checks["jws_header"] is False


def test_expired_card_fails_expiry_but_signature_valid() -> None:
    ok, checks = _check("expired.json")
    assert ok is False
    assert checks["expiry"] is False
    assert checks["signature"] is True


def test_unknown_kid_fails_resolution() -> None:
    ok, checks = _check("unknown_kid.json")
    assert ok is False
    assert checks["kid_resolves"] is False


def test_tampered_signatures_fails_signature() -> None:
    ok, checks = _check("tampered_signatures.json")
    assert ok is False
    assert checks["signature"] is False


# ---------------------------------------------------------------------------
# Determinism + verifiability: byte-identical report for identical inputs.
# ---------------------------------------------------------------------------


def test_report_is_byte_identical_across_runs() -> None:
    a = check_agent_card_v1_conformance(_load("valid.json"), jwks=_jwks(), now=_NOW)
    b = check_agent_card_v1_conformance(_load("valid.json"), jwks=_jwks(), now=_NOW)
    assert canonical_report_bytes(a) == canonical_report_bytes(b)
    assert report_hash(a) == report_hash(b)


def test_report_hash_changes_when_a_check_flips() -> None:
    good = check_agent_card_v1_conformance(_load("valid.json"), jwks=_jwks(), now=_NOW)
    bad = check_agent_card_v1_conformance(_load("expired.json"), jwks=_jwks(), now=_NOW)
    assert report_hash(good) != report_hash(bad)


def test_missing_required_field_fails_named_check() -> None:
    payload = _load("valid.json")
    del payload["protocolVersion"]
    report = check_agent_card_v1_conformance(payload, jwks=_jwks(), now=_NOW)
    checks = {c.name: c.passed for c in report.checks}
    assert report.ok is False
    assert checks["required_v1_fields"] is False
