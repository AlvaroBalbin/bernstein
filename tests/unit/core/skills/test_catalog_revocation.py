"""Signed revocation tests for the skill catalog (issue #2527).

Acceptance: a signed revocation of skill X over version range V is enforced
within one poll interval; versions outside V are unaffected; an unsigned or
wrongly-signed revocation is ignored.
"""

from __future__ import annotations

import pytest

from bernstein.core.skills.catalog.revocation import (
    RevocationChecker,
    RevocationEntry,
    RevocationError,
    parse_revocations,
    revocation_leaf_input,
    sign_revocation,
    verify_revocation,
    version_in_range,
)
from bernstein.core.skills.catalog.signature import generate_signer_keypair

# ---------------------------------------------------------------------------
# Version range matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("1.5.0", "*", True),
        ("1.5.0", "", True),
        ("1.5.0", ">=1.0.0,<2.0.0", True),
        ("2.0.0", ">=1.0.0,<2.0.0", False),
        ("0.9.0", ">=1.0.0,<2.0.0", False),
        ("1.2.3", "1.2.3", True),
        ("1.2.4", "1.2.3", False),
        ("1.2.3", "==1.2.3", True),
        ("1.2.3", "!=1.2.3", False),
        ("1.10.0", ">1.9.0", True),  # numeric compare, not lexical
        ("1.2.0-rc1", ">=1.2.0", True),  # pre-release suffix dropped
        ("v1.2.0", ">=1.2.0", True),  # leading v tolerated
    ],
)
def test_version_in_range(version: str, spec: str, expected: bool) -> None:
    assert version_in_range(version, spec) is expected


# ---------------------------------------------------------------------------
# Signing / verifying
# ---------------------------------------------------------------------------


def _entry() -> RevocationEntry:
    return RevocationEntry(
        skill_id="code-review",
        version_range=">=1.0.0,<2.0.0",
        reason="CVE-2026-1234",
        issued_at="2026-07-16T00:00:00Z",
    )


def test_sign_and_verify_roundtrip() -> None:
    priv, pub = generate_signer_keypair()
    signed = sign_revocation(_entry(), priv)
    assert signed.signature is not None
    assert verify_revocation(signed, pub)


def test_verify_rejects_wrong_key() -> None:
    priv, _pub = generate_signer_keypair()
    _priv2, pub2 = generate_signer_keypair()
    signed = sign_revocation(_entry(), priv)
    assert not verify_revocation(signed, pub2)


def test_verify_rejects_tampered_range() -> None:
    priv, pub = generate_signer_keypair()
    signed = sign_revocation(_entry(), priv)
    tampered = RevocationEntry(
        skill_id=signed.skill_id,
        version_range=">=0.0.0",  # widened after signing
        reason=signed.reason,
        issued_at=signed.issued_at,
        signature=signed.signature,
    )
    assert not verify_revocation(tampered, pub)


def test_parse_revocations_drops_unverified() -> None:
    priv, pub = generate_signer_keypair()
    good = sign_revocation(_entry(), priv).to_dict()
    forged = {**_entry().to_dict(), "signature": "AAAA"}  # not a real signature
    accepted = parse_revocations([good, forged], pub)
    assert len(accepted) == 1
    assert accepted[0].skill_id == "code-review"


def test_from_dict_rejects_missing_field() -> None:
    with pytest.raises(RevocationError):
        RevocationEntry.from_dict({"skill_id": "x", "version_range": "*", "reason": "y"})


def test_revocation_leaf_input_is_deterministic() -> None:
    priv, _pub = generate_signer_keypair()
    signed = sign_revocation(_entry(), priv)
    assert revocation_leaf_input(signed) == revocation_leaf_input(signed)
    # A different version range produces a different leaf.
    other = sign_revocation(
        RevocationEntry(
            skill_id="code-review",
            version_range=">=2.0.0",
            reason="x",
            issued_at="2026-07-16T00:00:00Z",
        ),
        priv,
    )
    assert revocation_leaf_input(signed) != revocation_leaf_input(other)


# ---------------------------------------------------------------------------
# Poll-interval checker
# ---------------------------------------------------------------------------


class _FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def test_checker_enforces_within_one_poll_interval() -> None:
    priv, pub = generate_signer_keypair()
    clock = _FakeClock()
    published: list[dict[str, object]] = []

    def load() -> list[RevocationEntry]:
        return parse_revocations(published, pub)

    checker = RevocationChecker(load_revocations=load, poll_interval_seconds=60, clock=clock)

    # Nothing revoked yet.
    assert checker.is_revoked("code-review", "1.5.0") is None

    # Publisher issues a revocation covering 1.x.
    published.append(sign_revocation(_entry(), priv).to_dict())

    # Before the interval elapses the cache is still stale (not yet enforced).
    clock.advance(30)
    assert checker.is_revoked("code-review", "1.5.0") is None

    # After one poll interval the checker re-polls and enforces.
    clock.advance(30)
    hit = checker.is_revoked("code-review", "1.5.0")
    assert hit is not None
    assert hit.reason == "CVE-2026-1234"

    # A version outside the revoked range is unaffected.
    assert checker.is_revoked("code-review", "2.0.0") is None
    # A different skill is unaffected.
    assert checker.is_revoked("other-skill", "1.5.0") is None


def test_checker_ignores_forged_revocation() -> None:
    _priv, pub = generate_signer_keypair()
    attacker_priv, _attacker_pub = generate_signer_keypair()
    clock = _FakeClock()
    published = [sign_revocation(_entry(), attacker_priv).to_dict()]  # signed by the wrong key

    def load() -> list[RevocationEntry]:
        return parse_revocations(published, pub)

    checker = RevocationChecker(load_revocations=load, poll_interval_seconds=1, clock=clock)
    assert checker.is_revoked("code-review", "1.5.0") is None
