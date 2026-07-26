"""Contract fixture for foreign attestations outside Bernstein's own chain.

The fixture deliberately uses no AIPOU or other protocol-specific fields.  It
pins the negative case first: when the foreign issuer cannot be independently
verified, a future verifier must report ``unverifiable`` rather than treating
the foreign envelope as proof from Bernstein's own lineage.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_FIXTURE_PATH = Path(__file__).with_name("fixtures") / "foreign_attestation_unverifiable.json"


def _fixture() -> dict[str, object]:
    return json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))


def test_foreign_attestation_fixture_is_protocol_neutral_and_unlinked() -> None:
    fixture = _fixture()
    record = fixture["lineage_record"]
    assert isinstance(record, dict)
    attestation = record["external_attestation"]
    assert isinstance(attestation, dict)
    expected = fixture["expected"]
    assert isinstance(expected, dict)

    assert fixture["schema"] == "bernstein.foreign-attestation-fixture/v1"
    assert attestation["trust_class"] == "third_party"
    assert str(attestation["content_hash"]).startswith("sha256:")
    assert attestation["claimed_subject"]
    assert "operator_hmac" not in attestation
    assert expected["foreign_attestation_is_not_hmac_chain_evidence"] is True
    assert expected["foreign_attestation_verdict"] == "unverifiable"
    assert expected["foreign_attestation_must_not_pass"] is True
    assert expected["derived_taint"] == "third_party"


@pytest.mark.xfail(
    strict=True,
    reason="issue #3133: foreign-attestation verification is not implemented yet",
)
def test_unverifiable_foreign_attestation_fails_closed_without_changing_local_chain() -> None:
    """Specify the verifier contract before its implementation exists.

    The import intentionally fails on current main.  When the public verifier
    lands, this test must become an ordinary passing contract test rather than
    allowing an unexpected pass to hide an incomplete migration.
    """
    from bernstein.core.lineage.foreign_attestation import verify_foreign_attestation

    fixture = _fixture()
    record = fixture["lineage_record"]
    assert isinstance(record, dict)
    attestation = record["external_attestation"]
    assert isinstance(attestation, dict)
    result = verify_foreign_attestation(attestation)

    assert result.verdict == "unverifiable"
    assert result.verified is False
    assert result.taint.value == "third_party"
    assert fixture["local_chain"] == {
        "expected_verdict": "verified",
        "evidence_source": "bernstein-lineage-only",
    }
