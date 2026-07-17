"""Inbound A2A v1.0 card verification + chain-anchored verdict receipts (#2525).

Covers:

* An inbound card verifies and is accepted only when trusted.
* Fail-closed rejection on missing kid, unknown alg, and tampered signatures.
* Every accept/reject verdict is a signed receipt anchored to the verdict spine
  that verifies offline; a tampered receipt fails verification.
"""

from __future__ import annotations

import json
from pathlib import Path

from bernstein.core.interop.a2a_conformance import jwk_fingerprint
from bernstein.core.interop.a2a_consume import (
    InboundCardVerdict,
    verify_inbound_agent_card_v1,
)
from bernstein.core.interop.a2a_lineage import (
    A2A_CARD_VERDICT_RUN_ID,
    CardVerdictReceipt,
    card_verdict_path,
    read_card_verdict,
    record_card_verdict,
    verify_card_verdict,
)

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "a2a" / "v1_agent_card"
_NOW = 1_700_000_100.0
_HMAC_KEY = b"0" * 32


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_bytes())


def _jwks() -> dict:
    return _load("jwks.json")


def _trusted_fingerprint() -> str:
    return jwk_fingerprint(_jwks()["keys"][0])


# ---------------------------------------------------------------------------
# Inbound verification + trust gate.
# ---------------------------------------------------------------------------


def test_trusted_valid_card_is_accepted() -> None:
    verdict = verify_inbound_agent_card_v1(
        _load("valid.json"),
        jwks=_jwks(),
        trusted_issuer_fingerprints=[_trusted_fingerprint()],
        now=_NOW,
    )
    assert isinstance(verdict, InboundCardVerdict)
    assert verdict.accepted is True
    assert verdict.reason_code == ""
    assert verdict.fingerprint == _trusted_fingerprint()
    assert verdict.report_hash.startswith("sha256:")


def test_untrusted_issuer_is_rejected_even_when_card_valid() -> None:
    verdict = verify_inbound_agent_card_v1(
        _load("valid.json"),
        jwks=_jwks(),
        trusted_issuer_fingerprints=["sha256:" + "00" * 32],
        now=_NOW,
    )
    assert verdict.accepted is False
    assert verdict.reason_code == "untrusted_issuer"


def test_missing_kid_fails_closed() -> None:
    payload = _load("valid.json")
    payload["signatures"][0]["kid"] = ""
    verdict = verify_inbound_agent_card_v1(
        payload,
        jwks=_jwks(),
        trusted_issuer_fingerprints=[_trusted_fingerprint()],
        now=_NOW,
    )
    assert verdict.accepted is False
    assert verdict.reason_code == "missing_kid"


def test_unknown_alg_fails_closed() -> None:
    payload = _load("valid.json")
    payload["signatures"][0]["alg"] = "RS256"
    verdict = verify_inbound_agent_card_v1(
        payload,
        jwks=_jwks(),
        trusted_issuer_fingerprints=[_trusted_fingerprint()],
        now=_NOW,
    )
    assert verdict.accepted is False
    assert verdict.reason_code == "unknown_alg"


def test_unresolvable_jwks_fails_closed() -> None:
    verdict = verify_inbound_agent_card_v1(
        _load("unknown_kid.json"),
        jwks=_jwks(),
        trusted_issuer_fingerprints=[_trusted_fingerprint()],
        now=_NOW,
    )
    assert verdict.accepted is False
    assert verdict.reason_code == "unresolvable_jwks"


def test_tampered_signatures_rejected() -> None:
    verdict = verify_inbound_agent_card_v1(
        _load("tampered_signatures.json"),
        jwks=_jwks(),
        trusted_issuer_fingerprints=[_trusted_fingerprint()],
        now=_NOW,
    )
    assert verdict.accepted is False
    assert verdict.reason_code == "signature"


def test_expired_card_rejected_with_expired_reason() -> None:
    verdict = verify_inbound_agent_card_v1(
        _load("expired.json"),
        jwks=_jwks(),
        trusted_issuer_fingerprints=[_trusted_fingerprint()],
        now=_NOW,
    )
    assert verdict.accepted is False
    assert verdict.reason_code == "expired"


# ---------------------------------------------------------------------------
# Verdict receipts: signed, anchored, verify offline.
# ---------------------------------------------------------------------------


def _record(tmp_path: Path, *, decision: str, reason_code: str, seq: int = 0) -> CardVerdictReceipt:
    return record_card_verdict(
        workdir=tmp_path / "work",
        lineage_root=tmp_path / "work" / ".sdd" / "lineage",
        hmac_key=_HMAC_KEY,
        identity_dir=tmp_path / "identity",
        task_ref="delegate-peer-x",
        decision=decision,
        issuer="bernstein",
        peer_card_fingerprint=_trusted_fingerprint(),
        reason_code=reason_code,
        report_hash="sha256:" + "cd" * 32,
        timestamp=1000 + seq,
        seq=seq,
    )


def test_reject_verdict_receipt_is_signed_and_anchored(tmp_path: Path) -> None:
    receipt = _record(tmp_path, decision="reject", reason_code="untrusted_issuer")
    assert receipt.decision == "reject"
    assert receipt.reason_code == "untrusted_issuer"
    assert receipt.signature
    assert receipt.signer_public_key_pem
    assert receipt.journal_entry_hash.startswith("sha256:")
    # Persisted and reloadable.
    loaded = read_card_verdict(tmp_path / "work", task_ref="delegate-peer-x", seq=0)
    assert loaded is not None
    assert loaded.journal_entry_hash == receipt.journal_entry_hash


def test_verdict_receipt_verifies_offline(tmp_path: Path) -> None:
    _record(tmp_path, decision="accept", reason_code="", seq=0)
    _record(tmp_path, decision="reject", reason_code="signature", seq=1)
    result = verify_card_verdict(
        workdir=tmp_path / "work",
        lineage_root=tmp_path / "work" / ".sdd" / "lineage",
        hmac_key=_HMAC_KEY,
        task_ref="delegate-peer-x",
    )
    assert result.ok, result.reason
    assert result.verdict_count == 2


def test_tampered_verdict_receipt_fails_verification(tmp_path: Path) -> None:
    _record(tmp_path, decision="reject", reason_code="untrusted_issuer", seq=0)
    path = card_verdict_path(tmp_path / "work", task_ref="delegate-peer-x", seq=0)
    row = json.loads(path.read_text())
    row["decision"] = "accept"  # flip the decision after signing
    path.write_text(json.dumps(row, separators=(",", ":"), sort_keys=True))
    result = verify_card_verdict(
        workdir=tmp_path / "work",
        lineage_root=tmp_path / "work" / ".sdd" / "lineage",
        hmac_key=_HMAC_KEY,
        task_ref="delegate-peer-x",
    )
    assert not result.ok


def test_verdict_spine_run_id_is_distinct_from_messages() -> None:
    assert A2A_CARD_VERDICT_RUN_ID == "a2a-card-verdicts"
