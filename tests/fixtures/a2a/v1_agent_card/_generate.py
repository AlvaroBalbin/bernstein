"""Regenerate the A2A v1.0 agent-card golden vector corpus (#2525).

Deterministic: the signing key is derived from a fixed 32-byte seed and every
timestamp is pinned, so re-running this script reproduces byte-identical
fixtures. Run from the repo root:

    uv run python tests/fixtures/a2a/v1_agent_card/_generate.py

The committed JSON files are the golden corpus the conformance suite pins:
a valid card plus one deliberately-broken variant per named check.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bernstein.core.security.agent_card_signer import (
    AGENT_CARD_V1_TYP,
    canonicalize_jcs,
    ed25519_public_jwk,
)

HERE = Path(__file__).resolve().parent

SEED = b"a2a-v1-conformance-golden-seed!!"  # exactly 32 bytes
KID = "agent-golden-orchestrator"
ISSUED_AT = 1_700_000_000.0
FAR_FUTURE = 4_100_000_000.0  # ~2099
PAST = 1_600_000_000.0  # ~2020


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEED)


def _public_pem() -> bytes:
    return (
        _private_key()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _card_body(*, expires_at: float | None) -> dict[str, object]:
    body: dict[str, object] = {
        "name": "bernstein",
        "description": "Bernstein orchestrator - A2A v1.0 golden fixture.",
        "version": "3.5.0",
        "protocolVersion": "1.0",
        "url": "https://agent.example.test",
        "documentationUrl": "https://github.com/sipyourdrink-ltd/bernstein",
        "supportedInterfaces": ["HTTP+JSON"],
        "securitySchemes": [
            {
                "id": "bearer-jwt",
                "type": "http",
                "scheme": "Bearer",
                "description": "JWT bearer token in the Authorization header.",
                "required": True,
            }
        ],
        "capabilities": [
            {"name": "task-crud", "description": "Create / read / complete / fail tasks."},
        ],
        "skills": [
            {
                "id": "task-orchestration",
                "name": "Task orchestration",
                "description": "Submit goals, watch progress, react to terminal state.",
                "tags": ["tasks", "orchestration"],
            }
        ],
        "createdAt": ISSUED_AT,
    }
    if expires_at is not None:
        body["expiresAt"] = expires_at
    return body


def _detached_jws(signing_body: bytes, *, typ: str, kid: str) -> str:
    header = {"alg": "EdDSA", "typ": typ, "kid": kid}
    header_b64 = _b64url(canonicalize_jcs(header))
    body_b64 = _b64url(signing_body)
    signing_input = f"{header_b64}.{body_b64}".encode("ascii")
    sig = _private_key().sign(signing_input)
    return f"{header_b64}..{_b64url(sig)}"


def _sign(
    body: dict[str, object],
    *,
    typ: str = AGENT_CARD_V1_TYP,
    kid: str = KID,
    signing_body_override: bytes | None = None,
) -> dict[str, object]:
    signing_body = signing_body_override if signing_body_override is not None else canonicalize_jcs(body)
    jws = _detached_jws(signing_body, typ=typ, kid=kid)
    signed = dict(body)
    signed["signatures"] = [{"kid": kid, "alg": "EdDSA", "typ": typ, "jws": jws}]
    return signed


def _write(name: str, payload: dict[str, object]) -> None:
    (HERE / name).write_bytes(canonicalize_jcs(payload))


def main() -> None:
    # Shared JWKS resolving KID to the golden public key.
    jwks = {"keys": [ed25519_public_jwk(_public_pem(), kid=KID)]}
    (HERE / "jwks.json").write_bytes(canonicalize_jcs(jwks))

    # 1. valid: signed correctly, unexpired.
    _write("valid.json", _sign(_card_body(expires_at=FAR_FUTURE)))

    # 2. bad_canonicalization: JWS computed over a NON-JCS serialisation, so a
    #    verifier that recomputes the JCS bytes finds the signature does not
    #    match. The body itself still canonicalises fine (jcs_canonical passes),
    #    isolating the failure to the signature check.
    body = _card_body(expires_at=FAR_FUTURE)
    non_jcs = json.dumps(body, indent=2).encode("utf-8")  # spaces, insertion order
    _write("bad_canonicalization.json", _sign(body, signing_body_override=non_jcs))

    # 3. wrong_typ: JWS protected header carries an unexpected typ.
    _write("wrong_typ.json", _sign(_card_body(expires_at=FAR_FUTURE), typ="wrong+jws"))

    # 4. expired: valid signature over a body whose expiresAt is in the past.
    _write("expired.json", _sign(_card_body(expires_at=PAST)))

    # 5. unknown_kid: signature kid is not present in the JWKS.
    _write("unknown_kid.json", _sign(_card_body(expires_at=FAR_FUTURE), kid="agent-not-in-jwks"))

    # 6. tampered_signatures: valid card, then the JWS signature segment is
    #    flipped so verification fails even though the header/kid are fine.
    tampered = _sign(_card_body(expires_at=FAR_FUTURE))
    sig_obj = tampered["signatures"][0]  # type: ignore[index]
    header_b64, _empty, sig_b64 = sig_obj["jws"].split(".")  # type: ignore[index]
    flipped = ("A" if sig_b64[0] != "A" else "B") + sig_b64[1:]
    sig_obj["jws"] = f"{header_b64}..{flipped}"  # type: ignore[index]
    _write("tampered_signatures.json", tampered)

    print("golden corpus written to", HERE)


if __name__ == "__main__":
    main()
