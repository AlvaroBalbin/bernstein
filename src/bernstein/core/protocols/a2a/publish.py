"""Project the node's signed capability card into registry manifests (#2609).

Discovery of an agent node is only useful if what you discover is checkable.
A registry entry that is just a name and a URL asks the reader to trust the
registry; a record carrying the signed capability card and a publisher
fingerprint lets the reader verify the claim against the node's own key,
with the registry reduced to a transport.

Surfaces
--------
Each target registry has its own schema and its own trust root, so each gets
its own projection rather than one lowest-common-denominator record:

``a2a-card``
    The signed capability card itself (JWS per RFC 7515 over RFC 8785
    canonical bytes), plus the endpoint and the publisher fingerprint.

``mcp-registry``
    A ``server.json``-shaped record carrying the ``ed25519/<fp>`` publisher
    block that :mod:`bernstein.core.protocols.mcp.mcp_verifier` already
    parses, so an MCP-side consumer needs no new primitive.

``agntcy-ads``
    An AGNTCY ADS record: an OASF capability descriptor (a deterministic
    projection of the signed card into the OASF schema shape) bound to the
    node's key by a Sigstore-style provenance statement. The provenance is a
    detached JWS (RFC 7515 §A.5) over the RFC 8785-canonical descriptor,
    signed with the same Ed25519 key that signed the card - the "local-key"
    mode of :mod:`bernstein.core.security.sigstore_attestation`. Online
    keyless submission (Fulcio + Rekor) is a separate follow-up; the record
    verifies offline today. This surface has its own trust root (the OASF
    descriptor + provenance signature) rather than the bare card, so it gets
    its own projection.

Every emitted record is verifiable offline with
:func:`verify_publication_record`, and resolvable to a capability-confirmed
node with :func:`resolve_publication_capability`, which is what makes the
registry a transport rather than an authority.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from bernstein.core.interop.a2a_card import (
    SignedCapabilityCard,
    card_public_key_fingerprint,
    verify_capability_card,
)
from bernstein.core.security.agent_card_signer import (
    canonicalize_jcs,
    sign_detached_jws_over_canonical,
    verify_detached_jws_over_canonical,
)

__all__ = [
    "AGNTCY_PROVENANCE_TYP",
    "OASF_SCHEMA_VERSION",
    "PUBLISH_SURFACES",
    "PublicationVerification",
    "ResolvedPublication",
    "build_a2a_card_record",
    "build_agntcy_ads_record",
    "build_mcp_registry_record",
    "build_publication",
    "resolve_publication_capability",
    "verify_publication_record",
]

#: Registry surfaces this node can publish to. The AGNTCY ADS surface signs a
#: fresh provenance, so - unlike the other two - it requires the node's signing
#: key rather than being a pure projection of the public card.
PUBLISH_SURFACES: tuple[str, ...] = ("a2a-card", "mcp-registry", "agntcy-ads")

#: Publication record schema version. Bumping requires a parallel reader.
_PUBLICATION_SCHEMA_VERSION: int = 1

#: Prefix the MCP verifier expects on a publisher fingerprint.
_ED25519_FINGERPRINT_PREFIX = "ed25519/"

#: OASF capability-descriptor schema version the AGNTCY ADS record targets.
OASF_SCHEMA_VERSION: str = "0.3.1"

#: JWS ``typ`` binding a provenance signature to the AGNTCY ADS surface, so a
#: signature minted for the capability card or a receipt cannot be replayed as
#: descriptor provenance.
AGNTCY_PROVENANCE_TYP: str = "agntcy-ads-provenance+jws"

#: in-toto predicate type carried on the provenance statement.
_AGNTCY_PREDICATE_TYPE: str = "https://in-toto.io/attestation/agntcy-ads-descriptor/v1"


def _canonical(payload: Any) -> bytes:
    """Return stable, sorted, compact JSON bytes."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _publisher_fingerprint(card: SignedCapabilityCard) -> str:
    """Return the ``ed25519/sha256:...`` fingerprint of the card's key."""
    return _ED25519_FINGERPRINT_PREFIX + card_public_key_fingerprint(card.card.public_key_pem)


def _require_publishable(card: SignedCapabilityCard) -> None:
    """Raise unless ``card`` is one a verifier would accept.

    Publishing a card that fails our own verifier just moves a broken record
    into someone else's index, where it is harder to retract than to never
    emit.
    """
    if card.card.is_expired():
        raise ValueError("refusing to publish an expired capability card")
    if not verify_capability_card(card, check_expiry=True):
        raise ValueError("refusing to publish a capability card that does not verify")


def build_a2a_card_record(card: SignedCapabilityCard, *, endpoint: str) -> dict[str, Any]:
    """Return the A2A Agent Card registry record.

    Args:
        card: The node's signed capability card.
        endpoint: Public base URL peers send A2A traffic to.

    Returns:
        A JSON-serialisable record. The embedded card is the full signed
        document, so a consumer verifies it without fetching anything.
    """
    _require_publishable(card)
    return {
        "schema_version": _PUBLICATION_SCHEMA_VERSION,
        "surface": "a2a-card",
        "endpoint": endpoint,
        "issuer": card.card.issuer,
        "name": card.card.name,
        "description": card.card.description,
        "advertised_tools": list(card.card.advertised_tools),
        "publisher": {
            "name": card.card.issuer,
            "fingerprint": _publisher_fingerprint(card),
            "kid": card.card.kid,
        },
        "capabilityCard": card.to_dict(),
    }


def build_mcp_registry_record(
    card: SignedCapabilityCard,
    *,
    endpoint: str,
    version: str,
) -> dict[str, Any]:
    """Return the MCP-registry record for this node.

    The ``publisher`` block mirrors the shape
    :func:`~bernstein.core.protocols.mcp.mcp_verifier.parse_manifest`
    validates (``name`` plus an ``ed25519/`` fingerprint), and
    ``content_hash`` is a ``sha256/`` digest over the canonical signed card -
    so swapping the card behind a published record is detectable.

    Args:
        card: The node's signed capability card.
        endpoint: Public base URL peers send A2A traffic to.
        version: Version string to publish (typically the release version).
    """
    _require_publishable(card)
    content_hash = "sha256/" + hashlib.sha256(_canonical(card.to_dict())).hexdigest()
    return {
        "schema_version": _PUBLICATION_SCHEMA_VERSION,
        "surface": "mcp-registry",
        "endpoint": endpoint,
        "server": {
            "name": card.card.name,
            "description": card.card.description,
            "version": version,
            "publisher": {
                "name": card.card.issuer,
                "fingerprint": _publisher_fingerprint(card),
            },
            "content_hash": content_hash,
        },
        "capabilityCard": card.to_dict(),
    }


def _build_oasf_descriptor(
    card: SignedCapabilityCard,
    *,
    endpoint: str,
    version: str,
) -> dict[str, Any]:
    """Return the OASF capability descriptor for this node.

    The descriptor is a **deterministic projection** of the signed card into
    the OASF schema shape: every field is derived from a card the node already
    signed, so a consumer that verifies the provenance and re-derives the
    descriptor confirms the advertised capabilities are the ones the signed
    identity backs - not a wider set bolted onto the registry entry.

    No wall-clock value enters the descriptor; ``created_at`` is taken from the
    signed card, so two runs over the same card yield byte-identical bytes.
    """
    body = card.card
    created_at = datetime.fromtimestamp(body.created_at, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "schema_version": OASF_SCHEMA_VERSION,
        "name": body.name,
        "namespace": body.issuer,
        "version": version,
        "description": body.description,
        "authors": [body.issuer],
        "created_at": created_at,
        "skills": [{"name": tool} for tool in body.advertised_tools],
        "locators": [{"type": "a2a", "url": endpoint}],
        "extensions": [
            {
                "name": "schema.oasf.agntcy.org/features/runtime/a2a-policies",
                "version": "v1",
                "data": body.policies.to_dict(),
            }
        ],
        "annotations": {"a2a.card.kid": body.kid},
    }


def build_agntcy_ads_record(
    card: SignedCapabilityCard,
    *,
    endpoint: str,
    version: str,
    signing_key_pem: bytes | None,
) -> dict[str, Any]:
    """Return the AGNTCY ADS record: OASF descriptor + signed provenance.

    The descriptor is projected from the signed card and then attested with a
    detached-JWS provenance signature over its RFC 8785-canonical bytes,
    produced with the node's Ed25519 key. That signature - not the registry -
    is the trust root: a consumer verifies it offline against the card key.

    Args:
        card: The node's signed capability card.
        endpoint: Public base URL peers send A2A traffic to.
        version: Version string to publish.
        signing_key_pem: The node's Ed25519 private key (PKCS#8 PEM). The
            AGNTCY surface signs fresh provenance, so - unlike the keyless
            surfaces - it cannot be built from the public card alone.

    Raises:
        ValueError: When no signing key is given, the card would not verify, or
            the key does not match the card's public key.
    """
    _require_publishable(card)
    if signing_key_pem is None:
        raise ValueError("publishing to 'agntcy-ads' requires the node signing key (signing_key_pem)")

    descriptor = _build_oasf_descriptor(card, endpoint=endpoint, version=version)
    canonical = canonicalize_jcs(descriptor)
    provenance_jws = sign_detached_jws_over_canonical(
        canonical, signing_key_pem, typ=AGNTCY_PROVENANCE_TYP, kid=card.card.kid
    )
    # Fail fast if the key does not match the card, rather than emit a record
    # that only fails at the consumer.
    if not verify_detached_jws_over_canonical(
        canonical, provenance_jws, card.card.public_key_pem.encode("ascii"), expected_typ=AGNTCY_PROVENANCE_TYP
    ):
        raise ValueError("signing key does not match the capability card's public key")

    subject_digest = hashlib.sha256(canonical).hexdigest()
    return {
        "schema_version": _PUBLICATION_SCHEMA_VERSION,
        "surface": "agntcy-ads",
        "endpoint": endpoint,
        "publisher": {
            "name": card.card.issuer,
            "fingerprint": _publisher_fingerprint(card),
            "kid": card.card.kid,
        },
        "oasfDescriptor": descriptor,
        "provenance": {
            "predicate_type": _AGNTCY_PREDICATE_TYPE,
            "subject": [{"name": card.card.name, "digest": {"sha256": subject_digest}}],
            "signature": {"alg": "EdDSA", "kid": card.card.kid, "jws": provenance_jws},
        },
        "capabilityCard": card.to_dict(),
    }


def build_publication(
    card: SignedCapabilityCard,
    *,
    endpoint: str,
    version: str,
    surfaces: tuple[str, ...] = PUBLISH_SURFACES,
    signing_key_pem: bytes | None = None,
) -> dict[str, dict[str, Any]]:
    """Return one record per requested surface, keyed by surface name.

    Args:
        card: The node's signed capability card.
        endpoint: Public base URL peers send A2A traffic to.
        version: Version string to publish.
        surfaces: Surfaces to emit; defaults to all supported ones.
        signing_key_pem: The node's Ed25519 private key, required only when
            ``agntcy-ads`` is among ``surfaces`` (its provenance is a fresh
            signature). Ignored by the keyless surfaces.

    Raises:
        ValueError: On an unknown surface, a card that would not verify, or a
            request for ``agntcy-ads`` without a signing key.
    """
    unknown = [s for s in surfaces if s not in PUBLISH_SURFACES]
    if unknown:
        raise ValueError(f"unknown publish surface(s): {', '.join(sorted(unknown))}")

    records: dict[str, dict[str, Any]] = {}
    for surface in surfaces:
        if surface == "a2a-card":
            records[surface] = build_a2a_card_record(card, endpoint=endpoint)
        elif surface == "mcp-registry":
            records[surface] = build_mcp_registry_record(card, endpoint=endpoint, version=version)
        elif surface == "agntcy-ads":
            records[surface] = build_agntcy_ads_record(
                card, endpoint=endpoint, version=version, signing_key_pem=signing_key_pem
            )
    return records


@dataclass(frozen=True, slots=True)
class PublicationVerification:
    """Outcome of verifying a published registry record."""

    ok: bool
    errors: list[str] = field(default_factory=list)
    fingerprint: str | None = None


def verify_publication_record(record: dict[str, Any]) -> PublicationVerification:
    """Verify a published record offline.

    Checks that the embedded capability card verifies, that the advertised
    publisher fingerprint matches the card's actual key, and - on the MCP
    surface - that ``content_hash`` still covers the embedded card.

    Expiry is deliberately **not** enforced here. Publication refuses an
    expired card at build time (see :func:`_require_publishable`), but a
    record already sitting in a registry index will age past its card's
    ``expires_at``, and at that point the useful question is "is this record
    authentic?" rather than "is it fresh?". A consumer deciding whether to
    *send work* must check expiry itself, via
    :func:`~bernstein.core.interop.a2a_card.verify_capability_card` on the
    embedded card.

    Args:
        record: A record produced by one of the ``build_*`` functions.

    Returns:
        :class:`PublicationVerification`. Never raises on malformed input.
    """
    errors: list[str] = []

    if not isinstance(record, dict):
        return PublicationVerification(ok=False, errors=["record is not an object"])

    surface = record.get("surface")
    if surface not in PUBLISH_SURFACES:
        return PublicationVerification(ok=False, errors=[f"unknown surface: {surface!r}"])

    try:
        card = SignedCapabilityCard.from_dict(record.get("capabilityCard", {}))
    except (ValueError, TypeError) as exc:
        return PublicationVerification(ok=False, errors=[f"capabilityCard is not parseable: {exc}"])

    if not verify_capability_card(card, check_expiry=False):
        errors.append("capabilityCard signature does not verify")

    fingerprint = _publisher_fingerprint(card)
    if surface == "mcp-registry":
        declared = ((record.get("server") or {}).get("publisher") or {}).get("fingerprint")
    else:  # a2a-card, agntcy-ads
        declared = (record.get("publisher") or {}).get("fingerprint")
    if declared != fingerprint:
        errors.append(f"publisher fingerprint {declared!r} does not match the card key {fingerprint!r}")

    if surface == "mcp-registry":
        expected = "sha256/" + hashlib.sha256(_canonical(card.to_dict())).hexdigest()
        declared_hash = (record.get("server") or {}).get("content_hash")
        if declared_hash != expected:
            errors.append("server.content_hash does not cover the embedded capability card")

    if surface == "agntcy-ads":
        errors.extend(_verify_agntcy_ads(record, card))

    if errors:
        return PublicationVerification(ok=False, errors=errors)
    return PublicationVerification(ok=True, fingerprint=fingerprint)


def _verify_agntcy_ads(record: dict[str, Any], card: SignedCapabilityCard) -> list[str]:
    """Return AGNTCY-ADS-specific verification errors (empty when valid).

    Three layered checks bind the OASF descriptor to the signed card:

    1. The descriptor must be the canonical projection of the card - so a
       widened capability list is caught even before touching the signature.
    2. The provenance ``subject`` digest must cover the descriptor bytes.
    3. The provenance JWS must verify against the card's public key with the
       AGNTCY-ADS ``typ`` - so only the node's own key can attest a descriptor.
    """
    errors: list[str] = []
    descriptor = record.get("oasfDescriptor")
    if not isinstance(descriptor, dict):
        return ["oasfDescriptor is missing or not an object"]

    expected = _build_oasf_descriptor(
        card, endpoint=str(record.get("endpoint", "")), version=str(descriptor.get("version", ""))
    )
    canonical = canonicalize_jcs(descriptor)
    if canonical != canonicalize_jcs(expected):
        errors.append("oasfDescriptor is not the canonical projection of the capability card")

    provenance = record.get("provenance")
    if not isinstance(provenance, dict):
        errors.append("provenance is missing or not an object")
        return errors

    subject = provenance.get("subject")
    declared_digest = None
    if isinstance(subject, list) and subject and isinstance(subject[0], dict):
        declared_digest = (subject[0].get("digest") or {}).get("sha256")
    if declared_digest != hashlib.sha256(canonical).hexdigest():
        errors.append("provenance subject digest does not cover the OASF descriptor")

    jws = (provenance.get("signature") or {}).get("jws")
    if not isinstance(jws, str) or not verify_detached_jws_over_canonical(
        canonical, jws, card.card.public_key_pem.encode("ascii"), expected_typ=AGNTCY_PROVENANCE_TYP
    ):
        errors.append("provenance signature does not verify against the capability card key")
    return errors


@dataclass(frozen=True, slots=True)
class ResolvedPublication:
    """Outcome of resolving a published record to a capability-confirmed node.

    ``ok`` is ``True`` only when the record verifies offline AND (if one was
    requested) the required capability is advertised. ``capabilities`` is the
    tool set the node's *signed* card attests, so a caller confirms capability
    against the identity, not against an unsigned registry field.
    """

    ok: bool
    surface: str | None = None
    endpoint: str | None = None
    issuer: str | None = None
    fingerprint: str | None = None
    capabilities: tuple[str, ...] = ()
    errors: list[str] = field(default_factory=list)


def resolve_publication_capability(
    record: dict[str, Any],
    *,
    required_capability: str | None = None,
) -> ResolvedPublication:
    """Resolve a published record to a verified, capability-confirmed node.

    The discovery round-trip a peer runs on any surface: verify the record's
    provenance offline, read the advertised capability set off the signed
    card, and - when ``required_capability`` is given - confirm it is present.
    Never raises on malformed input; a bad record returns ``ok=False``.

    Args:
        record: A record produced by one of the ``build_*`` functions.
        required_capability: Optional capability the caller needs. When set and
            absent from the node's advertised tools, resolution fails with the
            node still authenticated (the failure is capability, not identity).

    Returns:
        A :class:`ResolvedPublication`.
    """
    surface = record.get("surface") if isinstance(record, dict) else None
    verification = verify_publication_record(record)
    if not verification.ok:
        return ResolvedPublication(ok=False, surface=surface, errors=list(verification.errors))

    card = SignedCapabilityCard.from_dict(record["capabilityCard"])
    capabilities = tuple(card.card.advertised_tools)
    endpoint = record.get("endpoint")
    issuer = card.card.issuer

    if required_capability is not None and required_capability not in capabilities:
        advertised = ", ".join(capabilities) or "(none)"
        return ResolvedPublication(
            ok=False,
            surface=surface,
            endpoint=endpoint,
            issuer=issuer,
            fingerprint=verification.fingerprint,
            capabilities=capabilities,
            errors=[f"required capability {required_capability!r} not advertised (has: {advertised})"],
        )

    return ResolvedPublication(
        ok=True,
        surface=surface,
        endpoint=endpoint,
        issuer=issuer,
        fingerprint=verification.fingerprint,
        capabilities=capabilities,
    )
