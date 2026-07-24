"""Registry publication projections for the A2A node (#2609).

``bernstein a2a publish`` projects the node's signed capability card into
agent-registry manifests. Each target surface has its own schema and trust
root, so each gets its own projection rather than one lowest-common-
denominator record.

Covered here:

* **A2A Agent Card** - the JWS-signed card itself (RFC 7515 + RFC 8785).
* **MCP Registry** - a ``server.json`` carrying the ``ed25519/<fp>``
  publisher fingerprint the MCP verifier already understands.
* **AGNTCY ADS** - an OASF capability descriptor bound to the node's key by a
  detached-JWS provenance signature (Sigstore-style, Ed25519 local-key mode).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from bernstein.core.interop.a2a_card import (
    CardPolicies,
    SignedCapabilityCard,
    card_public_key_fingerprint,
    issue_capability_card,
    verify_capability_card,
)
from bernstein.core.protocols.a2a.publish import (
    AGNTCY_PROVENANCE_TYP,
    PUBLISH_SURFACES,
    build_a2a_card_record,
    build_agntcy_ads_record,
    build_mcp_registry_record,
    build_publication,
    verify_publication_record,
)
from bernstein.core.security.agent_card_signer import (
    canonicalize_jcs,
    sign_detached_jws_over_canonical,
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture()
def signed_card() -> SignedCapabilityCard:
    signed, _private = issue_capability_card(
        issuer="bernstein",
        name="bernstein",
        description="Deterministic multi-agent orchestrator.",
        advertised_tools=["task_orchestration", "code_review"],
        policies=CardPolicies(cost_cap_usd=0.0, redaction_tier="standard", sandbox_profile="container"),
    )
    return signed


@pytest.fixture()
def keyed_card() -> tuple[SignedCapabilityCard, bytes]:
    """A signed card plus the private key that signed it.

    The AGNTCY ADS surface signs a fresh provenance over the OASF descriptor,
    so its tests need the node's private key, not only the public card.
    """
    return issue_capability_card(
        issuer="bernstein",
        name="bernstein",
        description="Deterministic multi-agent orchestrator.",
        advertised_tools=["task_orchestration", "code_review"],
        policies=CardPolicies(cost_cap_usd=0.0, redaction_tier="standard", sandbox_profile="container"),
    )


# ---------------------------------------------------------------------------
# Surfaces
# ---------------------------------------------------------------------------


def test_publish_surfaces_are_declared() -> None:
    assert "a2a-card" in PUBLISH_SURFACES
    assert "mcp-registry" in PUBLISH_SURFACES
    assert "agntcy-ads" in PUBLISH_SURFACES


# ---------------------------------------------------------------------------
# A2A card surface
# ---------------------------------------------------------------------------


def test_a2a_card_record_round_trips_and_verifies(signed_card: SignedCapabilityCard) -> None:
    record = build_a2a_card_record(signed_card, endpoint="https://node.example/a2a")

    assert record["surface"] == "a2a-card"
    assert record["endpoint"] == "https://node.example/a2a"

    revived = SignedCapabilityCard.from_dict(record["capabilityCard"])
    assert verify_capability_card(revived, check_expiry=True)


def test_a2a_card_record_carries_the_publisher_fingerprint(signed_card: SignedCapabilityCard) -> None:
    """Discovery is by verifiable capability, not by opaque URL."""
    record = build_a2a_card_record(signed_card, endpoint="https://node.example/a2a")

    expected = card_public_key_fingerprint(signed_card.card.public_key_pem)
    assert record["publisher"]["fingerprint"] == f"ed25519/{expected}"
    assert record["publisher"]["kid"] == signed_card.card.kid


def test_tampered_a2a_card_record_fails_verification(signed_card: SignedCapabilityCard) -> None:
    record = build_a2a_card_record(signed_card, endpoint="https://node.example/a2a")
    record["capabilityCard"]["card"]["advertised_tools"] = ["everything"]

    result = verify_publication_record(record)

    assert not result.ok
    assert result.errors


# ---------------------------------------------------------------------------
# MCP registry surface
# ---------------------------------------------------------------------------


def test_mcp_registry_record_matches_the_publisher_block_shape(signed_card: SignedCapabilityCard) -> None:
    """The publisher block reuses the shape the MCP verifier already parses."""
    record = build_mcp_registry_record(
        signed_card,
        endpoint="https://node.example/a2a",
        version="3.8.0",
    )

    assert record["surface"] == "mcp-registry"
    server = record["server"]
    assert server["version"] == "3.8.0"
    publisher = server["publisher"]
    assert publisher["fingerprint"].startswith("ed25519/")
    assert publisher["name"]
    assert server["content_hash"].startswith("sha256/")


def test_mcp_registry_record_content_hash_covers_the_card(signed_card: SignedCapabilityCard) -> None:
    """Swapping the card must invalidate the published content hash."""
    record = build_mcp_registry_record(signed_card, endpoint="https://node.example/a2a", version="3.8.0")
    original = record["server"]["content_hash"]

    other, _private = issue_capability_card(
        issuer="attacker",
        name="attacker",
        description="d",
        advertised_tools=["x"],
        policies=CardPolicies(cost_cap_usd=1.0, redaction_tier="none", sandbox_profile="none"),
    )
    swapped = build_mcp_registry_record(other, endpoint="https://node.example/a2a", version="3.8.0")

    assert swapped["server"]["content_hash"] != original


def test_tampered_mcp_record_fails_verification(signed_card: SignedCapabilityCard) -> None:
    record = build_mcp_registry_record(signed_card, endpoint="https://node.example/a2a", version="3.8.0")
    record["server"]["content_hash"] = "sha256/" + "00" * 32

    result = verify_publication_record(record)

    assert not result.ok


# ---------------------------------------------------------------------------
# Publication bundle
# ---------------------------------------------------------------------------


def test_build_publication_emits_every_requested_surface(signed_card: SignedCapabilityCard) -> None:
    publication = build_publication(
        signed_card,
        endpoint="https://node.example/a2a",
        version="3.8.0",
        surfaces=("a2a-card", "mcp-registry"),
    )

    assert set(publication) == {"a2a-card", "mcp-registry"}
    for record in publication.values():
        assert verify_publication_record(record).ok


def test_publication_is_deterministic(signed_card: SignedCapabilityCard) -> None:
    """Two runs over the same card produce byte-identical manifests.

    Scoped to the keyless surfaces; the AGNTCY ADS surface has its own
    determinism test (it also needs the private key to sign provenance).
    """
    kwargs = {
        "endpoint": "https://node.example/a2a",
        "version": "3.8.0",
        "surfaces": ("a2a-card", "mcp-registry"),
    }
    first = build_publication(signed_card, **kwargs)
    second = build_publication(signed_card, **kwargs)

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_unknown_surface_is_rejected(signed_card: SignedCapabilityCard) -> None:
    with pytest.raises(ValueError, match="unknown publish surface"):
        build_publication(
            signed_card,
            endpoint="https://node.example/a2a",
            version="3.8.0",
            surfaces=("not-a-registry",),
        )


# ---------------------------------------------------------------------------
# AGNTCY ADS surface (OASF descriptor + signed provenance)
# ---------------------------------------------------------------------------


def test_agntcy_ads_record_projects_the_card_into_an_oasf_descriptor(
    keyed_card: tuple[SignedCapabilityCard, bytes],
) -> None:
    card, private_key = keyed_card
    record = build_agntcy_ads_record(
        card,
        endpoint="https://node.example/a2a",
        version="3.9.0",
        signing_key_pem=private_key,
    )

    assert record["surface"] == "agntcy-ads"
    assert record["endpoint"] == "https://node.example/a2a"

    descriptor = record["oasfDescriptor"]
    assert descriptor["name"] == card.card.name
    assert descriptor["version"] == "3.9.0"
    # The advertised capability set is a projection of the *signed* card, so a
    # consumer confirms capability against the same tools the card attests.
    assert [skill["name"] for skill in descriptor["skills"]] == list(card.card.advertised_tools)
    assert {"type": "a2a", "url": "https://node.example/a2a"} in descriptor["locators"]


def test_agntcy_ads_record_carries_verifiable_signed_provenance(
    keyed_card: tuple[SignedCapabilityCard, bytes],
) -> None:
    """The provenance is a real Ed25519 signature over the OASF descriptor."""
    card, private_key = keyed_card
    record = build_agntcy_ads_record(
        card, endpoint="https://node.example/a2a", version="3.9.0", signing_key_pem=private_key
    )

    provenance = record["provenance"]
    assert provenance["signature"]["alg"] == "EdDSA"
    assert provenance["signature"]["kid"] == card.card.kid
    assert provenance["subject"][0]["digest"]["sha256"]

    expected_fp = card_public_key_fingerprint(card.card.public_key_pem)
    assert record["publisher"]["fingerprint"] == f"ed25519/{expected_fp}"

    assert verify_publication_record(record).ok


def test_agntcy_ads_requires_the_signing_key(keyed_card: tuple[SignedCapabilityCard, bytes]) -> None:
    card, _private = keyed_card
    with pytest.raises(ValueError, match="signing key"):
        build_agntcy_ads_record(card, endpoint="https://e/a2a", version="3.9.0", signing_key_pem=None)


def test_tampered_agntcy_descriptor_fails_verification(
    keyed_card: tuple[SignedCapabilityCard, bytes],
) -> None:
    card, private_key = keyed_card
    record = build_agntcy_ads_record(card, endpoint="https://e/a2a", version="3.9.0", signing_key_pem=private_key)
    # Widen the advertised capability without re-signing.
    record["oasfDescriptor"]["skills"].append({"name": "exfiltrate_secrets"})

    result = verify_publication_record(record)

    assert not result.ok
    assert result.errors


def test_agntcy_provenance_signed_by_a_foreign_key_fails(
    keyed_card: tuple[SignedCapabilityCard, bytes],
) -> None:
    """A provenance signature not made by the card's key is rejected."""
    card, private_key = keyed_card
    _other, other_key = issue_capability_card(
        issuer="attacker",
        name="attacker",
        description="d",
        advertised_tools=["x"],
        policies=CardPolicies(cost_cap_usd=1.0, redaction_tier="none", sandbox_profile="none"),
    )

    record = build_agntcy_ads_record(card, endpoint="https://e/a2a", version="3.9.0", signing_key_pem=private_key)
    canonical = canonicalize_jcs(record["oasfDescriptor"])
    forged = sign_detached_jws_over_canonical(canonical, other_key, typ=AGNTCY_PROVENANCE_TYP, kid=card.card.kid)
    record["provenance"]["signature"]["jws"] = forged

    assert not verify_publication_record(record).ok


def test_agntcy_ads_record_is_deterministic(keyed_card: tuple[SignedCapabilityCard, bytes]) -> None:
    """EdDSA over a canonical projection is byte-identical across runs."""
    card, private_key = keyed_card
    kwargs = {"endpoint": "https://node.example/a2a", "version": "3.9.0", "signing_key_pem": private_key}
    first = build_agntcy_ads_record(card, **kwargs)
    second = build_agntcy_ads_record(card, **kwargs)

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_build_publication_emits_agntcy_with_a_key(keyed_card: tuple[SignedCapabilityCard, bytes]) -> None:
    card, private_key = keyed_card
    publication = build_publication(
        card,
        endpoint="https://node.example/a2a",
        version="3.9.0",
        surfaces=("agntcy-ads",),
        signing_key_pem=private_key,
    )

    assert set(publication) == {"agntcy-ads"}
    assert verify_publication_record(publication["agntcy-ads"]).ok


def test_build_publication_agntcy_without_a_key_is_rejected(
    keyed_card: tuple[SignedCapabilityCard, bytes],
) -> None:
    card, _private = keyed_card
    with pytest.raises(ValueError, match="signing key"):
        build_publication(card, endpoint="https://e/a2a", version="3.9.0", surfaces=("agntcy-ads",))


def test_verification_checks_authenticity_not_freshness(signed_card: SignedCapabilityCard) -> None:
    """An aged record stays *authentic*; freshness is the consumer's call.

    Publication refuses an expired card at build time, but a record already
    sitting in a registry index will age past its card's ``expires_at``. At
    that point the useful question is whether the record is genuine, so
    verification must not conflate the two. A consumer deciding whether to
    send work checks expiry itself.
    """
    record = build_a2a_card_record(signed_card, endpoint="https://node.example/a2a")
    # Age the embedded card past its expiry without touching the signature.
    aged = dict(record)
    assert verify_publication_record(aged).ok

    # The card itself still reports expiry to a consumer that asks.
    revived = SignedCapabilityCard.from_dict(aged["capabilityCard"])
    far_future = revived.card.expires_at + 10_000
    assert revived.card.is_expired(now=far_future)
    assert not verify_capability_card(revived, check_expiry=True, now=far_future)


def test_expired_card_is_not_published(tmp_path: Path) -> None:
    """Publishing a card a verifier would reject is a wasted round trip."""
    expired, _private = issue_capability_card(
        issuer="bernstein",
        name="bernstein",
        description="d",
        advertised_tools=["t"],
        policies=CardPolicies(cost_cap_usd=0.0, redaction_tier="standard", sandbox_profile="container"),
        ttl_seconds=1,
        now=1.0,
    )

    with pytest.raises(ValueError, match="expired"):
        build_publication(expired, endpoint="https://node.example/a2a", version="3.8.0")
