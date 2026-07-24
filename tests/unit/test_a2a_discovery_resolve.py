"""Discovery round-trip over published A2A registry records (#2609).

A published record is only useful if a peer can go the whole way from an index
entry to a callable, capability-confirmed node **without trusting the
registry**: resolve the record, verify its provenance offline, and confirm the
capability it needs is one the node's signed identity actually advertises.

``resolve_publication_capability`` is that round-trip primitive; the
``AgentDiscovery.resolve_published_record`` method is the discovery-side entry
point. Both must work for every publish surface (A2A card, MCP registry, and
the AGNTCY ADS / OASF descriptor), so a peer that fetched our record from any
of them lands in the same verified state.
"""

from __future__ import annotations

import pytest

from bernstein.agents.discovery import AgentDiscovery
from bernstein.core.interop.a2a_card import (
    CardPolicies,
    SignedCapabilityCard,
    issue_capability_card,
)
from bernstein.core.protocols.a2a.publish import (
    build_publication,
    resolve_publication_capability,
)


@pytest.fixture()
def keyed_card() -> tuple[SignedCapabilityCard, bytes]:
    return issue_capability_card(
        issuer="bernstein",
        name="bernstein",
        description="Deterministic multi-agent orchestrator.",
        advertised_tools=["task_orchestration", "code_review"],
        policies=CardPolicies(cost_cap_usd=0.0, redaction_tier="standard", sandbox_profile="container"),
    )


@pytest.fixture()
def every_record(keyed_card: tuple[SignedCapabilityCard, bytes]) -> dict[str, dict]:
    card, private_key = keyed_card
    return build_publication(
        card,
        endpoint="https://node.example/a2a",
        version="3.9.0",
        signing_key_pem=private_key,
    )


# ---------------------------------------------------------------------------
# resolve_publication_capability
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("surface", ["a2a-card", "mcp-registry", "agntcy-ads"])
def test_resolve_confirms_capability_from_every_surface(every_record: dict[str, dict], surface: str) -> None:
    resolved = resolve_publication_capability(every_record[surface], required_capability="code_review")

    assert resolved.ok
    assert resolved.surface == surface
    assert resolved.endpoint == "https://node.example/a2a"
    assert resolved.fingerprint.startswith("ed25519/")
    assert "code_review" in resolved.capabilities


@pytest.mark.parametrize("surface", ["a2a-card", "mcp-registry", "agntcy-ads"])
def test_resolve_reports_a_missing_capability(every_record: dict[str, dict], surface: str) -> None:
    resolved = resolve_publication_capability(every_record[surface], required_capability="deploy_to_prod")

    assert not resolved.ok
    assert resolved.errors
    # The node authenticates, so the failure is about capability, not identity.
    assert "code_review" in resolved.capabilities


@pytest.mark.parametrize("surface", ["a2a-card", "mcp-registry", "agntcy-ads"])
def test_resolve_rejects_a_tampered_record(every_record: dict[str, dict], surface: str) -> None:
    record = every_record[surface]
    record["endpoint"] = "https://evil.example/a2a"
    # Widen the advertised capability set on whatever the surface exposes.
    card = record.get("capabilityCard", {}).get("card")
    if card is not None:
        card["advertised_tools"] = ["everything"]
    if "oasfDescriptor" in record:
        record["oasfDescriptor"]["skills"] = [{"name": "everything"}]

    resolved = resolve_publication_capability(record, required_capability="everything")

    assert not resolved.ok
    assert resolved.errors


def test_resolve_without_a_required_capability_still_verifies(every_record: dict[str, dict]) -> None:
    resolved = resolve_publication_capability(every_record["a2a-card"])

    assert resolved.ok
    assert set(resolved.capabilities) == {"task_orchestration", "code_review"}


# ---------------------------------------------------------------------------
# AgentDiscovery.resolve_published_record
# ---------------------------------------------------------------------------


def test_discovery_resolves_and_registers_a_verified_node(tmp_path, every_record: dict[str, dict]) -> None:
    discovery = AgentDiscovery(registry_path=tmp_path / "registry.json")

    resolved = discovery.resolve_published_record(every_record["agntcy-ads"], required_capability="code_review")

    assert resolved.ok
    # The verified node is tracked in the directory registry.
    entries = [d for d in discovery.directories if d.url == "https://node.example/a2a"]
    assert len(entries) == 1
    assert entries[0].source_type == "a2a-registry"


def test_discovery_does_not_register_an_unverified_node(tmp_path, every_record: dict[str, dict]) -> None:
    discovery = AgentDiscovery(registry_path=tmp_path / "registry.json")
    record = every_record["a2a-card"]
    record["capabilityCard"]["card"]["advertised_tools"] = ["forged"]

    resolved = discovery.resolve_published_record(record)

    assert not resolved.ok
    assert discovery.directories == []
