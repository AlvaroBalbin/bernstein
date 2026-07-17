"""delegate_task_http refuses peers whose v1.0 card fails verification (#2525)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from bernstein.core.interop.a2a_conformance import jwk_fingerprint
from bernstein.core.interop.a2a_lineage import verify_card_verdict
from bernstein.core.protocols.a2a.a2a_federation import (
    A2ACardRejectedError,
    A2AFederation,
)

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "a2a" / "v1_agent_card"
_NOW = 1_700_000_100.0
_HMAC_KEY = b"0" * 32


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_bytes())


def _jwks() -> dict:
    return _load("jwks.json")


def _trusted_fp() -> str:
    return jwk_fingerprint(_jwks()["keys"][0])


def _receipt_ctx(tmp_path: Path, task_ref: str) -> dict:
    return {
        "workdir": tmp_path / "work",
        "lineage_root": tmp_path / "work" / ".sdd" / "lineage",
        "hmac_key": _HMAC_KEY,
        "identity_dir": tmp_path / "identity",
        "task_ref": task_ref,
        "timestamp": int(_NOW),
    }


def _fed() -> A2AFederation:
    fed = A2AFederation(local_endpoint="http://orchestrator:8052")
    fed.register_peer("peer-x", "http://peer-x.local:8052")
    return fed


@pytest.mark.asyncio
async def test_delegation_refused_when_card_untrusted(tmp_path: Path) -> None:
    fed = _fed()
    # A structurally valid card, but its issuer is not in the trusted set.
    with pytest.raises(A2ACardRejectedError) as excinfo:
        await fed.delegate_task_http(
            "peer-x",
            "do the thing",
            peer_agent_card=_load("valid.json"),
            peer_jwks=_jwks(),
            trusted_issuer_fingerprints=["sha256:" + "00" * 32],
            verdict_receipt_ctx=_receipt_ctx(tmp_path, "delegate-peer-x"),
            now=_NOW,
        )
    assert excinfo.value.reason == "untrusted_issuer"
    # No ledger entry was created for the refused delegation.
    assert fed.list_peers()[0].task_count == 0

    # The refusal is a signed receipt that verifies offline.
    result = verify_card_verdict(
        workdir=tmp_path / "work",
        lineage_root=tmp_path / "work" / ".sdd" / "lineage",
        hmac_key=_HMAC_KEY,
        task_ref="delegate-peer-x",
    )
    assert result.ok, result.reason
    assert result.verdict_count == 1


@pytest.mark.asyncio
async def test_delegation_refused_when_card_tampered(tmp_path: Path) -> None:
    fed = _fed()
    with pytest.raises(A2ACardRejectedError) as excinfo:
        await fed.delegate_task_http(
            "peer-x",
            "do the thing",
            peer_agent_card=_load("tampered_signatures.json"),
            peer_jwks=_jwks(),
            trusted_issuer_fingerprints=[_trusted_fp()],
            now=_NOW,
        )
    assert excinfo.value.reason == "signature"


@pytest.mark.asyncio
async def test_delegation_proceeds_when_card_trusted(tmp_path: Path) -> None:
    fed = _fed()
    posted: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        posted["url"] = str(request.url)
        return httpx.Response(202, json={"remote_task_id": "remote-1"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        task = await fed.delegate_task_http(
            "peer-x",
            "do the thing",
            peer_agent_card=_load("valid.json"),
            peer_jwks=_jwks(),
            trusted_issuer_fingerprints=[_trusted_fp()],
            verdict_receipt_ctx=_receipt_ctx(tmp_path, "delegate-peer-x"),
            now=_NOW,
            client=client,
        )
    assert task.remote_task_id == "remote-1"
    assert posted["url"].endswith("/a2a/v0/tasks")

    # The accept decision is also anchored as a signed receipt.
    result = verify_card_verdict(
        workdir=tmp_path / "work",
        lineage_root=tmp_path / "work" / ".sdd" / "lineage",
        hmac_key=_HMAC_KEY,
        task_ref="delegate-peer-x",
    )
    assert result.ok, result.reason


@pytest.mark.asyncio
async def test_delegation_without_card_is_unchanged(tmp_path: Path) -> None:
    """The default path (no peer card) must not require verification."""
    fed = _fed()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"remote_task_id": "remote-2"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        task = await fed.delegate_task_http("peer-x", "do the thing", client=client)
    assert task.remote_task_id == "remote-2"
