"""CLI surface for the A2A v1.0 conformance suite + anchored verdicts (#2525)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from click.testing import CliRunner

from bernstein.cli.commands.interop_cmd import interop_group
from bernstein.core.interop.a2a_conformance import jwk_fingerprint

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "a2a" / "v1_agent_card"
_NOW = "1700000100"


def _stage(tmp_path: Path, card_name: str) -> tuple[Path, Path]:
    card = tmp_path / "card.json"
    jwks = tmp_path / "jwks.json"
    shutil.copyfile(_FIXTURES / card_name, card)
    shutil.copyfile(_FIXTURES / "jwks.json", jwks)
    return card, jwks


def _trusted_fp() -> str:
    return jwk_fingerprint(json.loads((_FIXTURES / "jwks.json").read_bytes())["keys"][0])


def test_cli_v1_conformance_passes_on_valid_card(tmp_path: Path) -> None:
    card, jwks = _stage(tmp_path, "valid.json")
    result = CliRunner().invoke(
        interop_group,
        ["a2a", "conformance", "--agent-card", str(card), "--jwks", str(jwks), "--now", _NOW],
    )
    assert result.exit_code == 0, result.output
    assert "passes conformance" in result.output


def test_cli_v1_conformance_fails_on_tampered_card(tmp_path: Path) -> None:
    card, jwks = _stage(tmp_path, "tampered_signatures.json")
    result = CliRunner().invoke(
        interop_group,
        ["a2a", "conformance", "--agent-card", str(card), "--jwks", str(jwks), "--now", _NOW],
    )
    assert result.exit_code == 1, result.output


def test_cli_v1_conformance_json_report_is_deterministic(tmp_path: Path) -> None:
    card, jwks = _stage(tmp_path, "valid.json")
    args = ["a2a", "conformance", "--agent-card", str(card), "--jwks", str(jwks), "--now", _NOW]
    a = CliRunner().invoke(interop_group, args, obj={"JSON": True})
    b = CliRunner().invoke(interop_group, args, obj={"JSON": True})
    assert a.exit_code == 0, a.output
    pa, pb = json.loads(a.output), json.loads(b.output)
    assert pa["report_hash"] == pb["report_hash"]
    assert pa["accepted"] is True
    assert len(pa["checks"]) == 7


def test_cli_v1_conformance_rejects_untrusted_issuer(tmp_path: Path) -> None:
    card, jwks = _stage(tmp_path, "valid.json")
    result = CliRunner().invoke(
        interop_group,
        [
            "a2a",
            "conformance",
            "--agent-card",
            str(card),
            "--jwks",
            str(jwks),
            "--now",
            _NOW,
            "--trusted-fingerprint",
            "sha256:" + "00" * 32,
        ],
        obj={"JSON": True},
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["accepted"] is False
    assert payload["reason_code"] == "untrusted_issuer"


def test_cli_v1_anchor_and_verify_verdict_roundtrip(tmp_path: Path) -> None:
    card, jwks = _stage(tmp_path, "valid.json")
    workdir = tmp_path / "proj"
    workdir.mkdir()
    runner = CliRunner()
    anchor = runner.invoke(
        interop_group,
        [
            "a2a",
            "conformance",
            "--agent-card",
            str(card),
            "--jwks",
            str(jwks),
            "--now",
            _NOW,
            "--trusted-fingerprint",
            _trusted_fp(),
            "--anchor",
            "--workdir",
            str(workdir),
            "--task-ref",
            "peer-acme",
        ],
        obj={"JSON": True},
    )
    assert anchor.exit_code == 0, anchor.output
    payload = json.loads(anchor.output)
    assert payload["accepted"] is True
    assert payload["receipt"]["journal_entry_hash"].startswith("sha256:")

    verify = runner.invoke(
        interop_group,
        ["a2a", "verify-verdict", "--task-ref", "peer-acme", "--workdir", str(workdir)],
        obj={"JSON": True},
    )
    assert verify.exit_code == 0, verify.output
    vpayload = json.loads(verify.output)
    assert vpayload["ok"] is True
    assert vpayload["verdict_count"] == 1


def test_cli_rejects_both_profiles_at_once(tmp_path: Path) -> None:
    card, jwks = _stage(tmp_path, "valid.json")
    cap = tmp_path / "cap.json"
    cap.write_text("{}")
    result = CliRunner().invoke(
        interop_group,
        ["a2a", "conformance", "--card", str(cap), "--agent-card", str(card), "--jwks", str(jwks)],
    )
    assert result.exit_code == 1, result.output
