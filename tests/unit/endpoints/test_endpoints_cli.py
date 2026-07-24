"""``bernstein endpoints certify`` / ``verify`` CLI tests (issue #2889).

The self-hosted OpenAI-compatible endpoint path already exists as
conformance + signed certification machinery (issue #2356), previously
reachable only through ``bernstein doctor --endpoint``. This surface names
the capability directly:

* ``bernstein endpoints certify --base-url ...`` accepts an arbitrary base
  URL and produces the existing signed certification receipt.
* ``bernstein endpoints verify --base-url ... --model ...`` re-checks that
  receipt fully offline -- no server contact -- against the stored receipt
  and the certification spine.

All tests are hermetic: certify runs against an in-process fake
OpenAI-compatible server; verify never touches the network.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from click.testing import CliRunner

from bernstein.cli.main import cli
from tests.unit.endpoints.stub_endpoint import EndpointBehavior, stub_endpoint_server

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _invoke(args: list[str]) -> object:
    return CliRunner().invoke(cli, args)


def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BERNSTEIN_AUDIT_KEY_PATH", str(tmp_path / "audit.key"))


def test_endpoints_group_registered_on_main_cli() -> None:
    """The ``endpoints`` group is reachable and exposes certify + verify."""
    result = _invoke(["endpoints", "--help"])
    assert result.exit_code == 0, result.output
    assert "certify" in result.output
    assert "verify" in result.output


def test_endpoints_certify_accepts_arbitrary_base_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC2: certify takes an arbitrary base URL and seals a signed receipt."""
    _isolate(tmp_path, monkeypatch)
    with stub_endpoint_server() as base_url:
        result = _invoke(["endpoints", "certify", "--base-url", base_url, "--model", "tiny-coder"])
    assert result.exit_code == 0, result.output
    assert "certified" in result.output

    receipts = list((tmp_path / ".sdd" / "endpoints" / "certifications").glob("*.json"))
    assert len(receipts) == 1


def test_endpoints_certify_json_carries_signed_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC2: the JSON view exposes the signed-record fields (fingerprint, anchor)."""
    _isolate(tmp_path, monkeypatch)
    with stub_endpoint_server() as base_url:
        result = _invoke(
            ["endpoints", "certify", "--base-url", base_url, "--model", "tiny-coder", "--json"]
        )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["model"] == "tiny-coder"
    assert payload["fingerprint"]
    assert payload["journal_entry_hash"]
    assert payload["transcript_hash"].startswith("sha256:")


def test_endpoints_certify_rejects_with_reasons(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A gated role fails closed with a machine reason when a probe rejects."""
    _isolate(tmp_path, monkeypatch)
    with stub_endpoint_server(EndpointBehavior(tools_ok=False)) as base_url:
        result = _invoke(
            [
                "endpoints",
                "certify",
                "--base-url",
                base_url,
                "--model",
                "tiny-coder",
                "--role",
                "test_writer",
            ]
        )
    assert result.exit_code == 1
    assert "rejected" in result.output
    assert "no_tool_call" in result.output


def test_endpoints_certify_fails_usage_when_model_undiscoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit code 2 when no model can be resolved and none was passed."""
    _isolate(tmp_path, monkeypatch)
    with stub_endpoint_server(EndpointBehavior(models_ok=False)) as base_url:
        result = _invoke(["endpoints", "certify", "--base-url", base_url])
    assert result.exit_code == 2
    assert "--model" in result.output


def test_endpoints_verify_checks_receipt_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC2: after certify, verify passes fully offline (no server running)."""
    _isolate(tmp_path, monkeypatch)
    with stub_endpoint_server() as base_url:
        certify = _invoke(["endpoints", "certify", "--base-url", base_url, "--model", "tiny-coder"])
    assert certify.exit_code == 0, certify.output

    # The stub server is now shut down: verify must succeed without it.
    result = _invoke(["endpoints", "verify", "--base-url", base_url, "--model", "tiny-coder"])
    assert result.exit_code == 0, result.output
    assert "verified" in result.output.lower() or "ok" in result.output.lower()


def test_endpoints_verify_json_reports_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The verify JSON view is machine readable and reports success."""
    _isolate(tmp_path, monkeypatch)
    with stub_endpoint_server() as base_url:
        _invoke(["endpoints", "certify", "--base-url", base_url, "--model", "tiny-coder"])
    result = _invoke(
        ["endpoints", "verify", "--base-url", base_url, "--model", "tiny-coder", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["reason"] == ""
    assert payload["fingerprint"]


def test_endpoints_verify_missing_receipt_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifying an endpoint that was never certified fails closed."""
    _isolate(tmp_path, monkeypatch)
    result = _invoke(
        ["endpoints", "verify", "--base-url", "http://127.0.0.1:9/v1", "--model", "ghost", "--json"]
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert "no certification" in payload["reason"]


def test_endpoints_verify_detects_tampered_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Editing the sealed receipt breaks the signature check on verify."""
    _isolate(tmp_path, monkeypatch)
    with stub_endpoint_server() as base_url:
        _invoke(["endpoints", "certify", "--base-url", base_url, "--model", "tiny-coder"])

    receipts = list((tmp_path / ".sdd" / "endpoints" / "certifications").glob("*.json"))
    assert len(receipts) == 1
    receipt = receipts[0]
    data = json.loads(receipt.read_text())
    data["model"] = "tampered-model"
    receipt.write_text(json.dumps(data, separators=(",", ":"), sort_keys=True))

    # The tampered file no longer matches the requested (base_url, model).
    result = _invoke(
        ["endpoints", "verify", "--base-url", base_url, "--model", "tiny-coder", "--json"]
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["ok"] is False
