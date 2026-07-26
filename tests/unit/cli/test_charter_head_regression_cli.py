"""Post-seal charter tail loss through the real CLI surfaces.

These are the three crash/truncation shapes that used to pass every pillar:

* whole post-seal charter history dropped back to the seal boundary (all
  pillars green, revocation reverted),
* partial post-seal loss laundered permanently by a plain ``audit seal``,
* loss on a chain that was never sealed at all.

Each must now fail ``bernstein audit verify`` (charter pillar), refuse
``bernstein audit seal``, refuse ``tenant slice`` / ``tenant showback``, and be
reported by ``tenant verify`` - until acknowledged via
``bernstein audit ack-tear --segment charter:<tenant> --offset <seq>``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from bernstein.cli.commands.audit_cmd import audit_group
from bernstein.cli.commands.tenant_cmd import tenant_group

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    key_path = tmp_path / "audit.key"
    key_path.write_bytes(b"\x33" * 32)
    key_path.chmod(0o600)
    monkeypatch.setenv("BERNSTEIN_AUDIT_KEY_PATH", str(key_path))
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".sdd" / "audit").mkdir(parents=True)
    return tmp_path


def _tenant(args: list[str], workdir: Path) -> object:
    return CliRunner().invoke(tenant_group, [*args, "--workdir", str(workdir)])


def _audit(args: list[str]) -> object:
    return CliRunner().invoke(audit_group, args)


def _drop_last_records(workdir: Path, count: int) -> None:
    segment = max((workdir / ".sdd" / "audit").glob("*.jsonl"))
    records = segment.read_bytes().split(b"\n")[:-1]
    assert len(records) > count
    segment.write_bytes(b"\n".join(records[:-count]) + b"\n")


class TestPostSealTailLoss:
    def test_full_post_seal_loss_no_longer_passes_every_pillar(self, workdir: Path) -> None:
        """Case: everything since the nightly seal drops at a record boundary."""
        assert _tenant(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        assert _tenant(["grant", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        assert _audit(["seal"]).exit_code == 0
        assert _tenant(["grant", "acme", "--principal", "carol", "--by", "alice"], workdir).exit_code == 0
        assert _tenant(["revoke", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        _drop_last_records(workdir, 2)

        verify = _audit(["verify"])
        assert verify.exit_code == 1
        assert "charter" in verify.output.lower()
        assert "pinned" in verify.output.lower()

        sliced = _tenant(["slice", "acme", "--since", "2000-01-01", "--until", "2999-01-01"], workdir)
        assert sliced.exit_code != 0
        assert "refusing to mint an audit slice" in sliced.output

        statement = _tenant(["showback", "acme", "--from", "2000-01-01", "--to", "2999-01-01"], workdir)
        assert statement.exit_code != 0
        assert "refusing to mint a showback statement" in statement.output

        assert _audit(["seal"]).exit_code != 0

    def test_partial_post_seal_loss_is_not_laundered_by_a_plain_reseal(self, workdir: Path) -> None:
        assert _tenant(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        assert _tenant(["grant", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        assert _audit(["seal"]).exit_code == 0
        assert _tenant(["grant", "acme", "--principal", "carol", "--by", "alice"], workdir).exit_code == 0
        assert _tenant(["revoke", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        _drop_last_records(workdir, 1)

        reseal = _audit(["seal"])
        assert reseal.exit_code != 0, reseal.output
        assert "charter" in reseal.output.lower()

    def test_loss_on_a_never_sealed_chain_is_caught(self, workdir: Path) -> None:
        assert _tenant(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        assert _tenant(["grant", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        assert _tenant(["revoke", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        _drop_last_records(workdir, 1)

        verify = _audit(["verify"])
        assert verify.exit_code == 1
        assert "charter" in verify.output.lower()
        assert "pinned" in verify.output.lower()

        first_seal = _audit(["seal"])
        assert first_seal.exit_code != 0, first_seal.output

    def test_tenant_verify_reports_the_head_regression(self, workdir: Path) -> None:
        assert _tenant(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        assert _tenant(["grant", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        assert _tenant(["revoke", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        _drop_last_records(workdir, 1)

        result = _tenant(["verify", "acme", "--json"], workdir)
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["charter_head_ok"] is False
        assert payload["charter_head_errors"]

    def test_ack_tear_authorises_recovery(self, workdir: Path) -> None:
        assert _tenant(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        assert _tenant(["grant", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        assert _audit(["seal"]).exit_code == 0
        assert _tenant(["grant", "acme", "--principal", "carol", "--by", "alice"], workdir).exit_code == 0
        assert _tenant(["revoke", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        _drop_last_records(workdir, 1)
        assert _audit(["seal"]).exit_code != 0

        acked = _audit(
            ["ack-tear", "--segment", "charter:acme", "--offset", "3", "--reason", "restored from backup review"]
        )
        assert acked.exit_code == 0, acked.output

        assert _audit(["seal"]).exit_code == 0
        assert _audit(["verify"]).exit_code == 0
        sliced = _tenant(["slice", "acme", "--since", "2000-01-01", "--until", "2999-01-01"], workdir)
        assert sliced.exit_code == 0, sliced.output
