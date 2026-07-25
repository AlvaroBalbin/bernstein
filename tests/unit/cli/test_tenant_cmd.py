"""``bernstein tenant`` end-to-end over a real chain (#2554)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from bernstein.cli.commands.tenant_cmd import tenant_group
from bernstein.core.security.audit_chain import EVENT_TENANT_CHARTER


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A project root with an isolated audit key, so the CLI is self-contained."""
    key_path = tmp_path / "audit.key"
    key_path.write_bytes(b"\x33" * 32)
    key_path.chmod(0o600)
    monkeypatch.setenv("BERNSTEIN_AUDIT_KEY_PATH", str(key_path))
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".sdd" / "audit").mkdir(parents=True)
    return tmp_path


def _run(args: list[str], workdir: Path) -> object:
    return CliRunner().invoke(tenant_group, [*args, "--workdir", str(workdir)])


class TestTenantCli:
    def test_create_show_and_verify(self, workdir: Path) -> None:
        created = _run(["create", "acme", "--principal", "alice", "--budget-usd", "250.000000000", "--json"], workdir)
        assert created.exit_code == 0, created.output
        charter_hash = json.loads(created.output)["charter_hash"]

        shown = _run(["show", "acme", "--json"], workdir)
        assert shown.exit_code == 0, shown.output
        payload = json.loads(shown.output)
        assert payload["charter_hash"] == charter_hash
        assert payload["state"]["budget_usd"] == "250.000000000"
        assert payload["state"]["members"] == [{"principal": "alice", "role": "owner"}]

        verified = _run(["verify", "acme", "--json"], workdir)
        assert verified.exit_code == 0, verified.output
        assert json.loads(verified.output)["ok"] is True

    def test_creating_twice_is_refused(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        second = _run(["create", "acme", "--principal", "alice"], workdir)
        assert second.exit_code != 0
        assert "already exists" in second.output

    def test_grant_and_revoke_move_the_charter_hash(self, workdir: Path) -> None:
        created = _run(["create", "acme", "--principal", "alice", "--json"], workdir)
        opened = json.loads(created.output)["charter_hash"]

        granted = _run(
            ["grant", "acme", "--principal", "bob", "--role", "approver", "--by", "alice", "--json"], workdir
        )
        assert granted.exit_code == 0, granted.output
        after_grant = json.loads(granted.output)
        assert after_grant["charter_hash"] != opened
        assert {m["principal"] for m in after_grant["state"]["members"]} == {"alice", "bob"}

        # Re-granting an existing member records a role change, not a duplicate.
        re_roled = _run(["grant", "acme", "--principal", "bob", "--role", "member", "--by", "alice", "--json"], workdir)
        assert re_roled.exit_code == 0, re_roled.output
        assert json.loads(re_roled.output)["state"]["members"][1]["role"] == "member"

        revoked = _run(["revoke", "acme", "--principal", "bob", "--by", "alice", "--json"], workdir)
        assert revoked.exit_code == 0, revoked.output
        assert {m["principal"] for m in json.loads(revoked.output)["state"]["members"]} == {"alice"}

    def test_grant_without_a_charter_is_refused(self, workdir: Path) -> None:
        result = _run(["grant", "nope", "--principal", "bob"], workdir)
        assert result.exit_code != 0
        assert "no charter" in result.output

    def test_verify_fails_and_exits_non_zero_after_tampering(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        assert _run(["grant", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0

        log_path = next(iter(sorted((workdir / ".sdd" / "audit").glob("*.jsonl"))))
        patched: list[str] = []
        for line in log_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            body = (row.get("details") or {}).get("charter") or {}
            if row.get("event_type") == EVENT_TENANT_CHARTER and body.get("seq") == 1:
                body["body"]["role"] = "root"
            patched.append(json.dumps(row))
        log_path.write_text("\n".join(patched) + "\n", encoding="utf-8")

        result = _run(["verify", "acme", "--json"], workdir)
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["ok"] is False
        assert payload["reason"] == "broken_link"
        assert payload["audit_chain_ok"] is False

    def test_slice_is_charter_keyed(self, workdir: Path) -> None:
        from bernstein.core.security.audit_chain import AuditChainStore

        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        chain = AuditChainStore(workdir / ".sdd" / "audit", key=(workdir / "audit.key").read_bytes())
        chain.log_with_prev_digest(
            event_type="task.transition",
            actor="orchestrator",
            resource_type="task",
            resource_id="t1",
            details={"principal": "alice", "tenant_id": "acme"},
        )
        chain.log_with_prev_digest(
            event_type="task.transition",
            actor="orchestrator",
            resource_type="task",
            resource_id="t2",
            details={"principal": "mallory", "tenant_id": "acme"},
        )

        result = _run(["slice", "acme", "--since", "2000-01-01", "--until", "2999-01-01", "--json"], workdir)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["excluded_principals"] == [{"events": 1, "principal": "mallory"}]
        assert payload["members"] == ["alice"]

    def test_showback_and_verify_statement_round_trip(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0

        ledger = workdir / ".sdd" / "cost" / "ledger.jsonl"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        rows = [
            {
                "ts": 1.0,
                "ts_iso": "2026-07-10T00:00:00Z",
                "run_id": "run-1",
                "task_id": "task-1",
                "agent_id": "agent-1",
                "role": "backend",
                "feature_label": "f",
                "model": "claude-opus-4",
                "input_tokens": 10,
                "output_tokens": 5,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "cost_usd": 1.25,
                "tags": {"tenant_id": "acme", "lineage_record_id": "lin-1", "audit_entry_hmac": "ab" * 32},
            },
            {
                "ts": 2.0,
                "ts_iso": "2026-07-11T00:00:00Z",
                "run_id": "run-2",
                "task_id": "task-2",
                "agent_id": "agent-2",
                "role": "qa",
                "feature_label": "f",
                "model": "claude-opus-4",
                "input_tokens": 1,
                "output_tokens": 1,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "cost_usd": 0.5,
                "tags": {"tenant_id": "globex"},
            },
        ]
        ledger.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

        out = workdir / "statement.json"
        result = _run(
            ["showback", "acme", "--from", "2026-07-01", "--to", "2026-08-01", "--out", str(out), "--json"],
            workdir,
        )
        assert result.exit_code == 0, result.output
        statement = json.loads(result.output)
        # The sibling tenant's row is not in our statement.
        assert statement["totals"]["line_item_count"] == 1
        assert statement["totals"]["amount_usd"] == "1.250000000"
        assert statement["line_items"][0]["lineage_record_id"] == "lin-1"

        verified = CliRunner().invoke(tenant_group, ["verify-statement", str(out), "--json"])
        assert verified.exit_code == 0, verified.output
        assert json.loads(verified.output)["ok"] is True

    def test_verify_statement_exits_non_zero_on_a_flipped_field(self, workdir: Path, tmp_path: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        ledger = workdir / ".sdd" / "cost" / "ledger.jsonl"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text(
            json.dumps(
                {
                    "ts": 1.0,
                    "ts_iso": "2026-07-10T00:00:00Z",
                    "run_id": "run-1",
                    "task_id": "task-1",
                    "agent_id": "agent-1",
                    "role": "backend",
                    "feature_label": "f",
                    "model": "claude-opus-4",
                    "input_tokens": 10,
                    "output_tokens": 5,
                    "cache_read_tokens": 0,
                    "cache_write_tokens": 0,
                    "cost_usd": 1.25,
                    "tags": {"tenant_id": "acme"},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        out = tmp_path / "statement.json"
        assert (
            _run(
                ["showback", "acme", "--from", "2026-07-01", "--to", "2026-08-01", "--out", str(out)], workdir
            ).exit_code
            == 0
        )

        tampered = json.loads(out.read_text(encoding="utf-8"))
        tampered["line_items"][0]["amount_nano_usd"] = "1"
        out.write_text(json.dumps(tampered), encoding="utf-8")

        result = CliRunner().invoke(tenant_group, ["verify-statement", str(out), "--json"])
        assert result.exit_code == 1
        assert json.loads(result.output)["ok"] is False

    def test_show_without_a_charter_is_a_clean_error(self, workdir: Path) -> None:
        result = _run(["show", "ghost"], workdir)
        assert result.exit_code != 0
        assert "no charter" in result.output

    def test_human_output_renders(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        shown = _run(["show", "acme"], workdir)
        assert shown.exit_code == 0, shown.output
        assert "acme" in shown.output
        assert "charter hash" in shown.output


def test_group_is_registered_on_the_root_cli() -> None:
    from bernstein.cli.main import cli

    assert "tenant" in cli.commands
    assert os.path.basename(__file__) == "test_tenant_cmd.py"


def _age_and_archive(workdir: Path) -> list[str]:
    """Run ordinary retention over the audit dir, archiving the opening segment."""
    from bernstein.core.security.audit import AuditLog, RetentionPolicy

    audit_dir = workdir / ".sdd" / "audit"
    key = (workdir / "audit.key").read_bytes()
    for path in sorted(audit_dir.glob("*.jsonl")):
        path.rename(audit_dir / "2020-01-01.jsonl")
    return list(AuditLog(audit_dir=audit_dir, key=key).archive(RetentionPolicy(retention_days=1)).archived)


class TestCharterSurvivesRetentionThroughTheCli:
    """Retention must not be a governance bypass.

    Every one of these worked before the charter readers included archived
    segments, which made ordinary log retention - not forgery - the cheapest
    way to take over an existing tenant.
    """

    def test_a_second_create_is_refused_after_the_opening_segment_is_archived(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        assert _age_and_archive(workdir) == ["2020-01-01.jsonl"]

        takeover = _run(["create", "acme", "--principal", "mallory"], workdir)
        assert takeover.exit_code != 0
        assert "already exists" in takeover.output

        # The original owner is untouched.
        shown = _run(["show", "acme", "--json"], workdir)
        assert shown.exit_code == 0, shown.output
        assert json.loads(shown.output)["state"]["members"] == [{"principal": "alice", "role": "owner"}]

    def test_show_and_verify_still_work_after_archiving(self, workdir: Path) -> None:
        created = _run(["create", "acme", "--principal", "alice", "--json"], workdir)
        charter_hash = json.loads(created.output)["charter_hash"]
        _age_and_archive(workdir)

        shown = _run(["show", "acme", "--json"], workdir)
        assert shown.exit_code == 0, shown.output
        assert json.loads(shown.output)["charter_hash"] == charter_hash

        verified = _run(["verify", "acme", "--json"], workdir)
        assert verified.exit_code == 0, verified.output
        payload = json.loads(verified.output)
        assert payload["ok"] is True
        assert payload["audit_chain_ok"] is True

    def test_grant_still_extends_an_archived_charter(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        _age_and_archive(workdir)

        granted = _run(["grant", "acme", "--principal", "bob", "--by", "alice", "--json"], workdir)
        assert granted.exit_code == 0, granted.output
        assert {m["principal"] for m in json.loads(granted.output)["state"]["members"]} == {"alice", "bob"}

        revoked = _run(["revoke", "acme", "--principal", "bob", "--by", "alice", "--json"], workdir)
        assert revoked.exit_code == 0, revoked.output
        assert {m["principal"] for m in json.loads(revoked.output)["state"]["members"]} == {"alice"}


class TestVerifyReportsDamageInsteadOfCrashing:
    def _corrupt_budget(self, workdir: Path) -> None:
        log_path = next(iter(sorted((workdir / ".sdd" / "audit").glob("*.jsonl"))))
        patched: list[str] = []
        for line in log_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            body = (row.get("details") or {}).get("charter") or {}
            if row.get("event_type") == EVENT_TENANT_CHARTER and body.get("kind") == "charter.budget_set":
                body["body"]["budget_usd"] = "1e9"
            patched.append(json.dumps(row))
        log_path.write_text("\n".join(patched) + "\n", encoding="utf-8")

    def test_a_rewritten_budget_exits_one_with_a_verdict(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice", "--budget-usd", "250.000000000"], workdir).exit_code == 0
        self._corrupt_budget(workdir)

        result = _run(["verify", "acme", "--json"], workdir)
        assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["ok"] is False
        assert payload["reason"] in {"malformed_body", "broken_link"}
        assert payload["detail"]

    def test_grant_on_a_damaged_charter_fails_cleanly(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice", "--budget-usd", "250.000000000"], workdir).exit_code == 0
        self._corrupt_budget(workdir)

        result = _run(["grant", "acme", "--principal", "bob", "--by", "alice"], workdir)
        assert result.exit_code != 0
        # A ClickException, not a traceback the operator has to interpret.
        assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
