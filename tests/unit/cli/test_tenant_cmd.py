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
        # A third event so the one edited below has a successor: ``broken_link``
        # is the detector for an event whose recomputed hash no longer matches
        # what the next event points at, so the segment must have a next event.
        # Tampering with the tail is caught by the HMAC chain instead.
        assert _run(["grant", "acme", "--principal", "carol", "--by", "alice"], workdir).exit_code == 0

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

    def _flip_a_chain_byte(self, workdir: Path) -> None:
        """Corrupt one recorded HMAC so 'bernstein audit verify' rejects the chain."""
        log_path = next(iter(sorted((workdir / ".sdd" / "audit").glob("*.jsonl"))))
        lines = log_path.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[0])
        row["hmac"] = ("0" if row["hmac"][0] != "0" else "1") + row["hmac"][1:]
        lines[0] = json.dumps(row)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_slice_refuses_to_mint_from_a_chain_verify_rejects(self, workdir: Path) -> None:
        """A bundle's slice-local chain verifies cleanly even when the history it
        was cut from does not, so minting one from a rejected chain launders the
        damage. The refusal names the failing verify and the command to run."""
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        self._flip_a_chain_byte(workdir)

        result = _run(["slice", "acme", "--since", "2000-01-01", "--until", "2999-01-01", "--json"], workdir)
        assert result.exit_code != 0
        assert "refusing to mint an audit slice" in result.output, result.output
        assert "bernstein audit verify" in result.output
        assert "Traceback" not in result.output
        # Nothing was written.
        assert not list((workdir / ".sdd" / "evidence").glob("*")) if (workdir / ".sdd" / "evidence").is_dir() else True

    def test_showback_refuses_to_mint_from_a_chain_verify_rejects(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        self._flip_a_chain_byte(workdir)

        out = workdir / "statement.json"
        result = _run(
            ["showback", "acme", "--from", "2000-01-01", "--to", "2999-01-01", "--out", str(out), "--json"],
            workdir,
        )
        assert result.exit_code != 0
        assert "refusing to mint a showback statement" in result.output, result.output
        assert not out.exists()

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


class TestExportGateCoversEveryVerifyPillar:
    """The export gate must match the verdict ``bernstein audit verify`` prints.

    Gating exports on the HMAC walk alone let ``tenant slice`` and
    ``tenant showback`` sign exports cut from a chain state the top-level
    verifier rejects: a truncation back to a record boundary keeps the walk
    green while the checkpoint pillar reports divergence. The gate now runs
    every damage-detecting pillar (HMAC walk and tears, checkpoint extension,
    charter head pins, the tenant's own fold), so a state ``audit verify``
    rejects as damaged cannot mint a signed bundle.
    """

    def _seal(self) -> None:
        from bernstein.cli.commands.audit_cmd import audit_group

        sealed = CliRunner().invoke(audit_group, ["seal"])
        assert sealed.exit_code == 0, sealed.output

    def _drop_last_record(self, workdir: Path) -> None:
        segment = max((workdir / ".sdd" / "audit").glob("*.jsonl"))
        records = segment.read_bytes().split(b"\n")[:-1]
        segment.write_bytes(b"\n".join(records[:-1]) + b"\n")

    def _diverge_checkpoint(self, workdir: Path) -> None:
        """Reach a state only the checkpoint pillar rejects.

        The dropped record is a generic chained event, not a charter event, so
        the HMAC walk stays green and no charter head regresses: the refusal
        below can only come from the checkpoint-extension verdict.
        """
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
        self._seal()
        self._drop_last_record(workdir)

    def test_slice_refuses_after_a_checkpoint_divergence(self, workdir: Path) -> None:
        from bernstein.cli.commands.audit_cmd import audit_group

        self._diverge_checkpoint(workdir)
        # Sanity: this is a state the top-level verifier rejects.
        assert CliRunner().invoke(audit_group, ["verify"]).exit_code == 1

        result = _run(["slice", "acme", "--since", "2000-01-01", "--until", "2999-01-01"], workdir)
        assert result.exit_code != 0
        assert "refusing to mint an audit slice" in result.output, result.output
        assert "bernstein audit verify" in result.output
        evidence = workdir / ".sdd" / "evidence"
        assert not (evidence.is_dir() and list(evidence.glob("*")))

    def test_showback_refuses_after_a_checkpoint_divergence(self, workdir: Path) -> None:
        self._diverge_checkpoint(workdir)
        out = workdir / "statement.json"
        result = _run(
            ["showback", "acme", "--from", "2000-01-01", "--to", "2999-01-01", "--out", str(out)],
            workdir,
        )
        assert result.exit_code != 0
        assert "refusing to mint a showback statement" in result.output, result.output
        assert not out.exists()


class TestUnwritableExportTarget:
    """Export writes must refuse by name, never traceback.

    The module promises the read-only commands work on a read-only snapshot,
    and the slice's default output directory sits beside the audit dir - so an
    unwritable target is an ordinary operator situation, not an internal
    error.
    """

    def test_slice_refuses_cleanly_when_the_out_dir_cannot_be_created(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        blocked = workdir / "blocked"
        blocked.mkdir()
        blocked.chmod(0o500)
        try:
            result = _run(
                [
                    "slice",
                    "acme",
                    "--since",
                    "2000-01-01",
                    "--until",
                    "2999-01-01",
                    "--out",
                    str(blocked / "evidence"),
                ],
                workdir,
            )
        finally:
            blocked.chmod(0o700)
        assert result.exit_code != 0
        assert "not writable" in result.output, result.output
        assert "--out" in result.output
        assert not isinstance(result.exception, PermissionError)

    def test_showback_refuses_cleanly_when_the_out_path_is_unwritable(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        blocked = workdir / "blocked"
        blocked.mkdir()
        blocked.chmod(0o500)
        try:
            result = _run(
                [
                    "showback",
                    "acme",
                    "--from",
                    "2000-01-01",
                    "--to",
                    "2999-01-01",
                    "--out",
                    str(blocked / "deeper" / "statement.json"),
                ],
                workdir,
            )
        finally:
            blocked.chmod(0o700)
        assert result.exit_code != 0
        assert "not writable" in result.output, result.output
        assert not isinstance(result.exception, PermissionError)


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
        """Rewrite whichever recorded event carries the budget into an unusable one."""
        log_path = next(iter(sorted((workdir / ".sdd" / "audit").glob("*.jsonl"))))
        patched: list[str] = []
        for line in log_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            body = (row.get("details") or {}).get("charter") or {}
            if row.get("event_type") == EVENT_TENANT_CHARTER and "budget_usd" in (body.get("body") or {}):
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


class TestOpeningACharterIsOneAppend:
    """An interrupted ``create`` must leave nothing, not half a charter.

    The chain transaction is exclusion, not atomicity: a batch stopped midway
    commits the prefix already written, and an append-only log has no rollback.
    Opening as a batch (open, then member_add, then optionally budget_set) put a
    reachable state on the chain in which a Ctrl-C left an opened charter with
    nobody in it - folded as healthy by ``tenant verify``, ``tenant show`` and
    the ``audit verify`` charter pillar, and impossible to complete because the
    tenant id was taken.

    The opening now carries its whole meaning in one event, so there is no
    prefix to commit.
    """

    def _charter_records(self, workdir: Path) -> list[dict]:
        out: list[dict] = []
        for segment in sorted((workdir / ".sdd" / "audit").glob("*.jsonl")):
            for line in segment.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("event_type") == EVENT_TENANT_CHARTER:
                    out.append(row)
        return out

    def test_create_appends_exactly_one_charter_record(self, workdir: Path) -> None:
        assert _run(["create", "acme", "--principal", "alice", "--role", "owner"], workdir).exit_code == 0
        assert len(self._charter_records(workdir)) == 1

    def test_create_with_a_budget_still_appends_exactly_one(self, workdir: Path) -> None:
        created = _run(["create", "acme", "--principal", "alice", "--budget-usd", "250.000000000", "--json"], workdir)
        assert created.exit_code == 0, created.output
        assert len(self._charter_records(workdir)) == 1
        state = json.loads(created.output)["state"]
        assert state["budget_usd"] == "250.000000000"
        assert state["members"] == [{"principal": "alice", "role": "owner"}]

    @pytest.mark.parametrize("interrupt_at", [1, 2, 3])
    def test_an_interrupted_create_never_leaves_a_charter_without_its_owner(
        self, workdir: Path, monkeypatch: pytest.MonkeyPatch, interrupt_at: int
    ) -> None:
        """Ctrl-C at any append of the create: nothing, or a complete charter.

        ``KeyboardInterrupt`` from inside the Nth charter append is where an
        operator's Ctrl-C lands. Whatever survives must be diagnosable: an
        opened charter with nobody in it folds as healthy for every verifier,
        cannot be completed because the tenant id is taken, and cannot be undone
        because the log is append-only.
        """
        from bernstein.core.security.audit import AuditLog

        real_log = AuditLog.log
        seen = {"n": 0}

        def _interrupted(self: AuditLog, event_type: str, *args: object, **kwargs: object) -> object:
            if event_type == EVENT_TENANT_CHARTER:
                seen["n"] += 1
                if seen["n"] == interrupt_at:
                    raise KeyboardInterrupt
            return real_log(self, event_type, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(AuditLog, "log", _interrupted)
        _run(["create", "acme", "--principal", "alice", "--budget-usd", "250.000000000"], workdir)
        monkeypatch.undo()

        records = self._charter_records(workdir)
        if not records:
            # Nothing committed: the tenant id is still free, so a retry works.
            retried = _run(["create", "acme", "--principal", "alice", "--json"], workdir)
            assert retried.exit_code == 0, retried.output
            assert json.loads(retried.output)["state"]["members"] == [{"principal": "alice", "role": "owner"}]
            return

        shown = _run(["show", "acme", "--json"], workdir)
        assert shown.exit_code == 0, shown.output
        assert json.loads(shown.output)["state"]["members"], (
            f"an interrupt at append {interrupt_at} left an opened charter with no members; "
            "every verifier folds that as healthy and no operator can complete or undo it"
        )

    def test_a_charter_opened_without_a_member_is_still_readable(self, workdir: Path) -> None:
        """The API can still open an empty charter and enrol afterwards.

        The CLI no longer produces one, but the fold must not start refusing a
        shape it accepted, or an existing recorded charter would stop reading.
        """
        from bernstein.core.security.audit import load_or_create_audit_key
        from bernstein.core.security.audit_chain import AuditChainStore
        from bernstein.core.security.tenant_charter import (
            CHARTER_OPEN,
            next_event,
            record_charter_event,
        )

        chain = AuditChainStore(workdir / ".sdd" / "audit", key=load_or_create_audit_key())
        record_charter_event(chain, next_event(None, tenant_id="legacy", kind=CHARTER_OPEN, principal="ops"))

        shown = _run(["show", "legacy", "--json"], workdir)
        assert shown.exit_code == 0, shown.output
        assert json.loads(shown.output)["state"]["members"] == []
        assert _run(["grant", "legacy", "--principal", "alice", "--by", "ops"], workdir).exit_code == 0


class TestAConcurrentWriterIsSerialisedNotRaced:
    """Write commands hold one append section across read + mint + append.

    A rival can therefore only land *before* the command's section, never
    inside it: the command then reads the rival's event and applies to the new
    tail, so a concurrent grant or revoke succeeds instead of losing a race.
    The one refusal that remains through the CLI is ``create``'s duplicate
    guard - an opening is the only decision a later write cannot absorb - and
    it must read as ``Error: ...``, never as a traceback an operator cannot
    tell from a broken tool. (The stale-predecessor refusal stays the
    recording API's contract; test_tenant_charter.py covers it.)
    """

    def _rival_appends_first(self, monkeypatch: pytest.MonkeyPatch, workdir: Path, *, tenant: str) -> None:
        """Append to *tenant*'s charter just before the command enters its section."""
        import contextlib

        from bernstein.core.security.audit_chain import AuditChainStore
        from bernstein.core.security.tenant_charter import (
            CHARTER_MEMBER_ADD,
            next_event,
            open_event,
            read_charter_events,
            record_charter_event,
        )

        real_transaction = AuditChainStore.chain_transaction
        fired = {"done": False}

        @contextlib.contextmanager
        def _transaction(self: AuditChainStore) -> object:
            if not fired["done"]:
                fired["done"] = True
                recorded = read_charter_events(self, tenant)
                if recorded:
                    event = next_event(
                        recorded[-1],
                        tenant_id=tenant,
                        kind=CHARTER_MEMBER_ADD,
                        principal="rival",
                        body={"principal": "carol"},
                    )
                else:
                    event = open_event(tenant_id=tenant, principal="rival")
                record_charter_event(self, event)
            with real_transaction(self):
                yield

        monkeypatch.setattr(AuditChainStore, "chain_transaction", _transaction)

    def test_a_lost_create_race_says_the_charter_already_exists(
        self, workdir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An opening cannot be re-applied on top of the winner's, so it is refused."""
        self._rival_appends_first(monkeypatch, workdir, tenant="acme")
        result = _run(["create", "acme", "--principal", "alice"], workdir)

        assert result.exit_code != 0
        assert "a charter already exists for tenant 'acme'" in result.output, result.output
        assert "Traceback" not in result.output
        assert result.exception is None or isinstance(result.exception, SystemExit), result.exception

    def test_a_concurrent_grant_lands_on_the_new_tail(self, workdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        self._rival_appends_first(monkeypatch, workdir, tenant="acme")
        result = _run(["grant", "acme", "--principal", "bob", "--by", "alice", "--json"], workdir)

        assert result.exit_code == 0, result.output
        principals = {m["principal"] for m in json.loads(result.output)["state"]["members"]}
        assert principals == {"alice", "bob", "carol"}, principals

    def test_a_concurrent_revoke_lands_on_the_new_tail(self, workdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        assert _run(["grant", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        self._rival_appends_first(monkeypatch, workdir, tenant="acme")
        result = _run(["revoke", "acme", "--principal", "bob", "--by", "alice", "--json"], workdir)

        assert result.exit_code == 0, result.output
        principals = {m["principal"] for m in json.loads(result.output)["state"]["members"]}
        assert principals == {"alice", "carol"}, principals

    def test_the_charter_still_folds_after_a_refused_create(
        self, workdir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The refusal must leave the chain readable; the winner's opening is the tail."""
        self._rival_appends_first(monkeypatch, workdir, tenant="acme")
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code != 0

        verified = _run(["verify", "acme", "--json"], workdir)
        assert verified.exit_code == 0, verified.output
        payload = json.loads(verified.output)
        assert payload["ok"] is True
        assert payload["audit_chain_ok"] is True
        shown = json.loads(_run(["show", "acme", "--json"], workdir).output)
        principals = [member["principal"] for member in shown["state"]["members"]]
        assert principals == ["rival"], principals
