"""Unit tests for the ``bernstein approve-tool`` / ``reject-tool`` commands (op-002)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from bernstein.cli.commands.approval_cmd import approve_tool_cmd, reject_tool_cmd
from bernstein.cli.commands.approve_cmd import approve
from bernstein.cli.commands.reject_cmd import reject
from bernstein.core.approval.models import PendingApproval
from bernstein.core.approval.queue import ApprovalQueue


def _queue_at(workdir: Path) -> ApprovalQueue:
    return ApprovalQueue(base_dir=workdir / ".sdd" / "runtime" / "approvals")


def test_approve_tool_handles_empty_queue_gracefully(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(approve_tool_cmd, ["--workdir", str(tmp_path)])

    assert result.exit_code == 0
    assert "No pending approvals" in result.output


def test_approve_tool_resolves_oldest_by_default(tmp_path: Path) -> None:
    queue = _queue_at(tmp_path)
    oldest = queue.push(
        PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "ls"})
    )
    queue.push(PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "pwd"}))

    runner = CliRunner()
    result = runner.invoke(approve_tool_cmd, ["--workdir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    resolved = ApprovalQueue(base_dir=queue.base_dir).get_resolution(oldest.id)
    assert resolved is not None
    assert resolved.decision.value == "allow"


def test_approve_tool_with_always_promotes_rule(tmp_path: Path) -> None:
    queue = _queue_at(tmp_path)
    approval = queue.push(
        PendingApproval(
            session_id="S",
            agent_role="backend",
            tool_name="write_file",
            tool_args={"path": "src/lib/x.py"},
        )
    )

    runner = CliRunner()
    result = runner.invoke(
        approve_tool_cmd,
        ["--workdir", str(tmp_path), "--always"],
    )

    assert result.exit_code == 0, result.output
    rules_file = tmp_path / ".bernstein" / "always_allow.yaml"
    assert rules_file.exists()
    # The resolution is recorded with decision=always.
    resolved = ApprovalQueue(base_dir=queue.base_dir).get_resolution(approval.id)
    assert resolved is not None
    assert resolved.decision.value == "always"


def test_approve_tool_with_id_selects_specific_approval(tmp_path: Path) -> None:
    queue = _queue_at(tmp_path)
    first = queue.push(
        PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "ls"})
    )
    target = queue.push(
        PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "pwd"})
    )

    runner = CliRunner()
    result = runner.invoke(
        approve_tool_cmd,
        ["--workdir", str(tmp_path), "--id", target.id],
    )

    assert result.exit_code == 0, result.output
    reopened = ApprovalQueue(base_dir=queue.base_dir)
    assert reopened.get_resolution(target.id) is not None
    # The non-targeted approval is untouched.
    assert reopened.get_resolution(first.id) is None


def test_approve_tool_unknown_id_fails(tmp_path: Path) -> None:
    queue = _queue_at(tmp_path)
    queue.push(PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "ls"}))

    runner = CliRunner()
    result = runner.invoke(
        approve_tool_cmd,
        ["--workdir", str(tmp_path), "--id", "ap-unknown"],
    )

    assert result.exit_code == 1
    assert "ap-unknown" in result.output


def test_reject_tool_records_reject_decision(tmp_path: Path) -> None:
    queue = _queue_at(tmp_path)
    approval = queue.push(
        PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "rm -rf /"})
    )

    runner = CliRunner()
    result = runner.invoke(reject_tool_cmd, ["--workdir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    resolved_file = queue.base_dir / f"{approval.id}.resolved.json"
    assert resolved_file.exists()
    assert json.loads(resolved_file.read_text())["decision"] == "reject"


def test_reject_tool_handles_empty_queue(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(reject_tool_cmd, ["--workdir", str(tmp_path)])
    assert result.exit_code == 0
    assert "No pending approvals" in result.output


# --- flag form: ``approve --tool <id>`` / ``reject --tool <id>`` (issue #3141) ---


def test_approve_flag_form_resolves_tool_approval(tmp_path: Path) -> None:
    queue = _queue_at(tmp_path)
    first = queue.push(
        PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "ls"})
    )
    target = queue.push(
        PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "pwd"})
    )

    runner = CliRunner()
    result = runner.invoke(approve, ["--tool", target.id, "--workdir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    reopened = ApprovalQueue(base_dir=queue.base_dir)
    resolved = reopened.get_resolution(target.id)
    assert resolved is not None
    assert resolved.decision.value == "allow"
    # The non-targeted approval is untouched: the identifier was parsed as an
    # approval id, not resolved as the oldest entry.
    assert reopened.get_resolution(first.id) is None


def test_approve_flag_form_matches_alias_semantics(tmp_path: Path) -> None:
    # Equivalence: ``approve --tool <id>`` must resolve identically to
    # ``approve-tool --id <id>`` (same identifier, same decision, same exit code).
    def run(cmd, args):
        return CliRunner().invoke(cmd, args)

    q_alias = _queue_at(tmp_path)
    a_alias = q_alias.push(
        PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "ls"})
    )
    r_alias = run(approve_tool_cmd, ["--workdir", str(tmp_path), "--id", a_alias.id])

    q_flag = _queue_at(tmp_path)
    a_flag = q_flag.push(
        PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "ls"})
    )
    r_flag = run(approve, ["--workdir", str(tmp_path), "--tool", a_flag.id])

    assert r_flag.exit_code == r_alias.exit_code == 0, (r_flag.output, r_alias.output)
    res_alias = ApprovalQueue(base_dir=q_alias.base_dir).get_resolution(a_alias.id)
    res_flag = ApprovalQueue(base_dir=q_flag.base_dir).get_resolution(a_flag.id)
    assert res_alias is not None and res_flag is not None
    assert res_flag.decision.value == res_alias.decision.value == "allow"


def test_approve_flag_form_unknown_id_fails(tmp_path: Path) -> None:
    queue = _queue_at(tmp_path)
    queue.push(PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "ls"}))

    result = CliRunner().invoke(approve, ["--tool", "ap-unknown", "--workdir", str(tmp_path)])

    # Same exit code as ``approve-tool --id ap-unknown``.
    assert result.exit_code == 1
    assert "ap-unknown" in result.output


def test_reject_flag_form_records_reject(tmp_path: Path) -> None:
    queue = _queue_at(tmp_path)
    approval = queue.push(
        PendingApproval(session_id="S", agent_role="backend", tool_name="shell", tool_args={"command": "rm -rf /"})
    )

    result = CliRunner().invoke(reject, ["--tool", approval.id, "--workdir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    resolved_file = queue.base_dir / f"{approval.id}.resolved.json"
    assert resolved_file.exists()
    assert json.loads(resolved_file.read_text())["decision"] == "reject"


def test_approve_without_task_or_tool_is_usage_error(tmp_path: Path) -> None:
    result = CliRunner().invoke(approve, ["--workdir", str(tmp_path)])
    assert result.exit_code == 2
    assert "TASK_ID" in result.output


def test_reject_without_task_or_tool_is_usage_error(tmp_path: Path) -> None:
    result = CliRunner().invoke(reject, ["--workdir", str(tmp_path)])
    assert result.exit_code == 2
    assert "TASK_ID" in result.output


def test_help_strings_have_no_internal_references() -> None:
    # (op-002) is an internal reference a user cannot resolve from --help.
    for cmd in (approve_tool_cmd, reject_tool_cmd, approve, reject):
        result = CliRunner().invoke(cmd, ["--help"])
        assert result.exit_code == 0, result.output
        assert "(op-002)" not in result.output
