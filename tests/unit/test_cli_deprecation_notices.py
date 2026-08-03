"""Deprecation notices on ``bernstein consensus`` and ``bernstein issue-to-pr``.

Both command groups inspect state that no shipped runtime writes (#3144). They
stay registered through the 3.x line with a deprecation warning on invocation
and are removed in v4.0.0. The core modules stay importable and unchanged.

The tests go through the top-level ``cli`` entry point rather than the group
objects, so they pin the registered names; the module can be removed together
with the groups in v4.0.0.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner, Result

import bernstein.cli.commands.issue_to_pr_cmd as issue_to_pr_cmd
from bernstein.cli.main import cli


def _stderr_lines(result: Result) -> list[str]:
    return [line for line in (result.stderr or "").splitlines() if line.strip()]


def test_consensus_emits_deprecation_notice_on_invocation() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["consensus", "list"])

    assert result.exit_code == 0, result.output
    # The deprecation notice goes to stderr so stdout stays machine-parseable.
    assert any("'bernstein consensus' is deprecated" in line and "v4.0.0" in line for line in _stderr_lines(result)), (
        result.stderr
    )
    assert "no relay entries" in result.stdout


def test_consensus_notice_stays_off_stdout() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["consensus", "list"])

    assert result.exit_code == 0, result.output
    assert "deprecated" not in result.stdout
    assert "WARNING" not in result.stdout


def test_consensus_help_mentions_deprecation() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["consensus", "--help"])

    assert result.exit_code == 0, result.output
    assert "Deprecated" in result.stdout
    assert "4.0.0" in result.stdout


def test_issue_to_pr_emits_deprecation_notice_on_usage_error() -> None:
    runner = CliRunner()
    # Missing ISSUE_ID triggers a usage error, but the group callback (where
    # the deprecation notice lives) runs first -- so no gh subprocess, no
    # network, and the notice is still emitted.
    result = runner.invoke(cli, ["issue-to-pr", "trace"])

    assert result.exit_code == 2
    assert any(
        "'bernstein issue-to-pr' is deprecated" in line and "v4.0.0" in line for line in _stderr_lines(result)
    ), result.stderr
    assert "deprecated" not in result.stdout


def test_issue_to_pr_execution_keeps_stdout_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful ``trace`` run must keep its stdout identical to the
    undeprecated output, with the notice on stderr only -- so existing
    scripts keep working unchanged until v4.0.0."""

    class _StubTrace:
        def render(self) -> str:
            return "issue 42: plan comment absent, pr absent"

    class _StubPipeline:
        def __init__(self, *, config: object, client: object) -> None:
            del config, client

        def trace(self, repo: str, issue_number: int) -> _StubTrace:
            assert repo == "acme/web"
            assert issue_number == 42
            return _StubTrace()

    monkeypatch.setattr(issue_to_pr_cmd, "IssueToPRPipeline", _StubPipeline)

    runner = CliRunner()
    result = runner.invoke(cli, ["issue-to-pr", "trace", "42", "--repo", "acme/web"])

    assert result.exit_code == 0, result.output
    assert "issue 42: plan comment absent, pr absent" in result.stdout
    assert "deprecated" not in result.stdout
    assert "WARNING" not in result.stdout
    assert any("'bernstein issue-to-pr' is deprecated" in line for line in _stderr_lines(result)), result.stderr


def test_issue_to_pr_help_mentions_deprecation() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["issue-to-pr", "--help"])

    assert result.exit_code == 0, result.output
    assert "Deprecated" in result.stdout
    assert "4.0.0" in result.stdout
