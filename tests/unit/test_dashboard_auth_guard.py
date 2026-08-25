"""Regression tests for deprecated `bernstein dashboard` command (#4395)."""

from __future__ import annotations

from click.testing import CliRunner

from bernstein.cli.commands import advanced_cmd


def test_dashboard_command_is_deprecated_and_directs_to_gui_serve() -> None:
    """The legacy dashboard command prints deprecation guidance and exits non-zero."""
    runner = CliRunner()
    result = runner.invoke(advanced_cmd.dashboard, [])

    assert result.exit_code == 1
    assert "gui serve" in result.output
    assert "/ui" in result.output
    assert "bernstein[gui]" in result.output
