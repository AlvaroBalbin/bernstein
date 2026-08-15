"""Tests for issue #3773 — register MCP servers from a plugin's mcp.json.

Slice 2 of 2 of #3540. Validates that ``MCPServerConfig`` objects parsed from a
plugin's ``mcp.json`` (Agent Plugins v1.0.0 shape) flow through
``validate_mcp_configs`` and that ``${PLUGIN_ROOT}`` / ``${PLUGIN_DATA}``
template variables expand in stdio server commands and arguments.

All tests are offline: ``shutil.which`` and ``os.environ`` are stubbed so the
command / env-var checks are deterministic, and URL reachability is never
exercised.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from bernstein.core.protocols.mcp.mcp_config_validator import (
    validate_mcp_configs,
)
from bernstein.core.protocols.mcp.mcp_manager import MCPServerConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_plugin_mcp_json(
    plugin_dir: Path,
    *,
    server_name: str,
    command: list[str] | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    server_type: str = "stdio",
    url: str | None = None,
) -> Path:
    """Write an Agent Plugins v1.0.0 mcp.json with a single server entry."""
    payload: dict[str, Any] = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {
            server_name: {
                "command": command if command is not None else ["mytool"],
                "args": [],
                "type": server_type,
            },
        },
    }
    if env is not None:
        payload["mcpServers"][server_name]["env"] = env
    if cwd is not None:
        payload["mcpServers"][server_name]["cwd"] = cwd
    if url is not None:
        payload["mcpServers"][server_name]["url"] = url
    if server_type == "stdio":
        # Remove the spurious url key (mirrors the schema: type=stdio excludes url).
        payload["mcpServers"][server_name].pop("url", None)

    path = plugin_dir / "mcp.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _make_plugin(tmp_path: Path, name: str) -> Path:
    plugin_dir = tmp_path / "plugins" / name
    plugin_dir.mkdir(parents=True)
    return plugin_dir


# ---------------------------------------------------------------------------
# Module under test
# ---------------------------------------------------------------------------


# The implementation module is added by the slice. Importing it lazily keeps
# the RED phase honest: a missing module raises ModuleNotFoundError today.
def _load_register_module():
    from bernstein.core.protocols.mcp import agent_plugins_mcp_register

    return agent_plugins_mcp_register


# ---------------------------------------------------------------------------
# TDD RED assertions
# ---------------------------------------------------------------------------


class TestParsePluginMcpJson:
    """A plugin's mcp.json round-trips into MCPServerConfig objects."""

    def test_parse_single_valid_stdio_server(self, tmp_path: Path) -> None:
        plugin = _make_plugin(tmp_path, "alpha")
        _write_plugin_mcp_json(
            plugin,
            server_name="github",
            command=["npx", "-y", "@anthropic/github-mcp"],
            env={"GITHUB_TOKEN": "tok"},
        )

        mod = _load_register_module()
        configs = mod.parse_plugin_mcp_manifest(plugin)

        assert len(configs) == 1
        cfg = configs[0]
        assert isinstance(cfg, MCPServerConfig)
        assert cfg.name == "github"
        assert cfg.command == ["npx", "-y", "@anthropic/github-mcp"]
        assert cfg.transport == "stdio"
        assert cfg.env == {"GITHUB_TOKEN": "tok"}

    def test_parse_skips_invalid_server_alongside_valid(self, tmp_path: Path) -> None:
        """One server missing its command + one valid server in the same file.

        The valid server must still register; the invalid one must be skipped
        (not fatal) with a diagnostic captured by the caller.
        """
        plugin = _make_plugin(tmp_path, "beta")
        path = plugin / "mcp.json"
        path.write_text(
            json.dumps(
                {
                    "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
                    "mcpServers": {
                        "ghost": {"command": [], "args": [], "type": "stdio"},
                        "good": {"command": ["mytool"], "args": [], "type": "stdio"},
                    },
                }
            ),
            encoding="utf-8",
        )

        mod = _load_register_module()
        configs, diagnostics = mod.parse_plugin_mcp_manifest_with_diagnostics(plugin)

        names = {c.name for c in configs}
        assert "good" in names
        assert "ghost" not in names
        # Diagnostic for the invalid server names it.
        assert any("ghost" in d for d in diagnostics)


class TestValidatePluginMcpServers:
    """End-to-end: plugin mcp.json -> validate_mcp_configs accepts the good entry."""

    def test_valid_entry_passes_validation(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "bernstein.core.protocols.mcp.mcp_config_validator.shutil.which",
            lambda _exe: "/usr/bin/mytool",
        )
        plugin = _make_plugin(tmp_path, "gamma")
        _write_plugin_mcp_json(plugin, server_name="good", command=["mytool"])

        mod = _load_register_module()
        configs = mod.parse_plugin_mcp_manifest(plugin)
        errors = validate_mcp_configs(configs, check_urls=False)
        assert errors == []

    def test_missing_command_is_flagged_not_fatal(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "bernstein.core.protocols.mcp.mcp_config_validator.shutil.which",
            lambda exe: None if exe == "ghost-binary" else f"/usr/bin/{exe}",
        )
        plugin = _make_plugin(tmp_path, "delta")
        # Two servers: one with a missing command, one valid.
        path = plugin / "mcp.json"
        path.write_text(
            json.dumps(
                {
                    "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
                    "mcpServers": {
                        "broken": {"command": ["ghost-binary"], "args": [], "type": "stdio"},
                        "good": {"command": ["mytool"], "args": [], "type": "stdio"},
                    },
                }
            ),
            encoding="utf-8",
        )

        mod = _load_register_module()
        configs = mod.parse_plugin_mcp_manifest(plugin)

        errors = validate_mcp_configs(configs, check_urls=False)
        names_with_errors = {e.server_name for e in errors}
        assert "broken" in names_with_errors
        assert "good" not in names_with_errors


class TestTemplateExpansion:
    """${PLUGIN_ROOT} and ${PLUGIN_DATA} expand in stdio commands/args."""

    def test_plugin_root_expands_to_install_dir(self, tmp_path: Path) -> None:
        plugin = _make_plugin(tmp_path, "epsilon")
        _write_plugin_mcp_json(
            plugin,
            server_name="node-server",
            command=["node", "${PLUGIN_ROOT}/server.js"],
        )

        mod = _load_register_module()
        configs = mod.parse_plugin_mcp_manifest(plugin)

        assert len(configs) == 1
        # The path should now contain the real plugin install dir.
        resolved = configs[0].command[1]
        assert "${PLUGIN_ROOT}" not in resolved
        assert resolved.endswith("server.js")
        assert Path(resolved).resolve().is_relative_to(plugin.resolve())

    def test_plugin_data_persists_across_updates(self, tmp_path: Path) -> None:
        plugin = _make_plugin(tmp_path, "zeta")
        # Seed a file inside PLUGIN_DATA so we can verify persistence.
        mod = _load_register_module()
        data_dir = mod.resolve_plugin_data_dir(plugin)
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "marker.txt").write_text("alive", encoding="utf-8")

        # Simulate an update: re-resolve and confirm contents survive.
        resolved_again = mod.resolve_plugin_data_dir(plugin)
        assert (resolved_again / "marker.txt").read_text(encoding="utf-8") == "alive"


# ---------------------------------------------------------------------------
# PR meta: ensure the symbol signatures are importable from the right path.
# ---------------------------------------------------------------------------


def test_register_module_exposes_public_api() -> None:
    mod = _load_register_module()
    assert hasattr(mod, "parse_plugin_mcp_manifest")
    assert hasattr(mod, "resolve_plugin_data_dir")
