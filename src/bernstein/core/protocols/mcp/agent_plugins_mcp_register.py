"""Register MCP servers from a plugin's ``mcp.json`` (issue #3773).

Slice 2 of 2 of #3540. Parses the Agent Plugins v1.0.0 ``mcpServers``
shape into ``MCPServerConfig`` objects, expands ``${PLUGIN_ROOT}`` /
``${PLUGIN_DATA}`` template variables in stdio server commands and
arguments, and surfaces per-server validation diagnostics so a single
invalid entry never blocks the rest of a plugin from registering.

The ``${PLUGIN_ROOT}`` expansion follows the precedent set by the
hook-script plugin mechanism (``bernstein.plugins.manager``); we use the
same substitution approach (``substitute_template_vars``) but do not
couple this module to that one — a hook-script plugin and an Agent
Plugins v1.0.0 plugin are independent mechanisms.

``${PLUGIN_DATA}`` is intentionally scoped to MCP-plugin installs. It
lives next to its plugin's install root (so it survives a plugin
update that re-extracts the source tree but keeps the same name) and is
not shared with the hook-script plugin's data directory, avoiding
implicit coupling between two independent plugin shapes.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from bernstein.core.protocols.mcp.mcp_manager import (
    MCPServerConfig,
    parse_server_configs,
)

logger = logging.getLogger(__name__)


def _plugin_data_root() -> Path:
    """Root directory for per-plugin ``PLUGIN_DATA`` directories.

    Uses ``~/.bernstein/plugins-data/`` by default and honours the
    ``BERNSTEIN_PLUGIN_DATA_ROOT`` environment variable for tests and
    air-gap deployments.
    """
    override = os.environ.get("BERNSTEIN_PLUGIN_DATA_ROOT")
    if override:
        return Path(override)
    return Path.home() / ".bernstein" / "plugins-data"


def resolve_plugin_data_dir(plugin_root: Path) -> Path:
    """Resolve the persistent ``PLUGIN_DATA`` directory for a plugin.

    The directory is keyed on the plugin's *name* (top-level directory
    under the plugins tree), not its on-disk path. A plugin update that
    re-extracts the same name under a new parent directory therefore
    keeps the same ``PLUGIN_DATA`` and any state the plugin persisted
    there survives the upgrade.
    """
    name = Path(plugin_root).name
    return _plugin_data_root() / name


def _substitute(value: Any, mapping: dict[str, str]) -> Any:
    """Replace ``${VAR}`` occurrences in *value* using *mapping*.

    Mirrors the hook-script plugin mechanism's
    ``substitute_template_vars`` semantics: only known variables are
    replaced; unknown placeholders are left intact so a typo in a
    plugin's ``mcp.json`` is visible rather than silently dropped.
    """
    if not isinstance(value, str):
        return value
    out = value
    for key, replacement in mapping.items():
        out = out.replace("${" + key + "}", replacement)
    return out


def _expand_command(command: list[str], mapping: dict[str, str]) -> list[str]:
    return [_substitute(part, mapping) for part in command]


def _plugin_template_vars(plugin_root: Path) -> dict[str, str]:
    plugin_root = Path(plugin_root).resolve()
    return {
        "PLUGIN_ROOT": str(plugin_root),
        "PLUGIN_DATA": str(resolve_plugin_data_dir(plugin_root)),
    }


def _parse_raw_payload(
    payload: dict[str, Any],
    *,
    template_vars: dict[str, str] | None = None,
) -> tuple[list[MCPServerConfig], list[str]]:
    """Parse the ``mcpServers`` mapping of an Agent Plugins v1.0.0 manifest.

    Returns the parsed ``MCPServerConfig`` list and a list of diagnostic
    strings naming servers that were skipped (empty command list, empty
    plugin name, etc.). ``template_vars`` is applied to stdio command
    strings before ``parse_server_configs`` sees them.
    """
    raw_servers_obj: object = payload.get("mcpServers")
    if not isinstance(raw_servers_obj, dict) or not raw_servers_obj:
        return [], []
    raw_servers: dict[str, dict[str, Any]] = raw_servers_obj

    expanded: dict[str, dict[str, Any]] = {}
    diagnostics: list[str] = []

    for name_obj, defn_obj in raw_servers.items():
        name = str(name_obj)
        defn: Any = defn_obj
        if not isinstance(defn, dict):
            diagnostics.append(f"plugin server {name!r}: definition is not an object")
            continue

        # The Agent Plugins 1.0.0 schema requires every server to carry
        # an explicit ``type`` field. Reject missing types so plugins
        # with a typo cannot silently fall through to the wrong
        # transport.
        declared_type = defn.get("type")
        if declared_type not in {"stdio", "streamable-http", "sse"}:
            diagnostics.append(
                f"plugin server {name!r}: missing or invalid 'type' "
                f"(expected stdio | streamable-http | sse, got {declared_type!r})"
            )
            continue

        # stdio servers must have at least one command part. An empty
        # command list is a silent no-op further down the stack — flag
        # it here so callers can see *why* a server was skipped.
        if declared_type == "stdio":
            cmd_check_obj: object = defn.get("command", [])
            if isinstance(cmd_check_obj, list) and len(cmd_check_obj) == 0:
                diagnostics.append(f"plugin server {name!r}: stdio server has empty 'command'")
                continue

        expanded_defn: dict[str, Any] = dict(defn)
        if template_vars is not None and declared_type == "stdio":
            cmd_obj: object = expanded_defn.get("command", [])
            if isinstance(cmd_obj, list):
                expanded_defn["command"] = _expand_command([str(c) for c in cmd_obj], template_vars)
            args_obj: object = expanded_defn.get("args", [])
            if isinstance(args_obj, list):
                expanded_defn["args"] = _expand_command([str(a) for a in args_obj], template_vars)
            env_obj: object = expanded_defn.get("env", {})
            if isinstance(env_obj, dict):
                expanded_defn["env"] = {str(k): str(_substitute(v, template_vars)) for k, v in env_obj.items()}
        expanded[name] = expanded_defn

    configs = parse_server_configs(expanded)
    return configs, diagnostics


def parse_plugin_mcp_manifest(
    plugin_root: Path | str,
) -> list[MCPServerConfig]:
    """Parse a plugin's ``mcp.json`` into ``MCPServerConfig`` objects.

    ``${PLUGIN_ROOT}`` and ``${PLUGIN_DATA}`` are expanded in stdio
    commands, args, and env values. Invalid entries are skipped with a
    ``logger.warning`` diagnostic and do not prevent the rest of the
    plugin from registering. Returns an empty list if the plugin has no
    ``mcp.json`` (skill-only plugins are unaffected by this slice).
    """
    plugin_root = Path(plugin_root)
    manifest = plugin_root / "mcp.json"
    if not manifest.is_file():
        return []

    import json

    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        logger.warning(
            "plugin %s: invalid mcp.json (%s); skipping MCP registration",
            plugin_root.name,
            exc,
        )
        return []

    template_vars = _plugin_template_vars(plugin_root)
    configs, diagnostics = _parse_raw_payload(payload, template_vars=template_vars)
    for diag in diagnostics:
        logger.warning("plugin %s: %s", plugin_root.name, diag)
    return configs


def parse_plugin_mcp_manifest_with_diagnostics(
    plugin_root: Path | str,
) -> tuple[list[MCPServerConfig], list[str]]:
    """Same as :func:`parse_plugin_mcp_manifest` but also returns diagnostics.

    Useful for tests and operator-facing tooling that want to surface
    *why* a specific server entry was skipped without having to read the
    logs.
    """
    plugin_root = Path(plugin_root)
    manifest = plugin_root / "mcp.json"
    if not manifest.is_file():
        return [], []

    import json

    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [], [f"invalid mcp.json ({exc})"]

    template_vars = _plugin_template_vars(plugin_root)
    return _parse_raw_payload(payload, template_vars=template_vars)


__all__ = [
    "parse_plugin_mcp_manifest",
    "parse_plugin_mcp_manifest_with_diagnostics",
    "resolve_plugin_data_dir",
]
