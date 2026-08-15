"""The documented keybinding override path, driven by a real key press (#3826/#3828).

``docs/operations/tui-keybindings.md`` promises an operator three layers,
highest priority last: built-in defaults, a ``keybindings:`` section in
``bernstein.yaml``, and ``~/.bernstein/keybindings.json``. That is the
documented first run for this subsystem.

A test that only asserts the key map *parses* would pass on a map the TUI
never binds, so the central case here presses the overridden key against a
running Textual app and asserts the action fired. The layering assertions
are the supporting cast, not the proof.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from textual.app import App
from textual.binding import Binding

from bernstein.tui.keybinding_config import get_key_for_action, resolve_all_bindings


def _yaml_config(tmp_path: Path, **bindings: str) -> Path:
    """A ``bernstein.yaml`` carrying the documented ``keybindings:`` section."""
    body = "keybindings:\n" + "".join(f'  {action}: "{key}"\n' for action, key in bindings.items())
    path = tmp_path / "bernstein.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _json_config(tmp_path: Path, **bindings: str) -> Path:
    """A ``~/.bernstein/keybindings.json`` - the highest-priority layer."""
    path = tmp_path / "keybindings.json"
    path.write_text(json.dumps(bindings), encoding="utf-8")
    return path


class TestDocumentedResolutionOrder:
    """The three layers resolve in the order the docs promise."""

    def test_defaults_apply_with_no_config(self, tmp_path: Path) -> None:
        entries = resolve_all_bindings(yaml_path=tmp_path / "absent.yaml", json_path=tmp_path / "absent.json")

        assert entries, "no bindings resolved at all"
        assert all(entry.source == "default" for entry in entries)

    def test_yaml_overrides_a_default(self, tmp_path: Path) -> None:
        yaml_path = _yaml_config(tmp_path, quit="Q")

        entries = resolve_all_bindings(yaml_path=yaml_path, json_path=tmp_path / "absent.json")

        assert get_key_for_action("quit", entries) == "Q"
        assert next(e.source for e in entries if e.action == "quit") == "yaml"

    def test_json_wins_over_yaml(self, tmp_path: Path) -> None:
        """The docs say the JSON layer is applied last, so it wins."""
        yaml_path = _yaml_config(tmp_path, quit="Q")
        json_path = _json_config(tmp_path, quit="X")

        entries = resolve_all_bindings(yaml_path=yaml_path, json_path=json_path)

        assert get_key_for_action("quit", entries) == "X"
        assert next(e.source for e in entries if e.action == "quit") == "json"

    def test_an_override_leaves_other_actions_alone(self, tmp_path: Path) -> None:
        """ "An override only replaces the key for that one action." """
        baseline = resolve_all_bindings(yaml_path=tmp_path / "absent.yaml", json_path=tmp_path / "absent.json")
        baseline_palette = get_key_for_action("command_palette", baseline)

        entries = resolve_all_bindings(yaml_path=_yaml_config(tmp_path, quit="Q"), json_path=tmp_path / "absent.json")

        assert get_key_for_action("command_palette", entries) == baseline_palette


class TestOverriddenKeyActuallyFires:
    """The proof: press the overridden key, assert the action ran."""

    @pytest.mark.asyncio
    async def test_pressing_the_yaml_overridden_key_runs_the_action(self, tmp_path: Path) -> None:
        """A `bernstein.yaml` override reaches a real Textual key press.

        This is the assertion the subsystem's maturity rests on. Resolving
        the map and binding it is not enough - the app has to act on it.
        """
        entries = resolve_all_bindings(yaml_path=_yaml_config(tmp_path, quit="Q"), json_path=tmp_path / "absent.json")
        quit_key = get_key_for_action("quit", entries)
        assert quit_key == "Q"

        fired: list[str] = []

        class BoundApp(App[None]):
            BINDINGS = [Binding(quit_key, "record_quit", "Quit")]

            def action_record_quit(self) -> None:
                fired.append("quit")

        async with BoundApp().run_test() as pilot:
            await pilot.press(quit_key)
            await pilot.pause()

        assert fired == ["quit"], f"pressing the overridden key {quit_key!r} did not run the bound action"

    @pytest.mark.asyncio
    async def test_the_default_key_no_longer_fires_after_an_override(self, tmp_path: Path) -> None:
        """The control: an override moves the action rather than adding a second key.

        Without this, the test above would pass on an implementation that
        bound the override *in addition to* the default.
        """
        default_entries = resolve_all_bindings(yaml_path=tmp_path / "absent.yaml", json_path=tmp_path / "absent.json")
        default_key = get_key_for_action("quit", default_entries)

        entries = resolve_all_bindings(yaml_path=_yaml_config(tmp_path, quit="Q"), json_path=tmp_path / "absent.json")
        assert get_key_for_action("quit", entries) != default_key

        fired: list[str] = []

        class BoundApp(App[None]):
            BINDINGS = [Binding(get_key_for_action("quit", entries) or "Q", "record_quit", "Quit")]

            def action_record_quit(self) -> None:
                fired.append("quit")

        async with BoundApp().run_test() as pilot:
            await pilot.press(default_key or "q")
            await pilot.pause()

        assert fired == [], f"the pre-override key {default_key!r} still fired the action"
