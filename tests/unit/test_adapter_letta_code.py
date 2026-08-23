"""Unit tests for LettaCodeAdapter."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from bernstein.core.models import ModelConfig

from bernstein.adapters._contract import AdapterStrategy, DangerousModeStrategy
from bernstein.adapters.letta_code import LettaCodeAdapter
from bernstein.adapters.session_id import derive_session_id
from tests.unit._adapter_test_helpers import inner_cmd, make_popen_mock

if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.usefixtures("no_watchdog_threads")


def test_spawn_builds_run_command(tmp_path: Path) -> None:
    adapter = LettaCodeAdapter()
    proc_mock = make_popen_mock(900)

    with patch("bernstein.adapters.letta_code.subprocess.Popen", return_value=proc_mock) as popen:
        adapter.spawn(
            prompt="fix the bug",
            workdir=tmp_path,
            model_config=ModelConfig(model="sonnet", effort="high"),
            session_id="letta-s1",
        )

    cmd = popen.call_args.args[0]
    inner = inner_cmd(cmd)
    assert inner[:4] == ["letta", "--permission-mode", "unrestricted", "--new-agent"]
    assert inner[-2:] == ["-p", "fix the bug"]


def test_spawn_pins_deterministic_conversation_id(tmp_path: Path) -> None:
    adapter = LettaCodeAdapter()
    proc_mock = make_popen_mock(901)

    with patch("bernstein.adapters.letta_code.subprocess.Popen", return_value=proc_mock) as popen:
        adapter.spawn(
            prompt="fix the bug",
            workdir=tmp_path,
            model_config=ModelConfig(model="sonnet", effort="high"),
            session_id="letta-s1",
        )

    inner = inner_cmd(popen.call_args.args[0])
    assert inner[inner.index("--conversation") + 1] == str(derive_session_id("letta-s1", "letta_code"))


def test_two_sessions_do_not_share_a_conversation(tmp_path: Path) -> None:
    # AC: two consecutive runs in the same working directory do not share a
    # conversation - each session id must bind to a distinct --conversation.
    adapter = LettaCodeAdapter()

    with patch("bernstein.adapters.letta_code.subprocess.Popen", return_value=make_popen_mock(902)) as popen:
        adapter.spawn(
            prompt="first task",
            workdir=tmp_path,
            model_config=ModelConfig(model="sonnet", effort="high"),
            session_id="letta-s1",
        )
        first = inner_cmd(popen.call_args.args[0])

    with patch("bernstein.adapters.letta_code.subprocess.Popen", return_value=make_popen_mock(903)) as popen:
        adapter.spawn(
            prompt="second task",
            workdir=tmp_path,
            model_config=ModelConfig(model="sonnet", effort="high"),
            session_id="letta-s2",
        )
        second = inner_cmd(popen.call_args.args[0])

    assert first[first.index("--conversation") + 1] != second[second.index("--conversation") + 1]


def test_permission_mode_restricted_when_dangerous_mode_is_off(tmp_path: Path) -> None:
    adapter = LettaCodeAdapter()
    adapter.strategy_override = AdapterStrategy(dangerous_mode=DangerousModeStrategy.UNSUPPORTED)
    proc_mock = make_popen_mock(904)

    with patch("bernstein.adapters.letta_code.subprocess.Popen", return_value=proc_mock) as popen:
        adapter.spawn(
            prompt="fix the bug",
            workdir=tmp_path,
            model_config=ModelConfig(model="sonnet", effort="high"),
            session_id="letta-s3",
        )

    inner = inner_cmd(popen.call_args.args[0])
    assert "--yolo" not in inner
    assert "unrestricted" not in inner
    assert inner[inner.index("--permission-mode") + 1] == "standard"


def test_spawn_translates_missing_cli(tmp_path: Path) -> None:
    adapter = LettaCodeAdapter()
    with (
        patch(
            "bernstein.adapters.letta_code.subprocess.Popen",
            side_effect=FileNotFoundError("No such file"),
        ),
        pytest.raises(RuntimeError, match="letta not found"),
    ):
        adapter.spawn(
            prompt="hello",
            workdir=tmp_path,
            model_config=ModelConfig(model="sonnet", effort="high"),
            session_id="letta-missing",
        )


def test_name() -> None:
    assert LettaCodeAdapter().name() == "Letta Code"
