"""Unit tests for ClineAdapter spawn/name."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from bernstein.core.llm import LLMSettings
from bernstein.core.models import ModelConfig

from bernstein.adapters.cline import ClineAdapter
from tests.unit._adapter_test_helpers import inner_cmd, make_popen_mock

if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.usefixtures("no_watchdog_threads")


def _default_settings(**overrides: str | None) -> LLMSettings:
    """Build an LLMSettings with all keys cleared except overrides."""
    defaults: dict[str, str | None] = {
        "openrouter_api_key_paid": None,
        "openrouter_api_key_free": None,
        "togetherai_user_key": None,
        "oxen_api_key": None,
        "g4f_api_key": None,
        "openai_api_key": None,
        "openai_base_url": None,
        "tavily_api_key": None,
    }
    defaults.update(overrides)
    return LLMSettings(**defaults)  # type: ignore[arg-type]


class TestClineAdapterSpawn:
    """ClineAdapter.spawn() builds the expected command."""

    def test_spawn_builds_run_command(self, tmp_path: Path) -> None:
        adapter = ClineAdapter()
        proc_mock = make_popen_mock(pid=800)
        settings = _default_settings()
        with (
            patch("bernstein.adapters.cline.subprocess.Popen", return_value=proc_mock) as popen,
            patch("bernstein.adapters.cline.LLMSettings", return_value=settings),
        ):
            adapter.spawn(
                prompt="refactor module",
                workdir=tmp_path,
                model_config=ModelConfig(model="sonnet", effort="high"),
                session_id="cline-s1",
            )
        inner = inner_cmd(popen.call_args.args[0])
        assert inner[:2] == ["cline", "--yolo"]
        assert inner[-1] == "refactor module"


class TestClineSpawnMissingBinary:
    def test_spawn_translates_missing_cli(self, tmp_path: Path) -> None:
        adapter = ClineAdapter()
        settings = _default_settings()
        with (
            patch(
                "bernstein.adapters.cline.subprocess.Popen",
                side_effect=FileNotFoundError("No such file"),
            ),
            patch("bernstein.adapters.cline.LLMSettings", return_value=settings),
            pytest.raises(RuntimeError, match="not found in PATH"),
        ):
            adapter.spawn(
                prompt="hello",
                workdir=tmp_path,
                model_config=ModelConfig(model="sonnet", effort="high"),
                session_id="cline-missing",
            )


class TestClineOpenAICompatibleEndpoint:
    """A custom OpenAI-compatible endpoint must be persisted via ``cline auth``.

    Cline stores provider settings (including the base URL) on disk rather than
    reading them from the environment on every run, so ``OPENAI_BASE_URL`` alone
    has no effect on the spawned session (issue #4270).
    """

    def test_runs_cline_auth_when_base_url_configured(self, tmp_path: Path) -> None:
        adapter = ClineAdapter()
        proc_mock = make_popen_mock(pid=801)
        auth_result = MagicMock(returncode=0, stdout="", stderr="")
        settings = _default_settings(openai_api_key="sk-local-key", openai_base_url="http://localhost:20128/v1")
        with (
            patch("bernstein.adapters.cline.subprocess.Popen", return_value=proc_mock),
            patch("bernstein.adapters.cline.subprocess.run", return_value=auth_result) as run,
            patch("bernstein.adapters.cline.LLMSettings", return_value=settings),
        ):
            adapter.spawn(
                prompt="hello",
                workdir=tmp_path,
                model_config=ModelConfig(model="my-self-hosted-model", effort="high"),
                session_id="cline-auth1",
            )
        auth_cmd = run.call_args.args[0]
        assert auth_cmd[:3] == ["cline", "auth", "-p"]
        assert auth_cmd[3] == "openai-compatible"
        assert auth_cmd[auth_cmd.index("-k") + 1] == "sk-local-key"
        assert auth_cmd[auth_cmd.index("-m") + 1] == "my-self-hosted-model"
        assert auth_cmd[auth_cmd.index("-b") + 1] == "http://localhost:20128/v1"

    def test_no_cline_auth_without_base_url(self, tmp_path: Path) -> None:
        adapter = ClineAdapter()
        proc_mock = make_popen_mock(pid=802)
        settings = _default_settings(openai_api_key="sk-plain")
        with (
            patch("bernstein.adapters.cline.subprocess.Popen", return_value=proc_mock),
            patch("bernstein.adapters.cline.subprocess.run") as run,
            patch("bernstein.adapters.cline.LLMSettings", return_value=settings),
        ):
            adapter.spawn(
                prompt="hello",
                workdir=tmp_path,
                model_config=ModelConfig(model="sonnet", effort="high"),
                session_id="cline-auth2",
            )
        run.assert_not_called()

    def test_no_cline_auth_without_api_key(self, tmp_path: Path) -> None:
        adapter = ClineAdapter()
        proc_mock = make_popen_mock(pid=803)
        settings = _default_settings(openai_base_url="http://localhost:20128/v1")
        with (
            patch("bernstein.adapters.cline.subprocess.Popen", return_value=proc_mock),
            patch("bernstein.adapters.cline.subprocess.run") as run,
            patch("bernstein.adapters.cline.LLMSettings", return_value=settings),
        ):
            adapter.spawn(
                prompt="hello",
                workdir=tmp_path,
                model_config=ModelConfig(model="sonnet", effort="high"),
                session_id="cline-auth3",
            )
        run.assert_not_called()

    def test_raises_when_cline_auth_fails(self, tmp_path: Path) -> None:
        adapter = ClineAdapter()
        auth_result = MagicMock(returncode=1, stdout="", stderr="invalid provider")
        settings = _default_settings(openai_api_key="sk-local-key", openai_base_url="http://localhost:20128/v1")
        with (
            patch("bernstein.adapters.cline.subprocess.Popen") as popen,
            patch("bernstein.adapters.cline.subprocess.run", return_value=auth_result),
            patch("bernstein.adapters.cline.LLMSettings", return_value=settings),
            pytest.raises(RuntimeError, match="invalid provider"),
        ):
            adapter.spawn(
                prompt="hello",
                workdir=tmp_path,
                model_config=ModelConfig(model="sonnet", effort="high"),
                session_id="cline-auth4",
            )
        popen.assert_not_called()

    def test_missing_cline_binary_during_auth(self, tmp_path: Path) -> None:
        adapter = ClineAdapter()
        settings = _default_settings(openai_api_key="sk-local-key", openai_base_url="http://localhost:20128/v1")
        with (
            patch("bernstein.adapters.cline.subprocess.Popen") as popen,
            patch("bernstein.adapters.cline.subprocess.run", side_effect=FileNotFoundError("No such file")),
            patch("bernstein.adapters.cline.LLMSettings", return_value=settings),
            pytest.raises(RuntimeError, match="not found in PATH"),
        ):
            adapter.spawn(
                prompt="hello",
                workdir=tmp_path,
                model_config=ModelConfig(model="sonnet", effort="high"),
                session_id="cline-auth5",
            )
        popen.assert_not_called()


class TestClineAdapterName:
    def test_name(self) -> None:
        assert ClineAdapter().name() == "Cline"
