"""Cline CLI adapter."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from bernstein.core.models import ModelConfig

from bernstein.adapters.base import DEFAULT_TIMEOUT_SECONDS, CLIAdapter, SpawnResult, build_worker_cmd
from bernstein.adapters.env_isolation import build_filtered_env
from bernstein.core.llm import LLMSettings

_CLINE_NOT_FOUND_MSG = (
    "cline not found in PATH. Install with: npm install -g cline (see https://docs.cline.bot/cline-cli/overview)"
)


class ClineAdapter(CLIAdapter):
    """Spawn and monitor Cline CLI sessions.

    Cline is a CLI coding agent invoked directly as ``cline``.  The
    ``--yolo`` flag enables auto-approval for tool invocations so sessions
    can run unattended.

    See: https://docs.cline.bot/cline-cli/overview
    """

    def _configure_openai_compatible_endpoint(self, settings: LLMSettings, model_id: str) -> None:
        """Persist a custom OpenAI-compatible endpoint via ``cline auth``.

        Unlike ``codex``/``qwen``, Cline reads provider credentials (including
        the base URL) from settings it persists to disk rather than from the
        environment on every run, so ``OPENAI_BASE_URL`` alone has no effect.
        ``cline auth -p openai-compatible -b <url>`` is the CLI's own mechanism
        for writing that endpoint into its stored settings before a session
        that should target it.
        """
        try:
            result = subprocess.run(
                [
                    "cline",
                    "auth",
                    "-p",
                    "openai-compatible",
                    "-k",
                    settings.openai_api_key,
                    "-m",
                    model_id,
                    "-b",
                    settings.openai_base_url,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(_CLINE_NOT_FOUND_MSG) from exc
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"cline auth failed to configure the OpenAI-compatible endpoint: {detail}")

    def spawn(
        self,
        *,
        prompt: str,
        workdir: Path,
        model_config: ModelConfig,
        session_id: str,
        mcp_config: dict[str, Any] | None = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        task_scope: str = "medium",
        budget_multiplier: float = 1.0,
        system_addendum: str = "",
        multimodal_context: Any | None = None,
    ) -> SpawnResult:
        """Spawn a Cline CLI session.

        Args:
            prompt: Task prompt passed positionally to ``cline``.
            workdir: Project working directory.
            model_config: Model and effort configuration.  Cline selects its
                own model, except ``model_config.model`` is also used as the
                model id when a custom OpenAI-compatible endpoint is
                configured via ``OPENAI_BASE_URL``/``OPENAI_API_KEY``.
            session_id: Unique session identifier used for log/pid metadata.
            mcp_config: Unused; accepted for interface compatibility.
            timeout_seconds: Watchdog timeout for the spawned process.
            task_scope: Unused; accepted for interface compatibility.
            budget_multiplier: Unused; accepted for interface compatibility.
            system_addendum: Unused; accepted for interface compatibility.

        Returns:
            SpawnResult describing the launched worker process.

        Raises:
            RuntimeError: If ``cline`` is not installed or is not executable,
                or if a configured OpenAI-compatible endpoint cannot be
                persisted to Cline's settings.
        """
        self.refuse_multimodal_if_needed(multimodal_context)
        log_path = workdir / ".sdd" / "runtime" / f"{session_id}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        settings = LLMSettings()
        if settings.openai_base_url and settings.openai_api_key:
            self._configure_openai_compatible_endpoint(settings, model_config.model)

        cmd = ["cline", "--yolo", prompt]

        pid_dir = workdir / ".sdd" / "runtime" / "pids"
        wrapped_cmd = build_worker_cmd(
            cmd,
            role=session_id.rsplit("-", 1)[0],
            session_id=session_id,
            pid_dir=pid_dir,
            workdir=workdir,
            log_path=log_path,
            model=model_config.model,
        )

        env = build_filtered_env(
            ["CLINE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"],
        )
        with log_path.open("w") as log_file:
            try:
                proc = subprocess.Popen(
                    wrapped_cmd,
                    cwd=workdir,
                    env=env,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except FileNotFoundError as exc:
                raise RuntimeError(_CLINE_NOT_FOUND_MSG) from exc
            except PermissionError as exc:
                raise RuntimeError(f"Permission denied executing cline: {exc}") from exc

        result = SpawnResult(pid=proc.pid, log_path=log_path, proc=proc)
        if timeout_seconds > 0:
            result.timeout_timer = self._start_timeout_watchdog(proc.pid, timeout_seconds, session_id)
        return result

    def name(self) -> str:
        """Return the human-readable adapter name."""
        return "Cline"
