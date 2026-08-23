"""Letta Code CLI adapter."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Any

from bernstein.adapters._contract import DangerousModeStrategy
from bernstein.adapters.base import DEFAULT_TIMEOUT_SECONDS, CLIAdapter, SpawnResult, build_worker_cmd
from bernstein.adapters.env_isolation import build_filtered_env

if TYPE_CHECKING:
    from pathlib import Path

    from bernstein.core.models import ModelConfig

#: ``--permission-mode`` value for a spawn allowed to skip approval prompts.
#: Equivalent to the ``--yolo`` shorthand documented at
#: ``docs.letta.com/letta-code/cli-reference``.
_ESCALATED_PERMISSION_MODE = "unrestricted"

#: ``--permission-mode`` value for a spawn that has not opted into
#: unattended dangerous mode. ``standard`` asks before tool use rather than
#: bypassing prompts outright.
_RESTRICTED_PERMISSION_MODE = "standard"


class LettaCodeAdapter(CLIAdapter):
    """Spawn and monitor Letta Code CLI sessions.

    The CLI is invoked as
    ``letta --permission-mode <mode> --new-agent --conversation <id> -p
    <prompt>``. ``-p`` runs a one-off prompt in headless mode (per
    ``docs.letta.com/letta-code/cli-reference`` and ``/headless``);
    ``--permission-mode`` is derived from the adapter's declared
    dangerous-mode strategy rather than hardcoding the ``--yolo``
    shorthand, so a spawn that has not opted into unattended dangerous
    mode does not silently get unrestricted permissions. The binary
    ships as ``letta`` from the npm package ``@letta-ai/letta-code``.

    Letta Code's defining feature is *cross-task memory* persisted via
    Letta Cloud (``LETTA_API_KEY``): headless mode otherwise reuses "the
    last agent from the current directory and its default conversation",
    so two spawns in the same working directory would reach the same
    agent and the same conversation history, and a retry of a failed
    task would inherit the failed attempt's memory. ``--new-agent``
    forces a fresh agent on every spawn, and ``--conversation`` pins that
    agent's conversation to a deterministic id derived from the
    Bernstein session id (see ``docs/adapters/session_isolation.md``),
    so distinct spawns never share agent memory. Bernstein does not
    otherwise coordinate Letta's cross-task memory or memory blocks;
    that machinery still operates in Letta's own backend. If you want
    Bernstein-level state to survive across tasks, use Bernstein's
    ``.sdd/`` files, not Letta's memory.
    """

    registry_name = "letta_code"

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
        """Launch a Letta Code CLI session.

        Args:
            prompt: The headless prompt supplied via ``-p``.
            workdir: Working directory for the agent process.
            model_config: Model and effort configuration (retained for
                interface compatibility; Letta Code resolves the model
                via ``/connect`` config or ``--model``, not via the
                Bernstein scope mapping).
            session_id: Unique session identifier. A deterministic id
                derived from it is pinned via ``--conversation`` so the
                fresh agent this spawn creates does not collide with any
                other session's conversation.
            mcp_config: Optional MCP server definitions (unused).
            timeout_seconds: Process timeout in seconds.
            task_scope: Task scope hint (unused by Letta Code).
            budget_multiplier: Multiplier on scope budget (unused).
            system_addendum: Protocol-critical system instructions (unused).

        Returns:
            SpawnResult with the spawned PID and log path.

        Raises:
            RuntimeError: If the ``letta`` binary is missing from PATH
                or cannot be executed.
        """
        self.refuse_multimodal_if_needed(multimodal_context)
        log_path = workdir / ".sdd" / "runtime" / f"{session_id}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = ["letta", "--permission-mode", self._permission_mode(), "--new-agent"]
        cmd.extend(self.session_id_args(session_id))
        cmd.extend(["-p", prompt])

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
            [
                "LETTA_API_KEY",
                "LETTA_BASE_URL",
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
            ]
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
                msg = "letta not found in PATH. Install: npm install -g @letta-ai/letta-code"
                raise RuntimeError(msg) from exc
            except PermissionError as exc:
                raise RuntimeError(f"Permission denied executing letta: {exc}") from exc

        result = SpawnResult(pid=proc.pid, log_path=log_path, proc=proc)
        if timeout_seconds > 0:
            result.timeout_timer = self._start_timeout_watchdog(proc.pid, timeout_seconds, session_id)
        return result

    def _dangerous_mode(self) -> DangerousModeStrategy:
        """Return the declared dangerous-mode strategy for this adapter."""
        declared = getattr(self.strategy(), "dangerous_mode", DangerousModeStrategy.UNSUPPORTED)
        return declared if isinstance(declared, DangerousModeStrategy) else DangerousModeStrategy.UNSUPPORTED

    def _permission_mode(self) -> str:
        """Return the ``--permission-mode`` value for this spawn.

        Escalates to :data:`_ESCALATED_PERMISSION_MODE` only when the
        declared dangerous-mode strategy allows it, so a spawn that has
        not opted into unattended dangerous mode gets the restricted
        mode instead of the unconditional ``--yolo`` this adapter used
        to pass.
        """
        escalated = self._dangerous_mode() in (DangerousModeStrategy.CLI_FLAG, DangerousModeStrategy.ALWAYS_ON)
        return _ESCALATED_PERMISSION_MODE if escalated else _RESTRICTED_PERMISSION_MODE

    def name(self) -> str:
        """Return the human-readable adapter name."""
        return "Letta Code"
