"""Goose CLI adapter for Bernstein.

Adapter for Goose (https://github.com/aaif-goose/goose), now stewarded by the
Agentic AI Foundation (Linux Foundation) - the GitHub org has moved from
``block/goose`` to ``aaif-goose/goose``, and the old paths still resolve
through GitHub's rename redirect.  Goose is an AI agent that can execute
tasks autonomously; this adapter allows Bernstein to orchestrate Goose as a
worker agent.

``goose run`` takes the prompt either as ``-i/--instructions <FILE>`` or as
``-t/--text <TEXT>``; there is no singular ``--instruction`` that carries
prompt text.  Passing one makes the argument parser abort with exit code 2
before the agent starts, so the worker dies having done no work.

Every spawn also carries ``--output-format stream-json`` (structured
lifecycle events instead of prose), ``--no-session`` (a task leaves no
session behind), and ``--max-turns`` derived from the task scope, so a
looping agent stops on its own limit rather than the orchestrator's
watchdog.  Autonomy is set through the ``GOOSE_MODE`` environment variable -
Goose has no CLI flag for it - and is always assigned explicitly rather than
inherited from the operator's environment.

``goose run`` returns exit code 0 on every terminal path once the agent has
started, and its terminal event's ``status`` field reads ``"completed"``
even after an ``error`` event.  Neither is a success signal; only the
absence of an ``error`` event is.  See :func:`parse_run_events`.

Last verified against upstream Goose 1.45.0 on 2026-08-10.
Install: ``brew install --cask block-goose`` (macOS), or
``curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | bash``.
"""

from __future__ import annotations

import json
import logging
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bernstein.adapters.base import (
    DEFAULT_TIMEOUT_SECONDS,
    CLIAdapter,
    SpawnResult,
    build_worker_cmd,
)
from bernstein.adapters.env_isolation import build_filtered_env
from bernstein.core.defaults import COST

if TYPE_CHECKING:
    from pathlib import Path

    from bernstein.core.models import ModelConfig

logger = logging.getLogger(__name__)

# Model mapping: Bernstein logical names → Goose model IDs
# Updated 2026-04-17 - keep Opus alias in sync with claude.py canonical ID.
_MODEL_MAP: dict[str, str] = {
    "opus": "claude-opus-4-7",
    "opus-4-6": "claude-opus-4-6",  # pinned fallback
    "sonnet": "claude-sonnet-4-6",
    "haiku": "claude-haiku-4-5-20251001",
}

# GOOSE_MODE values, most to least autonomous. Bernstein only ever drives the
# two ends of the range: full autonomy for a normal spawn, and an approval
# gate when dangerous mode is off.
_GOOSE_MODE_DANGEROUS = "auto"
_GOOSE_MODE_RESTRICTED = "approve"


@dataclass(frozen=True)
class GooseUsage:
    """Token and cost accounting read from a goose completion envelope."""

    total_tokens: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost_usd: float


@dataclass(frozen=True)
class GooseRunResult:
    """Outcome of a goose ``--output-format stream-json`` run.

    ``succeeded`` is driven by whether an ``error`` event appeared in the
    stream, not by the terminal event's ``status`` field: goose assigns
    ``status: "completed"`` on every terminal path, including one that
    followed an error, so that field is never a verdict.
    """

    succeeded: bool
    usage: GooseUsage | None  # None: no completion envelope was found


def parse_run_events(stream_text: str) -> GooseRunResult:
    """Parse a recorded goose ``--output-format stream-json`` event log.

    Args:
        stream_text: The full newline-delimited JSON event stream, as
            written to the adapter's own log file.

    Returns:
        Whether the run succeeded and, when a completion envelope was
        present, the token/cost usage it carried.
    """
    saw_error = False
    usage: GooseUsage | None = None
    for line in stream_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        event_type = event.get("type")
        if event_type == "error":
            saw_error = True
        elif event_type == "complete":
            envelope = event.get("usage")
            if isinstance(envelope, dict):
                usage = GooseUsage(
                    total_tokens=int(envelope.get("total", 0)),
                    input_tokens=int(envelope.get("input", 0)),
                    output_tokens=int(envelope.get("output", 0)),
                    cache_read_tokens=int(envelope.get("cache_read", 0)),
                    cache_write_tokens=int(envelope.get("cache_write", 0)),
                    cost_usd=float(event.get("cost_usd", 0.0)),
                )
    return GooseRunResult(succeeded=not saw_error, usage=usage)


class GooseAdapter(CLIAdapter):
    """Goose CLI adapter for Bernstein.

    Integrates with the Goose CLI agent.
    GitHub: https://github.com/aaif-goose/goose
    """

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
        dangerous_mode: bool = True,
    ) -> SpawnResult:
        """Launch a Goose agent process.

        Args:
            prompt: Task description passed to the agent.
            workdir: Working directory (project root).
            model_config: Model and effort settings chosen by the orchestrator.
            session_id: Unique identifier for this agent session.
            mcp_config: Optional MCP server configuration (ignored by Goose).
            timeout_seconds: Hard kill timeout in seconds.
            task_scope: Task scope ("small", "medium", "large") used to
                derive ``--max-turns``.
            dangerous_mode: Whether the agent should skip its own approval
                gate. Goose has no CLI flag for this; it is driven through
                ``GOOSE_MODE``, set explicitly on every spawn rather than
                inherited from the operator's environment.

        Returns:
            SpawnResult with the process PID and log file path.

        Raises:
            RuntimeError: If the Goose binary is not found.
        """
        self.refuse_multimodal_if_needed(multimodal_context)
        self.enforce_network_policy()
        log_path = workdir / ".sdd" / "runtime" / f"{session_id}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        model_id = _MODEL_MAP.get(model_config.model, model_config.model)
        effort = getattr(model_config, "effort", "high")
        base_turns = COST.effort_base_turns.get(effort, 50)
        scope_multiplier = COST.scope_multipliers.get(task_scope, 1.5)
        max_turns = max(1, int(base_turns * scope_multiplier))

        cmd = [
            "goose",
            "run",
            "--text",
            prompt,
            "--output-format",
            "stream-json",
            "--no-session",
            "--max-turns",
            str(max_turns),
        ]
        if model_id:
            cmd += ["--model", model_id]

        pid_dir = workdir / ".sdd" / "runtime" / "pids"
        wrapped_cmd = build_worker_cmd(
            cmd,
            role=session_id.rsplit("-", 1)[0],
            session_id=session_id,
            pid_dir=pid_dir,
            workdir=workdir,
            log_path=log_path,
            model=model_id,
        )

        # Always pass an explicit ``env=`` - Popen with env=None inherits
        # the orchestrator's full environment, which is a credential-leak
        # vector (DB URLs, internal tokens, unrelated provider keys).
        # Goose accepts model creds via Anthropic/OpenAI/OpenRouter envs.
        env = build_filtered_env(
            ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY", "GOOGLE_API_KEY", "GOOSE_MODE"],
        )
        env["GOOSE_MODE"] = _GOOSE_MODE_DANGEROUS if dangerous_mode else _GOOSE_MODE_RESTRICTED
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
                raise RuntimeError("goose not found in PATH. Install: https://github.com/aaif-goose/goose") from exc
            except PermissionError as exc:
                raise RuntimeError(f"Permission denied executing goose: {exc}") from exc

        timer = self._start_timeout_watchdog(proc.pid, timeout_seconds, session_id)
        return SpawnResult(pid=proc.pid, log_path=log_path, proc=proc, timeout_timer=timer)

    def name(self) -> str:
        """Human-readable adapter name shown in bernstein ps and logs."""
        return "goose"

    def get_version(self) -> str | None:
        """Return the Goose CLI version string, or None if unavailable."""
        with suppress(Exception):
            result = subprocess.run(
                ["goose", "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        return None

    def is_available(self) -> bool:
        """Return True if the Goose CLI is installed and accessible."""
        try:
            result = subprocess.run(
                ["goose", "--help"],
                capture_output=True,
                timeout=10,
                check=False,
            )
            return result.returncode == 0
        except Exception:
            return False
