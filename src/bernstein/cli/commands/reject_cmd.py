"""``bernstein reject`` - refuse a pending approval gate.

Mirror of :mod:`bernstein.cli.commands.approve_cmd`: writes
``<workdir>/.sdd/runtime/approvals/<task_id>.rejected`` so the
post-completion review gate or the pre-spawn ``ApprovalSpec`` gate
(#1110) unblocks with a refusal. Idempotent under concurrent
invocations: the first writer wins via ``os.replace`` and subsequent
callers see the existing decision and report ``already resolved``.
"""

from __future__ import annotations

from pathlib import Path

import click

from bernstein.cli.commands.approve_cmd import _atomic_write_text, _foreground_confirm
from bernstein.cli.helpers import console


@click.command("reject")
@click.argument("task_id", required=False)
@click.option(
    "--workdir",
    default=".",
    help="Project root directory (parent of .sdd/).",
    type=click.Path(),
)
@click.option(
    "--prompt/--no-prompt",
    default=True,
    show_default=True,
    help="Foreground TTY prompts confirm before writing the sentinel.",
)
@click.option(
    "--tool",
    "tool_id",
    default=None,
    help="Resolve a pending tool-call approval by id instead of a task (flag form of ``reject-tool``).",
)
def reject(task_id: str | None, workdir: str, prompt: bool, tool_id: str | None) -> None:
    """Reject a pending task (review gate or pre-spawn approval gate).

    Writes a ``<task_id>.rejected`` decision file under
    ``.sdd/runtime/approvals/``. The orchestrator marks the task failed
    and skips the agent body (or, post-completion, discards the work
    without merging).

    Concurrent ``bernstein reject`` calls are idempotent: the first one
    creates the file, subsequent invocations exit with ``already
    resolved``.

    Pass ``--tool <id>`` instead to refuse a pending tool-call approval
    from the interactive approval queue; ``reject-tool`` remains as an
    alias for this flag form.

    \b
    Examples:
      bernstein reject T-abc123
      bernstein reject --tool ap-1a2b3c4d5e6f
    """
    if tool_id is not None:
        from bernstein.cli.commands.approval_cmd import reject_tool

        reject_tool(latest=False, approval_id=tool_id, workdir=workdir)
        return

    if task_id is None:
        raise click.UsageError(
            "Missing argument 'TASK_ID'; pass a task id, or --tool <id> to resolve a pending tool-call approval."
        )

    from bernstein.core.orchestration.approval_gate import UnsafeApprovalIdError, approval_path

    # Same rule as the approve and read sides; validated before mkdir.
    try:
        decision_file = approval_path(Path(workdir), task_id, ".rejected")
        approved_file = approval_path(Path(workdir), task_id, ".approved")
    except UnsafeApprovalIdError as exc:
        console.print(f"[red]Refusing to reject:[/red] {exc}")
        raise SystemExit(1) from exc

    approvals_dir = decision_file.parent
    approvals_dir.mkdir(parents=True, exist_ok=True)

    if approved_file.exists():
        console.print(
            f"[yellow]Already resolved:[/yellow] task [bold]{task_id}[/bold] was approved; "
            "leaving the approval in place."
        )
        return

    if decision_file.exists():
        console.print(f"[dim]Already rejected:[/dim] task [bold]{task_id}[/bold] (no-op)")
        return

    if prompt and not _foreground_confirm(f"Reject task {task_id}?"):
        console.print(f"[dim]Skipped[/dim] rejection for [bold]{task_id}[/bold]")
        return

    created = _atomic_write_text(decision_file, "rejected")
    if created:
        console.print(f"[red]Rejected:[/red] task [bold]{task_id}[/bold]: work will be discarded.")
    else:
        console.print(f"[dim]Already rejected:[/dim] task [bold]{task_id}[/bold] (no-op)")


__all__ = ["reject"]
