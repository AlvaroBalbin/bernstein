"""The approval gate shared by every MCP surface that exposes ``bernstein_approve``.

``bernstein_approve`` is reachable both through the in-process FastMCP server
(:mod:`bernstein.mcp.server`) and through the streamable HTTP transport
(:mod:`bernstein.mcp.remote_transport`). Both enforce the gate from here, so a
caller cannot pick a transport to get a weaker rule, and the approvable set is
projected from the task state machine
(:data:`bernstein.core.tasks.lifecycle.APPROVABLE_TASK_STATUSES`) rather than
restated per surface.

Approval means two different operations depending on which side of execution
the task sits (see :data:`bernstein.core.tasks.lifecycle.TASK_APPROVAL_TARGETS`):
a ``planned`` task is released for execution, and a ``pending_approval`` task
is signed off as complete. Every other status is refused.
"""

from __future__ import annotations

from typing import Any

from bernstein.core.tasks.lifecycle import APPROVABLE_TASK_STATUSES
from bernstein.core.tasks.models import TaskStatus

#: Status values an approval may act on, sorted for a stable wire payload.
APPROVABLE_STATUS_VALUES: tuple[str, ...] = tuple(sorted(s.value for s in APPROVABLE_TASK_STATUSES))

#: Error code carried by the refusal payload.
REFUSAL_ERROR: str = "task_not_awaiting_approval"


def is_approvable(status: str) -> bool:
    """Return True when *status* is a state an approval is defined for.

    An unknown or empty status is not approvable, so a task payload without a
    readable status fails closed rather than being completed.
    """
    return status in APPROVABLE_STATUS_VALUES


def releases_for_execution(status: str) -> bool:
    """Return True when approving *status* releases the task for execution.

    A ``planned`` task is approved *before* it runs, so the approval promotes
    it to ``open`` instead of completing work that never happened.
    """
    return status == TaskStatus.PLANNED.value


def refusal_payload(task_id: str, current_status: str) -> dict[str, Any]:
    """Build the structured refusal for a task with no approval to grant.

    The payload names the current status so the caller can pick a different
    action instead of retrying the approval, and lists the states an approval
    is defined for.

    Args:
        task_id: The task the approval was attempted on.
        current_status: The status the task server reported, or an empty
            string when the task payload carried none.

    Returns:
        The refusal as a JSON-serialisable dict.
    """
    approvable = ", ".join(APPROVABLE_STATUS_VALUES)
    reported = current_status or "unknown"
    return {
        "error": REFUSAL_ERROR,
        "task_id": task_id,
        "current_status": reported,
        "approvable_statuses": list(APPROVABLE_STATUS_VALUES),
        "message": (
            f"Task {task_id} is in status '{reported}'. bernstein_approve only acts on a task "
            f"waiting on an approval decision ({approvable}), and never forces another state "
            f"to complete."
        ),
        "hint": (
            "To finish work you are executing, use bernstein_complete. "
            "To report that the task is stuck, post to the task mailbox with bernstein_update. "
            "To abandon the work, cancel the task (bernstein task cancel <task_id>)."
        ),
    }
