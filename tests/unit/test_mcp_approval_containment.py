"""Containment of the MCP approval and completion verbs, against the real routes (#3081).

The approval gate is a client-side pre-check: it decides which endpoint the
tool reaches. Proving it with a mocked HTTP client only shows which URL was
built, never what the task server did with it. These tests bridge the real MCP
tool handlers to the in-process ASGI app, so every assertion is about the task
the server actually holds afterwards.

Two containment properties are asserted here:

* An approval verb may not grant a decision that belongs to the plan gate.
  Plan mode holds work in ``planned`` until an operator decides the plan;
  releasing a single task for execution leaves the plan undecided, so the
  operator's later rejection has nothing left to cancel.
* A completion verb may not finish work that is structurally not the caller's
  to finish: a parent whose subtasks are still running, or a task whose worker
  was declared gone.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from bernstein.core.server import create_app
from bernstein.core.tasks.models import TaskStatus

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.asyncio

_SERVER_URL = "http://localhost:8052"


def _unwrap(result: object) -> dict[str, Any]:
    """Parse a tool result, stripping the MCP cost-meter envelope."""
    text = result[0][0].text  # type: ignore[index]
    parsed = json.loads(text)
    if isinstance(parsed, dict) and "_meter" in parsed and "result" in parsed:
        parsed = parsed["result"]
    return parsed  # type: ignore[no-any-return]


def _bridge(app: object) -> Any:
    """Return an httpx client factory bound to the in-process ASGI app."""

    def _factory(**_kwargs: object) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=app), base_url=_SERVER_URL)  # type: ignore[arg-type]

    return _factory


async def _make_task(app: object, *, title: str, role: str = "backend") -> str:
    async with AsyncClient(transport=ASGITransport(app=app), base_url=_SERVER_URL) as http:  # type: ignore[arg-type]
        resp = await http.post("/tasks", json={"title": title, "description": title, "role": role})
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


# ---------------------------------------------------------------------------
# The approval verb may not grant the plan gate's decision
# ---------------------------------------------------------------------------


async def test_approve_refuses_a_planned_task_and_leaves_the_plan_decision_intact(tmp_path: Path) -> None:
    """Approving a planned task over MCP must not release it for execution.

    Plan mode exists so that work waits for an operator decision recorded on
    the plan. Promoting one task out of ``planned`` leaves the plan
    ``pending`` while the work runs, and the operator's later rejection then
    cancels nothing. The refusal has to point at the plan decision instead.
    """
    from bernstein.core.plan_approval import create_plan

    from bernstein.mcp.server import create_mcp_server

    app = create_app(jsonl_path=tmp_path / "runtime" / "tasks.jsonl", plan_mode=True)
    task_id = await _make_task(app, title="rotate production secrets", role="security")

    store = app.state.store
    store._tasks[task_id].status = TaskStatus.PLANNED
    plan = create_plan("held for review", [store._tasks[task_id]])
    app.state.plan_store.save_plan(plan)

    mcp = create_mcp_server(server_url=_SERVER_URL)
    with patch("bernstein.mcp.server.httpx.AsyncClient", side_effect=_bridge(app)):
        result = await mcp.call_tool("bernstein_approve", {"task_id": task_id, "note": "looks fine"})

    parsed = _unwrap(result)
    assert parsed["error"] == "task_not_awaiting_approval"
    assert parsed["current_status"] == "planned"
    assert "plan" in parsed["hint"].lower()

    # The task never left the plan gate, so the operator's decision still bites.
    assert store._tasks[task_id].status is TaskStatus.PLANNED
    assert app.state.plan_store.get_plan(plan.id).status.value == "pending"

    async with AsyncClient(transport=ASGITransport(app=app), base_url=_SERVER_URL) as http:
        reject = await http.post(f"/plans/{plan.id}/reject", json={"reason": "not authorised"})
    assert reject.status_code == 200, reject.text
    assert reject.json()["tasks_cancelled"] == 1
    assert store._tasks[task_id].status is TaskStatus.CANCELLED


async def test_approve_signs_off_a_pending_approval_task_against_the_real_state_machine(
    tmp_path: Path,
) -> None:
    """The one state the approval verb acts on has to work end to end.

    A gate whose only approvable state is rejected by the task server is a
    tool that can never succeed, and the caller sees a transport-shaped error
    rather than a decision.
    """
    from bernstein.mcp.server import create_mcp_server

    app = create_app(jsonl_path=tmp_path / "runtime" / "tasks.jsonl")
    task_id = await _make_task(app, title="await sign-off")
    store = app.state.store
    store._tasks[task_id].status = TaskStatus.PENDING_APPROVAL

    mcp = create_mcp_server(server_url=_SERVER_URL)
    with patch("bernstein.mcp.server.httpx.AsyncClient", side_effect=_bridge(app)):
        result = await mcp.call_tool("bernstein_approve", {"task_id": task_id, "note": "signed off"})

    parsed = _unwrap(result)
    assert "error" not in parsed, parsed
    assert parsed["status"] == "done"
    assert parsed["approval"] == "completion_signed_off"
    assert store._tasks[task_id].status is TaskStatus.DONE
    assert store._tasks[task_id].result_summary == "signed off"


# ---------------------------------------------------------------------------
# The completion verb may not finish work that is not the caller's to finish
# ---------------------------------------------------------------------------


async def test_complete_refuses_a_parent_whose_subtasks_have_not_finished(tmp_path: Path) -> None:
    """A parent in ``waiting_for_subtasks`` is finished by its children, not by a caller.

    Completing it directly marks the parent done while the subtasks are still
    running, which is the completion-of-unfinished-work this gate exists to
    prevent.
    """
    from bernstein.mcp.server import create_mcp_server

    app = create_app(jsonl_path=tmp_path / "runtime" / "tasks.jsonl")
    task_id = await _make_task(app, title="parent")
    store = app.state.store
    store._tasks[task_id].status = TaskStatus.WAITING_FOR_SUBTASKS

    mcp = create_mcp_server(server_url=_SERVER_URL)
    with patch("bernstein.mcp.server.httpx.AsyncClient", side_effect=_bridge(app)):
        result = await mcp.call_tool(
            "bernstein_complete",
            {"task_id": task_id, "result_summary": "subtasks look fine to me"},
        )

    parsed = _unwrap(result)
    assert parsed["error"] == "task_not_completable"
    assert parsed["current_status"] == "waiting_for_subtasks"
    assert store._tasks[task_id].status is TaskStatus.WAITING_FOR_SUBTASKS


async def test_complete_refuses_an_orphaned_task(tmp_path: Path) -> None:
    """An orphaned task's worker is gone, so no caller is executing it.

    Crash recovery decides what happens to it; a completion summary invented
    by whoever noticed it is not a result.
    """
    from bernstein.mcp.server import create_mcp_server

    app = create_app(jsonl_path=tmp_path / "runtime" / "tasks.jsonl")
    task_id = await _make_task(app, title="crashed worker")
    store = app.state.store
    store._tasks[task_id].status = TaskStatus.ORPHANED

    mcp = create_mcp_server(server_url=_SERVER_URL)
    with patch("bernstein.mcp.server.httpx.AsyncClient", side_effect=_bridge(app)):
        result = await mcp.call_tool(
            "bernstein_complete",
            {"task_id": task_id, "result_summary": "close enough"},
        )

    parsed = _unwrap(result)
    assert parsed["error"] == "task_not_completable"
    assert parsed["current_status"] == "orphaned"
    assert store._tasks[task_id].status is TaskStatus.ORPHANED


async def test_complete_still_finishes_the_mcp_worker_loop_task(tmp_path: Path) -> None:
    """The containment must not remove the worker loop's completion path.

    The MCP claim path claims from the shared backlog and leaves the task
    ``open`` in the task store, so ``open`` stays completable.
    """
    from bernstein.core.tasks.claim import Backlog, BacklogEntry
    from bernstein.mcp.server import create_mcp_server

    app = create_app(jsonl_path=tmp_path / "runtime" / "tasks.jsonl")
    task_id = await _make_task(app, title="loop")
    Backlog.write(app.state.claim_backlog_path, [BacklogEntry(id=task_id, role="backend")])

    mcp = create_mcp_server(server_url=_SERVER_URL)
    with patch("bernstein.mcp.server.httpx.AsyncClient", side_effect=_bridge(app)):
        claim = await mcp.call_tool("bernstein_claim", {"claimer_id": "worker-1", "role": "backend"})
        assert _unwrap(claim)["granted"] is True
        result = await mcp.call_tool(
            "bernstein_complete",
            {"task_id": task_id, "result_summary": "shipped it"},
        )

    parsed = _unwrap(result)
    assert parsed["status"] == "done"
    assert app.state.store._tasks[task_id].status is TaskStatus.DONE


# ---------------------------------------------------------------------------
# The window between the read and the write is closed by the server, not the gate
# ---------------------------------------------------------------------------


async def test_a_task_that_moves_between_the_read_and_the_write_is_not_completed(
    tmp_path: Path,
) -> None:
    """The gate reads, then writes; the task server is what makes the window safe.

    The gate cannot be atomic across two HTTP calls, so the guarantee has to
    come from the state machine refusing the write. Here the task leaves the
    approvable state after the read and the completion is rejected rather than
    applied to whatever the task became.
    """
    from bernstein.mcp.server import create_mcp_server

    app = create_app(jsonl_path=tmp_path / "runtime" / "tasks.jsonl")
    task_id = await _make_task(app, title="moves under us")
    store = app.state.store
    store._tasks[task_id].status = TaskStatus.PENDING_APPROVAL

    moved = {"done": False}

    async def _racing_app(scope: Any, receive: Any, send: Any) -> None:
        """Forward to the task server, then decide the task behind the gate's back."""
        await app(scope, receive, send)
        if scope.get("method") == "GET" and not moved["done"]:
            store._tasks[task_id].status = TaskStatus.CANCELLED
            moved["done"] = True

    def _racing_factory(**_kwargs: object) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=_racing_app), base_url=_SERVER_URL)

    mcp = create_mcp_server(server_url=_SERVER_URL)
    with patch("bernstein.mcp.server.httpx.AsyncClient", side_effect=_racing_factory):
        result = await mcp.call_tool("bernstein_approve", {"task_id": task_id, "note": "sign-off"})

    parsed = _unwrap(result)
    assert moved["done"], "the race never happened, so the test proves nothing"
    assert "error" in parsed, parsed
    assert store._tasks[task_id].status is TaskStatus.CANCELLED
