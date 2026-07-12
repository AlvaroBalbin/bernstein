"""Tests for the MCP Tasks extension and trace context propagation."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.types import (
    CallToolResult,
    CancelTaskRequest,
    CancelTaskRequestParams,
    CancelTaskResult,
    CreateTaskResult,
    GetTaskPayloadRequest,
    GetTaskPayloadRequestParams,
    GetTaskRequest,
    GetTaskRequestParams,
    GetTaskResult,
    ListTasksRequest,
    ListTasksResult,
    TextContent,
)

from bernstein.adapters.base import record_artifact_write
from bernstein.core.lineage.spine import LineageSpine, SpineStatus
from bernstein.core.routes.task_crud import create_task
from bernstein.core.server import TaskCreate
from bernstein.core.tasks.models import TaskStatus, TaskType
from bernstein.mcp.server import (
    _get_journal_head,  # pyright: ignore[reportPrivateUsage]
    _project_task_helper,  # pyright: ignore[reportPrivateUsage]
    create_mcp_server,
)

_KEY = b"k" * 32


@pytest.fixture
def mock_client() -> AsyncMock:
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


def _make_task_dict(task_id: str, status: str = "open", result_summary: str | None = None) -> dict[str, Any]:
    return {
        "id": task_id,
        "title": "Test task",
        "description": "A test task description",
        "role": "backend",
        "status": status,
        "created_at": 1711574400.0,
        "result_summary": result_summary,
    }


@pytest.mark.asyncio
async def test_get_journal_head_empty_when_missing() -> None:
    assert _get_journal_head("non-existent-task") == ""


@pytest.mark.asyncio
async def test_project_task_helper() -> None:
    data = _make_task_dict("t-123", status="done", result_summary="Success summary")
    task_obj = _project_task_helper(data)
    assert task_obj.taskId == "t-123"
    assert task_obj.status == "completed"
    assert task_obj.statusMessage == "Success summary"


@pytest.mark.asyncio
async def test_get_task_endpoint(mock_client: AsyncMock) -> None:
    mcp = create_mcp_server()
    handler = mcp._mcp_server.request_handlers[GetTaskRequest]  # pyright: ignore[reportPrivateUsage]

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value=_make_task_dict("task-abc", status="in_progress"))
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("bernstein.mcp.server.httpx.AsyncClient", return_value=mock_client):
        req = GetTaskRequest(params=GetTaskRequestParams(taskId="task-abc"))
        server_res = await handler(req)
        res = server_res.root
        assert isinstance(res, GetTaskResult)
        assert res.taskId == "task-abc"
        assert res.status == "working"
        assert res.statusMessage == "Task is running"


@pytest.mark.asyncio
async def test_get_task_result_endpoint(mock_client: AsyncMock) -> None:
    mcp = create_mcp_server()
    handler = mcp._mcp_server.request_handlers[GetTaskPayloadRequest]  # pyright: ignore[reportPrivateUsage]

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value=_make_task_dict("task-abc", status="done", result_summary="Done task"))
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("bernstein.mcp.server.httpx.AsyncClient", return_value=mock_client):
        req = GetTaskPayloadRequest(params=GetTaskPayloadRequestParams(taskId="task-abc"))
        server_res = await handler(req)
        res = server_res.root
        assert isinstance(res, CallToolResult)
        assert not res.isError
        first_content = res.content[0]
        assert isinstance(first_content, TextContent)
        assert first_content.text == "Done task"


@pytest.mark.asyncio
async def test_list_tasks_endpoint(mock_client: AsyncMock) -> None:
    mcp = create_mcp_server()
    handler = mcp._mcp_server.request_handlers[ListTasksRequest]  # pyright: ignore[reportPrivateUsage]

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(
        return_value=[
            _make_task_dict("task-1", status="done"),
            _make_task_dict("task-2", status="failed"),
        ]
    )
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("bernstein.mcp.server.httpx.AsyncClient", return_value=mock_client):
        req = ListTasksRequest()
        server_res = await handler(req)
        res = server_res.root
        assert isinstance(res, ListTasksResult)
        assert res.tasks is not None
        assert len(res.tasks) == 2
        assert res.tasks[0].taskId == "task-1"
        assert res.tasks[0].status == "completed"
        assert res.tasks[1].taskId == "task-2"
        assert res.tasks[1].status == "failed"


@pytest.mark.asyncio
async def test_cancel_task_endpoint(mock_client: AsyncMock) -> None:
    mcp = create_mcp_server()
    handler = mcp._mcp_server.request_handlers[CancelTaskRequest]  # pyright: ignore[reportPrivateUsage]

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value=_make_task_dict("task-abc", status="cancelled"))
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("bernstein.mcp.server.httpx.AsyncClient", return_value=mock_client):
        req = CancelTaskRequest(params=CancelTaskRequestParams(taskId="task-abc"))
        server_res = await handler(req)
        res = server_res.root
        assert isinstance(res, CancelTaskResult)
        assert res.taskId == "task-abc"
        assert res.status == "cancelled"


@pytest.mark.asyncio
async def test_bernstein_run_with_client_supports_tasks(mock_client: AsyncMock) -> None:
    from mcp.types import CallToolRequest, CallToolRequestParams

    mcp = create_mcp_server()
    handler = mcp._mcp_server.request_handlers[CallToolRequest]  # pyright: ignore[reportPrivateUsage]

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value=_make_task_dict("task-tasks-support", status="open"))
    mock_client.post = AsyncMock(return_value=mock_response)

    # Mock experimental client capabilities
    mock_experimental = MagicMock()
    mock_experimental.client_supports_tasks = True

    mock_meta = MagicMock()
    mock_meta.model_extra = {
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "tracestate": "state-xyz",
        "baggage": "baggage-abc",
    }

    mock_request_context = MagicMock()
    mock_request_context.experimental = mock_experimental
    mock_request_context.meta = mock_meta

    # Set request_context on low-level server using contextvar
    from mcp.server.lowlevel.server import request_ctx

    token = request_ctx.set(mock_request_context)

    try:
        with patch("bernstein.mcp.server.httpx.AsyncClient", return_value=mock_client):
            req = CallToolRequest(params=CallToolRequestParams(name="bernstein_run", arguments={"goal": "Task run"}))
            server_res = await handler(req)
            res = server_res.root
    finally:
        request_ctx.reset(token)

    assert isinstance(res, CreateTaskResult)
    assert res.task.taskId == "task-tasks-support"
    assert res.task.status == "working"

    # Assert trace context headers were forwarded
    headers = cast(dict[str, Any], mock_client.post.call_args.kwargs.get("headers") or {})
    assert headers.get("traceparent") == "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    assert headers.get("tracestate") == "state-xyz"
    assert headers.get("baggage") == "baggage-abc"


@pytest.mark.asyncio
async def test_trace_context_propagation_to_lineage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BERNSTEIN_LINEAGE_ENABLED", "1")
    monkeypatch.setenv("TRACEPARENT", "00-abc-123-01")
    monkeypatch.setenv("TRACESTATE", "state-abc")
    monkeypatch.setenv("BAGGAGE", "bag-abc")

    root = tmp_path / "lineage"
    h = record_artifact_write(
        artifact_path="src/bar.py",
        content=b"test",
        actor="agent:test",
        step_id="tc-99",
        model="claude",
        lineage_root=root,
        run_id="run-trace-01",
        hmac_key=_KEY,
        timestamp=1,
    )
    assert h

    spine = LineageSpine(root, run_id="run-trace-01", hmac_key=_KEY)
    entries = list(spine.iter_entries())
    assert len(entries) == 1
    assert entries[0].traceparent == "00-abc-123-01"
    assert entries[0].tracestate == "state-abc"
    assert entries[0].baggage == "bag-abc"

    result = spine.verify()
    assert result.status is SpineStatus.OK


@pytest.mark.asyncio
async def test_create_task_endpoint_ingests_trace_headers() -> None:
    # Mock FastAPI request
    mock_request = MagicMock()
    mock_request.app.state.sdd_dir = Path("/tmp")
    mock_request.app.state.tenant_isolation_manager.check_quota.return_value = (True, "OK")
    mock_request.app.state.seed_config = None
    mock_request.headers = {
        "traceparent": "00-abc-123-01",
        "tracestate": "state-abc",
        "baggage": "bag-abc",
        "x-tenant-id": "default",
    }

    mock_store = MagicMock()
    mock_task = MagicMock()
    mock_task.id = "task-mock-id"
    mock_task.status = TaskStatus.OPEN
    mock_store.create = AsyncMock(return_value=mock_task)
    mock_store.count_by_status.return_value = {"total": 0}

    body = TaskCreate(
        title="Test",
        description="Desc",
        role="backend",
        task_type=TaskType.STANDARD.value,
    )

    with (
        patch("bernstein.core.routes.task_crud._get_store", return_value=mock_store),
        patch("bernstein.core.routes.task_crud._get_sse_bus", return_value=MagicMock()),
        patch("bernstein.core.routes.task_crud.get_plugin_manager", return_value=MagicMock()),
        patch("bernstein.core.routes.task_crud.append_assessment_log", return_value=None),
        patch("bernstein.core.routes.task_crud.task_to_response", return_value=MagicMock()),
    ):
        await create_task(body, mock_request)
        created_task_body = mock_store.create.call_args[0][0]
        assert created_task_body.metadata.get("traceparent") == "00-abc-123-01"
        assert created_task_body.metadata.get("tracestate") == "state-abc"
        assert created_task_body.metadata.get("baggage") == "bag-abc"


@pytest.mark.parametrize(
    ("task_status", "expected_mcp_status"),
    [
        # Terminal statuses must NOT project to "working" or a spec client polls forever.
        ("done", "completed"),
        ("closed", "completed"),
        ("failed", "failed"),
        ("refused", "failed"),
        ("abandoned", "failed"),
        ("cancelled", "cancelled"),
        # Non-terminal / needs-input.
        ("open", "working"),
        ("in_progress", "working"),
        ("waiting_for_subtasks", "working"),
        ("orphaned", "working"),
        ("blocked", "input_required"),
        ("pending_approval", "input_required"),
        ("planned", "input_required"),
        ("blocked_by_abandon", "input_required"),
    ],
)
def test_project_task_helper_maps_all_terminal_statuses(task_status: str, expected_mcp_status: str) -> None:
    task_obj = _project_task_helper(_make_task_dict("t-map", status=task_status))
    assert task_obj.status == expected_mcp_status


@pytest.mark.asyncio
@pytest.mark.parametrize("error_status", ["failed", "refused", "abandoned", "orphaned", "blocked_by_abandon"])
async def test_get_task_result_signals_error_for_terminal_error_states(
    mock_client: AsyncMock, error_status: str
) -> None:
    mcp = create_mcp_server()
    handler = mcp._mcp_server.request_handlers[GetTaskPayloadRequest]  # pyright: ignore[reportPrivateUsage]
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value=_make_task_dict("task-err", status=error_status))
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("bernstein.mcp.server.httpx.AsyncClient", return_value=mock_client):
        req = GetTaskPayloadRequest(params=GetTaskPayloadRequestParams(taskId="task-err"))
        res = (await handler(req)).root
        assert isinstance(res, CallToolResult)
        assert res.isError is True


@pytest.mark.asyncio
async def test_get_task_result_guards_non_terminal_task(mock_client: AsyncMock) -> None:
    mcp = create_mcp_server()
    handler = mcp._mcp_server.request_handlers[GetTaskPayloadRequest]  # pyright: ignore[reportPrivateUsage]
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value=_make_task_dict("task-inflight", status="in_progress"))
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("bernstein.mcp.server.httpx.AsyncClient", return_value=mock_client):
        req = GetTaskPayloadRequest(params=GetTaskPayloadRequestParams(taskId="task-inflight"))
        res = (await handler(req)).root
        assert isinstance(res, CallToolResult)
        # An in-flight task has no result: signal error, never fabricate "Task completed".
        assert res.isError is True
        first_content = res.content[0]
        assert isinstance(first_content, TextContent)
        assert "still" in first_content.text


def test_spawn_for_tasks_trace_env_is_scoped_and_restored(monkeypatch: pytest.MonkeyPatch) -> None:
    """A task's W3C trace-context must not leak into the next task's environment.

    Regression for the cross-task lineage-attribution leak: the spawn must set
    the trace env only for the duration of its own spawn and restore it after, so
    a task without trace-context can never inherit a previous task's traceparent.
    """
    import os

    from bernstein.core.agents.spawner_core import AgentSpawner

    spawner = AgentSpawner.__new__(AgentSpawner)  # bypass heavy __init__
    seen: dict[str, str | None] = {}

    def _fake_internal(tasks: Any, model_override: str | None = None) -> Any:
        seen["TRACEPARENT"] = os.environ.get("TRACEPARENT")
        return MagicMock()

    spawner._spawn_for_tasks_internal = _fake_internal  # type: ignore[method-assign]

    for key in ("TRACEPARENT", "TRACESTATE", "BAGGAGE"):
        monkeypatch.delenv(key, raising=False)

    task_a = MagicMock()
    task_a.metadata = {"traceparent": "tp-A", "tracestate": "ts-A", "baggage": "bg-A"}
    task_a.role = "backend"
    spawner.spawn_for_tasks([task_a])
    assert seen["TRACEPARENT"] == "tp-A"  # A's own subprocess sees A's trace
    assert os.environ.get("TRACEPARENT") is None  # restored after the spawn

    task_b = MagicMock()
    task_b.metadata = {}  # no trace-context
    task_b.role = "backend"
    spawner.spawn_for_tasks([task_b])
    assert seen["TRACEPARENT"] is None  # B must NOT inherit A's traceparent
    assert os.environ.get("TRACEPARENT") is None
