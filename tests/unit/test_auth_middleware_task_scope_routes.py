"""Route-table-derived coverage for per-agent task scoping (#3036).

``_check_agent_task_scope`` binds an agent identity to the tasks its token
was issued for.  The guarded set used to be a hand-maintained alternation
of action names, so every task route added afterwards silently escaped the
check.  These tests derive the expectations from the *registered* route
table instead of a literal list: a newly added ``/tasks/{task_id}/...``
mutation is covered automatically, and a newly added collection route under
``/tasks/`` fails the pinning test until it is exempted deliberately.
"""

# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import pytest
from bernstein.core.auth_middleware import (
    _TASK_ID_PATH_RE,
    TASK_COLLECTION_SEGMENTS,
    _check_agent_task_scope,
)
from fastapi.testclient import TestClient

if TYPE_CHECKING:
    from pathlib import Path

    from fastapi import FastAPI

# These tests exercise the secure-by-default middleware, so opt out of the
# autouse fixture that sets ``BERNSTEIN_AUTH_DISABLED`` for the suite.
pytestmark = pytest.mark.auth_enabled

_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Any path template that addresses a single task by id, on the root mount or
# on a versioned mirror (``/api/v1/...``).
_TASK_ID_ROUTE_RE = re.compile(r"^(?:/api/v\d+)?/tasks/\{task_id\}(?:/|$)")

# A literal segment directly under ``/tasks/`` - a collection route, not a
# task id (e.g. ``/tasks/self-create``).
_TASK_COLLECTION_ROUTE_RE = re.compile(r"^(?:/api/v\d+)?/tasks/(?P<segment>[^/{}]+)(?:/|$)")

_IN_SCOPE_TASK_ID = "task-mine"
_OUT_OF_SCOPE_TASK_ID = "task-not-mine"

# Sanity floor: the enumeration must actually find the task surface. Without
# it a refactor that stops matching route templates would make every
# enumerating assertion pass vacuously.
_MIN_EXPECTED_MUTATING_ROUTES = 20


@pytest.fixture
def app(tmp_path: Path) -> FastAPI:
    """Build the real application so its route table drives the assertions."""
    from bernstein.core.server import create_app

    return create_app(jsonl_path=tmp_path / ".sdd" / "runtime" / "tasks.jsonl")


def _mutating_task_id_routes(application: FastAPI) -> list[tuple[str, str]]:
    """Return ``(method, path_template)`` for every mutating per-task route."""
    found: set[tuple[str, str]] = set()
    for route in application.routes:
        template = getattr(route, "path", "")
        if not template or not _TASK_ID_ROUTE_RE.match(template):
            continue
        for method in getattr(route, "methods", set()) or set():
            if method.upper() not in _READ_METHODS:
                found.add((method.upper(), template))
    return sorted(found)


def _task_collection_segments(application: FastAPI) -> set[str]:
    """Return the literal (non task-id) first segments under ``/tasks/``."""
    segments: set[str] = set()
    for route in application.routes:
        template = getattr(route, "path", "")
        match = _TASK_COLLECTION_ROUTE_RE.match(template) if template else None
        if match is not None:
            segments.add(match.group("segment"))
    return segments


def test_enumeration_finds_the_task_surface(app: FastAPI) -> None:
    """The route enumeration is non-empty, so the assertions below can bite."""
    routes = _mutating_task_id_routes(app)

    assert len(routes) >= _MIN_EXPECTED_MUTATING_ROUTES, routes


def test_every_mutating_task_route_is_scope_checked(app: FastAPI) -> None:
    """Every mutating per-task route reports an out-of-scope task id."""
    for method, template in _mutating_task_id_routes(app):
        path = template.replace("{task_id}", _OUT_OF_SCOPE_TASK_ID)
        error = _check_agent_task_scope(path, [_IN_SCOPE_TASK_ID])

        assert error is not None, f"{method} {path} is not scope-checked"
        assert _OUT_OF_SCOPE_TASK_ID in error, f"{method} {path}"


def test_every_mutating_task_route_denies_out_of_scope_identity(app: FastAPI) -> None:
    """A token scoped to task A is rejected on every mutating task-B route.

    End-to-end through the real middleware stack: the handler must never run
    for a task the token was not issued for.
    """
    store: Any = app.state.identity_store
    _, token = store.create_identity("session-scope-probe", "backend", task_ids=[_IN_SCOPE_TASK_ID])
    headers = {"Authorization": f"Bearer {token}"}

    routes = _mutating_task_id_routes(app)
    for index, (method, template) in enumerate(routes):
        path = template.replace("{task_id}", _OUT_OF_SCOPE_TASK_ID)
        # A fresh peer address per request: the write rate limiter allows 30
        # requests/minute per client and would answer 429 long before the
        # enumeration finished, masking the authorization result.
        client = TestClient(app, client=(f"10.{index // 256}.{index % 256}.1", 40000 + index))
        response = client.request(method, path, headers=headers, json={})

        assert response.status_code == 403, f"{method} {path} -> {response.status_code}"


def test_every_mutating_task_route_allows_in_scope_identity(app: FastAPI) -> None:
    """The same routes are permitted when the path addresses the token's own task."""
    for method, template in _mutating_task_id_routes(app):
        path = template.replace("{task_id}", _IN_SCOPE_TASK_ID)

        assert _check_agent_task_scope(path, [_IN_SCOPE_TASK_ID]) is None, f"{method} {path}"


def test_task_collection_segments_are_pinned_to_the_route_table(app: FastAPI) -> None:
    """Exempt segments match the collection routes actually registered.

    Adding a new ``/tasks/<literal>`` route fails here until the segment is
    added to ``TASK_COLLECTION_SEGMENTS`` deliberately - the exemption can
    never be acquired by accident.
    """
    assert _task_collection_segments(app) == set(TASK_COLLECTION_SEGMENTS)


def test_collection_routes_are_not_treated_as_task_ids(app: FastAPI) -> None:
    """Collection routes stay reachable for a task-scoped agent."""
    for segment in _task_collection_segments(app):
        assert _check_agent_task_scope(f"/tasks/{segment}", [_IN_SCOPE_TASK_ID]) is None, segment
        assert _check_agent_task_scope(f"/api/v1/tasks/{segment}", [_IN_SCOPE_TASK_ID]) is None, segment


def test_versioned_mirror_is_scope_checked() -> None:
    """The ``/api/v1`` mirror of a task route is gated like the root mount."""
    error = _check_agent_task_scope(f"/api/v1/tasks/{_OUT_OF_SCOPE_TASK_ID}/complete", [_IN_SCOPE_TASK_ID])

    assert error is not None
    assert _OUT_OF_SCOPE_TASK_ID in error


def test_dead_steal_alternative_is_gone() -> None:
    """``/tasks/{id}/steal`` never existed; the pattern no longer names it."""
    assert "steal" not in _TASK_ID_PATH_RE.pattern


def test_cluster_steal_is_not_a_task_scoped_path() -> None:
    """The real steal route (``POST /cluster/steal``) is outside this gate."""
    assert _check_agent_task_scope("/cluster/steal", [_IN_SCOPE_TASK_ID]) is None


def test_non_task_paths_are_unaffected() -> None:
    """Bulletin/status/task-collection paths never trigger a scope error."""
    for path in ("/bulletin", "/status", "/tasks", "/tasks/", "/agents/a1/kill", "/api/v1/tasks"):
        assert _check_agent_task_scope(path, [_IN_SCOPE_TASK_ID]) is None, path
