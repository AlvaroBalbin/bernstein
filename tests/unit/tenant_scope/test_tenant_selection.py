"""Tenant selection, binding, and request-scope resolution over HTTP.

Split out of the former ``tests/unit/test_tenant_scope_http_isolation.py``.
That file built a fresh app per test across 137 tests; the per-test teardown
cost scales with the live heap, so the whole file ran ~200s locally and blew
past the runner's 300s per-file budget on the slower macOS host. The runner
budgets per *file* and gives each one its own subprocess, so three focused
modules sharing one conftest keep every group well inside the budget.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from bernstein.core.tenanting import DEFAULT_TENANT_ID, request_tenant_id
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from bernstein.core.server import create_app
from bernstein.core.server.server_models import TaskCreate
from tests.unit.tenant_scope.conftest import (
    READ_CREDENTIALS,
    READ_CREDENTIALS_WITH_OWN_TENANT,
    REJECTION_STATUSES,
    TENANT_A,
    TENANT_B,
    WRITE_CREDENTIALS,
    Fixture,
    _credential,
    _tenant_task_ids,
)

# ``auth_enabled`` opts out of the autouse ``BERNSTEIN_AUTH_DISABLED`` shim:
# these tests are about what authentication binds, so authentication has to
# actually run. A ``pytestmark`` in the conftest would not reach here -- it
# only applies to tests collected in the module that declares it.
pytestmark = [pytest.mark.ci, pytest.mark.auth_enabled]

# ---------------------------------------------------------------------------
# GET /tasks/{id}
# ---------------------------------------------------------------------------


@pytest.mark.anyio()
@pytest.mark.parametrize("credential_name", READ_CREDENTIALS)
async def test_get_task_rejects_tenant_selected_by_header(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
) -> None:
    """Reading another tenant's task is refused however the caller asks for it."""
    credential = _credential(fx, credential_name)

    response = await client.get(
        f"/tasks/{fx.task_b_id}",
        headers=credential.crossing_headers(),
    )

    assert response.status_code in REJECTION_STATUSES, (
        f"{credential_name} read tenant B's task with X-Tenant-Id: got {response.status_code}"
    )


# ---------------------------------------------------------------------------
# PATCH /tasks/{id}
# ---------------------------------------------------------------------------


@pytest.mark.anyio()
@pytest.mark.parametrize("credential_name", WRITE_CREDENTIALS)
async def test_patch_task_rejects_tenant_selected_by_header(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
) -> None:
    """Mutating another tenant's task is refused, and the row is untouched."""
    credential = _credential(fx, credential_name)
    store: Any = fx.app.state.store
    before = store.get_task(fx.task_b_id)
    assert before is not None

    response = await client.patch(
        f"/tasks/{fx.task_b_id}",
        headers=credential.crossing_headers(),
        json={"priority": 0, "role": "security"},
    )

    assert response.status_code in REJECTION_STATUSES, (
        f"{credential_name} patched tenant B's task with X-Tenant-Id: got {response.status_code}"
    )
    after = store.get_task(fx.task_b_id)
    assert after is not None
    assert (after.priority, after.role) == (before.priority, before.role), (
        f"{credential_name} mutated tenant B's task despite the refusal"
    )


# ---------------------------------------------------------------------------
# POST /tasks
# ---------------------------------------------------------------------------


@pytest.mark.anyio()
@pytest.mark.parametrize("credential_name", WRITE_CREDENTIALS)
async def test_create_task_does_not_enqueue_into_selected_tenant(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
) -> None:
    """A create naming another tenant must not land a row in that tenant's queue.

    This is the one that reaches past the API surface: a row written into
    tenant B's queue is picked up by tenant B's own ``claim_next``, so a
    create that merely *returned* an error while still storing the row would
    hand the caller's work to another tenant's agents.
    """
    credential = _credential(fx, credential_name)
    before = _tenant_task_ids(fx, TENANT_B)

    response = await client.post(
        "/tasks",
        headers=credential.crossing_headers(),
        json={"title": "injected", "description": "created while naming tenant B", "role": "backend"},
    )

    assert response.status_code in REJECTION_STATUSES, (
        f"{credential_name} created a task while naming tenant B: got {response.status_code}"
    )
    assert _tenant_task_ids(fx, TENANT_B) == before, f"{credential_name} stored a row into tenant B's queue"


# ---------------------------------------------------------------------------
# The scope a credential IS bound to stays reachable
# ---------------------------------------------------------------------------


@pytest.mark.anyio()
@pytest.mark.parametrize("credential_name", ["sso_viewer", "agent_task_scoped", "agent_unrestricted"])
async def test_bound_tenant_remains_readable(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
) -> None:
    """Positive control: a credential still reads the tenant it is bound to.

    Without this, every assertion above would be satisfied by a server that
    refused everything.
    """
    credential = _credential(fx, credential_name)

    response = await client.get(f"/tasks/{fx.task_a_id}", headers=credential.headers)

    assert response.status_code == 200, f"{credential_name} lost access to its own tenant"
    assert response.json()["id"] == fx.task_a_id


@pytest.mark.anyio()
@pytest.mark.parametrize(
    ("credential_name", "own_tenant"),
    [
        ("sso_viewer", TENANT_A),
        ("agent_task_scoped", TENANT_A),
        ("agent_unrestricted", TENANT_A),
        ("legacy_bearer", DEFAULT_TENANT_ID),
        ("cluster_secret", DEFAULT_TENANT_ID),
    ],
)
async def test_naming_the_bound_tenant_explicitly_still_succeeds(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
    own_tenant: str,
) -> None:
    """Asking for the scope you already hold is still granted.

    Clients that send ``X-Tenant-Id`` on every request - the documented way
    to be explicit about which tenant you mean - keep working, because the
    selector is authorized against the bound scope rather than rejected on
    sight.  Only a selector that disagrees with the binding is refused.
    """
    credential = _credential(fx, credential_name)
    task_id = fx.task_a_id if own_tenant == TENANT_A else fx.task_default_id

    response = await client.get(
        f"/tasks/{task_id}",
        headers=credential.crossing_headers(own_tenant),
    )

    assert response.status_code == 200, (
        f"{credential_name} was refused its own tenant '{own_tenant}': got {response.status_code}"
    )
    assert response.json()["id"] == task_id


@pytest.mark.anyio()
@pytest.mark.parametrize("credential_name", ["legacy_bearer", "cluster_secret"])
async def test_default_bound_credential_cannot_reach_a_named_tenant(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
) -> None:
    """A credential with no tenant of its own is confined to the default tenant.

    The legacy operator bearer and the cluster worker secret are single
    shared strings that carry no tenant claim.  They bind to the default
    tenant, and the default tenant is a tenant like any other - not a
    wildcard that reaches every named tenant.
    """
    credential = _credential(fx, credential_name)

    response = await client.get(
        f"/tasks/{fx.task_a_id}",
        headers=credential.crossing_headers(TENANT_A),
    )

    assert response.status_code in REJECTION_STATUSES, (
        f"{credential_name} reached tenant A from the default tenant: got {response.status_code}"
    )


# ---------------------------------------------------------------------------
# What the request's scope is actually derived from
# ---------------------------------------------------------------------------


@pytest.mark.anyio()
@pytest.mark.parametrize(
    ("credential_name", "expected_tenant"),
    [
        ("legacy_bearer", DEFAULT_TENANT_ID),
        ("cluster_secret", DEFAULT_TENANT_ID),
        ("sso_viewer", TENANT_A),
        ("agent_task_scoped", TENANT_A),
        ("agent_unrestricted", TENANT_A),
    ],
)
async def test_request_scope_comes_from_the_credential_not_the_header(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
    expected_tenant: str,
) -> None:
    """``request_tenant_id`` reports what authentication bound, nothing else.

    Asserted through a probe route on the real app so the whole middleware
    chain runs: if any layer between the socket and the handler - the access
    log included - could write the request's scope from a header, the header
    sent here would be what the handler reads.
    """
    probe_path = "/_probe_request_tenant"

    @fx.app.get(probe_path)
    def _probe(request: Request) -> dict[str, str]:
        return {"tenant": request_tenant_id(request)}

    response = await client.get(
        probe_path,
        headers=_credential(fx, credential_name).crossing_headers(),
    )

    assert response.status_code == 200
    assert response.json()["tenant"] == expected_tenant


# ---------------------------------------------------------------------------
# Development mode (BERNSTEIN_AUTH_DISABLED) keeps its documented behaviour
# ---------------------------------------------------------------------------


@pytest.fixture()
async def dev_mode_client(
    jsonl_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[tuple[AsyncClient, FastAPI, str]]:
    """The app as it runs locally with authentication switched off."""
    monkeypatch.setenv("BERNSTEIN_AUTH_DISABLED", "1")

    app = create_app(jsonl_path=jsonl_path)
    store: Any = app.state.store
    task_b = await store.create(
        TaskCreate(title="tenant B work", description="belongs to tenant B", role="backend", tenant_id=TENANT_B)
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac, app, task_b.id


@pytest.mark.anyio()
async def test_dev_mode_selects_the_tenant_named_by_the_caller(
    dev_mode_client: tuple[AsyncClient, FastAPI, str],
) -> None:
    """With auth off, ``X-Tenant-Id`` still chooses the tenant.

    There is no credential to derive a scope from in this mode, and local
    multi-tenant development depends on being able to pick a tenant, so the
    documented header behaviour is preserved exactly where it is safe: with
    authentication switched off there is no boundary to hold.
    """
    client, _app, task_b_id = dev_mode_client

    response = await client.get(f"/tasks/{task_b_id}", headers={"X-Tenant-Id": TENANT_B})

    assert response.status_code == 200
    assert response.json()["id"] == task_b_id


@pytest.mark.anyio()
async def test_dev_mode_without_a_header_falls_back_to_the_default_tenant(
    dev_mode_client: tuple[AsyncClient, FastAPI, str],
) -> None:
    """The documented ``DEFAULT_TENANT_ID`` fallback still applies with auth off."""
    client, app, _task_b_id = dev_mode_client
    probe_path = "/_probe_dev_mode_tenant"

    @app.get(probe_path)
    def _probe(request: Request) -> dict[str, str]:
        return {"tenant": request_tenant_id(request)}

    response = await client.get(probe_path)

    assert response.status_code == 200
    assert response.json()["tenant"] == DEFAULT_TENANT_ID


# ---------------------------------------------------------------------------
# Read paths beyond GET /tasks/{id}
#
# The scope a request resolves to has to be applied on every route that
# reads or writes a task, not only the one that reads a task by id.  These
# cases pin the routes that reach task rows by another route: a neighbour
# walk, a log stream, and the three create paths that name an existing
# parent in the request body.
# ---------------------------------------------------------------------------


# Each read credential paired with the tenant it is bound to, so a case can
# address a row the caller may legitimately read.


@pytest.mark.anyio()
@pytest.mark.parametrize(("credential_name", "own_tenant"), READ_CREDENTIALS_WITH_OWN_TENANT)
async def test_graph_neighbors_stay_inside_the_callers_scope(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
    own_tenant: str,
) -> None:
    """A dependency edge that leaves the caller's scope is not materialised.

    The route reads the requested task under the scope gate, then builds its
    two neighbour lists from a separate store walk.  If that walk is not
    itself constrained, a row outside the scope that names the requested task
    as a dependency comes back with its title, status and role attached.
    """
    credential = _credential(fx, credential_name)
    own_task_id = fx.task_a_id if own_tenant == TENANT_A else fx.task_default_id
    store: Any = fx.app.state.store
    # A row outside the caller's scope that points at the in-scope task.
    outsider = await store.create(
        TaskCreate(
            title="outside-scope dependent",
            description="declares the in-scope task as a dependency",
            role="backend",
            tenant_id=TENANT_B,
            depends_on=[own_task_id],
        )
    )

    response = await client.get(
        f"/tasks/{own_task_id}/graph-neighbors",
        headers=credential.headers,
    )

    assert response.status_code == 200, f"{credential_name} could not read its own task's neighbours"
    payload = response.json()
    returned = {entry["id"] for entry in payload["upstream"]} | {entry["id"] for entry in payload["downstream"]}
    assert outsider.id not in returned, f"{credential_name} saw an out-of-scope neighbour in {payload['downstream']}"


@pytest.mark.anyio()
@pytest.mark.parametrize("credential_name", READ_CREDENTIALS)
async def test_task_log_stream_requires_the_callers_scope(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
) -> None:
    """The log stream applies the same gate the task-detail route applies."""
    credential = _credential(fx, credential_name)

    response = await client.get(
        f"/dashboard/tasks/{fx.task_b_id}/logs/stream",
        headers=credential.crossing_headers(),
    )

    assert response.status_code in REJECTION_STATUSES, (
        f"{credential_name} opened a log stream for an out-of-scope task: got {response.status_code}"
    )


@pytest.mark.anyio()
@pytest.mark.parametrize("credential_name", WRITE_CREDENTIALS)
async def test_create_task_refuses_a_parent_outside_the_callers_scope(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
) -> None:
    """A body-supplied parent has to resolve inside the scope the child lands in.

    The child row is written into the caller's own scope, so an accepted
    request would leave a parent-child edge spanning two scopes and let one
    side's write drive the other side's subtree completion logic.
    """
    credential = _credential(fx, credential_name)
    before = _tenant_task_ids(fx, TENANT_B)

    response = await client.post(
        "/tasks",
        headers=credential.headers,
        json={
            "title": "child naming an out-of-scope parent",
            "description": "parent_task_id resolves outside the caller's scope",
            "role": "backend",
            "parent_task_id": fx.task_b_id,
        },
    )

    assert response.status_code in REJECTION_STATUSES, (
        f"{credential_name} attached a child to an out-of-scope parent: got {response.status_code}"
    )
    assert _tenant_task_ids(fx, TENANT_B) == before, f"{credential_name} wrote a row despite the refusal"


@pytest.mark.anyio()
@pytest.mark.parametrize("credential_name", WRITE_CREDENTIALS)
async def test_batch_create_refuses_a_parent_outside_the_callers_scope(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
) -> None:
    """The batch path applies the same parent rule as the single-create path."""
    credential = _credential(fx, credential_name)
    before = _tenant_task_ids(fx, TENANT_B)

    response = await client.post(
        "/tasks/batch",
        headers=credential.headers,
        json={
            "tasks": [
                {
                    "title": "batch child naming an out-of-scope parent",
                    "description": "parent_task_id resolves outside the caller's scope",
                    "role": "backend",
                    "parent_task_id": fx.task_b_id,
                }
            ]
        },
    )

    assert response.status_code in REJECTION_STATUSES, (
        f"{credential_name} batch-attached a child to an out-of-scope parent: got {response.status_code}"
    )
    assert _tenant_task_ids(fx, TENANT_B) == before, f"{credential_name} wrote a row despite the refusal"


@pytest.mark.anyio()
@pytest.mark.parametrize("credential_name", WRITE_CREDENTIALS)
async def test_self_create_subtask_refuses_a_parent_outside_the_callers_scope(
    fx: Fixture,
    client: AsyncClient,
    credential_name: str,
) -> None:
    """The self-create path transitions its parent, so the parent must be in scope.

    This route moves the named parent to ``waiting_for_subtasks``.  The
    assertion covers the transition as well as the status code: a refusal
    that still moved the parent would pass a status-only check.
    """
    credential = _credential(fx, credential_name)
    store: Any = fx.app.state.store
    before_status = store.get_task(fx.task_b_id).status.value

    response = await client.post(
        "/tasks/self-create",
        headers=credential.headers,
        json={
            "title": "subtask naming an out-of-scope parent",
            "description": "parent_task_id resolves outside the caller's scope",
            "role": "backend",
            "parent_task_id": fx.task_b_id,
        },
    )

    assert response.status_code in REJECTION_STATUSES, (
        f"{credential_name} subtasked an out-of-scope parent: got {response.status_code}"
    )
    assert store.get_task(fx.task_b_id).status.value == before_status, (
        f"{credential_name} transitioned an out-of-scope parent despite the refusal"
    )
