"""Cost and usage aggregation must stay inside the caller's tenant.

Split out of the former ``tests/unit/test_tenant_scope_http_isolation.py``.
That file built a fresh app per test across 137 tests; the per-test teardown
cost scales with the live heap, so the whole file ran ~200s locally and blew
past the runner's 300s per-file budget on the slower macOS host. The runner
budgets per *file* and gives each one its own subprocess, so three focused
modules sharing one conftest keep every group well inside the budget.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from bernstein.core.tenanting import DEFAULT_TENANT_ID
from httpx import AsyncClient

from tests.unit.tenant_scope.conftest import (
    TENANT_B,
    Fixture,
    _credential,
)

# ``auth_enabled`` opts out of the autouse ``BERNSTEIN_AUTH_DISABLED`` shim:
# these tests are about what authentication binds, so authentication has to
# actually run. A ``pytestmark`` in the conftest would not reach here -- it
# only applies to tests collected in the module that declares it.
pytestmark = [pytest.mark.ci, pytest.mark.auth_enabled]

# ---------------------------------------------------------------------------
# Cost surface
#
# A run's cost file holds the usages of every tenant that spent against that
# run.  The aggregate readers therefore have to narrow to the caller's scope
# before they total anything, or one scope's spend, model mix and task titles
# are reported to another.  These cases seed one run with usages from two
# scopes and assert each endpoint reports only the caller's own.
# ---------------------------------------------------------------------------

# ``/costs`` and ``/costs/live`` already narrowed before this change; the rest
# are the readers that did not.
SCOPED_COST_ENDPOINTS = [
    "/costs",
    "/costs/live",
    "/costs/current",
    "/costs/export",
    "/costs/top-tasks",
    "/costs/history",
    "/costs/forecast",
    "/costs/by-adapter",
    "/costs/token-efficiency",
    "/costs/cache-stats",
    "/costs/efficiency",
]

# Spend recorded for the out-of-scope tenant. Distinctive enough that a leak
# is visible as a literal in the response body.
OUTSIDER_COST_USD = 987.654321
OUTSIDER_MODEL = "outsider-only-model"
OUTSIDER_AGENT = "outsider-only-agent"


@pytest.fixture()
def seeded_costs(fx: Fixture, sdd_dir: Path) -> float:
    """Write one run file carrying usages from two scopes.

    Returns the in-scope spend, which is what a correctly narrowed reader
    must report.
    """
    from bernstein.core.cost_tracker import CostTracker

    in_scope_cost = 1.5
    tracker = CostTracker(run_id="mixed-scope-run", budget_usd=10_000.0)
    tracker.record(
        "agent-in-scope",
        fx.task_default_id,
        "in-scope-model",
        1_000,
        500,
        cost_usd=in_scope_cost,
        tenant_id=DEFAULT_TENANT_ID,
    )
    tracker.record(
        OUTSIDER_AGENT,
        fx.task_b_id,
        OUTSIDER_MODEL,
        9_000,
        9_000,
        cost_usd=OUTSIDER_COST_USD,
        tenant_id=TENANT_B,
    )
    tracker.save(sdd_dir)
    return in_scope_cost


@pytest.mark.anyio()
@pytest.mark.parametrize("endpoint", SCOPED_COST_ENDPOINTS)
async def test_cost_endpoints_report_only_the_callers_scope(
    fx: Fixture,
    client: AsyncClient,
    seeded_costs: float,
    endpoint: str,
) -> None:
    """No cost reader surfaces spend recorded outside the caller's scope.

    The assertion is on the serialised body rather than one parsed field:
    these endpoints differ in shape, and the property under test is that the
    out-of-scope figures appear in none of them - as a total, a per-model or
    per-agent row, an export line, or a task title.
    """
    credential = _credential(fx, "legacy_bearer")

    response = await client.get(endpoint, headers=credential.headers)

    assert response.status_code == 200, f"{endpoint} returned {response.status_code}"
    body = response.text
    assert str(OUTSIDER_COST_USD) not in body, f"{endpoint} reported out-of-scope spend"
    assert OUTSIDER_MODEL not in body, f"{endpoint} reported an out-of-scope model"
    assert OUTSIDER_AGENT not in body, f"{endpoint} reported an out-of-scope agent"


@pytest.mark.anyio()
async def test_cost_current_still_reports_the_callers_own_spend(
    fx: Fixture,
    client: AsyncClient,
    seeded_costs: float,
) -> None:
    """Narrowing does not over-refuse: in-scope spend is still reported.

    The companion to the leak assertions - a reader that returned zero for
    everyone would satisfy those and be useless.
    """
    credential = _credential(fx, "legacy_bearer")

    response = await client.get("/costs/current", headers=credential.headers)

    assert response.status_code == 200
    assert response.json()["spent_usd"] == pytest.approx(seeded_costs)


# ---------------------------------------------------------------------------
# Narrowing correctness: what the scoped readers must NOT drop or mis-divide
# ---------------------------------------------------------------------------
# The leak cases above pin that out-of-scope rows stay out.  These pin the
# other half - that narrowing keeps every in-scope row, and that a figure
# derived from the narrowed set is divided by the cap that bounds that set.


def _rewrite_usage_tenants(sdd_dir: Path, run_id: str, stored: str) -> None:
    """Rewrite the persisted tenant on every usage of a run file.

    Usage records are persisted verbatim - ``TokenUsage.from_dict`` does not
    normalize - so a file written before the tenant was normalized on the way
    in carries whatever string was recorded, padding included.
    """
    import json

    path = sdd_dir / "runtime" / "costs" / f"{run_id}.json"
    payload = json.loads(path.read_text())
    for usage in payload["usages"]:
        usage["tenant_id"] = stored
    path.write_text(json.dumps(payload))


@pytest.mark.anyio()
@pytest.mark.parametrize("endpoint", ["/costs", "/costs/live"])
async def test_scoped_totals_keep_usages_whose_stored_tenant_needs_normalizing(
    fx: Fixture,
    client: AsyncClient,
    sdd_dir: Path,
    endpoint: str,
) -> None:
    """A legacy tenant string that normalizes into scope is still counted.

    ``CostTracker.load`` admits a usage by comparing normalized tenant ids,
    so a row persisted as ``"  default  "`` belongs to the default scope.  A
    reducer that re-compared the raw field afterwards would drop exactly the
    rows the load admitted and report a total short by their spend.
    """
    from bernstein.core.cost_tracker import CostTracker

    recorded_cost = 2.25
    tracker = CostTracker(run_id="legacy-tenant-run", budget_usd=10_000.0)
    tracker.record(
        "legacy-agent",
        fx.task_default_id,
        "legacy-model",
        1_000,
        500,
        cost_usd=recorded_cost,
        tenant_id=DEFAULT_TENANT_ID,
    )
    tracker.save(sdd_dir)
    _rewrite_usage_tenants(sdd_dir, "legacy-tenant-run", f"  {DEFAULT_TENANT_ID}  ")

    credential = _credential(fx, "legacy_bearer")
    response = await client.get(endpoint, headers=credential.headers)

    assert response.status_code == 200
    body = response.json()
    reported = body["total_spent_usd"] if endpoint == "/costs" else body["spent_usd"]
    assert reported == pytest.approx(recorded_cost)
    assert body["per_agent"]["legacy-agent"] == pytest.approx(recorded_cost)
    assert body["per_model"]["legacy-model"] == pytest.approx(recorded_cost)


@pytest.mark.anyio()
async def test_scoped_status_divides_by_the_tenants_cap_not_the_runs(
    fx: Fixture,
    client: AsyncClient,
    sdd_dir: Path,
    seeded_costs: float,
) -> None:
    """A tenant-scoped budget figure uses the tenant's configured cap.

    The cap persisted in a run file bounds the whole run across every tenant
    that spent against it.  Reporting one tenant's narrowed spend against it
    divides an in-scope numerator by an out-of-scope denominator, so the
    percentage, the remaining amount and the warn/stop flags all describe a
    budget the caller does not have.  Where the deployment configures a cap
    for the tenant, that cap is the one the scoped read must use.
    """
    from bernstein.core.tenanting import TenantConfig, TenantRegistry

    tenant_cap = 3.0
    assert seeded_costs < tenant_cap, "precondition: in-scope spend fits inside the tenant cap"
    fx.app.state.tenant_registry = TenantRegistry(tenants=(TenantConfig(id=DEFAULT_TENANT_ID, budget_usd=tenant_cap),))

    credential = _credential(fx, "legacy_bearer")
    response = await client.get("/costs/current", headers=credential.headers)

    assert response.status_code == 200
    body = response.json()
    # The run file was seeded with a 10_000.0 run-wide cap; the tenant's is 3.0.
    assert body["budget_usd"] == pytest.approx(tenant_cap)
    assert body["percentage_used"] == pytest.approx(seeded_costs / tenant_cap, abs=1e-4)
    assert body["remaining_usd"] == pytest.approx(tenant_cap - seeded_costs)


# ---------------------------------------------------------------------------
# Row-level robustness of the cost replay
# ---------------------------------------------------------------------------


def _write_usage_rows(sdd_dir: Path, run_id: str, rows: list[dict[str, Any]]) -> None:
    """Replace a run file's usage rows with *rows* verbatim."""
    import json

    path = sdd_dir / "runtime" / "costs" / f"{run_id}.json"
    payload = json.loads(path.read_text())
    payload["usages"] = rows
    path.write_text(json.dumps(payload))


def _usage_row(**overrides: Any) -> dict[str, Any]:
    """A well-formed persisted usage row, before any override."""
    row: dict[str, Any] = {
        "input_tokens": 10,
        "output_tokens": 5,
        "model": "row-model",
        "cost_usd": 1.0,
        "agent_id": "row-agent",
        "task_id": "row-task",
        "tenant_id": DEFAULT_TENANT_ID,
        "timestamp": 1_700_000_000.0,
    }
    row.update(overrides)
    return row


@pytest.mark.anyio()
async def test_one_unreadable_usage_row_does_not_discard_the_run(
    fx: Fixture,
    client: AsyncClient,
    sdd_dir: Path,
) -> None:
    """A single bad row is skipped; the rows beside it still count.

    A run file accumulates thousands of rows.  Aborting the whole replay on
    the first unreadable one reports a run that spent money as having spent
    nothing, which is the more dangerous failure of the two.
    """
    from bernstein.core.cost_tracker import CostTracker

    tracker = CostTracker(run_id="row-robustness-run", budget_usd=10_000.0)
    tracker.record("seed-agent", fx.task_default_id, "seed-model", 1, 1, cost_usd=0.0, tenant_id=DEFAULT_TENANT_ID)
    tracker.save(sdd_dir)
    _write_usage_rows(
        sdd_dir,
        "row-robustness-run",
        [
            _usage_row(cost_usd=1.25),
            {"input_tokens": 1},  # missing every required key
            _usage_row(cost_usd="not-a-number"),
            _usage_row(cost_usd=2.75),
        ],
    )

    credential = _credential(fx, "legacy_bearer")
    response = await client.get("/costs/live", headers=credential.headers)

    assert response.status_code == 200
    assert response.json()["spent_usd"] == pytest.approx(4.0)


@pytest.mark.anyio()
@pytest.mark.parametrize("bad_tenant", [42, True, ["default"], {"id": "default"}])
async def test_a_row_whose_tenant_is_not_a_tenant_reaches_no_aggregate(
    fx: Fixture,
    client: AsyncClient,
    sdd_dir: Path,
    bad_tenant: object,
) -> None:
    """A non-string stored tenant is refused, not coerced into a scope.

    ``str()`` would turn each of these into a plausible-looking scope label
    and file the row's spend under a tenant nobody ever had - and ``None``
    would file it under the default tenant, which is somebody's.
    """
    from bernstein.core.cost_tracker import CostTracker

    good_cost = 3.5
    tracker = CostTracker(run_id="bad-tenant-run", budget_usd=10_000.0)
    tracker.record("seed-agent", fx.task_default_id, "seed-model", 1, 1, cost_usd=0.0, tenant_id=DEFAULT_TENANT_ID)
    tracker.save(sdd_dir)
    _write_usage_rows(
        sdd_dir,
        "bad-tenant-run",
        [
            _usage_row(cost_usd=good_cost),
            _usage_row(cost_usd=99.5, tenant_id=bad_tenant, agent_id="ghost-agent"),
        ],
    )

    credential = _credential(fx, "legacy_bearer")
    response = await client.get("/costs/live", headers=credential.headers)

    assert response.status_code == 200
    body = response.json()
    assert body["spent_usd"] == pytest.approx(good_cost)
    assert "ghost-agent" not in body["per_agent"]


@pytest.mark.anyio()
@pytest.mark.parametrize("endpoint", ["/costs/current", "/costs/alerts"])
async def test_scoped_cost_responses_name_their_scope(
    fx: Fixture,
    client: AsyncClient,
    seeded_costs: float,
    endpoint: str,
) -> None:
    """A tenant projection says which tenant it is a projection of.

    These endpoints return one tenant's share of a run in fields whose names
    read as run-wide accounting, so the response has to carry the scope for a
    client to tell the two apart.
    """
    credential = _credential(fx, "legacy_bearer")

    response = await client.get(endpoint, headers=credential.headers)

    assert response.status_code == 200
    assert response.json()["tenant_id"] == DEFAULT_TENANT_ID
