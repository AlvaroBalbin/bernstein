"""Release-receipt regression tests (#3037).

Claiming a task mints a ``task.claim_receipt`` on the audit chain. These tests
pin the other half: every transition that ends a held claim mints the matching
``task.release_receipt``, so folding the chain reconstructs the real holder of
a task instead of the last node that acquired it.

The tests are organised as:

* an enumeration over every un-claim path in :class:`TaskStore`, so a new path
  that forgets the receipt is caught by name rather than by luck;
* an offline reconstruction of claim -> release -> re-claim asserted from the
  chain alone;
* the same reconstruction on a plain ``bernstein serve`` node, with the
  orchestrator's ``BERNSTEIN_AUDIT`` lifecycle wiring absent;
* a static guard that no future method can clear ``claimed_by_session``
  without minting the receipt.
"""

from __future__ import annotations

import ast
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from fastapi.testclient import TestClient

from bernstein.core.security.audit_chain import (
    EVENT_TASK_CLAIM_RECEIPT,
    EVENT_TASK_RELEASE_RECEIPT,
    AuditChainStore,
    reconstruct_claim_holders,
)
from bernstein.core.tasks.contracts import ContractViolation, RefusalKind, WorkerRefusal
from bernstein.core.tasks.models import Task, TaskStatus
from bernstein.core.tasks.task_store_core import TaskStore

if TYPE_CHECKING:
    from bernstein.core.security.audit import AuditEvent

_KEY = b"release-receipt-test-key"
_HOLDER = "node-a"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _store(tmp_path: Path) -> tuple[TaskStore, AuditChainStore]:
    """Build a TaskStore with an audit chain attached, as ``create_app`` does."""
    runtime = tmp_path / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    store = TaskStore(runtime / "tasks.jsonl", archive_path=tmp_path / "archive" / "tasks.jsonl")
    chain = AuditChainStore(tmp_path / "audit", key=_KEY)
    store.attach_audit_chain(chain)
    return store, chain


def _held(store: TaskStore, task_id: str = "T-1", **overrides: Any) -> Task:
    """Insert a task that a worker currently holds a claim on."""
    base: dict[str, Any] = {
        "id": task_id,
        "title": "t",
        "description": "d",
        "role": "backend",
        "status": TaskStatus.IN_PROGRESS,
        "claimed_at": time.time(),
        "claimed_by_session": _HOLDER,
    }
    base.update(overrides)
    task = Task(**base)
    store._tasks[task.id] = task
    store._index_add(task)
    return task


def _releases(chain: AuditChainStore) -> list[AuditEvent]:
    return chain.query(event_type=EVENT_TASK_RELEASE_RECEIPT)


# ---------------------------------------------------------------------------
# One test per un-claim path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestEveryUnclaimPathMintsAReceipt:
    """Enumerates the un-claim paths instead of spot-checking one of them."""

    async def test_force_claim(self, tmp_path: Path) -> None:
        store, chain = _store(tmp_path)
        _held(store)
        await store.force_claim("T-1")
        events = _releases(chain)
        assert len(events) == 1
        assert events[0].details["release_path"] == "force_claim"
        assert events[0].details["released_by"] == _HOLDER
        assert events[0].details["from_status"] == "in_progress"
        assert events[0].details["to_status"] == "open"

    async def test_reopen(self, tmp_path: Path) -> None:
        store, chain = _store(tmp_path)
        _held(store, status=TaskStatus.DONE)
        await store.reopen("T-1", "janitor verification failed")
        events = _releases(chain)
        assert len(events) == 1
        assert events[0].details["release_path"] == "reopen"
        assert events[0].details["released_by"] == _HOLDER
        assert events[0].details["to_status"] == "open"

    async def test_cancel(self, tmp_path: Path) -> None:
        store, chain = _store(tmp_path)
        _held(store)
        await store.cancel("T-1", "operator cancelled")
        events = _releases(chain)
        assert len(events) == 1
        assert events[0].details["release_path"] == "cancel"
        assert events[0].details["to_status"] == "cancelled"

    async def test_cancel_cascade(self, tmp_path: Path) -> None:
        # The /tasks/{id}/cancel route cascades, so the cascade body needs its
        # own receipt: a child held by another node is un-claimed here too.
        store, chain = _store(tmp_path)
        _held(store, "T-1")
        _held(store, "T-2", parent_task_id="T-1", claimed_by_session="node-b")
        await store.cancel_cascade("T-1", "operator cancelled the tree")
        released = {e.details["task_id"]: e.details["released_by"] for e in _releases(chain)}
        assert released == {"T-1": _HOLDER, "T-2": "node-b"}

    async def test_fail(self, tmp_path: Path) -> None:
        store, chain = _store(tmp_path)
        _held(store)
        await store.fail("T-1", "tests red")
        events = _releases(chain)
        assert len(events) == 1
        assert events[0].details["release_path"] == "fail"
        assert events[0].details["to_status"] == "failed"

    async def test_fail_contract_violation(self, tmp_path: Path) -> None:
        store, chain = _store(tmp_path)
        _held(store)
        await store.fail_contract_violation("T-1", ContractViolation(path="$.status", message="missing"))
        events = _releases(chain)
        assert len(events) == 1
        assert events[0].details["release_path"] == "fail_contract_violation"

    async def test_refuse(self, tmp_path: Path) -> None:
        store, chain = _store(tmp_path)
        _held(store)
        await store.refuse(
            "T-1",
            WorkerRefusal(kind=RefusalKind.SCOPE_EXCEEDED, detail="needs a spec change"),
        )
        events = _releases(chain)
        assert len(events) == 1
        assert events[0].details["release_path"] == "refuse"
        assert events[0].details["to_status"] == "refused"

    async def test_abandon(self, tmp_path: Path) -> None:
        store, chain = _store(tmp_path)
        _held(store)
        await store.abandon("T-1", "out_of_scope", "spec mismatch")
        events = _releases(chain)
        assert len(events) == 1
        assert events[0].details["release_path"] == "abandon"
        assert events[0].details["to_status"] == "abandoned"

    async def test_restart_recovery(self, tmp_path: Path) -> None:
        store, chain = _store(tmp_path)
        _held(store, "T-1", status=TaskStatus.CLAIMED)
        _held(store, "T-2", status=TaskStatus.IN_PROGRESS)
        assert store.recover_stale_claimed_tasks() == 2
        events = _releases(chain)
        assert {e.details["task_id"] for e in events} == {"T-1", "T-2"}
        assert {e.details["release_path"] for e in events} == {"restart_recovery"}

    async def test_node_departure(self, tmp_path: Path) -> None:
        store, chain = _store(tmp_path)
        _held(store, "T-1")
        _held(store, "T-2", claimed_by_session="node-b")
        assert store.reopen_tasks_for_node(_HOLDER) == 1
        events = _releases(chain)
        assert len(events) == 1
        assert events[0].details["task_id"] == "T-1"
        assert events[0].details["release_path"] == "node_departure"
        assert events[0].details["released_by"] == _HOLDER


@pytest.mark.asyncio
class TestReceiptShape:
    async def test_a_never_claimed_task_surrenders_nothing(self, tmp_path: Path) -> None:
        # Cancelling an open task that no worker ever held is not a surrender,
        # so it must not add a release with nothing to release.
        store, chain = _store(tmp_path)
        _held(store, status=TaskStatus.OPEN, claimed_at=None, claimed_by_session=None)
        await store.cancel("T-1", "never started")
        assert _releases(chain) == []

    async def test_receipt_carries_the_post_transition_version_and_reason(self, tmp_path: Path) -> None:
        store, chain = _store(tmp_path)
        task = _held(store)
        before = task.version
        await store.fail("T-1", "tests red")
        details = _releases(chain)[0].details
        assert details["task_version"] == before + 1
        assert details["reason"] == "tests red"
        assert details["role"] == "backend"
        # Chain-anchored exactly like the claim receipt it answers.
        assert details["prev_chain_digest"]
        ok, errors = chain.verify()
        assert ok, errors

    async def test_a_chain_append_failure_never_blocks_the_transition(self, tmp_path: Path) -> None:
        store, _chain = _store(tmp_path)

        class _Broken:
            def log_with_prev_digest(self, **_: Any) -> None:
                raise OSError("chain volume is read-only")

        store.attach_audit_chain(_Broken())  # type: ignore[arg-type]
        _held(store)
        task = await store.force_claim("T-1")
        assert task.status is TaskStatus.OPEN


# ---------------------------------------------------------------------------
# Offline reconstruction from the chain alone
# ---------------------------------------------------------------------------


def _seed_claim(chain: AuditChainStore, task_id: str, holder: str) -> None:
    from bernstein.core.security.audit_chain import record_task_claim_receipt

    record_task_claim_receipt(
        chain=chain,
        task_id=task_id,
        role="backend",
        claimed_by=holder,
        depends_on=[],
        task_version=1,
        claim_path="by_id",
    )


@pytest.mark.asyncio
async def test_replay_reconstructs_the_holder_at_each_point(tmp_path: Path) -> None:
    """claim -> release -> re-claim, read back offline from the chain."""
    store, chain = _store(tmp_path)
    _held(store, status=TaskStatus.CLAIMED)
    _seed_claim(chain, "T-1", _HOLDER)
    assert reconstruct_claim_holders(chain.query()) == {"T-1": _HOLDER}

    await store.force_claim("T-1")
    assert reconstruct_claim_holders(chain.query()) == {}

    _held(store, status=TaskStatus.CLAIMED, claimed_by_session="node-b")
    _seed_claim(chain, "T-1", "node-b")
    assert reconstruct_claim_holders(chain.query()) == {"T-1": "node-b"}

    # Every prefix answers the question, not just the head: a verifier holding
    # a copy of the chain replays ownership as of any point.
    events = chain.query()
    holders_by_prefix = [reconstruct_claim_holders(events[:n]) for n in range(len(events) + 1)]
    assert holders_by_prefix[-1] == {"T-1": "node-b"}
    assert {} in holders_by_prefix

    # A second store over the same on-disk chain reaches the same answer.
    reloaded = AuditChainStore(tmp_path / "audit", key=_KEY)
    assert reconstruct_claim_holders(reloaded.query()) == {"T-1": "node-b"}


def test_an_acquisition_only_chain_misreports_the_holder(tmp_path: Path) -> None:
    """The failure this issue is about, pinned as the contrast case."""
    chain = AuditChainStore(tmp_path / "audit", key=_KEY)
    _seed_claim(chain, "T-1", "node-a")
    _seed_claim(chain, "T-1", "node-b")
    # Claims alone cannot distinguish "node-a handed it over" from "both hold
    # it": only the release receipt in between makes the sequence legible.
    claims = [e.details["claimed_by"] for e in chain.query(event_type=EVENT_TASK_CLAIM_RECEIPT)]
    assert claims == ["node-a", "node-b"]
    assert reconstruct_claim_holders(chain.query()) == {"T-1": "node-b"}


# ---------------------------------------------------------------------------
# Plain ``bernstein serve`` node -- no BERNSTEIN_AUDIT wiring
# ---------------------------------------------------------------------------


@pytest.fixture()
def plain_serve_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """A server built the way ``bernstein serve`` builds one.

    ``BERNSTEIN_AUDIT`` is what wires the orchestrator's lifecycle audit log,
    which is where the generic ``task.transition`` event comes from. It is
    cleared here, and the lifecycle module's global is reset, so the only
    events this app can produce are the ones the server itself writes.
    """
    from bernstein.core.server import create_app
    from bernstein.core.tasks import lifecycle

    monkeypatch.delenv("BERNSTEIN_AUDIT", raising=False)
    monkeypatch.setattr(lifecycle, "_audit_log", None)
    app = create_app(jsonl_path=tmp_path / "runtime" / "tasks.jsonl")
    app.state.draining = False
    return app


def _create_and_claim(client: TestClient, title: str = "release me") -> str:
    created = client.post("/tasks", json={"title": title, "description": "d", "role": "backend"})
    assert created.status_code == 201, created.text
    task_id = created.json()["id"]
    claimed = client.post(f"/tasks/{task_id}/claim", params={"claimed_by_session": _HOLDER})
    assert claimed.status_code == 200, claimed.text
    return str(task_id)


@pytest.mark.parametrize(
    ("endpoint", "body", "release_path"),
    [
        ("force-claim", None, "force_claim"),
        ("cancel", {"reason": "operator cancelled"}, "cancel_cascade"),
        ("fail", {"reason": "tests red"}, "fail"),
    ],
)
def test_plain_serve_node_mints_the_receipt(
    plain_serve_app: Any,
    endpoint: str,
    body: dict[str, str] | None,
    release_path: str,
) -> None:
    from bernstein.core.tasks.lifecycle import get_audit_log

    assert get_audit_log() is None, "the orchestrator's BERNSTEIN_AUDIT wiring must be absent"
    chain = plain_serve_app.state.audit_chain
    with TestClient(plain_serve_app) as client:
        task_id = _create_and_claim(client, f"release via {endpoint}")
        before = len(chain.query(event_type=EVENT_TASK_RELEASE_RECEIPT))
        resp = client.post(f"/tasks/{task_id}/{endpoint}", json=body)
        assert resp.status_code == 200, resp.text

    events = chain.query(event_type=EVENT_TASK_RELEASE_RECEIPT)
    assert len(events) == before + 1
    mine = [e for e in events if e.details["task_id"] == task_id]
    assert len(mine) == 1
    assert mine[0].details["release_path"] == release_path
    assert mine[0].details["released_by"] == _HOLDER


def test_plain_serve_node_reconstructs_the_holder_over_http(plain_serve_app: Any) -> None:
    """The whole loop on a plain node: claim, release, re-claim, replay."""
    chain = plain_serve_app.state.audit_chain
    with TestClient(plain_serve_app) as client:
        task_id = _create_and_claim(client, "reclaimed after release")
        assert reconstruct_claim_holders(chain.query()).get(task_id) == _HOLDER

        assert client.post(f"/tasks/{task_id}/force-claim").status_code == 200
        assert task_id not in reconstruct_claim_holders(chain.query())

        reclaimed = client.post(f"/tasks/{task_id}/claim", params={"claimed_by_session": "node-b"})
        assert reclaimed.status_code == 200, reclaimed.text
        assert reconstruct_claim_holders(chain.query()).get(task_id) == "node-b"

    ok, errors = chain.verify()
    assert ok, errors


def test_plain_serve_node_mints_the_receipt_on_reopen(plain_serve_app: Any) -> None:
    chain = plain_serve_app.state.audit_chain
    with TestClient(plain_serve_app) as client:
        task_id = _create_and_claim(client, "reopened after janitor")
        assert client.post(f"/tasks/{task_id}/complete", json={"result_summary": "done"}).status_code == 200
        resp = client.post(f"/tasks/{task_id}/reopen", json={"reason": "janitor signals failed"})
        assert resp.status_code == 200, resp.text

    mine = [e for e in chain.query(event_type=EVENT_TASK_RELEASE_RECEIPT) if e.details["task_id"] == task_id]
    assert len(mine) == 1
    assert mine[0].details["release_path"] == "reopen"
    assert task_id not in reconstruct_claim_holders(chain.query())


# ---------------------------------------------------------------------------
# Static guard: no future un-claim path can skip the receipt
# ---------------------------------------------------------------------------


_STORE_SOURCE = Path(__file__).resolve().parents[2] / "src" / "bernstein" / "core" / "tasks" / "task_store_core.py"


def _clears_claim(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Assign):
            continue
        if not (isinstance(child.value, ast.Constant) and child.value.value is None):
            continue
        for target in child.targets:
            if isinstance(target, ast.Attribute) and target.attr == "claimed_by_session":
                return True
    return False


def _mints_receipt(node: ast.AST) -> bool:
    return any(isinstance(child, ast.Attribute) and child.attr == "_record_release_receipt" for child in ast.walk(node))


def test_every_method_that_clears_a_claim_mints_the_receipt() -> None:
    """A new un-claim path is a compile-time-visible omission, not a silent one.

    The asymmetry this issue reports came from adding un-claim paths one at a
    time, each next to the last. This walks the store instead of trusting the
    list above to stay complete.
    """
    tree = ast.parse(_STORE_SOURCE.read_text(encoding="utf-8"))
    store_class = next(node for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and node.name == "TaskStore")
    offenders = [
        method.name
        for method in store_class.body
        if isinstance(method, ast.FunctionDef | ast.AsyncFunctionDef)
        and _clears_claim(method)
        and not _mints_receipt(method)
    ]
    assert offenders == [], (
        f"{offenders} clear claimed_by_session without minting a task.release_receipt; "
        "call self._record_release_receipt with a snapshot taken before the transition"
    )


def test_the_guard_sees_the_known_unclaim_paths() -> None:
    """The guard above is only worth anything if it actually matches methods."""
    tree = ast.parse(_STORE_SOURCE.read_text(encoding="utf-8"))
    store_class = next(node for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and node.name == "TaskStore")
    clearing = {
        method.name
        for method in store_class.body
        if isinstance(method, ast.FunctionDef | ast.AsyncFunctionDef) and _clears_claim(method)
    }
    assert {"force_claim", "reopen", "recover_stale_claimed_tasks", "reopen_tasks_for_node"} <= clearing
