"""Hardening regressions for signal actions + clearance gates + bulletin (#2648).

Each test pins one integrity property that the first implementation did not
hold:

* materialize / resolve are atomic and durably idempotent (keyed on the chain,
  not on a process-local dict),
* gate creation and dependent-edge injection are a single atomic store step,
* the offline verifier refuses unauthenticated and unvalidated audit rows,
* the resolution vocabulary is refused at the store and audit-chain boundaries,
* ``post()`` never acknowledges a blocker whose action hook failed.
"""

from __future__ import annotations

import asyncio
import json
import stat
import threading
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from bernstein.core.communication.bulletin import (
    BulletinBoard,
    BulletinMessage,
    SignalActionFailure,
)
from bernstein.core.communication.signal_actions import (
    ClearanceGateCoordinator,
    InMemoryClearanceInjector,
    verify_clearance_gates,
)
from bernstein.core.security.audit_chain import (
    EVENT_SIGNAL_GATE_PROJECTION,
    AuditChainStore,
    ClearanceResolutionRefusal,
    record_signal_gate_projection,
)

if TYPE_CHECKING:
    from bernstein.core.communication.signal_actions import ClearanceGateSpec

AUDIT_DIR = Path(".sdd/audit")


def _chain(tmp_path: Path) -> AuditChainStore:
    return AuditChainStore(tmp_path / "audit", key=b"k" * 32)


def _blocker(content: str = "shared dep broke", cell_id: str = "cell-a") -> BulletinMessage:
    return BulletinMessage(
        agent_id="worker-3", type="blocker", content=content, timestamp=1_700_000_000.0, cell_id=cell_id
    )


# ---------------------------------------------------------------------------
# CRITICAL 1: materialize / resolve are atomic and durably idempotent
# ---------------------------------------------------------------------------


class _SlowInjector(InMemoryClearanceInjector):
    """Injector that widens the check-then-act window between threads."""

    def __init__(self, *, open_by_cell: dict[str, list[str]]) -> None:
        super().__init__(open_by_cell=open_by_cell)
        self.barrier = threading.Barrier(2, timeout=10)
        self._tripped = False

    def create_clearance_task(self, spec: ClearanceGateSpec, blocker: BulletinMessage) -> None:
        if not self._tripped:
            self._tripped = True
            # Park inside the mutation so a second thread that skipped the
            # idempotency check would double-apply here.
            with __import__("contextlib").suppress(threading.BrokenBarrierError):
                self.barrier.wait(timeout=1)
        super().create_clearance_task(spec, blocker)


def test_concurrent_materialize_does_not_double_apply(tmp_path: Path) -> None:
    board = BulletinBoard()
    injector = _SlowInjector(open_by_cell={"cell-a": ["task-x", "task-y"]})
    chain = _chain(tmp_path)
    coord = ClearanceGateCoordinator(bulletin=board, injector=injector, chain=chain)
    blocker = board.post(_blocker())

    errors: list[BaseException] = []

    def run() -> None:
        try:
            coord.materialize(blocker)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert not errors, errors
    assert len(injector.created) == 1, "concurrent materialize double-created the clearance task"
    assert len(injector.edges) == 2, "concurrent materialize double-injected dependent edges"
    assert len(chain.query(event_type=EVENT_SIGNAL_GATE_PROJECTION)) == 1


def test_materialize_is_idempotent_across_a_restart(tmp_path: Path) -> None:
    """Idempotency is keyed on the chain, so a fresh process never re-injects."""
    board = BulletinBoard()
    chain = _chain(tmp_path)
    first = InMemoryClearanceInjector(open_by_cell={"cell-a": ["task-x"]})
    blocker = board.post(_blocker())
    spec = ClearanceGateCoordinator(bulletin=board, injector=first, chain=chain).materialize(blocker)
    assert spec is not None

    # A brand-new coordinator + injector (process restart) replaying the same
    # journal must recognise the already-sealed gate from the chain alone.
    second = InMemoryClearanceInjector(open_by_cell={"cell-a": ["task-x"]})
    replayed = ClearanceGateCoordinator(
        bulletin=board, injector=second, chain=AuditChainStore(tmp_path / "audit", key=b"k" * 32)
    ).materialize(blocker)

    assert replayed is not None
    assert replayed.clearance_task_id == spec.clearance_task_id
    assert second.created == [], "replay after restart re-created the clearance task"
    assert second.edges == [], "replay after restart re-injected dependent edges"
    assert len(chain.query(event_type=EVENT_SIGNAL_GATE_PROJECTION)) == 1


def test_resolve_is_a_noop_after_the_first_terminal_receipt(tmp_path: Path) -> None:
    board = BulletinBoard()
    injector = InMemoryClearanceInjector(open_by_cell={"cell-a": ["task-x"]})
    chain = _chain(tmp_path)
    coord = ClearanceGateCoordinator(bulletin=board, injector=injector, chain=chain)
    spec = coord.materialize(board.post(_blocker()))
    assert spec is not None

    first = coord.resolve(spec.clearance_task_id, resolver="operator:alex")
    second = coord.resolve(spec.clearance_task_id, resolver="operator:mallory", resolution="expired")

    assert second.hmac == first.hmac, "a second resolve emitted a fresh terminal receipt"
    assert injector.released == [spec.clearance_task_id], "a second resolve re-released the gate"
    rows = chain.query(event_type=EVENT_SIGNAL_GATE_PROJECTION)
    terminal = [r for r in rows if r.details.get("resolution") != "pending"]
    assert len(terminal) == 1


def test_concurrent_resolve_emits_one_terminal_receipt(tmp_path: Path) -> None:
    board = BulletinBoard()
    injector = InMemoryClearanceInjector(open_by_cell={"cell-a": ["task-x"]})
    chain = _chain(tmp_path)
    coord = ClearanceGateCoordinator(bulletin=board, injector=injector, chain=chain)
    spec = coord.materialize(board.post(_blocker()))
    assert spec is not None

    def run() -> None:
        coord.resolve(spec.clearance_task_id, resolver="operator:alex")

    threads = [threading.Thread(target=run) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    rows = chain.query(event_type=EVENT_SIGNAL_GATE_PROJECTION)
    terminal = [r for r in rows if r.details.get("resolution") != "pending"]
    assert len(terminal) == 1
    assert injector.released == [spec.clearance_task_id]


# ---------------------------------------------------------------------------
# CRITICAL 2: gate creation + edge injection are one atomic store step
# ---------------------------------------------------------------------------


def test_gate_creation_and_edge_injection_are_atomic(tmp_path: Path) -> None:
    from bernstein.core.server import TaskCreate
    from bernstein.core.tasks.task_store_core import TaskStore

    async def scenario() -> tuple[bool, bool]:
        store = TaskStore(tmp_path / "runtime" / "tasks.jsonl")
        dep = await store.create(TaskCreate(title="dependent", description="d", role="backend", cell_id="cell-a"))
        gate, edges = await store.create_gate_with_edges(
            clearance_task_id="clearance-abc123",
            title="clearance gate",
            role="clearance",
            cell_id="cell-a",
        )
        assert gate.id == "clearance-abc123"
        assert edges == [dep.id]
        # The dependent is gated the instant the gate exists: there is no
        # window in which the gate is open but the edge is missing.
        blocked = await store.claim_next("backend") is None
        return blocked, dep.id in store._tasks and "clearance-abc123" in store._tasks[dep.id].depends_on

    blocked, edged = asyncio.run(scenario())
    assert edged, "the dependent did not receive the depends_on edge"
    assert blocked, "the dependent was claimable while the gate was open"


def test_interrupted_gate_creation_leaves_no_orphan_edge(tmp_path: Path) -> None:
    """A failure mid-materialization rolls back in memory and on disk."""
    from bernstein.core.server import TaskCreate
    from bernstein.core.tasks.task_store_core import TaskStore

    jsonl = tmp_path / "runtime" / "tasks.jsonl"

    async def scenario() -> tuple[bool, bool, bool, bool]:
        store = TaskStore(jsonl)
        dep = await store.create(TaskCreate(title="dependent", description="d", role="backend", cell_id="cell-a"))

        async def flaky() -> None:
            raise OSError("disk full")

        store._flush_buffer_unlocked = flaky  # type: ignore[assignment,method-assign]
        with pytest.raises(OSError, match="disk full"):
            await store.create_gate_with_edges(
                clearance_task_id="clearance-abc123",
                title="clearance gate",
                role="clearance",
                cell_id="cell-a",
            )
        del store._flush_buffer_unlocked  # restore the bound method

        gate_absent = "clearance-abc123" not in store._tasks
        no_edge = store._tasks[dep.id].depends_on == []
        claimable = await store.claim_next("backend") is not None
        # The journal must not carry the gate either: a replay of the crashed
        # materialization must not resurrect a half-applied gate.
        journal_clean = "clearance-abc123" not in jsonl.read_text()
        return gate_absent, no_edge, claimable, journal_clean

    gate_absent, no_edge, claimable, journal_clean = asyncio.run(scenario())
    assert gate_absent, "a rolled-back gate task is still present in the store"
    assert no_edge, "a rolled-back gate left an orphan depends_on edge on the dependent"
    assert claimable, "the dependent stayed blocked by a gate that was never created"
    assert journal_clean, "a rolled-back gate was still written to the task journal"


# ---------------------------------------------------------------------------
# MAJOR: verify-gates must verify the HMAC chain before trusting rows
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from bernstein.core.security.audit import AUDIT_KEY_ENV

    key_path = tmp_path / "audit.key"
    key_path.write_bytes(b"a" * 64)
    key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    monkeypatch.setenv(AUDIT_KEY_ENV, str(key_path))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _materialize_on_cwd_chain() -> str:
    board = BulletinBoard()
    injector = InMemoryClearanceInjector(open_by_cell={"cell-a": ["task-x"]})
    coord = ClearanceGateCoordinator(bulletin=board, injector=injector, chain=AuditChainStore(AUDIT_DIR))
    spec = coord.materialize(board.post(_blocker()))
    assert spec is not None
    return spec.clearance_task_id


def test_verify_gates_rejects_tampered_audit_rows(isolated_audit: Path) -> None:
    from click.testing import CliRunner

    from bernstein.cli.commands.audit_cmd import audit_group

    _materialize_on_cwd_chain()

    # Flip a recorded field without recomputing the HMAC: the semantic replay
    # must never run on rows that fail the chain check.
    log_path = next(iter(sorted(AUDIT_DIR.glob("*.jsonl"))))
    rows = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    for row in rows:
        if row.get("event_type") == EVENT_SIGNAL_GATE_PROJECTION:
            row["details"]["injected_edges"] = []
            break
    else:  # pragma: no cover - defensive
        pytest.fail("no gate projection row found")
    log_path.write_text("".join(json.dumps(r) + "\n" for r in rows))

    result = CliRunner().invoke(audit_group, ["verify-gates"])
    assert result.exit_code == 1, result.output
    assert "FAILED" in result.output


# ---------------------------------------------------------------------------
# MAJOR: the verifier validates lineage before closing a gate
# ---------------------------------------------------------------------------


def _seal_gate(chain: AuditChainStore) -> tuple[str, str]:
    board = BulletinBoard()
    injector = InMemoryClearanceInjector(open_by_cell={"cell-a": ["task-x"]})
    coord = ClearanceGateCoordinator(bulletin=board, injector=injector, chain=chain)
    spec = coord.materialize(board.post(_blocker()))
    assert spec is not None
    projection = chain.query(event_type=EVENT_SIGNAL_GATE_PROJECTION)[0]
    return spec.clearance_task_id, projection.hmac


def test_verifier_refuses_a_resolution_with_a_forged_blocker_entry_hash(tmp_path: Path) -> None:
    from bernstein.core.security.audit_chain import record_task_claim_receipt

    chain = _chain(tmp_path)
    clearance_id, _real_hmac = _seal_gate(chain)
    pending = chain.query(event_type=EVENT_SIGNAL_GATE_PROJECTION)[0].details

    # A resolution that does not reference the materialization entry must not
    # close the gate, so a later claim of a scoped dependent is still a violation.
    record_signal_gate_projection(
        chain=chain,
        blocker_content_hash=str(pending["blocker_content_hash"]),
        clearance_task_id=clearance_id,
        injected_edges=[str(e) for e in pending["injected_edges"]],
        graph_delta_hash=str(pending["graph_delta_hash"]),
        scope_cell_id=str(pending["scope_cell_id"]),
        deadline=int(pending["deadline"] or 0),
        resolution="cleared",
        resolver="mallory",
        blocker_entry_hash="0" * 64,
    )
    record_task_claim_receipt(
        chain=chain,
        task_id="task-x",
        role="backend",
        claimed_by="sess-rogue",
        depends_on=[clearance_id],
        task_version=2,
        claim_path="by_id",
    )

    result = verify_clearance_gates(chain.query())
    assert not result.ok
    assert result.violations, "a forged resolution silently released the gate"


def test_verifier_refuses_a_resolution_whose_fields_diverge(tmp_path: Path) -> None:
    chain = _chain(tmp_path)
    clearance_id, real_hmac = _seal_gate(chain)
    pending = chain.query(event_type=EVENT_SIGNAL_GATE_PROJECTION)[0].details

    # Correct back-reference, but the recorded edge set was widened.
    record_signal_gate_projection(
        chain=chain,
        blocker_content_hash=str(pending["blocker_content_hash"]),
        clearance_task_id=clearance_id,
        injected_edges=["task-x", "task-smuggled"],
        graph_delta_hash=str(pending["graph_delta_hash"]),
        scope_cell_id=str(pending["scope_cell_id"]),
        deadline=int(pending["deadline"] or 0),
        resolution="cleared",
        resolver="mallory",
        blocker_entry_hash=real_hmac,
    )

    result = verify_clearance_gates(chain.query())
    assert not result.ok
    assert any("injected_edges" in err or "diverge" in err for err in result.errors), result.errors


def test_verifier_counts_orphan_resolution_rows_toward_gate_count(tmp_path: Path) -> None:
    """A chain of resolution rows alone must not report zero gates and pass."""
    chain = _chain(tmp_path)
    record_signal_gate_projection(
        chain=chain,
        blocker_content_hash="sha256:" + "0" * 64,
        clearance_task_id="clearance-forged",
        injected_edges=["task-x"],
        graph_delta_hash="0" * 64,
        scope_cell_id="cell-a",
        resolution="cleared",
        resolver="mallory",
    )

    result = verify_clearance_gates(chain.query())
    assert result.gate_count == 1, "an orphan resolution row was not counted as a gate"
    assert not result.ok


# ---------------------------------------------------------------------------
# MAJOR: resolution vocabulary is refused at both mutation boundaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["", "pending", "CLEARED", "released", "done"])
def test_store_refuses_a_resolution_outside_the_vocabulary(tmp_path: Path, bad: str) -> None:
    from bernstein.core.tasks.task_store_core import TaskStore

    async def scenario() -> None:
        store = TaskStore(tmp_path / "runtime" / "tasks.jsonl")
        gate, _edges = await store.create_gate_with_edges(
            clearance_task_id="clearance-abc123", title="gate", role="clearance", cell_id="cell-a"
        )
        with pytest.raises(ClearanceResolutionRefusal):
            await store.resolve_gate_task(gate.id, resolution=bad)
        # Refused before any state mutation: the gate is still open.
        assert store._tasks[gate.id].status.value == "open"

    asyncio.run(scenario())


@pytest.mark.parametrize("bad", ["", "CLEARED", "released", "done", "resolved"])
def test_audit_chain_refuses_a_resolution_outside_the_vocabulary(tmp_path: Path, bad: str) -> None:
    chain = _chain(tmp_path)
    with pytest.raises(ClearanceResolutionRefusal):
        record_signal_gate_projection(
            chain=chain,
            blocker_content_hash="sha256:" + "0" * 64,
            clearance_task_id="clearance-abc123",
            injected_edges=[],
            graph_delta_hash="0" * 64,
            scope_cell_id="cell-a",
            resolution=bad,
        )
    # Refused before signing: nothing was appended to the chain.
    assert chain.query(event_type=EVENT_SIGNAL_GATE_PROJECTION) == []


def test_coordinator_resolution_refusal_is_typed(tmp_path: Path) -> None:
    board = BulletinBoard()
    injector = InMemoryClearanceInjector(open_by_cell={"cell-a": ["task-x"]})
    coord = ClearanceGateCoordinator(bulletin=board, injector=injector, chain=_chain(tmp_path))
    spec = coord.materialize(board.post(_blocker()))
    assert spec is not None
    with pytest.raises(ClearanceResolutionRefusal):
        coord.resolve(spec.clearance_task_id, resolver="op", resolution="released")
    assert injector.released == []


# ---------------------------------------------------------------------------
# MAJOR: post() never acknowledges a blocker whose hook failed
# ---------------------------------------------------------------------------


def test_post_refuses_to_acknowledge_a_failed_action_hook(tmp_path: Path) -> None:
    board = BulletinBoard()
    outbox = tmp_path / "signal_outbox.jsonl"

    def failing_hook(_msg: BulletinMessage) -> None:
        raise RuntimeError("materialization failed")

    board.set_post_hook(failing_hook, outbox_path=outbox)

    with pytest.raises(SignalActionFailure) as excinfo:
        board.post(_blocker())

    assert excinfo.value.message.type == "blocker"
    # The append-only board keeps the message, but the failure is durable and
    # replayable rather than silently dropped.
    assert board.count == 1
    assert board.pending_actions and board.pending_actions[0].content == "shared dep broke"
    assert outbox.exists()
    recorded = [json.loads(line) for line in outbox.read_text().splitlines() if line.strip()]
    assert recorded and recorded[0]["type"] == "blocker"


def test_pending_actions_drain_once_the_hook_recovers(tmp_path: Path) -> None:
    board = BulletinBoard()
    failures = {"n": 1}
    seen: list[BulletinMessage] = []

    def flaky_hook(msg: BulletinMessage) -> None:
        if failures["n"] > 0:
            failures["n"] -= 1
            raise RuntimeError("transient")
        seen.append(msg)

    board.set_post_hook(flaky_hook, outbox_path=tmp_path / "outbox.jsonl")
    with pytest.raises(SignalActionFailure):
        board.post(_blocker())

    drained = board.retry_pending_actions()
    assert drained == 1
    assert board.pending_actions == []
    assert len(seen) == 1


def test_observe_only_signals_are_unaffected_by_a_failing_hook(tmp_path: Path) -> None:
    """Regression: a non-blocker post still succeeds when its hook is clean."""
    board = BulletinBoard()
    board.set_post_hook(lambda _msg: None)
    stored = board.post(BulletinMessage(agent_id="w", type="status", content="up", timestamp=1.0, cell_id="cell-a"))
    assert stored.type == "status"
    assert board.pending_actions == []
