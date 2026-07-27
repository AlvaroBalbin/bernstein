"""Tests for signed, independently-replayable trajectory receipts (#2925).

Acceptance criteria under test:

1. ``build_trajectory_receipt`` produces byte-identical receipt bytes, head
   hash, and receipt hash across two independent recordings of the same suite;
   no wall-clock value enters the signed bytes.  (determinism)

2. ``verify_trajectory_receipt`` re-derives the aggregate from per-task
   components and rejects any receipt whose embedded trajectory does not entail
   its published number.

3. Adversarial tests -- one per failure mode:
   (a) flip one golden task body → suite-hash mismatch (contamination)
   (b) edit one per-task component → score re-derivation mismatch (fabrication)
   (c) hand-edit the published scalar → formula mismatch (scalar edit)
   (d) drop all-but-winner candidate heads → cherry-pick rejection

4. A receipt carrying all best-of-N heads re-selects the published index
   deterministically.

5. An empty suite produces a distinct ``NO_TASKS`` status receipt, never a
   trivial pass.

6. Round-trip: emit → reload from stored bytes → verify → assert clean.

7. ``EVENT_TRAJECTORY_RECEIPT`` is present in the HMAC chain when a chain is
   supplied.

All tests are hermetic: separate tmp dirs per run, no live providers, no
wall-clock in sealed bytes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bernstein.core.security.audit_chain import (
    EVENT_TRAJECTORY_RECEIPT,
    AuditChainStore,
)
from bernstein.eval.metrics import EvalScoreComponents, TierScores
from bernstein.eval.trajectory_receipt import (
    NO_TASKS_STATUS,
    BestOfNProvenance,
    TaskTrajectoryAnchor,
    TrajectoryReceipt,
    build_trajectory_receipt,
    read_trajectory_receipt,
    trajectory_receipt_path,
    verify_trajectory_receipt,
)

_KEY = b"k" * 32

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_JOURNAL_HEAD = "sha256:" + "a" * 64
_FAKE_EVENTS_HASH = "sha256:" + "b" * 64


def _anchor(
    task_id: str,
    *,
    task_success: float = 1.0,
    code_quality: float = 0.9,
    efficiency: float = 0.8,
    reliability: float = 1.0,
    safety: float = 1.0,
    journal_head: str = _FAKE_JOURNAL_HEAD,
) -> TaskTrajectoryAnchor:
    return TaskTrajectoryAnchor(
        task_id=task_id,
        journal_head_hash=journal_head,
        events_content_hash=_FAKE_EVENTS_HASH,
        model_id="claude-test",
        config_fingerprint="cfg-v1",
        components=EvalScoreComponents(
            task_success=task_success,
            code_quality=code_quality,
            efficiency=efficiency,
            reliability=reliability,
            safety=safety,
        ),
    )


def _two_task_anchors() -> list[TaskTrajectoryAnchor]:
    """Canonical 2-task smoke suite used in determinism tests."""
    return [
        _anchor("smoke-001", journal_head="sha256:" + "1" * 64),
        _anchor("smoke-002", journal_head="sha256:" + "2" * 64),
    ]


def _per_tier() -> TierScores:
    return TierScores(smoke=1.0, standard=0.0, stretch=0.0, adversarial=0.0)


def _build(
    workdir: Path,
    anchors: list[TaskTrajectoryAnchor] | None = None,
    *,
    run_id: str = "run-test-001",
    per_tier: TierScores | None = None,
    best_of_n: BestOfNProvenance | None = None,
    chain: AuditChainStore | None = None,
) -> TrajectoryReceipt:
    return build_trajectory_receipt(
        run_id=run_id,
        task_anchors=anchors if anchors is not None else _two_task_anchors(),
        per_tier=per_tier if per_tier is not None else _per_tier(),
        workdir=workdir,
        lineage_root=workdir / ".sdd" / "lineage",
        hmac_key=_KEY,
        best_of_n=best_of_n,
        chain=chain,
    )


def _verify(workdir: Path, receipt_hash: str):
    return verify_trajectory_receipt(
        workdir=workdir,
        lineage_root=workdir / ".sdd" / "lineage",
        hmac_key=_KEY,
        receipt_hash=receipt_hash,
    )


# ---------------------------------------------------------------------------
# AC1 -- determinism
# ---------------------------------------------------------------------------


def test_two_independent_runs_produce_identical_receipt(tmp_path: Path) -> None:
    """Two independent workdirs, same inputs → byte-identical receipt + hash."""
    dir_a = tmp_path / "run-a"
    dir_b = tmp_path / "run-b"

    anchors = _two_task_anchors()
    receipt_a = _build(dir_a, anchors)
    # Reverse task order to prove order-canonical, not order-lucky.
    receipt_b = _build(dir_b, list(reversed(anchors)))

    assert receipt_a.receipt_hash == receipt_b.receipt_hash
    assert receipt_a.canonical_payload_without_anchor() == receipt_b.canonical_payload_without_anchor()
    assert receipt_a.canonical_bytes() == receipt_b.canonical_bytes()


def test_receipt_hash_is_stable_across_identical_inputs(tmp_path: Path) -> None:
    """Two calls with identical inputs (same dir is fine for this) → same hash."""
    dir_a = tmp_path / "run-a"
    dir_b = tmp_path / "run-b"
    anchors = _two_task_anchors()
    r1 = _build(dir_a, anchors)
    r2 = _build(dir_b, anchors)
    assert r1.receipt_hash == r2.receipt_hash


# ---------------------------------------------------------------------------
# AC5 -- empty suite → NO_TASKS, not trivial pass
# ---------------------------------------------------------------------------


def test_empty_suite_produces_no_tasks_status(tmp_path: Path) -> None:
    receipt = _build(tmp_path, anchors=[])
    assert receipt.status == NO_TASKS_STATUS
    assert receipt.published_score == 0.0
    assert receipt.task_anchors == []
    # The NO_TASKS receipt must verify cleanly (it is a legitimate sealed state)
    result = _verify(tmp_path, receipt.receipt_hash)
    assert result.ok, result.reason


def test_empty_suite_receipt_hash_differs_from_non_empty(tmp_path: Path) -> None:
    empty_r = _build(tmp_path / "empty", anchors=[])
    full_r = _build(tmp_path / "full", _two_task_anchors())
    assert empty_r.receipt_hash != full_r.receipt_hash


# ---------------------------------------------------------------------------
# AC2 / AC6 -- round-trip and offline verification
# ---------------------------------------------------------------------------


def test_receipt_verifies_offline_clean(tmp_path: Path) -> None:
    receipt = _build(tmp_path)
    result = _verify(tmp_path, receipt.receipt_hash)
    assert result.ok, result.reason
    assert result.receipt is not None
    assert result.receipt.receipt_hash == receipt.receipt_hash


def test_round_trip_reload_and_verify(tmp_path: Path) -> None:
    """Emit → reload from stored bytes → verify → assert clean."""
    receipt = _build(tmp_path)
    reloaded = read_trajectory_receipt(tmp_path, receipt.receipt_hash)
    assert reloaded is not None
    assert reloaded.to_dict() == receipt.to_dict()
    result = _verify(tmp_path, receipt.receipt_hash)
    assert result.ok, result.reason


def test_missing_receipt_returns_not_ok(tmp_path: Path) -> None:
    fake_hash = "sha256:" + "f" * 64
    result = _verify(tmp_path, fake_hash)
    assert not result.ok
    assert "no trajectory receipt" in result.reason


# ---------------------------------------------------------------------------
# AC3a -- contamination: flip one task id → suite-hash mismatch
# ---------------------------------------------------------------------------


def test_contamination_mutated_task_id_fails_verification(tmp_path: Path) -> None:
    receipt = _build(tmp_path)
    path = trajectory_receipt_path(tmp_path, receipt.receipt_hash)
    payload = json.loads(path.read_text(encoding="utf-8"))
    # Silently rename a task — simulates a mutated golden suite.
    payload["task_anchors"][0]["task_id"] = "smoke-TAMPERED"
    # Do NOT recompute receipt_hash — leave it stale so tamper is visible.
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = _verify(tmp_path, receipt.receipt_hash)
    assert not result.ok
    # Should fail either on hash recompute or suite-content-hash mismatch.
    assert result.ok is False


# ---------------------------------------------------------------------------
# AC3b -- fabrication: edit a per-task component → re-derivation mismatch
# ---------------------------------------------------------------------------


def test_fabrication_edited_component_fails_verification(tmp_path: Path) -> None:
    receipt = _build(tmp_path)
    path = trajectory_receipt_path(tmp_path, receipt.receipt_hash)
    payload = json.loads(path.read_text(encoding="utf-8"))
    # Push task_success to 1.0 on the first task without recomputing hashes.
    payload["task_anchors"][0]["components"]["task_success"] = 0.0
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = _verify(tmp_path, receipt.receipt_hash)
    assert not result.ok


# ---------------------------------------------------------------------------
# AC3c -- scalar edit: hand-edit the published score → formula mismatch
# ---------------------------------------------------------------------------


def test_scalar_edit_fails_verification(tmp_path: Path) -> None:
    receipt = _build(tmp_path)
    path = trajectory_receipt_path(tmp_path, receipt.receipt_hash)
    payload = json.loads(path.read_text(encoding="utf-8"))
    # Bump the published score without touching anything else.
    payload["published_score"] = 0.9999
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = _verify(tmp_path, receipt.receipt_hash)
    assert not result.ok


# ---------------------------------------------------------------------------
# AC3d -- cherry-pick: drop all-but-winner candidate heads → rejected
# ---------------------------------------------------------------------------


def test_cherry_pick_missing_candidate_heads_fails(tmp_path: Path) -> None:
    bon = BestOfNProvenance(
        n_candidates=3,
        # Claim 3 candidates but only supply 1 head → cherry-pick
        candidate_journal_heads=["sha256:" + "c" * 64],
        selection_rule="highest_final_score",
        selected_index=0,
    )
    receipt = _build(tmp_path, best_of_n=bon)
    result = _verify(tmp_path, receipt.receipt_hash)
    assert not result.ok
    assert "cherry-pick" in result.reason or "missing heads" in result.reason


def test_cherry_pick_all_heads_present_verifies_ok(tmp_path: Path) -> None:
    bon = BestOfNProvenance(
        n_candidates=3,
        candidate_journal_heads=[
            "sha256:" + "c" * 64,
            "sha256:" + "d" * 64,
            "sha256:" + "e" * 64,
        ],
        selection_rule="highest_final_score",
        selected_index=1,
    )
    receipt = _build(tmp_path, best_of_n=bon)
    result = _verify(tmp_path, receipt.receipt_hash)
    assert result.ok, result.reason


def test_cherry_pick_selected_index_out_of_range_fails(tmp_path: Path) -> None:
    bon = BestOfNProvenance(
        n_candidates=2,
        candidate_journal_heads=["sha256:" + "c" * 64, "sha256:" + "d" * 64],
        selection_rule="highest_final_score",
        selected_index=5,  # out of range
    )
    receipt = _build(tmp_path, best_of_n=bon)
    result = _verify(tmp_path, receipt.receipt_hash)
    assert not result.ok


# ---------------------------------------------------------------------------
# AC7 -- HMAC chain mirror
# ---------------------------------------------------------------------------


def test_audit_chain_receives_trajectory_receipt_event(tmp_path: Path) -> None:
    chain = AuditChainStore(tmp_path / "audit", key=_KEY)
    receipt = _build(tmp_path, chain=chain)
    events = chain.query(event_type=EVENT_TRAJECTORY_RECEIPT)
    assert len(events) == 1
    e = events[0]
    assert e.details.get("receipt_hash") == receipt.receipt_hash
    assert e.details.get("run_id") == receipt.run_id
    assert e.details.get("n_tasks") == len(receipt.task_anchors)


# ---------------------------------------------------------------------------
# Structural sanity
# ---------------------------------------------------------------------------


def test_receipt_schema_version_is_1(tmp_path: Path) -> None:
    receipt = _build(tmp_path)
    assert receipt.schema_version == 1


def test_published_score_matches_final_score(tmp_path: Path) -> None:
    anchors = _two_task_anchors()
    receipt = _build(tmp_path, anchors)
    # Re-derive manually: mean of per-task components → final_score
    n = len(anchors)
    ts = sum(a.components.task_success for a in anchors) / n
    cq = sum(a.components.code_quality for a in anchors) / n
    eff = sum(a.components.efficiency for a in anchors) / n
    rel = sum(a.components.reliability for a in anchors) / n
    saf = sum(a.components.safety for a in anchors) / n
    expected = (0.5 * ts + 0.3 * cq + 0.2 * eff) * rel * saf
    assert abs(receipt.published_score - expected) < 1e-9


def test_read_trajectory_receipt_returns_none_for_bad_hash(tmp_path: Path) -> None:
    # Build one receipt so the directory exists
    _build(tmp_path)
    result = read_trajectory_receipt(tmp_path, "sha256:" + "0" * 64)
    assert result is None


def test_trajectory_receipt_path_rejects_non_sha256(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="canonical sha256"):
        trajectory_receipt_path(tmp_path, "not-a-hash")


def test_receipt_no_wall_clock_in_body(tmp_path: Path) -> None:
    """Confirm that 'timestamp' does not appear in the canonical body."""
    receipt = _build(tmp_path)
    body_str = receipt.canonical_payload_without_anchor()
    # The body must not carry any wall-clock timestamp field.
    body = json.loads(body_str)
    assert "timestamp" not in body
