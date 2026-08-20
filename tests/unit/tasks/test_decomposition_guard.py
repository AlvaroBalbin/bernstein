"""Unit tests for bounded recursive task decomposition guard (#4179)."""

from __future__ import annotations

from bernstein.core.tasks.decomposition_guard import (
    DEFAULT_ROOT_RANK,
    ENV_MAX_DECOMPOSITION_DEPTH,
    DecompositionRefusalCode,
    evaluate_decomposition_proposal,
    get_default_root_rank,
)


def test_single_level_decomposition_defaults_root_rank_and_passes() -> None:
    """Existing single-level decompositions pass without configuration."""
    children = [{"id": "c1", "title": "Child 1"}, {"id": "c2", "title": "Child 2"}]
    verdict, child_ranks = evaluate_decomposition_proposal("P-100", None, children, now_ts=1000.0)

    assert verdict.accepted is True
    assert verdict.reason_code is None
    assert verdict.receipt is None
    assert child_ranks == [DEFAULT_ROOT_RANK - 1, DEFAULT_ROOT_RANK - 1]


def test_non_decreasing_rank_refused_with_machine_readable_code() -> None:
    """Decomposition whose child rank >= parent rank is refused with DECOMPOSITION_RANK_NON_DECREASING."""
    children = [
        {"id": "c1", "decomposition_rank": 3},
        {"id": "c2", "decomposition_rank": 5},  # Illegal: child_rank 5 >= parent_rank 5
    ]
    verdict, child_ranks = evaluate_decomposition_proposal("P-101", 5, children, now_ts=1000.0)

    assert verdict.accepted is False
    assert verdict.reason_code == DecompositionRefusalCode.DECOMPOSITION_RANK_NON_DECREASING
    assert verdict.receipt is not None
    assert verdict.receipt.parent_task_id == "P-101"
    assert verdict.receipt.offending_child_id == "c2"
    assert verdict.receipt.parent_rank == 5
    assert verdict.receipt.child_rank == 5
    assert child_ranks == []


def test_decomposition_chain_terminates_at_depth_limit() -> None:
    """A chain of valid decompositions terminates when parent rank reaches 0."""
    root_rank = 3
    current_parent_rank = root_rank
    current_parent_id = "P-0"

    # Walk down 3 levels: rank 3 -> 2 -> 1 -> 0
    for level in range(3):
        children = [{"id": f"P-{level + 1}"}]
        verdict, assigned = evaluate_decomposition_proposal(
            current_parent_id, current_parent_rank, children, now_ts=1000.0
        )
        assert verdict.accepted is True
        current_parent_id = f"P-{level + 1}"
        current_parent_rank = assigned[0]

    assert current_parent_rank == 0

    # Level 4 from parent_rank 0 must be refused with DECOMPOSITION_RANK_EXHAUSTED
    children = [{"id": "P-4"}]
    verdict, assigned = evaluate_decomposition_proposal(current_parent_id, current_parent_rank, children, now_ts=1000.0)
    assert verdict.accepted is False
    assert verdict.reason_code == DecompositionRefusalCode.DECOMPOSITION_RANK_EXHAUSTED
    assert verdict.receipt is not None
    assert verdict.receipt.parent_rank == 0
    assert verdict.receipt.offending_child_id == "P-4"


def test_receipt_canonical_bytes_determinism() -> None:
    """The refusal receipt produces deterministic byte-identical canonical output."""
    children = [{"id": "bad-child", "decomposition_rank": 10}]
    v1, _ = evaluate_decomposition_proposal("P-200", 5, children, now_ts=1000.0)
    v2, _ = evaluate_decomposition_proposal("P-200", 5, children, now_ts=9999.0)

    assert v1.receipt is not None
    assert v2.receipt is not None
    assert v1.receipt.canonical_bytes() == v2.receipt.canonical_bytes()


def test_env_var_overrides_default_root_rank(monkeypatch) -> None:
    """BERNSTEIN_MAX_DECOMPOSITION_DEPTH environment variable configures root rank ceiling."""
    monkeypatch.setenv(ENV_MAX_DECOMPOSITION_DEPTH, "10")
    assert get_default_root_rank() == 10

    children = [{"id": "c1"}]
    verdict, assigned = evaluate_decomposition_proposal("P-300", None, children, now_ts=1000.0)
    assert verdict.accepted is True
    assert assigned == [9]
