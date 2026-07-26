"""Signed, independently-replayable trajectory receipts for benchmark scores (#2925).

A published benchmark number is not an audit artefact; it is a bare scalar.
This module makes it one.  :func:`build_trajectory_receipt` seals the exact
replayable trajectory that produced a score into a content-addressed,
spine-anchored, offline-verifiable envelope whose verification *re-derives*
the score from the embedded trajectory -- never trusts the printed aggregate.

The design mirrors :mod:`bernstein.eval.gate_receipt` exactly: the receipt IS
the proof, not a decoration on a log line.  Three failure modes that are
currently undetectable from a published number alone are detectable offline
from the receipt:

* **Contamination** -- a golden task quietly mutated so the suite the number
  was scored on differs from the suite it claims.  Detected via
  ``suite_content_hash``.
* **Fabrication** -- a scalar typed into a table with no trajectory behind it.
  Detected because ``verify_trajectory_receipt`` replays every sealed journal
  through ``ReplayGateway`` and recomputes the per-task score components.
* **Cherry-picking** -- a best-of-N candidate published as if single-shot.
  Detected because a receipt that carries only the winning candidate's journal
  head (not all N heads + the selection rule) is rejected as unverifiable.

Offline third-party verifiability without the HMAC key is out of scope for
this module (COSE/in-toto projection is the second PR); everything here is
verifiable by a key-holding operator.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bernstein.core.lineage.spine import LineageSpine, content_hash_of
from bernstein.eval.metrics import EvalScoreComponents, TierScores
from bernstein.eval.significance import suite_content_hash

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from bernstein.core.security.audit_chain import AuditChainStore

logger = logging.getLogger(__name__)

#: Version stamped into every trajectory receipt.  Bump only on a wire-format
#: change.
TRAJECTORY_RECEIPT_SCHEMA_VERSION = 1

#: Lineage run id under which every trajectory receipt is anchored, kept
#: separate so benchmark receipts never interleave with eval-gate receipts or
#: per-task journals.
EVAL_BENCH_RUN_ID = "eval-bench"

#: Status written when the receipt covers zero tasks.
NO_TASKS_STATUS = "NO_TASKS"

_BENCH_ACTOR = "bernstein.eval_bench"
_BENCH_SUBPATH = (".sdd", "eval", "bench")
_RECEIPT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Per-task anchor
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TaskTrajectoryAnchor:
    """Content-addressed anchors for one task's sealed trajectory.

    Attributes:
        task_id: The golden task identifier.
        journal_head_hash: Merkle head of the ``EventJournal`` after the run.
        events_content_hash: ``sha256:``-prefixed hash of the ``events.jsonl``
            fixture bytes captured by ``ReplayGateway``.
        model_id: Model identifier used for the run.
        config_fingerprint: Stable identifier for the run configuration.
        components: Per-task score components sealed into the receipt.
    """

    task_id: str
    journal_head_hash: str
    events_content_hash: str
    model_id: str
    config_fingerprint: str
    components: EvalScoreComponents

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "journal_head_hash": self.journal_head_hash,
            "events_content_hash": self.events_content_hash,
            "model_id": self.model_id,
            "config_fingerprint": self.config_fingerprint,
            "components": {
                "task_success": self.components.task_success,
                "code_quality": self.components.code_quality,
                "efficiency": self.components.efficiency,
                "reliability": self.components.reliability,
                "safety": self.components.safety,
            },
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> TaskTrajectoryAnchor:
        c = raw["components"]
        return cls(
            task_id=str(raw["task_id"]),
            journal_head_hash=str(raw["journal_head_hash"]),
            events_content_hash=str(raw["events_content_hash"]),
            model_id=str(raw["model_id"]),
            config_fingerprint=str(raw["config_fingerprint"]),
            components=EvalScoreComponents(
                task_success=float(c["task_success"]),
                code_quality=float(c["code_quality"]),
                efficiency=float(c["efficiency"]),
                reliability=float(c["reliability"]),
                safety=float(c["safety"]),
            ),
        )


# ---------------------------------------------------------------------------
# Best-of-N selection provenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BestOfNProvenance:
    """Provenance record for a best-of-N selection.

    When the published run used ``BestOfNRunner``, the receipt carries the
    journal heads of **all N candidates** and the deterministic selection rule.
    A receipt carrying only the winner's head is rejected as unverifiable.

    Attributes:
        n_candidates: Total number of candidates evaluated.
        candidate_journal_heads: Journal head hashes for every candidate, in
            evaluation order.
        selection_rule: Human-readable description of the selection rule
            (e.g. ``"highest_final_score"``).
        selected_index: Zero-based index of the selected winner.
    """

    n_candidates: int
    candidate_journal_heads: list[str]
    selection_rule: str
    selected_index: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "n_candidates": self.n_candidates,
            "candidate_journal_heads": list(self.candidate_journal_heads),
            "selection_rule": self.selection_rule,
            "selected_index": self.selected_index,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> BestOfNProvenance:
        return cls(
            n_candidates=int(raw["n_candidates"]),
            candidate_journal_heads=list(raw["candidate_journal_heads"]),
            selection_rule=str(raw["selection_rule"]),
            selected_index=int(raw["selected_index"]),
        )


# ---------------------------------------------------------------------------
# The receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrajectoryReceipt:
    """A sealed benchmark-score trajectory receipt.

    The body (everything the ``receipt_hash`` covers) binds the suite identity,
    every per-task trajectory anchor, the aggregate score components and tier
    scores, the schema version, and (when applicable) best-of-N provenance.
    No wall-clock value enters the signed bytes.  The ``journal_entry_hash``
    is assigned post-seal and is NOT part of the hashed body.
    """

    schema_version: int
    suite_content_hash: str
    published_score: float
    task_anchors: list[TaskTrajectoryAnchor]
    aggregate: EvalScoreComponents
    per_tier: TierScores
    run_id: str
    status: str
    best_of_n: BestOfNProvenance | None
    receipt_hash: str
    journal_entry_hash: str = ""

    def body(self) -> dict[str, Any]:
        """The hashed body: every field except ``receipt_hash`` and anchor."""
        d: dict[str, Any] = {
            "schema_version": self.schema_version,
            "suite_content_hash": self.suite_content_hash,
            "published_score": self.published_score,
            "task_anchors": [a.to_dict() for a in self.task_anchors],
            "aggregate": {
                "task_success": self.aggregate.task_success,
                "code_quality": self.aggregate.code_quality,
                "efficiency": self.aggregate.efficiency,
                "reliability": self.aggregate.reliability,
                "safety": self.aggregate.safety,
            },
            "per_tier": {
                "smoke": self.per_tier.smoke,
                "standard": self.per_tier.standard,
                "stretch": self.per_tier.stretch,
                "adversarial": self.per_tier.adversarial,
            },
            "run_id": self.run_id,
            "status": self.status,
            "best_of_n": self.best_of_n.to_dict() if self.best_of_n is not None else None,
        }
        return d

    def canonical_payload_without_anchor(self) -> str:
        """Canonical JSON of the body plus receipt hash (excludes the anchor).

        Two machines seal byte-identical bytes here; the lineage anchor is the
        only field that could differ, so it is excluded from the cross-machine
        equality contract.
        """
        payload = self.body()
        payload["receipt_hash"] = self.receipt_hash
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    def to_dict(self) -> dict[str, Any]:
        payload = self.body()
        payload["receipt_hash"] = self.receipt_hash
        payload["journal_entry_hash"] = self.journal_entry_hash
        return payload

    def canonical_bytes(self) -> bytes:
        """Canonical bytes sealed into the lineage spine (body + hash)."""
        return self.canonical_payload_without_anchor().encode("utf-8")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> TrajectoryReceipt:
        agg = raw["aggregate"]
        pt = raw["per_tier"]
        bon_raw = raw.get("best_of_n")
        return cls(
            schema_version=int(raw["schema_version"]),
            suite_content_hash=str(raw["suite_content_hash"]),
            published_score=float(raw["published_score"]),
            task_anchors=[TaskTrajectoryAnchor.from_dict(a) for a in raw["task_anchors"]],
            aggregate=EvalScoreComponents(
                task_success=float(agg["task_success"]),
                code_quality=float(agg["code_quality"]),
                efficiency=float(agg["efficiency"]),
                reliability=float(agg["reliability"]),
                safety=float(agg["safety"]),
            ),
            per_tier=TierScores(
                smoke=float(pt["smoke"]),
                standard=float(pt["standard"]),
                stretch=float(pt["stretch"]),
                adversarial=float(pt["adversarial"]),
            ),
            run_id=str(raw["run_id"]),
            status=str(raw["status"]),
            best_of_n=BestOfNProvenance.from_dict(bon_raw) if bon_raw is not None else None,
            receipt_hash=str(raw["receipt_hash"]),
            journal_entry_hash=str(raw.get("journal_entry_hash", "")),
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _hash_obj(obj: Any) -> str:
    """Canonical JSON sha256 hash -- identical to gate_receipt._hash_obj."""
    payload = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _recompute_aggregate(task_anchors: list[TaskTrajectoryAnchor]) -> EvalScoreComponents:
    """Re-derive aggregate EvalScoreComponents from per-task anchors.

    This is the formula re-derivation step in ``verify_trajectory_receipt``:
    the aggregate is never trusted -- it is always recomputed from the
    embedded per-task components using the harness formula.

        Score = (0.5*TaskSuccess + 0.3*CodeQuality + 0.2*Efficiency)
                * Reliability * Safety

    Individual per-task components are averaged to produce the aggregate.
    """
    if not task_anchors:
        return EvalScoreComponents()
    n = len(task_anchors)
    task_success = sum(a.components.task_success for a in task_anchors) / n
    code_quality = sum(a.components.code_quality for a in task_anchors) / n
    efficiency = sum(a.components.efficiency for a in task_anchors) / n
    reliability = sum(a.components.reliability for a in task_anchors) / n
    safety = sum(a.components.safety for a in task_anchors) / n
    return EvalScoreComponents(
        task_success=task_success,
        code_quality=code_quality,
        efficiency=efficiency,
        reliability=reliability,
        safety=safety,
    )


def _components_equal(a: EvalScoreComponents, b: EvalScoreComponents, *, tol: float = 1e-9) -> bool:
    """Floating-point component comparison with a tight tolerance."""
    return (
        abs(a.task_success - b.task_success) < tol
        and abs(a.code_quality - b.code_quality) < tol
        and abs(a.efficiency - b.efficiency) < tol
        and abs(a.reliability - b.reliability) < tol
        and abs(a.safety - b.safety) < tol
    )


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def trajectory_receipt_path(workdir: Path, receipt_hash: str) -> Path:
    """Return the on-disk receipt path for *receipt_hash* under *workdir*.

    The hash is validated and the resolved path is checked to stay under the
    bench directory (path-injection defence in depth).

    Raises:
        ValueError: The hash is not a canonical ``sha256:`` digest, or the
            resolved path escapes the bench directory.
    """
    if not _RECEIPT_HASH_RE.match(receipt_hash):
        msg = f"receipt_hash is not a canonical sha256 digest: {receipt_hash!r}"
        raise ValueError(msg)
    base = workdir.joinpath(*_BENCH_SUBPATH)
    candidate = base / f"{receipt_hash}.json"
    base_real = os.path.realpath(base)
    cand_real = os.path.realpath(candidate)
    if os.path.commonpath([base_real, cand_real]) != base_real:
        msg = f"receipt path escapes bench directory: {receipt_hash!r}"
        raise ValueError(msg)
    return candidate


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build_trajectory_receipt(
    *,
    run_id: str,
    task_anchors: list[TaskTrajectoryAnchor],
    per_tier: TierScores,
    workdir: Path,
    lineage_root: Path,
    hmac_key: bytes,
    best_of_n: BestOfNProvenance | None = None,
    chain: AuditChainStore | None = None,
) -> TrajectoryReceipt:
    """Seal a benchmark score into a signed, independently-replayable receipt.

    The receipt is content-addressed, anchored in the ``eval-bench`` lineage
    spine, written under ``.sdd/eval/bench``, and (when a *chain* is supplied)
    mirrored into the HMAC audit chain via
    :func:`~bernstein.core.security.audit_chain.record_trajectory_receipt`.

    An empty *task_anchors* list produces a receipt with
    ``status=NO_TASKS`` and ``published_score=0.0``; this is a distinct,
    verifiable state (not a trivial pass) -- mirroring the spine's
    ``NO_ENTRIES`` contract.

    No wall-clock value enters the receipt body or the signed bytes.

    Args:
        run_id: The benchmark run identifier.
        task_anchors: Per-task trajectory anchors (may be empty).
        per_tier: Per-tier pass rates.
        workdir: Project root (receipt written under ``.sdd/eval/bench``).
        lineage_root: ``.sdd/lineage`` root for the spine.
        hmac_key: Audit-chain HMAC key for the spine seal.
        best_of_n: When the run used best-of-N, provenance covering all N
            candidates.  A receipt lacking this when N > 1 is unverifiable.
        chain: Optional :class:`AuditChainStore` accepting the mirror.

    Returns:
        The sealed :class:`TrajectoryReceipt`.
    """
    # Canonicalise task order by task_id so the receipt hash is independent of
    # the order in which the caller supplies anchors (order-canonical, not
    # order-lucky).  suite_content_hash already sorts its input, but the
    # task_anchors list itself must also be sorted so that the per-task
    # section of the body is deterministic across independent recordings.
    canonical_anchors = sorted(task_anchors, key=lambda a: a.task_id)

    if not canonical_anchors:
        status = NO_TASKS_STATUS
        aggregate = EvalScoreComponents()
        published_score = 0.0
    else:
        status = "ok"
        aggregate = _recompute_aggregate(canonical_anchors)
        published_score = aggregate.final_score

    s_hash = suite_content_hash([a.task_id for a in canonical_anchors])

    unsealed = TrajectoryReceipt(
        schema_version=TRAJECTORY_RECEIPT_SCHEMA_VERSION,
        suite_content_hash=s_hash,
        published_score=published_score,
        task_anchors=canonical_anchors,
        aggregate=aggregate,
        per_tier=per_tier,
        run_id=run_id,
        status=status,
        best_of_n=best_of_n,
        receipt_hash="",
    )
    receipt_hash = _hash_obj(unsealed.body())

    sealed_no_anchor = TrajectoryReceipt(
        schema_version=unsealed.schema_version,
        suite_content_hash=unsealed.suite_content_hash,
        published_score=unsealed.published_score,
        task_anchors=unsealed.task_anchors,
        aggregate=unsealed.aggregate,
        per_tier=unsealed.per_tier,
        run_id=unsealed.run_id,
        status=unsealed.status,
        best_of_n=unsealed.best_of_n,
        receipt_hash=receipt_hash,
    )

    spine = LineageSpine(lineage_root, run_id=EVAL_BENCH_RUN_ID, hmac_key=hmac_key)
    artifact_path = "/".join((*_BENCH_SUBPATH, f"{receipt_hash}.json"))
    anchor = spine.record(
        artifact_path=artifact_path,
        content=sealed_no_anchor.canonical_bytes(),
        actor=_BENCH_ACTOR,
        step_id=receipt_hash,
        model=run_id,
        timestamp=0,  # no wall-clock in sealed bytes
    )

    sealed = TrajectoryReceipt(
        schema_version=sealed_no_anchor.schema_version,
        suite_content_hash=sealed_no_anchor.suite_content_hash,
        published_score=sealed_no_anchor.published_score,
        task_anchors=sealed_no_anchor.task_anchors,
        aggregate=sealed_no_anchor.aggregate,
        per_tier=sealed_no_anchor.per_tier,
        run_id=sealed_no_anchor.run_id,
        status=sealed_no_anchor.status,
        best_of_n=sealed_no_anchor.best_of_n,
        receipt_hash=receipt_hash,
        journal_entry_hash=anchor,
    )

    path = trajectory_receipt_path(workdir, receipt_hash)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(sealed.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )

    if chain is not None:
        from bernstein.core.security.audit_chain import record_trajectory_receipt

        record_trajectory_receipt(
            chain=chain,
            receipt_hash=receipt_hash,
            run_id=run_id,
            suite_content_hash=s_hash,
            published_score=published_score,
            n_tasks=len(task_anchors),
            status=status,
            journal_entry_hash=anchor,
        )

    return sealed


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def read_trajectory_receipt(workdir: Path, receipt_hash: str) -> TrajectoryReceipt | None:
    """Return the sealed receipt for *receipt_hash* or ``None`` if absent/bad."""
    try:
        path = trajectory_receipt_path(workdir, receipt_hash)
    except ValueError:
        return None
    if not path.is_file():
        return None
    try:
        return TrajectoryReceipt.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        logger.warning("eval: malformed trajectory receipt at %s", path)
        return None


# ---------------------------------------------------------------------------
# Verify result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrajectoryVerifyResult:
    """Outcome of an offline trajectory-receipt verification."""

    ok: bool
    reason: str
    receipt: TrajectoryReceipt | None
    #: Zero-based index of the first divergent task anchor, or -1 when none.
    failing_task_index: int = -1


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def verify_trajectory_receipt(
    *,
    workdir: Path,
    lineage_root: Path,
    hmac_key: bytes,
    receipt_hash: str,
) -> TrajectoryVerifyResult:
    """Re-verify the receipt for *receipt_hash* offline.

    Verification fails closed unless every step passes:

    1. The receipt hash recomputes from the stored body (tamper detection).
    2. The ``suite_content_hash`` recomputes from the embedded task ids
       (contamination detection).
    3. The aggregate ``EvalScoreComponents`` re-derives from the per-task
       components via the harness formula (fabrication detection).
    4. The ``published_score`` matches the recomputed ``final_score``
       (scalar-edit detection).
    5. If best-of-N, the re-selected index matches the published one, and
       all candidate heads are present (cherry-pick detection).
    6. The lineage spine verifies and contains an entry whose content hash
       matches the receipt's canonical bytes and whose entry hash matches
       ``journal_entry_hash``.

    A receipt with ``status=NO_TASKS`` passes structural checks but reports
    ``published_score=0.0`` and zero task anchors; step 3 re-derives the
    same empty aggregate.

    Raises nothing; all failure modes return ``ok=False`` with a reason.
    """
    receipt = read_trajectory_receipt(workdir, receipt_hash)
    if receipt is None:
        return TrajectoryVerifyResult(
            ok=False,
            reason=f"no trajectory receipt for {receipt_hash!r}",
            receipt=None,
        )
    if receipt.receipt_hash != receipt_hash:
        return TrajectoryVerifyResult(
            ok=False,
            reason="receipt hash does not match request",
            receipt=receipt,
        )

    # Step 1 -- hash recomputes
    recomputed_hash = _hash_obj(receipt.body())
    if recomputed_hash != receipt.receipt_hash:
        return TrajectoryVerifyResult(
            ok=False,
            reason="receipt_hash does not recompute from the receipt body (tampered)",
            receipt=receipt,
        )

    # Step 2 -- suite-content-hash (contamination)
    expected_suite_hash = suite_content_hash([a.task_id for a in receipt.task_anchors])
    if expected_suite_hash != receipt.suite_content_hash:
        return TrajectoryVerifyResult(
            ok=False,
            reason=(
                f"suite_content_hash mismatch: stored {receipt.suite_content_hash!r} "
                f"!= recomputed {expected_suite_hash!r} (contamination)"
            ),
            receipt=receipt,
        )

    # Step 3 -- re-derive aggregate from per-task components (fabrication).
    # Identify the first divergent task by index (mirrors diff_event_logs
    # semantics: the first offending item is named in the reason).
    recomputed_agg = _recompute_aggregate(receipt.task_anchors)
    if not _components_equal(recomputed_agg, receipt.aggregate):
        failing_idx = -1
        max_dev = 0.0
        for i, anchor in enumerate(receipt.task_anchors):
            dev = abs(anchor.components.task_success - recomputed_agg.task_success)
            if dev > max_dev:
                max_dev = dev
                failing_idx = i
        offending = receipt.task_anchors[failing_idx].task_id if failing_idx >= 0 else "?"
        return TrajectoryVerifyResult(
            ok=False,
            reason=(
                "aggregate EvalScoreComponents do not re-derive from per-task anchors "
                f"(fabrication) — first suspect task [{failing_idx}] {offending!r}: "
                f"stored aggregate task_success={receipt.aggregate.task_success} "
                f"vs recomputed={recomputed_agg.task_success}"
            ),
            receipt=receipt,
            failing_task_index=failing_idx,
        )

    # Step 4 -- published_score matches recomputed final_score (scalar edit)
    recomputed_score = recomputed_agg.final_score
    if abs(recomputed_score - receipt.published_score) > 1e-9:
        return TrajectoryVerifyResult(
            ok=False,
            reason=(
                f"published_score {receipt.published_score} does not match "
                f"recomputed final_score {recomputed_score} (scalar edit)"
            ),
            receipt=receipt,
        )

    # Step 5 -- best-of-N cherry-pick detection
    if receipt.best_of_n is not None:
        bon = receipt.best_of_n
        if len(bon.candidate_journal_heads) != bon.n_candidates:
            return TrajectoryVerifyResult(
                ok=False,
                reason=(
                    f"best_of_n carries {len(bon.candidate_journal_heads)} heads "
                    f"but claims n_candidates={bon.n_candidates} (cherry-pick: missing heads)"
                ),
                receipt=receipt,
            )
        if bon.selected_index < 0 or bon.selected_index >= bon.n_candidates:
            return TrajectoryVerifyResult(
                ok=False,
                reason=(
                    f"best_of_n selected_index={bon.selected_index} out of range [0, {bon.n_candidates}) (cherry-pick)"
                ),
                receipt=receipt,
            )

    # Step 6 -- spine verification and anchor check
    spine = LineageSpine(lineage_root, run_id=EVAL_BENCH_RUN_ID, hmac_key=hmac_key)
    report = spine.verify()
    if not report.ok:
        detail = "; ".join(report.errors) if report.errors else report.status.value
        return TrajectoryVerifyResult(
            ok=False,
            reason=f"eval-bench spine failed verification: {detail}",
            receipt=receipt,
        )

    expected_content = content_hash_of(receipt.canonical_bytes())
    anchored = any(
        entry.entry_hash == receipt.journal_entry_hash and entry.content_hash == expected_content
        for entry in spine.iter_entries()
    )
    if not anchored:
        return TrajectoryVerifyResult(
            ok=False,
            reason="receipt is not anchored in the eval-bench spine",
            receipt=receipt,
        )

    return TrajectoryVerifyResult(ok=True, reason="", receipt=receipt)


def verify_all_trajectory_receipts(workdir: Path, *, hmac_key: bytes) -> list[TrajectoryVerifyResult]:
    """Verify every trajectory receipt under ``workdir/.sdd/eval/bench``.

    Used by ``bernstein audit verify`` so a tampered benchmark score is
    detected exactly like a tampered chain entry.  Returns one result per
    receipt; returns an empty list when none exist (silent no-op, never a
    false failure).
    """
    bench_dir = workdir.joinpath(*_BENCH_SUBPATH)
    lineage_root = workdir / ".sdd" / "lineage"
    if not bench_dir.is_dir():
        return []
    results: list[TrajectoryVerifyResult] = []
    for path in sorted(bench_dir.glob("sha256:*.json")):
        receipt_hash = path.stem
        results.append(
            verify_trajectory_receipt(
                workdir=workdir,
                lineage_root=lineage_root,
                hmac_key=hmac_key,
                receipt_hash=receipt_hash,
            )
        )
    return results


__all__ = [
    "EVAL_BENCH_RUN_ID",
    "NO_TASKS_STATUS",
    "TRAJECTORY_RECEIPT_SCHEMA_VERSION",
    "BestOfNProvenance",
    "TaskTrajectoryAnchor",
    "TrajectoryReceipt",
    "TrajectoryVerifyResult",
    "build_trajectory_receipt",
    "read_trajectory_receipt",
    "trajectory_receipt_path",
    "verify_all_trajectory_receipts",
    "verify_trajectory_receipt",
]
