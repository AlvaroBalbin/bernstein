"""Deterministic fork-and-race over one content-addressed base snapshot (#2613).

``best_of_n`` today spawns K candidate workers from *scratch* in separate
worktrees, so the K attempts never actually start from one identical
captured state - rerun the race and the base differs, so the winner is not
attributable to the candidate's work alone. :func:`fork_race` closes that
gap. It resumes K candidate sessions from the *same* content-addressed
base snapshot digest, runs each to a terminal snapshot, and selects the
winner with the existing deterministic ranker
(:func:`bernstein.core.orchestration.best_of_n.select_winner` backed by
TOPSIS) - **no LLM in the selection path**. The output is a signed
:class:`~bernstein.core.sandbox.selection_receipt.SelectionReceipt` that
reconstructs the whole race offline.

Two determinism disciplines are load-bearing and easy to get wrong:

- **Rank on a wall-clock-free profile.** :data:`DETERMINISTIC_PROFILE`
  ranks on ``correctness``/``cost``/``reversibility`` only. It deliberately
  omits the ``latency`` axis, which
  :func:`best_of_n._to_rank_candidate` would populate from ``runtime_s`` -
  a host wall-clock measurement that differs every run and could flip the
  winner on scheduler jitter, breaking the byte-identical-receipt gate.
- **Fix candidate order before ranking, not just before serialising.**
  TOPSIS sums over the candidate matrix, and float addition is not
  associative, so two runs whose candidate submission order differs can
  produce last-bit-different scores. Candidates are sorted by ``task_id``
  *before* they reach ``select_winner``, so the ranking input is identical
  across runs.

The audit append is a single serialised call after all K candidates and
the ranker have finished (``AuditLog`` has no internal lock; a per-candidate
fan-out would race ``prev_hmac`` and corrupt the chain). Publication is
crash-safe: CAS blobs are already stored by ``snapshot()``, then the
receipt is signed, then the audit entry lands, then the receipt file is
exposed via tmp+rename - so a crash never leaves a validly-signed but
unanchored receipt visible.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from typing import TYPE_CHECKING, Any, Protocol

from bernstein.core.orchestration.best_of_n import CandidateResult, select_winner
from bernstein.core.orchestration.multi_criteria_rank import (
    CriterionProfile,
    build_criterion_profile,
)
from bernstein.core.sandbox.selection_receipt import (
    RaceCandidate,
    SelectionReceipt,
    build_selection_receipt,
    sign_receipt,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator
    from pathlib import Path

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from bernstein.core.sandbox.backend import SandboxSession
    from bernstein.core.security.audit import AuditLog

#: The deterministic ranking profile fork-race pins. No wall-clock axis:
#: ``latency`` (which maps from ``runtime_s``) is deliberately excluded so
#: the winner is a pure function of the candidates' deliverables.
DETERMINISTIC_PROFILE: CriterionProfile = build_criterion_profile(
    ["correctness", "cost", "reversibility"],
)

#: Audit event-type for a completed fork-race selection.
FORK_RACE_EVENT_TYPE = "sandbox.fork_race"


@contextlib.contextmanager
def _cross_process_audit_lock(lock_path: Path | None) -> Iterator[None]:
    """Serialise the single audit append across concurrent fork-race *processes*.

    Within one event loop the append is a synchronous ``AuditLog.log`` call
    that cannot interleave with another coroutine, so the in-process case is
    already safe. This guards the remaining window: two *separate processes*
    running a fork-race against the same audit directory, where ``AuditLog``
    has no lock of its own and both could read the same ``prev_hmac`` and fork
    the chain. A no-op when *lock_path* is ``None`` or on a platform without
    ``fcntl`` (e.g. Windows).
    """
    if lock_path is None:
        yield
        return
    try:
        import fcntl
    except ImportError:
        yield
        return
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


class ForkRaceBackend(Protocol):
    """The slice of a sandbox backend :func:`fork_race` needs.

    Any SNAPSHOT-capable backend whose ``snapshot()`` returns a CAS digest
    satisfies this; in practice that is
    :class:`~bernstein.core.sandbox.backends.microvm.MicroVMSandboxBackend`.
    """

    name: str

    async def resume(self, snapshot_id: str) -> SandboxSession: ...

    async def destroy(self, session: SandboxSession) -> None: ...


def _score_vector(result: CandidateResult) -> dict[str, float]:
    """Project a candidate onto the deterministic axes recorded in the receipt.

    Mirrors :func:`best_of_n._to_rank_candidate` for the wall-clock-free
    axes only, so the vector stored in the receipt matches what the ranker
    actually consumed.
    """
    correctness = 1.0 if result.tests_passing else 0.0
    judge = result.judge_score if result.judge_score is not None else correctness
    correctness = max(0.0, min(1.0, 0.5 * correctness + 0.5 * judge))
    return {
        "correctness": correctness,
        "cost": max(0.0, 1.0 - max(0.0, min(1.0, result.lint_score))),
        "reversibility": 1.0,
    }


def _profile_to_dict(profile: CriterionProfile) -> dict[str, Any]:
    return {
        "method": "topsis",
        "criteria": [{"name": c.name, "direction": c.direction, "weight": c.weight} for c in profile.criteria],
    }


async def fork_race(
    *,
    backend: ForkRaceBackend,
    base_snapshot_digest: str,
    run_candidate: Callable[[SandboxSession, int], Awaitable[CandidateResult]],
    k: int,
    signing_key: Ed25519PrivateKey,
    profile: CriterionProfile | None = None,
    audit_log: AuditLog | None = None,
    audit_lock_path: Path | None = None,
    actor: str = "fork_race",
) -> SelectionReceipt:
    """Fork K candidates from one base snapshot and return a signed receipt.

    Args:
        backend: A SNAPSHOT-capable backend whose ``snapshot()`` returns a
            CAS digest (the microVM backend).
        base_snapshot_digest: The single content-addressed base every
            candidate forks from - the anchor that makes the race
            attributable.
        run_candidate: Async callback that mutates a resumed session and
            returns its :class:`CandidateResult` (task_id + deterministic
            scores). It must not snapshot; fork_race captures the terminal
            snapshot after it returns.
        k: Number of candidates (>= 1).
        signing_key: Ed25519 private key that signs the receipt.
        profile: Ranking profile. Defaults to :data:`DETERMINISTIC_PROFILE`.
        audit_log: When provided, the receipt is appended to the HMAC audit
            chain in exactly one serialised call after ranking.
        audit_lock_path: Optional lock file guarding the audit append against
            concurrent fork-race *processes* sharing the audit directory (the
            in-process append is already atomic). No-op when ``None``.
        actor: Actor recorded on the audit entry.

    Returns:
        The signed :class:`SelectionReceipt`.

    Raises:
        ValueError: When *k* < 1.
    """
    if k < 1:
        raise ValueError(f"fork_race requires k >= 1, got {k}")
    ranking_profile = profile or DETERMINISTIC_PROFILE
    pub = signing_key.public_key()

    async def _one(index: int) -> tuple[CandidateResult, str]:
        session = await backend.resume(base_snapshot_digest)
        try:
            result = await run_candidate(session, index)
            terminal_digest = await session.snapshot()
        finally:
            await backend.destroy(session)
        return result, terminal_digest

    # Race the candidates concurrently; the barrier here is intentional -
    # ranking and the single audit append need the full result set. If any
    # candidate raises, gather surfaces the first error but leaves its siblings
    # running in the (persistent) event loop - explicitly cancel and drain them
    # so no in-flight candidate outlives the race and every _one finally-block
    # (which destroys its session) still runs.
    tasks = [asyncio.ensure_future(_one(i)) for i in range(k)]
    try:
        outcomes = await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise

    # D2: fix candidate order BEFORE ranking so the TOPSIS matrix (and its
    # float sums) is identical across runs - not merely before serialising.
    ordered = sorted(outcomes, key=lambda pair: pair[0].task_id)
    results = [result for result, _ in ordered]
    terminal_by_id = {result.task_id: digest for result, digest in ordered}

    winner = select_winner(results, profile=ranking_profile)

    race_candidates = [
        RaceCandidate(
            task_id=result.task_id,
            terminal_snapshot_digest=terminal_by_id[result.task_id],
            score_vector=_score_vector(result),
            isolation=backend.name,
        )
        for result in results
    ]

    receipt = build_selection_receipt(
        base_snapshot_digest=base_snapshot_digest,
        candidates=race_candidates,
        winner_task_id=winner.task_id,
        ranker_profile=_profile_to_dict(ranking_profile),
        public_key=pub,
    )
    signed = sign_receipt(receipt, private_key=signing_key)

    # Single serialised audit append AFTER all candidates + ranking. The
    # receipt body is chain-position-agnostic; this wrapper entry is what
    # binds it into the tamper-evident chain (bound by its own prev_hmac).
    if audit_log is not None:
        from bernstein.core.sandbox.selection_receipt import receipt_to_dict

        # The cross-process flock can block on contention from another fork-race
        # process, and audit_log.log does a synchronous file write - both would
        # stall the caller's event loop (fork_race is a library coroutine that
        # may be awaited alongside other tasks). Offload the lock+append to a
        # worker thread. It is still awaited before returning, so the crash-safe
        # ordering (CAS blobs -> sign -> audit -> receipt file) holds, and lock
        # and append stay together in one call, so the chain's prev_hmac is
        # still written under exclusive serialisation.
        def _append() -> None:
            with _cross_process_audit_lock(audit_lock_path):
                audit_log.log(
                    FORK_RACE_EVENT_TYPE,
                    actor,
                    "sandbox_selection_receipt",
                    signed.payload_digest,
                    {
                        "base_snapshot_digest": signed.base_snapshot_digest,
                        "winner_task_id": signed.winner_task_id,
                        "winner_snapshot_digest": signed.winner_snapshot_digest,
                        "keyid": signed.keyid,
                        "receipt": receipt_to_dict(signed),
                    },
                )

        await asyncio.to_thread(_append)

    return signed


__all__ = [
    "DETERMINISTIC_PROFILE",
    "FORK_RACE_EVENT_TYPE",
    "ForkRaceBackend",
    "fork_race",
]
