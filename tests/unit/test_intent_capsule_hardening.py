"""Hardening regressions for intent capsules (#2649).

Every value a verifier treats as authoritative must be derived from signed or
Merkle-chained state, never from caller-supplied or unsigned input:

* the run a capsule is verified against comes from the signed ``intent.capsule``
  audit event, not from the unsigned on-disk sidecar, and the journal must carry
  exactly one matching ``intent.capsule_bound`` anchor;
* the declared capsule scope (file globs, adapters, expiry) is enforced rather
  than merely recorded, and ``allow_unclassified`` actually gates unclassified
  events;
* a worker-stamped ``action_class`` cannot override the reviewed tool mapping;
* a drift escalation signs a verdict recomputed from the journal, never the
  verdict its caller handed in;
* the read-only ``intent verify`` path never mints audit key material.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bernstein.core.replay.journal import EventJournal, load_events
from bernstein.core.security.audit_chain import AuditChainStore
from bernstein.core.security.intent_capsule import (
    DriftPolicy,
    IntentCapsule,
    IntentCapsuleError,
    approve_and_capsule,
    assemble_intent_drift_escalation,
    bind_capsule_into_journal,
    capsule_hash,
    classify_journal_event,
    compile_capsule,
    evaluate_conformance,
    verify_intent_conformance,
)
from bernstein.core.tasks.models import TaskCostEstimate, TaskPlan

_HMAC_KEY = b"k" * 32
_RUN_ID = "run-intent-h1"
_TASK_ID = "task-hardening-1"

#: Far-future expiry so fixtures that build real journals (whose events carry a
#: wall-clock ``ts``) are not incidentally expired. Expiry enforcement itself is
#: covered by its own regression below.
_FUTURE_EXPIRY = 4_102_444_800  # 2100-01-01T00:00:00Z


def _sdd(tmp_path: Path) -> Path:
    return tmp_path / ".sdd"


def _plan() -> TaskPlan:
    return TaskPlan(
        id="planh1",
        goal="Refactor the pricing module for clarity; no external calls.",
        task_estimates=[
            TaskCostEstimate(
                task_id=_TASK_ID,
                title="Refactor pricing",
                role="backend",
                model="sonnet",
                estimated_tokens=80_000,
                estimated_cost_usd=0.24,
                risk_level="low",
            )
        ],
        total_estimated_cost_usd=0.24,
        total_estimated_minutes=30,
    )


def _capsule(**overrides) -> IntentCapsule:
    kwargs = {
        "allowed_action_classes": ["fs.read", "fs.write", "git.commit"],
        "file_scope_globs": ["src/pricing/**"],
        "permitted_adapters": ["claude"],
        "egress_classes": [],
        "expiry_ts": _FUTURE_EXPIRY,
    }
    kwargs.update(overrides)
    return compile_capsule(plan=_plan(), task_id=_TASK_ID, **kwargs)


def _chain(tmp_path: Path) -> AuditChainStore:
    return AuditChainStore(_sdd(tmp_path) / "audit", key=_HMAC_KEY)


def _approve(tmp_path: Path, *, run_id: str = _RUN_ID, **overrides) -> IntentCapsule:
    kwargs = {
        "allowed_action_classes": ["fs.read", "fs.write", "git.commit"],
        "file_scope_globs": ["src/pricing/**"],
        "permitted_adapters": ["claude"],
        "egress_classes": [],
        "expiry_ts": _FUTURE_EXPIRY,
    }
    kwargs.update(overrides)
    capsule, _ = approve_and_capsule(
        chain=_chain(tmp_path),
        sdd_dir=_sdd(tmp_path),
        plan=_plan(),
        task_id=_TASK_ID,
        run_id=run_id,
        **kwargs,
    )
    return capsule


def _journal(tmp_path: Path, run_id: str, *, capsule_h: str, bind: bool = True, drift: bool = False) -> EventJournal:
    journal = EventJournal(run_id, _sdd(tmp_path))
    if bind:
        bind_capsule_into_journal(journal, task_id=_TASK_ID, capsule_hash=capsule_h)
    journal.record("tool.call", tool="Read", path="src/pricing/rates.py", seq=1)
    journal.record("tool.call", tool="Edit", path="src/pricing/rates.py", seq=2)
    if drift:
        journal.record("tool.call", tool="WebFetch", seq=3)
    return journal


def _sidecar_path(tmp_path: Path) -> Path:
    return _sdd(tmp_path) / "intent" / "capsules" / f"{_TASK_ID}.json"


def _rewrite_sidecar_run_id(tmp_path: Path, run_id: str) -> None:
    path = _sidecar_path(tmp_path)
    row = json.loads(path.read_text(encoding="utf-8"))
    row["run_id"] = run_id
    path.write_text(json.dumps(row), encoding="utf-8")


# ---------------------------------------------------------------------------
# Critical: the verified run comes from the signed audit event, not the sidecar
# ---------------------------------------------------------------------------


def test_forged_sidecar_run_id_is_rejected(tmp_path: Path) -> None:
    """Repointing the unsigned sidecar at a clean run must not launder drift."""
    capsule = _approve(tmp_path)
    ch = capsule_hash(capsule)
    # The run the audit chain actually attests to drifted.
    _journal(tmp_path, _RUN_ID, capsule_h=ch, drift=True)
    # The attacker stages a clean run and repoints the unsigned sidecar at it.
    _journal(tmp_path, "run-decoy", capsule_h=ch, drift=False)
    _rewrite_sidecar_run_id(tmp_path, "run-decoy")

    result = verify_intent_conformance(sdd_dir=_sdd(tmp_path), chain=_chain(tmp_path), task_id=_TASK_ID)

    assert not result.ok
    assert not result.conformant
    assert "run_id" in result.reason
    # The authoritative run_id is the signed one, not the forged sidecar value.
    assert result.run_id == _RUN_ID


def test_verify_uses_audit_run_id_when_sidecar_is_silent(tmp_path: Path) -> None:
    """An empty sidecar run_id makes no claim; the signed run_id still governs."""
    capsule = _approve(tmp_path)
    _journal(tmp_path, _RUN_ID, capsule_h=capsule_hash(capsule))
    _rewrite_sidecar_run_id(tmp_path, "")

    result = verify_intent_conformance(sdd_dir=_sdd(tmp_path), chain=_chain(tmp_path), task_id=_TASK_ID)

    assert result.ok, result.reason
    assert result.run_id == _RUN_ID


def test_verify_requires_a_capsule_bound_anchor(tmp_path: Path) -> None:
    """A journal that never bound the capsule is not attributable to it."""
    capsule = _approve(tmp_path)
    _journal(tmp_path, _RUN_ID, capsule_h=capsule_hash(capsule), bind=False)

    result = verify_intent_conformance(sdd_dir=_sdd(tmp_path), chain=_chain(tmp_path), task_id=_TASK_ID)

    assert not result.ok
    assert "capsule_bound" in result.reason


def test_verify_rejects_a_capsule_bound_anchor_for_another_capsule(tmp_path: Path) -> None:
    """An anchor naming a different capsule does not attribute this run."""
    _approve(tmp_path)
    _journal(tmp_path, _RUN_ID, capsule_h="sha256:" + "0" * 64)

    result = verify_intent_conformance(sdd_dir=_sdd(tmp_path), chain=_chain(tmp_path), task_id=_TASK_ID)

    assert not result.ok
    assert "0 matching" in result.reason
    assert "capsule_bound" in result.reason


def test_verify_rejects_duplicate_capsule_bound_anchors(tmp_path: Path) -> None:
    """Exactly one anchor: two bindings make attribution ambiguous."""
    capsule = _approve(tmp_path)
    journal = _journal(tmp_path, _RUN_ID, capsule_h=capsule_hash(capsule))
    bind_capsule_into_journal(journal, task_id=_TASK_ID, capsule_hash=capsule_hash(capsule))

    result = verify_intent_conformance(sdd_dir=_sdd(tmp_path), chain=_chain(tmp_path), task_id=_TASK_ID)

    assert not result.ok
    assert "capsule_bound" in result.reason


# ---------------------------------------------------------------------------
# The declared capsule scope is enforced, not merely recorded
# ---------------------------------------------------------------------------


def test_file_scope_globs_are_enforced(tmp_path: Path) -> None:
    capsule = _capsule(file_scope_globs=["src/pricing/**"])
    events = [
        {"event": "tool.call", "tool": "Edit", "path": "src/pricing/rates.py"},
        {"event": "tool.call", "tool": "Edit", "path": "src/billing/secrets.py"},
    ]

    verdict = evaluate_conformance(events, capsule)

    assert not verdict.conformant
    assert [d.step_index for d in verdict.divergences] == [1]
    assert verdict.divergences[0].reason == "file_scope_violation"


def test_file_scope_globs_do_not_match_across_directory_separators(tmp_path: Path) -> None:
    """A single ``*`` must not silently span ``/`` and widen the approved scope."""
    capsule = _capsule(file_scope_globs=["src/*.py"])
    events = [{"event": "tool.call", "tool": "Edit", "path": "src/nested/deep.py"}]

    verdict = evaluate_conformance(events, capsule)

    assert not verdict.conformant
    assert verdict.divergences[0].reason == "file_scope_violation"


def test_file_scope_globs_are_not_escapable_by_traversal(tmp_path: Path) -> None:
    """``..`` must be collapsed before matching, or the prefix is a free pass."""
    capsule = _capsule(file_scope_globs=["src/pricing/**"])
    events = [
        {"event": "tool.call", "tool": "Edit", "path": "src/pricing/../../etc/passwd"},
        {"event": "tool.call", "tool": "Edit", "path": "src/pricing/./rates.py"},
    ]

    verdict = evaluate_conformance(events, capsule)

    assert [d.step_index for d in verdict.divergences] == [0]
    assert verdict.divergences[0].reason == "file_scope_violation"


def test_path_in_scope_collapses_traversal_and_dot_segments() -> None:
    from bernstein.core.security.intent_capsule import path_in_scope

    globs = ("src/pricing/**",)
    assert path_in_scope("src/pricing/rates.py", globs)
    assert path_in_scope("./src/pricing/rates.py", globs)
    assert path_in_scope("src/pricing/nested/deep.py", globs)
    assert not path_in_scope("src/pricing/../secrets.py", globs)
    assert not path_in_scope("src/pricing/../../../etc/passwd", globs)


def test_empty_file_scope_globs_leave_writes_unconstrained(tmp_path: Path) -> None:
    capsule = _capsule(file_scope_globs=[])
    events = [{"event": "tool.call", "tool": "Edit", "path": "anywhere/at/all.py"}]

    assert evaluate_conformance(events, capsule).conformant


def test_permitted_adapters_are_enforced(tmp_path: Path) -> None:
    capsule = _capsule(permitted_adapters=["claude"])
    events = [
        {"event": "tool.call", "tool": "Read", "adapter": "claude"},
        {"event": "tool.call", "tool": "Read", "adapter": "codex"},
    ]

    verdict = evaluate_conformance(events, capsule)

    assert not verdict.conformant
    assert [d.step_index for d in verdict.divergences] == [1]
    assert verdict.divergences[0].reason == "adapter_not_permitted"


def test_expiry_ts_is_enforced(tmp_path: Path) -> None:
    capsule = _capsule(expiry_ts=1_700_000_000)
    events = [
        {"event": "tool.call", "tool": "Read", "ts": 1_699_999_999},
        {"event": "tool.call", "tool": "Read", "ts": 1_700_000_001},
    ]

    verdict = evaluate_conformance(events, capsule)

    assert not verdict.conformant
    assert [d.step_index for d in verdict.divergences] == [1]
    assert verdict.divergences[0].reason == "capsule_expired"


def test_allow_unclassified_false_counts_unclassified_events(tmp_path: Path) -> None:
    capsule = _capsule()
    events = [{"event": "tool.call", "tool": "some_unknown_tool"}]

    assert evaluate_conformance(events, capsule, policy=DriftPolicy()).conformant
    strict = evaluate_conformance(events, capsule, policy=DriftPolicy(allow_unclassified=False))
    assert not strict.conformant
    assert strict.divergences[0].reason == "unclassified_event"


def test_allow_unclassified_false_still_ignores_the_binding_anchor(tmp_path: Path) -> None:
    """The capsule-binding anchor is structural, not a worker action."""
    from bernstein.core.security.intent_capsule import CAPSULE_BOUND_EVENT

    capsule = _capsule()
    events = [{"event": CAPSULE_BOUND_EVENT, "task_id": _TASK_ID, "capsule_hash": capsule_hash(capsule)}]

    assert evaluate_conformance(events, capsule, policy=DriftPolicy(allow_unclassified=False)).conformant


# ---------------------------------------------------------------------------
# A worker-stamped action_class cannot override the reviewed tool mapping
# ---------------------------------------------------------------------------


def test_worker_action_class_cannot_relabel_a_recognized_tool() -> None:
    """A shell call stamped ``git.commit`` still classifies as ``shell.exec``."""
    assert classify_journal_event({"tool": "Bash", "action_class": "git.commit"}) == "shell.exec"
    assert classify_journal_event({"tool": "WebFetch", "action_class": "fs.read"}) == "web.fetch"


def test_explicit_action_class_is_the_fallback_for_unknown_tools() -> None:
    assert classify_journal_event({"tool": "custom_mcp_tool", "action_class": "fs.read"}) == "fs.read"


def test_relabelled_shell_call_surfaces_as_drift(tmp_path: Path) -> None:
    capsule = _capsule()
    events = [{"event": "tool.call", "tool": "Bash", "action_class": "git.commit"}]

    verdict = evaluate_conformance(events, capsule)

    assert not verdict.conformant
    assert verdict.divergences[0].action_class == "shell.exec"


# ---------------------------------------------------------------------------
# The escalation signs a recomputed verdict, never the caller's
# ---------------------------------------------------------------------------


def _identity(tmp_path: Path) -> tuple[str, str]:
    from bernstein.core.orchestration.escalation import load_or_create_escalation_identity

    return load_or_create_escalation_identity(_sdd(tmp_path) / "identity")


def _escalate(tmp_path: Path, capsule: IntentCapsule, verdict, **overrides):
    private_pem, public_pem = _identity(tmp_path)
    kwargs = {
        "sdd_dir": _sdd(tmp_path),
        "lineage_root": _sdd(tmp_path) / "lineage",
        "hmac_key": _HMAC_KEY,
        "private_key_pem": private_pem,
        "public_key_pem": public_pem,
        "run_id": _RUN_ID,
        "capsule": capsule,
        "verdict": verdict,
        "worker_id": "abcdef012345",
        "session_id": "sess-1",
        "worktree_id": "wt-1",
        "install_rev": "abc1234567890def",
        "timestamp": 1_700_000_000,
    }
    kwargs.update(overrides)
    return assemble_intent_drift_escalation(**kwargs)


def test_escalation_refuses_a_forged_verdict(tmp_path: Path) -> None:
    """A caller cannot have a verdict signed that the journal does not support."""
    capsule = _capsule()
    journal = _journal(tmp_path, _RUN_ID, capsule_h=capsule_hash(capsule), drift=True)
    real = evaluate_conformance(load_events(journal.path), capsule)
    forged = type(real)(
        conformant=False,
        capsule_hash=real.capsule_hash,
        policy_mode=real.policy_mode,
        divergences=(),
        verdict_hash="sha256:" + "0" * 64,
    )

    with pytest.raises(IntentCapsuleError, match="verdict"):
        _escalate(tmp_path, capsule, forged)


def test_escalation_refuses_a_conformant_verdict(tmp_path: Path) -> None:
    capsule = _capsule()
    journal = _journal(tmp_path, _RUN_ID, capsule_h=capsule_hash(capsule), drift=False)
    verdict = evaluate_conformance(load_events(journal.path), capsule)
    assert verdict.conformant

    with pytest.raises(IntentCapsuleError, match="conformant"):
        _escalate(tmp_path, capsule, verdict)


def test_escalation_refuses_when_the_journal_is_missing(tmp_path: Path) -> None:
    capsule = _capsule()
    journal = _journal(tmp_path, _RUN_ID, capsule_h=capsule_hash(capsule), drift=True)
    verdict = evaluate_conformance(load_events(journal.path), capsule)
    journal.path.unlink()

    with pytest.raises(IntentCapsuleError, match="journal"):
        _escalate(tmp_path, capsule, verdict)


def test_escalation_refuses_a_tampered_journal(tmp_path: Path) -> None:
    capsule = _capsule()
    journal = _journal(tmp_path, _RUN_ID, capsule_h=capsule_hash(capsule), drift=True)
    verdict = evaluate_conformance(load_events(journal.path), capsule)
    lines = journal.path.read_text(encoding="utf-8").splitlines()
    lines[-1], lines[-2] = lines[-2], lines[-1]
    journal.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(IntentCapsuleError, match="journal"):
        _escalate(tmp_path, capsule, verdict)


def test_escalation_signs_the_recomputed_verdict(tmp_path: Path) -> None:
    capsule = _capsule()
    journal = _journal(tmp_path, _RUN_ID, capsule_h=capsule_hash(capsule), drift=True)
    verdict = evaluate_conformance(load_events(journal.path), capsule)

    receipt = _escalate(tmp_path, capsule, verdict)

    assert receipt.extra_binding is not None
    assert receipt.extra_binding["verdict_hash"] == verdict.verdict_hash
    assert [d["action_class"] for d in receipt.extra_binding["divergent_events"]] == ["web.fetch"]


def test_escalation_recomputes_under_the_supplied_policy(tmp_path: Path) -> None:
    """The recomputation must use the same policy the caller's verdict used."""
    capsule = _capsule()
    journal = _journal(tmp_path, _RUN_ID, capsule_h=capsule_hash(capsule), drift=True)
    policy = DriftPolicy(mode="block")
    verdict = evaluate_conformance(load_events(journal.path), capsule, policy=policy)

    receipt = _escalate(tmp_path, capsule, verdict, policy=policy)

    assert receipt.extra_binding is not None
    assert receipt.extra_binding["verdict_hash"] == verdict.verdict_hash
