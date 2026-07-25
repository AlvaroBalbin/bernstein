"""Cross-process read-modify-append on the audit chain must be serialisable.

Opening a tenant charter is a read-modify-append: read the recorded charter
events, decide whether the tenant is already owned, and append the opening
batch only if it is not. The read and the append are two separate touches of
the same append-only log. Without a lock that spans both, two processes each
observe "no charter exists", each append an opening event, and the resulting
segment carries two events claiming ``seq == 0``.

Both appends are individually well-formed, so the HMAC chain still verifies:
``bernstein audit verify`` reports ``audit_chain_ok: true`` while the charter
fold reports ``gap``. The log is append-only, so the duplicate can never be
removed - the charter is permanently unreadable.

Three properties of this test are load-bearing and must not be "simplified":

1. **Real subprocesses.** Threads share the in-process mutex and would pass
   even with the cross-process primitive removed.
2. **A filesystem barrier after imports.** Interpreter and import cost is paid
   before the race window opens, so the workers arrive at the read within
   microseconds of each other. Without it, startup jitter desynchronises the
   workers and the defect reproduces only intermittently.
3. **Read-decide-append is the unit under test**, not the append alone. An
   append-only race is already serialised; the defect lives in the gap between
   the read and the append.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow

#: How many workers race for the same charter. The defect reproduces at every
#: concurrency level once the barrier removes startup jitter; this is simply
#: comfortably above the level at which the unsynchronised repro was flaky.
WORKERS = 10

#: How many independent trials each assertion must survive. The unfixed tree
#: wedges on every trial; a single green trial would therefore be evidence of
#: a broken harness, not of a fixed defect.
TRIALS = 3

_WORKER_SOURCE = textwrap.dedent(
    '''
    """One racing worker: read the charter, decide, append the opening batch."""

    import json
    import os
    import sys
    import time
    from pathlib import Path

    workdir = Path(sys.argv[1])
    barrier_dir = Path(sys.argv[2])
    worker_id = sys.argv[3]
    expected = int(sys.argv[4])
    tenant_id = sys.argv[5]

    from bernstein.core.security.audit_chain import AuditChainStore
    from bernstein.core.security.tenant_charter import (
        CHARTER_MEMBER_ADD,
        CHARTER_OPEN,
        next_event,
        read_charter_events,
        record_charter_event,
    )

    try:
        from bernstein.core.security.audit import chain_transaction
    except ImportError:  # unfixed tree: no transaction primitive exists yet
        chain_transaction = None

    audit_dir = workdir / ".sdd" / "audit"
    chain = AuditChainStore(audit_dir)

    def _read_decide_append() -> str:
        """The read-modify-append under test."""
        existing = read_charter_events(chain, tenant_id)
        if existing:
            return "REFUSED"
        opening = next_event(None, tenant_id=tenant_id, kind=CHARTER_OPEN, principal=worker_id)
        member = next_event(
            opening,
            tenant_id=tenant_id,
            kind=CHARTER_MEMBER_ADD,
            principal=worker_id,
            body={"principal": worker_id, "role": "owner"},
        )
        for event in (opening, member):
            record_charter_event(chain, event)
        return "OPENED"

    # Filesystem barrier: pay interpreter startup and import cost BEFORE the
    # race window opens, so every worker reaches the read at the same instant.
    (barrier_dir / f"ready.{worker_id}").write_text("1", encoding="utf-8")
    deadline = time.monotonic() + 60.0
    while len(list(barrier_dir.glob("ready.*"))) < expected:
        if time.monotonic() >= deadline:
            print(json.dumps({"worker": worker_id, "outcome": "BARRIER_TIMEOUT"}))
            sys.exit(2)
        time.sleep(0.001)

    try:
        if chain_transaction is None:
            outcome = _read_decide_append()
        else:
            with chain_transaction(audit_dir):
                outcome = _read_decide_append()
        error = ""
    except BaseException as exc:  # noqa: BLE001 - the worker reports, the parent asserts
        outcome = "ERROR"
        error = f"{type(exc).__name__}: {exc}"

    print(json.dumps({"worker": worker_id, "outcome": outcome, "error": error}))
    '''
).strip()


def _run_trial(tmp_path: Path, trial: int, tenant_id: str) -> tuple[list[dict[str, str]], Path]:
    """Race ``WORKERS`` real processes to open the same charter. Returns their reports."""
    workdir = tmp_path / f"trial-{trial}"
    barrier_dir = workdir / "barrier"
    barrier_dir.mkdir(parents=True, exist_ok=True)
    (workdir / ".sdd" / "audit").mkdir(parents=True, exist_ok=True)

    worker_py = workdir / "worker.py"
    worker_py.write_text(_WORKER_SOURCE, encoding="utf-8")

    # Every worker signs with the same key, exactly as separate CLI invocations
    # under one operator do.
    key_path = workdir / "audit.key"
    key_path.write_bytes(b"0" * 32)
    key_path.chmod(0o600)

    env = dict(os.environ)
    env["BERNSTEIN_AUDIT_KEY_PATH"] = str(key_path)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[3] / "src")

    procs = [
        subprocess.Popen(
            [sys.executable, str(worker_py), str(workdir), str(barrier_dir), f"w{i}", str(WORKERS), tenant_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )
        for i in range(WORKERS)
    ]

    reports: list[dict[str, str]] = []
    for proc in procs:
        out, err = proc.communicate(timeout=180)
        line = out.strip().splitlines()[-1] if out.strip() else ""
        if not line:
            reports.append({"worker": "?", "outcome": "NO_OUTPUT", "error": err.strip()[-2000:]})
            continue
        reports.append(json.loads(line))
    return reports, workdir


@pytest.mark.timeout(600)
def test_concurrent_charter_open_serialises(tmp_path: Path) -> None:
    """Exactly one racing process may open a charter, and the fold stays readable.

    On a tree without a cross-process read-modify-append primitive this fails
    with two or more OPENED winners and a charter that folds to ``gap`` while
    the HMAC chain still reports clean - the signature of the defect.
    """
    from bernstein.core.security.audit_chain import AuditChainStore
    from bernstein.core.security.tenant_charter import read_charter_events, verify_charter

    failures: list[str] = []

    for trial in range(TRIALS):
        tenant_id = f"acme{trial}"
        reports, workdir = _run_trial(tmp_path, trial, tenant_id)

        winners = [r for r in reports if r["outcome"] == "OPENED"]
        refusals = [r for r in reports if r["outcome"] == "REFUSED"]
        errors = [r for r in reports if r["outcome"] not in {"OPENED", "REFUSED"}]

        chain = AuditChainStore(workdir / ".sdd" / "audit", key=b"0" * 32)
        verdict = verify_charter(chain, tenant_id)
        chain_ok, chain_errors = chain.verify()
        events = read_charter_events(chain, tenant_id)

        detail = (
            f"trial {trial}: winners={len(winners)} refusals={len(refusals)} errors={len(errors)} "
            f"charter_ok={verdict.ok} reason={verdict.reason!r} "
            f"audit_chain_ok={chain_ok} audit_chain_errors={len(chain_errors)} "
            f"events={len(events)} seqs={[e.seq for e in events]}"
        )
        if errors:
            detail += f" first_error={errors[0].get('error', '')[:300]!r}"

        if len(winners) != 1 or not verdict.ok or not chain_ok or len(events) != 2 or errors:
            failures.append(detail)
        else:
            print(f"PASS {detail}")

    assert not failures, "concurrent charter opens were not serialised:\n" + "\n".join(failures)
