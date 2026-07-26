"""``bernstein tenant`` - chain-governed team boundaries (#2554).

Every subcommand here is a projection of the same thing: the charter event
segment on the HMAC audit chain. ``create`` / ``grant`` / ``revoke`` append to
it, ``show`` and ``verify`` fold it, and ``slice`` / ``showback`` /
``verify-statement`` derive views that a second party can recompute.

Write commands hold the chain's cross-process append section
(:meth:`AuditChainStore.chain_transaction`) across read + decide + append, so
two operators editing one charter are serialised rather than raced. Read-only
commands take no lock at all: they must work on a read-only copy of the audit
directory - an incident snapshot, a mounted archive - where even opening the
lock sentinel for writing would fail.

The verbs are ``tenant`` rather than ``team`` or ``workspace``: ``team`` is
taken by agent role manifests and ``workspace`` by multi-repo management.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from bernstein.cli.helpers import console

if TYPE_CHECKING:
    from collections.abc import Iterator


def _chain(workdir: Path) -> Any:
    """Return the audit chain store for *workdir* with the operator HMAC key."""
    from bernstein.core.security.audit import load_or_create_audit_key
    from bernstein.core.security.audit_chain import AuditChainStore

    return AuditChainStore(workdir / ".sdd" / "audit", key=load_or_create_audit_key())


def _warn_if_lock_degraded() -> None:
    """Say plainly when this platform cannot serialise writers across processes.

    The append section degrades to in-process-only ordering on platforms
    without ``fcntl`` (Windows). Degrading silently would let two operator
    shells interleave charter writes with no hint that the serialisation the
    docs promise is not in force here, so the degradation is named instead.
    """
    from bernstein.core.security import audit as audit_module

    if audit_module.fcntl is None:  # pragma: no cover - Windows path
        console.print(
            "[yellow]warning:[/yellow] this platform has no fcntl, so charter writes from "
            "separate processes are not serialised; concurrent writes may be refused "
            "rather than queued"
        )


@contextlib.contextmanager
def _charter_write_section(chain: Any) -> Iterator[None]:
    """Hold the chain's append section for one read-decide-append command.

    Turns the two operating-system failures an operator can actually hit into
    refusals that say what to do, because a raw ``PermissionError`` traceback
    out of a lock file is indistinguishable from a broken tool:

    * a read-only audit directory (the lock sentinel cannot be created), and
    * any other ``OSError`` acquiring or holding the section.
    """
    try:
        with chain.chain_transaction():
            yield
    except PermissionError as exc:
        raise click.ClickException(
            f"the audit directory is not writable ({exc}); charter changes append to the "
            "chain, so run this command where .sdd/audit is writable. Read-only commands "
            "('tenant show', 'tenant verify', 'tenant slice', 'tenant showback') work on "
            "a read-only copy."
        ) from exc
    except OSError as exc:
        raise click.ClickException(f"could not hold the audit chain's append section: {exc}") from exc


def _append_charter_event(chain: Any, event: Any) -> None:
    """Append a minted charter event, turning a refusal into an ``Error:`` line.

    ``record_charter_event`` refuses an event whose declared predecessor is no
    longer the recorded tail. Commands here mint inside the append section, so
    through this CLI the refusal is unreachable; it stays guarded because the
    recording API is public and a refusal must read as a refusal, not as a
    traceback an operator cannot tell from a broken tool.

    The message ``CharterChainError`` carries already names the offending seq
    and says to re-read and mint again, so it is passed through unchanged.
    """
    from bernstein.core.security.tenant_charter import CharterChainError, record_charter_event

    try:
        record_charter_event(chain, event)
    except CharterChainError as exc:
        raise click.ClickException(str(exc)) from exc


def _refuse_unverified_chain(chain: Any, *, tenant_id: str, minting: str) -> None:
    """Refuse to mint an export from a chain state ``audit verify`` rejects.

    A slice or a statement is a claim a second party recomputes. Minting one
    from a chain whose HMAC walk fails would launder the damage: the bundle's
    slice-local chain verifies cleanly even when the history it was cut from
    does not. The refusal names the first error and the command that shows
    the rest.
    """
    chain_ok, chain_errors = chain.verify()
    if chain_ok:
        return
    first = chain_errors[0] if chain_errors else "-"
    raise click.ClickException(
        f"refusing to mint {minting} for {tenant_id!r}: the audit chain does not verify "
        f"({len(chain_errors)} error(s); first: {first}). Run 'bernstein audit verify' and "
        "resolve the damage first."
    )


def _emit(payload: dict[str, Any], *, as_json: bool, lines: list[str]) -> None:
    """Print either machine JSON or the prepared human lines."""
    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    for line in lines:
        console.print(line)


@click.group(name="tenant")
def tenant_group() -> None:
    """Tenant charters: membership, scoped slices, and cost statements.

    \b
    Examples:
      bernstein tenant create acme --principal alice --role owner
      bernstein tenant grant acme --principal bob --role member
      bernstein tenant show acme
      bernstein tenant verify acme
      bernstein tenant slice acme --since 2026-07-01 --until 2026-08-01
      bernstein tenant verify-statement statement.json
    """


@tenant_group.command("create")
@click.argument("tenant_id")
@click.option("--principal", required=True, help="Principal opening the charter (from .sdd/auth/users).")
@click.option("--role", default="owner", show_default=True, help="Role for the opening principal.")
@click.option("--budget-usd", default=None, help="Optional budget envelope, e.g. '250.000000000'.")
@click.option("--workdir", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit machine-readable JSON.")
def create_cmd(tenant_id: str, principal: str, role: str, budget_usd: str | None, workdir: Path, as_json: bool) -> None:
    """Open a charter for TENANT_ID and enrol its first principal."""
    from bernstein.core.security.tenant_charter import (
        CharterChainError,
        fold_charter,
        open_event,
        read_charter_events,
    )

    chain = _chain(workdir)
    _warn_if_lock_degraded()
    # The duplicate guard reads the *whole* history, archived segments
    # included. A live-only read would let anyone open a second charter for an
    # existing tenant once retention archived the opening day - an ownership
    # takeover requiring no forgery, just patience.
    #
    # Guard, mint, and append run inside one cross-process append section.
    # Without it, two processes each reading "no charter exists" and each
    # appending an opening event leave a segment with two events claiming
    # seq 0: both records are individually valid, so the HMAC chain still
    # verifies while the fold is permanently unreadable. Inside the section
    # the second ``create`` reads the winner's opening and is refused.
    # Charter histories are one event per lifecycle change, so the read the
    # section holds is small.
    #
    # The opening is exactly one event, so the section wraps a single append.
    # That is deliberate: the section is exclusion, not atomicity, so a batch
    # interrupted midway would commit the prefix already written. See
    # ``open_event``.
    with _charter_write_section(chain):
        try:
            existing = read_charter_events(chain, tenant_id)
        except CharterChainError as exc:
            raise click.ClickException(
                f"refusing to create {tenant_id!r}: its recorded charter history is unreadable ({exc}). "
                f"Run 'bernstein tenant verify {tenant_id}' before creating anything."
            ) from exc
        if existing:
            raise click.ClickException(f"a charter already exists for tenant {tenant_id!r}")

        try:
            event = open_event(tenant_id=tenant_id, principal=principal, role=role, budget_usd=budget_usd)
            state = fold_charter([event])
        except CharterChainError as exc:
            raise click.ClickException(str(exc)) from exc

        _append_charter_event(chain, event)

    payload = {"charter_hash": state.charter_hash(), "state": state.to_body()}
    _emit(
        payload,
        as_json=as_json,
        lines=[
            f"[green]Charter opened[/green] for [bold]{tenant_id}[/bold]",
            f"  charter hash: {state.charter_hash()}",
            f"  members:      {', '.join(sorted(state.principals))}",
        ],
    )


@tenant_group.command("grant")
@click.argument("tenant_id")
@click.option("--principal", required=True, help="Principal to enrol or re-role.")
@click.option("--role", default="member", show_default=True, help="Role to bind.")
@click.option("--by", "actor", default=None, help="Principal recording the change (defaults to --principal).")
@click.option("--workdir", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit machine-readable JSON.")
def grant_cmd(tenant_id: str, principal: str, role: str, actor: str | None, workdir: Path, as_json: bool) -> None:
    """Enrol PRINCIPAL in TENANT_ID's charter, or change their role."""
    from bernstein.core.security.tenant_charter import (
        CHARTER_MEMBER_ADD,
        CHARTER_ROLE_SET,
        CharterChainError,
        fold_charter,
        next_event,
        read_charter_events,
    )

    chain = _chain(workdir)
    _warn_if_lock_degraded()
    # Read, fold, mint, and append inside one append section: the event is
    # minted against the tail the read observed, and no other writer can move
    # that tail before the append lands. A concurrent charter write from
    # another process waits on the section and then applies to the new tail -
    # serialised, not refused.
    with _charter_write_section(chain):
        try:
            events = read_charter_events(chain, tenant_id)
            if not events:
                raise click.ClickException(f"no charter for tenant {tenant_id!r}; run 'bernstein tenant create' first")
            current = fold_charter(events)
            kind = CHARTER_ROLE_SET if current.is_member(principal) else CHARTER_MEMBER_ADD
            event = next_event(
                events[-1],
                tenant_id=tenant_id,
                kind=kind,
                principal=actor or principal,
                body={"principal": principal, "role": role},
            )
            state = fold_charter([*events, event])
        except CharterChainError as exc:
            raise click.ClickException(str(exc)) from exc

        _append_charter_event(chain, event)

    payload = {"charter_hash": state.charter_hash(), "state": state.to_body()}
    _emit(
        payload,
        as_json=as_json,
        lines=[
            f"[green]{principal}[/green] bound as [bold]{role}[/bold] in {tenant_id}",
            f"  charter hash: {state.charter_hash()}",
        ],
    )


@tenant_group.command("revoke")
@click.argument("tenant_id")
@click.option("--principal", required=True, help="Principal to remove.")
@click.option("--by", "actor", default=None, help="Principal recording the change (defaults to --principal).")
@click.option("--workdir", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit machine-readable JSON.")
def revoke_cmd(tenant_id: str, principal: str, actor: str | None, workdir: Path, as_json: bool) -> None:
    """Remove PRINCIPAL from TENANT_ID's charter."""
    from bernstein.core.security.tenant_charter import (
        CHARTER_MEMBER_REMOVE,
        CharterChainError,
        fold_charter,
        next_event,
        read_charter_events,
    )

    chain = _chain(workdir)
    _warn_if_lock_degraded()
    # Read, mint, and append inside one append section (see ``grant``). A
    # revocation is a decision someone acts on, so the append underneath is
    # durable: it survives a host crash rather than silently reverting.
    with _charter_write_section(chain):
        try:
            events = read_charter_events(chain, tenant_id)
            if not events:
                raise click.ClickException(f"no charter for tenant {tenant_id!r}")
            event = next_event(
                events[-1],
                tenant_id=tenant_id,
                kind=CHARTER_MEMBER_REMOVE,
                principal=actor or principal,
                body={"principal": principal},
            )
            state = fold_charter([*events, event])
        except CharterChainError as exc:
            raise click.ClickException(str(exc)) from exc

        _append_charter_event(chain, event)

    payload = {"charter_hash": state.charter_hash(), "state": state.to_body()}
    _emit(
        payload,
        as_json=as_json,
        lines=[
            f"[yellow]{principal}[/yellow] removed from {tenant_id}",
            f"  charter hash: {state.charter_hash()}",
        ],
    )


@tenant_group.command("show")
@click.argument("tenant_id")
@click.option("--workdir", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit machine-readable JSON.")
def show_cmd(tenant_id: str, workdir: Path, as_json: bool) -> None:
    """Fold and print TENANT_ID's charter state."""
    from bernstein.core.security.tenant_charter import CharterChainError, load_charter

    chain = _chain(workdir)
    # Read-only: takes no lock, so it works on a directory that will not grant
    # one at all - a read-only incident snapshot is exactly where an operator
    # asks what a charter says.
    try:
        state = load_charter(chain, tenant_id)
    except CharterChainError as exc:
        raise click.ClickException(str(exc)) from exc

    payload = {"charter_hash": state.charter_hash(), "state": state.to_body()}
    members = "\n".join(f"    {principal:<24} {role}" for principal, role in state.members) or "    (none)"
    closed_tag = "  [red](closed)[/red]" if state.closed else ""
    quota = state.quota_max_concurrent if state.quota_max_concurrent is not None else "(none)"
    _emit(
        payload,
        as_json=as_json,
        lines=[
            f"[bold]{state.tenant_id}[/bold]  charter v{state.version}{closed_tag}",
            f"  charter hash: {state.charter_hash()}",
            f"  head event:   {state.head_event_hash}",
            f"  budget:       {state.to_body()['budget_usd'] or '(none)'}",
            f"  quota:        {quota}",
            "  members:",
            members,
        ],
    )


@tenant_group.command("verify")
@click.argument("tenant_id")
@click.option("--workdir", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit machine-readable JSON.")
def verify_cmd(tenant_id: str, workdir: Path, as_json: bool) -> None:
    """Verify TENANT_ID's charter chain and report the offending event on failure.

    Exits non-zero when the event segment does not fold: a broken hash link, a
    backdated event, a gap in the sequence, a spliced foreign tenant, or a body
    that cannot be read at all. Every one of those is a FAIL verdict naming the
    offending event - never a traceback, which an operator cannot distinguish
    from a broken tool.
    """
    from bernstein.core.security.tenant_charter import verify_charter

    chain = _chain(workdir)
    # Both reads are lock-free walks of the directory - the same read path
    # 'bernstein audit verify' uses - so this works on a read-only copy.
    # Writers cannot interleave with retention (the archiver publishes its
    # swap-and-unlink under the append section), so the one transient this can
    # observe on a live directory is an archive pass racing the walk; re-run.
    result = verify_charter(chain, tenant_id)
    chain_ok, chain_errors = chain.verify()

    payload = result.to_dict()
    payload["audit_chain_ok"] = chain_ok
    payload["audit_chain_errors"] = chain_errors[:20]

    lines: list[str]
    if result.ok and chain_ok:
        state = result.state
        lines = [
            f"[green]OK[/green] charter {tenant_id} folds cleanly (v{state.version if state else 0})",
            f"  charter hash: {state.charter_hash() if state else '-'}",
        ]
    else:
        lines = [f"[red]FAIL[/red] charter {tenant_id}"]
        if not result.ok:
            lines.append(f"  {result.reason}: {result.detail}")
        if not chain_ok:
            first = chain_errors[0] if chain_errors else "-"
            lines.append(f"  audit chain: {len(chain_errors)} error(s); first: {first}")

    _emit(payload, as_json=as_json, lines=lines)
    if not (result.ok and chain_ok):
        raise SystemExit(1)


@tenant_group.command("slice")
@click.argument("tenant_id")
@click.option("--since", required=True, help="ISO-8601 inclusive lower bound.")
@click.option("--until", required=True, help="ISO-8601 exclusive upper bound.")
@click.option("--out", type=click.Path(file_okay=False, path_type=Path), default=None, help="Output directory.")
@click.option("--workdir", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit machine-readable JSON.")
def slice_cmd(tenant_id: str, since: str, until: str, out: Path | None, workdir: Path, as_json: bool) -> None:
    """Export the audit slice TENANT_ID's charter governs.

    Keyed on charter membership rather than on the free-form tenant id, so an
    event written by a principal the charter never enrolled stays out of the
    bundle. Excluded principals are reported rather than dropped silently.
    """
    from bernstein.core.security.audit import load_or_create_audit_key
    from bernstein.core.security.tenant_charter import CharterChainError, load_charter
    from bernstein.core.security.tenant_charter_slice import export_charter_slice

    chain = _chain(workdir)
    # Read-only (no lock, works on a read-only snapshot), but not
    # unconditional: a slice is a claim a second party recomputes, so it is
    # never minted from a chain state 'bernstein audit verify' rejects.
    _refuse_unverified_chain(chain, tenant_id=tenant_id, minting="an audit slice")
    try:
        state = load_charter(chain, tenant_id)
    except CharterChainError as exc:
        raise click.ClickException(str(exc)) from exc

    result = export_charter_slice(
        workdir / ".sdd" / "audit",
        state,
        since=since,
        until=until,
        key=load_or_create_audit_key(),
        output_dir=out,
    )
    payload = result.to_dict()
    lines = [
        f"[green]Slice written[/green] for {tenant_id}: {result.export.event_count} event(s)",
        f"  charter hash: {result.charter_hash}",
        f"  head sha256:  {result.export.head_sha256}",
        f"  path:         {result.export.bundle_path}",
    ]
    for principal, count in result.excluded_principals:
        lines.append(f"  [yellow]excluded[/yellow] {principal}: {count} event(s) - not a charter member")
    _emit(payload, as_json=as_json, lines=lines)


@tenant_group.command("showback")
@click.argument("tenant_id")
@click.option("--from", "since", required=True, help="ISO-8601 inclusive lower bound.")
@click.option("--to", "until", required=True, help="ISO-8601 exclusive upper bound.")
@click.option("--ledger", type=click.Path(dir_okay=False, path_type=Path), default=None, help="Spend ledger path.")
@click.option("--out", type=click.Path(dir_okay=False, path_type=Path), default=None, help="Write the statement here.")
@click.option("--workdir", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit machine-readable JSON.")
def showback_cmd(
    tenant_id: str,
    since: str,
    until: str,
    ledger: Path | None,
    out: Path | None,
    workdir: Path,
    as_json: bool,
) -> None:
    """Emit TENANT_ID's showback statement for a window.

    A pure projection: the same charter state, ledger window, and chain head
    produce byte-identical output on any machine, so both sides of a billing
    question recompute rather than reconcile.
    """
    from bernstein.core.cost.showback_statement import build_statement, statement_bytes
    from bernstein.core.security.audit import load_or_create_audit_key
    from bernstein.core.security.tenant_charter import CharterChainError, load_charter
    from bernstein.core.security.tenant_charter_slice import export_charter_slice

    chain = _chain(workdir)
    # Read-only (no lock, works on a read-only snapshot), but a statement is a
    # billing claim anchored to the chain head, so it is never minted from a
    # chain state 'bernstein audit verify' rejects.
    _refuse_unverified_chain(chain, tenant_id=tenant_id, minting="a showback statement")
    try:
        state = load_charter(chain, tenant_id)
    except CharterChainError as exc:
        raise click.ClickException(str(exc)) from exc

    sliced = export_charter_slice(
        workdir / ".sdd" / "audit",
        state,
        since=since,
        until=until,
        key=load_or_create_audit_key(),
        write=False,
    )
    items = _ledger_line_items(
        ledger or (workdir / ".sdd" / "cost" / "ledger.jsonl"),
        tenant_id=tenant_id,
        since=since,
        until=until,
    )
    statement = build_statement(
        charter=state,
        line_items=items,
        since=since,
        until=until,
        head_sha256=sliced.export.head_sha256,
    )
    raw = statement_bytes(statement)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(raw)

    if as_json:
        click.echo(raw.decode("utf-8"))
        return
    console.print(f"[bold]{tenant_id}[/bold] showback {since} -> {until}")
    console.print(f"  charter hash:   {state.charter_hash()}")
    console.print(f"  line items:     {statement['totals']['line_item_count']}")
    console.print(f"  total:          {statement['totals']['amount_usd']} USD")
    console.print(f"  statement hash: {statement['statement_hash']}")
    if out is not None:
        console.print(f"  written:        {out}")


@tenant_group.command("verify-statement")
@click.argument("statement_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--head", "expected_head", default=None, help="Shared chain head sha256 to check the anchor against.")
@click.option("--charter-hash", "expected_charter", default=None, help="Charter hash the statement must cite.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit machine-readable JSON.")
def verify_statement_cmd(
    statement_file: Path,
    expected_head: str | None,
    expected_charter: str | None,
    as_json: bool,
) -> None:
    """Verify a showback statement offline.

    Needs the statement file and nothing else - no ledger, no chain, no
    network. Every line item's receipt hash, the item fold, the totals, and
    the statement hash are recomputed, so flipping any single field of any
    line item fails here.
    """
    from bernstein.core.cost.showback_statement import verify_statement

    parsed = json.loads(statement_file.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise click.ClickException(f"{statement_file} does not contain a statement object")
    result = verify_statement(
        parsed,
        expected_head_sha256=expected_head,
        expected_charter_hash=expected_charter,
    )
    lines = (
        [
            f"[green]OK[/green] {result.tenant_id}: {result.line_item_count} line item(s), "
            f"{result.to_dict()['total_usd']} USD",
        ]
        if result.ok
        else [f"[red]FAIL[/red] {result.tenant_id}", *(f"  {err}" for err in result.errors)]
    )
    _emit(result.to_dict(), as_json=as_json, lines=lines)
    if not result.ok:
        raise SystemExit(1)


def _ledger_line_items(ledger_path: Path, *, tenant_id: str, since: str, until: str) -> list[Any]:
    """Read the spend ledger and project the window into showback line items."""
    from bernstein.core.cost.showback_statement import ShowbackLineItem
    from bernstein.core.cost.spend_ledger import LedgerEntry

    if not ledger_path.is_file():
        return []
    items: list[Any] = []
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        entry = LedgerEntry.from_dict(parsed)
        if not (since <= entry.ts_iso < until):
            continue
        tags = entry.tags or {}
        if str(tags.get("tenant_id", "")) != tenant_id:
            continue
        items.append(
            ShowbackLineItem.from_ledger_entry(
                entry,
                tenant_id=tenant_id,
                lineage_record_id=str(tags.get("lineage_record_id", "")),
                audit_entry_hmac=str(tags.get("audit_entry_hmac", "")),
            )
        )
    items.sort(key=lambda item: (item.occurred_at, item.line_id))
    return items
