# Tenant charters

An install that serves more than one group of humans used to have exactly one
authority level: everyone who could reach the fleet was root on the fleet.
`tenant_id` was a free-form string any caller could set, and no governed record
said who belonged to it, so a per-tenant audit slice and a per-team cost number
both rested on a mutable field.

A **charter** replaces that field with a chain object.

## The charter is a fold, not a config file

Current charter state is the deterministic fold of an append-only sequence of
charter events on the HMAC audit chain:

```text
open -> member_add -> member_add -> budget_set -> member_remove -> ...
                                |
                                v
                        CharterState (members, roles, quota, budget)
```

| Event kind | Body | Effect on the fold |
|---|---|---|
| `charter.open` | – | starts the segment; must be first, must point at the genesis sentinel |
| `charter.member_add` | `{principal, role}` | enrols a principal (duplicate enrolment is refused) |
| `charter.role_set` | `{principal, role}` | rebinds an existing member's role |
| `charter.member_remove` | `{principal}` | removes a member (removing a non-member is refused) |
| `charter.quota_set` | `{max_concurrent_tasks}` | sets the scheduler quota |
| `charter.budget_set` | `{budget_usd}` | sets the budget envelope (parsed to integer nano-USD) |
| `charter.close` | – | closes the charter; any later event is refused |

Every event is stored inside the chain event's `details`, so it is covered by
the chain HMAC, and every event additionally carries `prev_event_hash` — the
charter's own Merkle linkage inside the chain.

The folded state's `charter_hash` is the SHA-256 of its RFC 8785 canonical
bytes, taken through the shipped canonical core
([showback-canonical](../cost/showback-canonical.md)), which rejects floats and
non-NFC text rather than repairing them. Two verifiers holding the same event
segment therefore reach the same hash on any machine.

The hash covers `head_event_hash`, so "which charter was in force" names one
exact history rather than one membership snapshot. Two different histories that
happen to reach the same member list are still two charters.

## Backdating breaks verification

There are two independent detectors, and both must be defeated for a rewrite to
go unnoticed:

| Attack | Detector | Failure |
|---|---|---|
| Append an event dated before its predecessor | `next_event` / `fold_charter` monotonicity | `CharterChainError(reason="backdated")` |
| Edit a recorded event's timestamp or body | successor's `prev_event_hash` no longer matches | `CharterChainError(reason="broken_link")` naming the orphaned seq |
| Same, on disk | chain HMAC over `details` | `bernstein audit verify` fails |
| Reorder or delete an event | `seq` contiguity + hash linkage | `gap` / `broken_link` |
| Splice a sibling tenant's events in | tenant-id equality across the segment | `tenant_mismatch` |

`bernstein tenant verify <id>` runs both layers and exits non-zero on either,
printing the reason and the offending sequence number.

A recorded body that cannot be interpreted at all — a rewritten `budget_usd`,
quota, principal, or role — is reported as `malformed_body` (or
`malformed_event` when the damage is to the event envelope). It is deliberately
a FAIL verdict rather than a raised `MoneyFormatError` or `NonCanonicalTextError`:
the verifier for a tamper-detection feature must report tampering, and an
operator cannot distinguish a traceback from a broken tool.

## Retention

Charter reads include archived segments (`include_archived=True`), and this is a
correctness requirement rather than a tuning choice. A charter is a linkage
structure whose opening event is by definition the oldest, so it is the first
thing ordinary retention compresses into `archive/`.

A live-only read would mean that once the opening day aged out:

- `tenant show` / `verify` report the charter as non-existent,
- `grant` / `revoke` / `slice` / `showback` break permanently, and
- **`tenant create` for the same tenant succeeds** — an ownership takeover of an
  existing tenant achieved by waiting for retention, with no forgery and no
  chain break.

The duplicate-charter guard therefore reads the full history too. Duty refusals
are read the same way: a refusal is evidence, and evidence that disappears when
retention runs is not evidence.

One boundary remains: `tenant slice`'s *event window* comes from the shipped v2
exporter, which reads live segments only. The charter (and therefore the
membership key) resolves against full history, but a window reaching past the
retention boundary yields fewer events than expected. Cut slices inside the
retention window until that exporter is widened.

Retention publishes inside the chain transaction described below. Archiving a
segment is a compress followed by an unlink, and a read landing between the two
sees either that day's events twice or not at all. Neither needs a concurrent
writer, and the second one reads as "no charter exists". Only the publish - the
rename and the unlink - is held under the transaction; the compress itself runs
outside it, because its cost grows with the retention window and no exclusive
lock may be held for that long.

## Concurrent writes

Every command that appends to a charter first reads the recorded history and
decides from it. That read and the append run inside one cross-process
transaction, so two operators running `tenant create` for the same tenant at the
same moment produce one charter, not two.

Without it both processes observe "no charter exists" and each append an opening
event. Both records are individually well-formed, so the HMAC chain still
verifies while the fold reports a duplicate `seq`, and because the log is
append-only the duplicate cannot be removed. The charter is unreadable
permanently.

Two outcomes are reported differently, and the distinction matters:

| Outcome | What you see | What to do |
|---|---|---|
| Another writer got there first | `a charter already exists for tenant 'acme'`, exit 1 | Nothing. This is the same answer you would get running the commands a minute apart. |
| The transaction could not be acquired | `Error: could not acquire the audit chain transaction on ...`, exit 1 | Investigate. Something is holding the lock, commonly a process that forked without `exec` and was then killed, leaving the duplicated descriptor alive. |

Identify the holder (`lsof .sdd/audit/.chain.lock`) rather than deleting the
lock file. The lock's identity is the file's inode, so a fresh one admits a
second writer alongside the current holder.

Independently of the lock, appending an event whose declared predecessor is no
longer the recorded tail is refused with `stale_predecessor`. A caller that
bypasses the transaction gets a deterministic refusal rather than a silently
broken charter.

## Certificates: what a run may do

A charter says who belongs to a tenant. A **tenant certificate** says what a run
working for that tenant may do. It is minted from a folded charter state and
carries that charter's hash, so authority and membership are one record:
changing the membership mints a new certificate rather than quietly
reinterpreting the old one.

```python
from bernstein.core.security.tenant_certificate import authorize_duty, mint_certificate

cert = mint_certificate(charter, version="1", duties=frozenset({"spawn"}))
refusal = authorize_duty(
    cert, charter, principal="bob", duty="approve", resource_id="gate-9", spawned_by="bob"
)
```

`authorize_duty` returns `None` on a grant and a `DutyRefusal` otherwise. The
refusal names the certificate hash, the charter hash in force at decision time,
and the missing scope. Checks run in a fixed order so the reported reason is
deterministic:

| Reason | Meaning |
|---|---|
| `charter_drift` | the certificate cites a charter version that is no longer in force |
| `charter_closed` | the charter has been closed |
| `principal_not_a_member` | the principal is not enrolled |
| `certificate_expired` | past `not_after` |
| `duty_not_granted` | the certificate's scope does not carry the duty at all |
| `self_approval` | the duty is granted, but the principal is the one that spawned the resource |

The last two are deliberately distinct. A run holding a **spawn-only**
certificate that tries to approve a gate lands on `duty_not_granted`. A run
holding a spawn-and-approve certificate that tries to approve work it spawned
lands on `self_approval` — a chain can narrow perfectly and still let one worker
bless its own work, so separation of duties is its own check, not a scope axis.

Refusals are written to the chain as `tenant.duty_refusal`, so a denial leaves
evidence rather than a gap. `require_duty(..., chain=chain)` records and raises
in one step.

## Charter-keyed audit slices

`bernstein tenant slice` reuses the existing v2 multi-tenant export (see
[Multi-tenant audit export](audit-multitenant.md)) and contributes the
membership key: an event must claim the charter's tenant id **and** be
attributed to a principal the charter enrolled. Attribution reads
`details.principal`, falling back to `actor`.

An event that merely claims a tenant id, written by a principal the charter
never enrolled, is excluded — a forged string cannot inject rows into someone
else's slice. Excluded principals are reported with their event counts rather
than dropped silently, so a mis-enrolled service identity surfaces as a warning
instead of a short slice.

Service identities that act for a tenant must be enrolled like any other
principal. There is no implicit allowlist.

## Commands

| Command | Purpose |
|---|---|
| `bernstein tenant create <id> --principal <p>` | Open a charter and enrol its first principal |
| `bernstein tenant grant <id> --principal <p> --role <r>` | Enrol a principal, or rebind an existing member's role |
| `bernstein tenant revoke <id> --principal <p>` | Remove a member |
| `bernstein tenant show <id>` | Fold and print the charter state plus its hash |
| `bernstein tenant verify <id>` | Verify the charter chain and the surrounding HMAC chain |
| `bernstein tenant slice <id> --since --until` | Export the charter-keyed audit slice |
| `bernstein tenant showback <id> --from --to` | Emit the showback statement |
| `bernstein tenant verify-statement <file>` | Verify a statement offline |

The verb is `tenant` because `team` is taken by agent role manifests and
`workspace` by multi-repo management.

`bernstein audit verify` folds every recorded charter as one of its integrity
pillars, so a broken charter fails the top-level verifier rather than passing
it. That check is orthogonal to `--hmac-only` and `--merkle-only` and runs
regardless of either: the HMAC verdict answers whether the bytes are authentic,
which is not the same question as whether the history they record is
consistent. A fold failure keeps its own reason (`gap`, `bad_seq`,
`stale_predecessor`, `malformed_body`, ...) rather than being reported as a
chain error, because the two have different causes and different remedies:
altered bytes on one side, an inconsistent history of authentic records on the
other.

## Related

- [Showback statements](../cost/showback-statement.md) — the cost projection
- [Showback canonicalization](../cost/showback-canonical.md) — the encoding core
- [Multi-tenant audit export](audit-multitenant.md) — the slice bundle format
- [Delegation narrowing](delegation-narrowing.md) — per-hop authority recomputation
