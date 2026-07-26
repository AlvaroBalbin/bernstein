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
open -> member_add -> role_set -> budget_set -> member_remove -> ...
                             |
                             v
                     CharterState (members, roles, quota, budget)
```

| Event kind | Body | Effect on the fold |
|---|---|---|
| `charter.open` | `{principal, role, budget_usd?}` | starts the segment; must be first, must point at the genesis sentinel. Enrols the named principal and sets the budget in the same event; a body without them opens an empty charter |
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

## Opening a charter is one append

`charter.open` carries the first member and the optional budget in its own body,
so `bernstein tenant create` appends exactly one chain record. That is not a
convenience: the chain transaction is exclusion, not atomicity, so a batch of
appends interrupted midway commits the prefix already written and an append-only
log has no rollback. Opening as a batch left a reachable state — an opened
charter with nobody in it — that `tenant verify`, `tenant show` and the
`audit verify` charter pillar all folded as healthy, that nothing could complete
because the tenant id was taken, and that no operator could undo.

A `charter.open` with no `principal` remains valid and opens an empty charter,
so a caller that enrols separately still reads back.

## Backdating breaks verification

There are two independent detectors, and both must be defeated for a rewrite to
go unnoticed:

| Attack | Detector | Failure |
|---|---|---|
| Append an event dated before its predecessor | `next_event` / `fold_charter` monotonicity | `CharterChainError(reason="backdated")` |
| Edit a recorded event's timestamp or body | successor's `prev_event_hash` no longer matches | `CharterChainError(reason="broken_link")` naming the orphaned seq |
| Same, on disk | chain HMAC over `details` | `bernstein audit verify` fails |
| Reorder or delete an event **other than the newest** | `seq` contiguity + hash linkage | `gap` / `broken_link` |
| Delete the newest event(s) | durable charter head pin; see below | `charter_head_behind` conflict |
| Splice a sibling tenant's events in | tenant-id equality across the segment | `tenant_mismatch` |

`bernstein tenant verify <id>` runs both layers and exits non-zero on either,
printing the reason and the offending sequence number.

### The newest event was the blind spot; the head pin closes it

Both fold detectors are internal to the recorded segment: contiguity and hash
linkage compare each event against the one before it. Cutting events off the
*end* leaves a shorter history that is still contiguous and still correctly
linked, so the fold reads it as healthy, one version behind. A revocation
removed that way would read as if it never happened. The Merkle seal cannot
close this on its own: it only binds bytes it already sealed, so a truncation
back to the last seal boundary passes it, and loss of records appended after
the seal used to be adopted by the next ordinary `bernstein audit seal`.

Three layers close it, and they cover different causes:

- **A crash cannot cause it.** Charter events are written durably: `create`,
  `grant` and `revoke` return only once the record is on stable storage, so an
  acknowledged charter change is not in the group of records a host crash drops
  off the tail. See "What an append guarantees against a crash" in
  [audit-log.md](audit-log.md).
- **Host-level tail loss and truncation are caught by the charter head pin.**
  Every charter append also records `(tenant_id, seq, event_hash)` in
  `.sdd/audit/checkpoints/charter-heads.jsonl` - append-only, signed with the
  audit key, predecessor-linked, and fsynced under the same append section as
  the chain record it pins. A history whose fold is behind its pinned head (or
  whose event at the pinned seq no longer matches it) fails the tenant-charter
  pillar of `bernstein audit verify`, fails `tenant verify`, blocks
  `bernstein audit seal`, and blocks `tenant slice` / `tenant showback`. The
  conflict does not depend on a seal ever having been taken and does not clear
  itself; after investigating, acknowledge it with
  `bernstein audit ack-tear --segment charter:<tenant> --offset <pinned seq>
  --reason "..."`. The acknowledgement is a chain record naming the pinned
  head, so it authorises exactly one loss, and the evidence stays recorded.
- **Truncation of already-sealed bytes is caught by the checkpoint pillar**,
  which pins entry counts and byte prefixes at seal time; see
  [audit-log.md](audit-log.md). `bernstein audit verify --hmac-only` consults
  neither seal-derived pillar: run the full verify from the alerting job.

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

Retention publishes under the same append section writers hold. Archiving a
segment is a compress followed by an unlink, and a read landing between the two
sees either that day's events twice or not at all. Neither needs a concurrent
writer, and the second one reads as "no charter exists". The archiver holds the
chain's append section across the pair (per segment, not for the whole
retention pass), so a charter read taken inside the section - which is where
every write command reads - can never straddle that window.

## Concurrent writes

Every command that appends to a charter first reads the recorded history and
decides from it, and two operators running `tenant create` for the same tenant at
the same moment must produce one charter, not two.

Without exclusion both processes observe "no charter exists" and each append an
opening event. Both records are individually well-formed, so the HMAC chain still
verifies while the fold reports a duplicate `seq`, and because the log is
append-only the duplicate cannot be removed. The charter is unreadable
permanently.

So a write command holds the chain's cross-process append section - a blocking
`flock` on `.sdd/audit/.chain.lock`, the same section every chained append in
the deployment takes - across read + decide + append. A second writer waits for
the section rather than racing it, then reads the winner's event and applies to
the new tail. The section is re-entrant for the holding thread and exclusive
against every other thread and process.

The read under the section is bounded. Charter reads cover the full history,
archived segments included, and decompressing the archive under the exclusive
section would stall every audit writer in every process for a duration that
grows with total history size. Write commands therefore read in two phases:
the full-history read runs *before* the section, and inside it only live
segments are re-read and merged onto the pre-read history. The merge is exact,
not heuristic - a competing writer's append lands in the current day's live
segment, and retention never archives the current day, so nothing recorded
between the two phases can be missed.

The append is **durable**: a charter event is a decision someone acts on, so it
is flushed to stable storage before the command returns. An append that only
reached the page cache can be dropped off the tail by a host crash, silently
reverting a revocation while every verifier still reports the chain healthy.

Two outcomes are reported, and the distinction matters:

| Outcome | What you see | What to do |
|---|---|---|
| Another writer opened this charter first | `a charter already exists for tenant 'acme'`, exit 1 | Nothing. This is the same answer you would get running the commands a minute apart. |
| The audit directory is not writable | `Error: the audit directory is not writable ...`, exit 1 | Run the write command where `.sdd/audit` is writable. The read-only commands work in place. |
| An export target is not writable | `Error: cannot write the slice bundle: ... not writable ...`, exit 1 | Pass `--out` pointing at a writable location. Reading stays possible on the read-only copy. |

Do not delete `.sdd/audit/.chain.lock` to "unstick" anything: the lock's
identity is the file's inode, so a fresh file admits a second writer alongside
any current holder. A healthy deployment passes the section between processes
in milliseconds; if a write genuinely hangs, identify the holder
(`lsof .sdd/audit/.chain.lock`) rather than removing the file.

Independently of the section, appending an event whose declared predecessor is
no longer the recorded tail is refused with `stale_predecessor` (`Error:
refusing to append charter event seq N ... Re-read the charter and mint
again.`). The section provides liveness; the precondition provides safety: an
API caller that mints an event outside the section and records it later gets a
deterministic refusal rather than a silently broken charter.

Read-only commands - `tenant show`, `tenant verify`, `tenant slice`,
`tenant showback` - take no lock at all. They work on a read-only copy of the
audit directory (an incident snapshot, a mounted archive), where even opening
the lock sentinel for writing would fail; a genuinely read-only copy has no
concurrent archiver, so the unlocked read is exact there.

`tenant slice` and `tenant showback` refuse to mint an export from a chain
state `bernstein audit verify` reports as damaged, because a bundle whose
slice-local chain verifies cleanly must not launder a source history that does
not. The refusal runs one shared gate over the damage-detecting pillars: the
HMAC walk with its tear model, checkpoint extension of the last signed pin,
the charter head pins, and the exporting tenant's own charter fold. The gate
deliberately does not compare current file hashes against the last Merkle
seal: any legitimate append after a seal changes every file hash, so that
comparison separates "sealed just now" from "sealed a while ago" rather than
damage from health, and the rewrite-of-sealed-bytes case it would catch is
already the checkpoint pillar's prefix check.

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
