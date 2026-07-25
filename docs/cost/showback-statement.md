# Showback statements

When finance asks which team burned the budget, a CSV exported from a mutable
ledger settles nothing: the disputing side has to trust whoever ran the export.
A **showback statement** is the opposite shape — a pure function from a chain
window to canonical bytes, recomputed independently by both sides and compared
byte for byte.

## Shape

```json
{
  "binding":   { "charter_hash": "sha256:…", "charter_version": 4, … },
  "head_anchor": { "head_sha256": "…" },
  "line_items": [ … ],
  "line_items_root": "sha256:…",
  "schema": "tenant-showback-statement-v1",
  "tenant_id": "acme",
  "totals": { "amount_nano_usd": "1484567898", "amount_usd": "1.484567898", "line_item_count": 3 },
  "window": { "since": "2026-07-01", "until": "2026-08-01" },
  "statement_hash": "sha256:…"
}
```

Each line item carries the four links that let a reader resolve it without the
live install:

| Field | Resolves to |
|---|---|
| `line_id` | the ledger row (derived deterministically from its identifying fields) |
| `task_id` | the unit of work |
| `lineage_record_id` | the artefact record |
| `audit_entry_hmac` | the nearest audit-chain entry |

## Three bindings, so any flip is caught

| Binding | Catches |
|---|---|
| `receipt_hash` per item | a changed amount, task id, model, or link |
| `line_items_root` | reordering, insertion, removal — which per-item hashes alone cannot see |
| `statement_hash` | the charter binding, window, totals, and head anchor |

The fold is sequential (`H(prev ‖ receipt_hash)`) rather than a balanced Merkle
tree: order is part of what the statement asserts, so the fold must be
order-sensitive, and a linear fold leaves no tree-shape convention for a second
implementation to get wrong.

A tamperer who edits an amount and recomputes `statement_hash` still trips the
root; one who repairs the root too still trips the totals.

## Money

Amounts never round-trip through a float. The single rounding step happens when
a line item is built from the ledger's float value
(`nano_usd_from_float`, banker's rounding — see
[showback-canonical](showback-canonical.md)); every total is an exact integer
sum. Aggregation order therefore cannot change a digit, and two parties get
identical bytes rather than amounts that agree to within a rounding step.

Inside the payload, amounts travel as string-encoded integers, keeping every raw
JSON number inside the I-JSON safe range. `amount_usd` is a display rendering
and is re-derived on verification, so editing only the pretty field is still
caught.

## Offline verification

```console
$ bernstein tenant showback acme --from 2026-07-01 --to 2026-08-01 --out statement.json
$ bernstein tenant verify-statement statement.json
OK acme: 3 line item(s), 1.484567898 USD
```

`verify-statement` needs the statement file and nothing else — no ledger, no
chain, no network. Two optional equalities check the statement against material
the auditor already holds:

```console
$ bernstein tenant verify-statement statement.json \
    --head <shared chain head sha256> \
    --charter-hash sha256:<charter hash>
```

A failure exits non-zero and lists every disagreement, naming the line item
index and the field:

```console
$ bernstein tenant verify-statement tampered.json
FAIL acme
  line_items[1] (line:…) does not re-derive: a field was altered
  line_items_root is sha256:… but the items fold to sha256:…; an item was reordered, inserted, or removed
  totals.amount_nano_usd is 1484567898 but the line items sum to 999999999999 nano-USD
```

## Determinism

The projection reads no clock, touches no filesystem, and never orders by dict
iteration. Repeated runs over the same charter state, ledger window, and chain
head produce byte-identical output, including in a fresh interpreter with a
different `PYTHONHASHSEED` — which is the property the CI hash comparison rests
on.

## Related

- [Showback canonicalization](showback-canonical.md) — the encoding core
- [Tenant charters](../security/tenant-charters.md) — where the charter binding comes from
