# Approval cards v2

An approval card is what an operator sees when a gated tool call needs a human
decision. In v2 the card is a **hash-committed decision record**: the whole
decision context is canonicalised, hashed, and appended to the HMAC audit
chain, so a postmortem can prove not just *what* was approved but *what the
approver was told* at decision time.

## What the card carries

Every field below lives inside one hashed envelope (`ApprovalCardV2`):

| Field | Meaning |
|---|---|
| `action` | Tool name plus a canonical SHA-256 digest of its arguments |
| `reasoning` | The agent's stated intent, bounded to a fixed length |
| `impact` | Blast-radius score, `hard_one_way` flag, rationale, and the ids of every detector that fired |
| `rollback` | A per-tool-class undo procedure, with an explicit `irreversible` marker when a one-way-door detector fired |
| `not_after` | The expiry deadline, in unix epoch seconds |

`card_hash` is the SHA-256 over the canonical JSON of the envelope (sorted
keys, compact separators). Because it commits to every field the operator saw,
a decision that echoes `card_hash` commits to exactly what was displayed. A
card that merely displays extra text without hashing it cannot offer that
guarantee.

## The lifecycle

1. **Issue.** The gate builds the envelope, computes `card_hash`, and appends a
   `chat.approval_card.issued` event carrying the full envelope, the hash, and
   the previous chain digest. The event is appended *before* the card becomes
   resolvable, so a failed append leaves no settleable card behind. Drivers
   render the envelope fields **verbatim** (`render_card_text`): every hashed
   field is shown with a round-trippable value, and the canonical JSON envelope
   is printed alongside the hash, so an operator can re-hash exactly what they
   read and confirm it equals the committed record.
2. **Resolve.** A decision must echo the exact `card_hash`. The whole
   check-and-commit runs under one lock, so concurrent decisions on the same
   hash cannot both settle. The gate refuses, recording a
   `chat.approval_card.refused` event, when:

   | Reason | Refused because |
   |---|---|
   | `hash_mismatch` | The echoed hash matches no issued envelope, so some field the operator saw was changed |
   | `already_settled` | The card has already been decided; a card settles exactly once |
   | `invalid_decision` | The decision is not `approve` or `reject` |
   | `expired` | The decision arrived at or after `not_after` |
   | `cross_worktree` | The card was pinned to a different worktree |
   | `cross_conversation` | The card was issued on a different conversation |

   A clean resolve records `chat.approval_card.resolved`.
3. **Verify offline.** `bernstein audit verify` walks the chain in order and,
   for every resolved card, confirms the stored envelope still hashes to its
   recorded `card_hash`, that the decision echoed an envelope issued *earlier
   in the chain*, and that the decision timestamp is finite, positive, and
   inside the envelope's window (`created_at <= resolved_at < not_after`).

## Settling exactly once

A card settles once. The settled set is rebuilt from the chain's `resolved` and
terminally-`refused` events, not from process memory, so a restart does not
reopen a card the chain already shows as decided, and a captured `card_hash` is
a single-use token rather than a reusable one.

Only expiry counts as a terminal refusal. Expiry is monotone: once the chain has
seen a card pass its `not_after`, no later clock reading revives it. The other
refusal reasons describe a rejected *attempt*, not a settled card, and
deliberately leave the card pending. Burning a card on a `cross_worktree` or
`hash_mismatch` refusal would let anyone who can reach the chat surface deny the
operator their pending decision.

## Origin pinning

A card issued into a worktree and a conversation commits to that origin. A
decision arriving from a different worktree or conversation is refused and
chain-recorded rather than honoured, so observing a `card_hash` in one context
does not let it be exercised in another. Each check is skipped when the card
carried no such pin, and the conversation check is skipped when the caller
supplies no conversation, so drivers that cannot attribute one are unaffected.

## Chain-enforced expiry

Expiry is decided by the chain-side clock against the envelope's `not_after`,
never by whatever buttons the chat client still renders. This holds across a
chat-process restart: a fresh process reconstructs the issued envelope from the
audit chain and still refuses a stale approve. The refusal is chain-recorded,
so an operator can prove a late decision was contained and never executed.

## Determinism

Issuing the same pending approval against identical repository state produces
byte-identical envelopes and an identical `card_hash`. The envelope is a pure
projection of its inputs (the tool call, the stated intent, the blast-radius
detectors, and the issue time), so two operators reconstruct the same card.

Timestamps must be finite numbers, and integer timestamps are widened to
floats before hashing. Both rules protect the projection: `NaN` compares false
against everything, so a `NaN` `not_after` would produce a card that never
expires, and `1000` and `1000.0` serialise to different bytes, so the same
instant would otherwise yield two different hashes. Canonical JSON is emitted
with `allow_nan` disabled, so an envelope can never hash over bytes that no
conforming JSON parser reads back.

## Irreversible actions

When a change trips a `hard_one_way` blast-radius detector (schema migration,
secrets write, `rm -rf`, `DROP`/`DELETE` SQL, ...), the card carries
`rollback.irreversible = true` and renders an explicit irreversible marker.
Because the flag is part of the hashed envelope, the marker is cryptographically
committed and cannot be stripped without changing `card_hash`.

## Server-initiated prompts

MCP `elicitation/create` requests that match no auto-resolve policy, and A2A
tasks entering `input-required`, are routed into the same pipeline. The
server-initiated prompt becomes a v2 card on the bound chat thread and inherits
the whole discipline: committed decision context, chain-side expiry, and the
audit trail. For an MCP elicitation the response equals the operator decision,
and the issue and resolve events share `card_hash`, so the answer and the
approval record are chain-linked.

## Related

- Chat bridges (delivery surfaces): `operations/chat-bridges.md`
- Microsoft Teams setup: `integrations/teams-setup.md`
- Audit log and `bernstein audit verify`: `security/audit-log.md`
