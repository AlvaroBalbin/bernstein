# Run receipt format specification

`core/replay/run_receipt.py` (issue #2924) builds and offline-verifies the
signed run receipt described operationally in
[deterministic replay](../operations/deterministic-replay.md#signed-run-receipt-one-file-offline-verification)
and exposed at [`bernstein verify receipt`](../reference/cli/verify.md#run-receipts).
This page is the normative wire-format spec: a reader with no access to
`src/` should be able to implement a conforming verifier from this document
and the [audit bundle spec](audit-receipt.md) it reuses conventions from, and
check that implementation against the test vectors below.

The reference implementation of everything on this page is
[`tools/verify_run_receipt.py`](https://github.com/sipyourdrink-ltd/bernstein/blob/main/tools/verify_run_receipt.py) -
stdlib plus `cryptography`, no `bernstein` import. `bernstein verify receipt`
recomputes the same way from inside the package; the two are exercised
against the same vectors so neither can drift from this spec unnoticed.

## Canonicalization profile

Every hash and signature in this format is computed over **canonical JSON**:
`json.dumps(obj, sort_keys=True, separators=(",", ":"))`, UTF-8 encoded - keys
sorted, no insignificant whitespace, no trailing newline inside the hashed
bytes. The one exception is the on-disk receipt file itself, which is
canonical JSON followed by a single trailing `\n`; that trailing byte is not
part of anything hashed.

An embedded audit-range event list is canonicalized as **JSONL**: each event
serialized with the same rule, joined with `\n`, plus a final `\n` (empty list
serializes to zero bytes).

## Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Wire-format version, currently `"1.0.0"`. |
| `receipt_type` | string | `"https://bernstein.run/attestations/run-receipt/v1"`. A verifier rejects any other value. |
| `run_id` | string | The attested run. |
| `subject.digest.sha256` | hex string | SHA-256 of the canonical [subject binding](#subject-binding). The signed value. |
| `journal` | object | See [Journal block](#journal-block). |
| `spine` | object | See [Spine block](#spine-block). |
| `signing` | object | See [Signing block](#signing-block). |
| `audit_range` | object, optional | See [Audit-range block](#audit-range-block-opt-in). |

## Journal block

```json
"journal": {
  "head_hash": "<hex>",
  "event_count": 26,
  "events": [ { "event": "run_started", "index": 0, "prev_hash": "", "payload_hash": "<hex>", "event_hash": "<hex>", "...": "..." }, "..." ]
}
```

Each embedded event is the on-disk journal row with only `ts` and
`elapsed_s` removed (wall-clock fields never enter a receipt - a faithful
replay that differs only in timing hashes identically). Every other field
the journal recorded, including the chain fields, stays on the row.

For each row at 0-based array position `i`, with `payload` defined as the row
with `ts`, `elapsed_s`, `index`, `prev_hash`, `payload_hash`, and
`event_hash` removed (the row's own stored `index` is excluded from the
hash - the array position `i` is the value that is hashed):

```
payload_hash = SHA256(canonical_json({**payload, "event": row.event}))
event_hash   = SHA256(canonical_json({
                 "prev_hash": prev_hash_of_row_i,
                 "event_type": row.event,
                 "payload_hash": payload_hash,
                 "index": i,
               }))
```

`prev_hash_of_row_i` is `""` (genesis) for `i == 0`, else the previous row's
`event_hash`. A verifier walks every row from genesis, recomputes both
hashes, and confirms `row.event_hash` and `row.prev_hash` match at every
step; the first mismatch is reported by its 0-based step index. `head_hash`
must equal the last row's `event_hash`, and `event_count` must equal
`len(events)`. An empty `events` array is malformed - a receipt with no
journal rows attests nothing.

## Spine block

```json
"spine": {
  "head_hash": "<hex-or-empty>",
  "entry_count": 0,
  "entries": [ { "v": 1, "prev_hash": "...", "artifact_path": "...", "content_hash": "...", "actor": "...", "step_id": "...", "model": "...", "timestamp": 0, "entry_hash": "..." }, "..." ]
}
```

Every entry carries `v`, `prev_hash`, `artifact_path`, `content_hash`,
`actor`, `step_id`, `model`, `timestamp`, and `entry_hash`; the keyed `hmac`
tag the on-disk spine also carries is stripped (`entry_hash` is plain
SHA-256 over caller-visible fields, so it recomputes without the operator's
HMAC key). `traceparent`, `tracestate`, and `baggage` are carried when
present, omitted otherwise.

```
entry_hash = SHA256(canonical_json({
               "prev_hash": ..., "artifact_path": ..., "content_hash": ...,
               "actor": ..., "step_id": ..., "model": ...,
               "timestamp": ..., ["traceparent": ...,] ["tracestate": ...,] ["baggage": ...,]
             }))
```

A verifier walks every entry from genesis (`""`), confirms `prev_hash` links
and `entry_hash` recompute, and confirms `head_hash` equals the last entry's
`entry_hash` (or `""` for zero entries) and `entry_count` equals
`len(entries)`. An empty spine is valid - not every run produces lineage.

## Audit-range block (opt-in)

```json
"audit_range": {
  "since": "2026-01-01T00:00:00Z",
  "until": "2026-02-01T00:00:00Z",
  "head_hmac": "<hex>",
  "head_sha256": "<hex>",
  "event_count": 3,
  "events": [ "..." ]
}
```

Present only when the receipt was built with `--include-audit-range`. A
verifier recomputes `head_sha256 = SHA256(jsonl(events))` (the canonical
JSONL rule above) and confirms it matches, along with `event_count`.
`head_hmac` is a build-time artifact of the operator's HMAC key and is
**not** re-checked at verify time - no HMAC key is ever needed to verify a
receipt.

## Subject binding

The signed subject is the SHA-256 of the canonical JSON of this block,
rebuilt from **recomputed** heads only - never from a value the receipt
merely asserts:

```json
{
  "journal_event_count": 26,
  "journal_head": "<recomputed journal head>",
  "run_id": "<run_id>",
  "spine_entry_count": 0,
  "spine_head": "<recomputed spine head>",
  "audit_range_head_sha256": "<recomputed audit head>"
}
```

`audit_range_head_sha256` is present only when `audit_range` is embedded (it
is omitted, not set to `null`, when absent - stripping the opt-in block
changes the binding bytes and collapses verification rather than silently
nulling a field). `subject.digest.sha256` must equal this recomputed digest;
any mismatch is tamper, not malformed input, since every other field parsed.

## Signing block

```json
"signing": {
  "alg": "EdDSA",
  "key_id": "<kid>",
  "payload_type": "application/vnd.bernstein.run-receipt+json",
  "public_key_jwk": { "kty": "OKP", "crv": "Ed25519", "x": "<base64url>", "kid": "<kid>" },
  "signature_b64": "<base64>"
}
```

`public_key_jwk` is an RFC 7517 / RFC 8037 OKP Ed25519 JWK (32-byte raw
public key, base64url-encoded without padding in `x`). The signature input
is the [DSSE](https://github.com/secure-systems-lab/dsse) Pre-Authentication
Encoding (PAE) of the subject binding bytes:

```
PAE(payload_type, payload) = "DSSEv1 " + len(payload_type) + " " + payload_type
                              + " " + len(payload) + " " + payload
signature = Ed25519.sign(signing_key, PAE("application/vnd.bernstein.run-receipt+json", binding_bytes))
```

`payload_type` domain-separates this signature from every other DSSE
envelope kind the same Ed25519 key might sign (audit receipts, A2A
messages, ...) - a run-receipt signature cannot be replayed as any other
envelope. Signing is deterministic (RFC 8032), so receipt bytes for a fixed
run and key are byte-identical across independent builds.

## Verdict tiers

What a passing verification *proves* depends on where the verifying key came
from - this is load-bearing, not a cosmetic label:

- **Integrity-only** (default, no pinned key): the signature is checked
  against `signing.public_key_jwk`, the key embedded in the receipt itself
  (trust-on-first-use). A pass proves the file is internally
  self-consistent - every head recomputes and any post-signing mutation is
  caught at a precise step - but not *who* produced it: an attacker
  controlling the whole file could swap in their own key and re-sign.
- **Provenance** (an out-of-band public key is supplied and pinned): the
  embedded JWK must additionally match the pinned key, byte-for-byte on its
  raw 32-byte form. A pass then proves the receipt was signed by that
  specific key.

A pinned key that does **not** match the embedded JWK is tamper, not a
degraded pass - the command never silently falls back to integrity-only.

## Exit-code contract

| Exit code | Condition |
|---|---|
| `0` | Verified. Every head recomputes from the embedded ranges and the signature checks out (either verdict tier). |
| `1` | Malformed input - unreadable file, non-JSON content, or a required field/range missing/wrong-typed. Nothing was tampered; there was nothing coherent enough to check. |
| `2` | Tamper detected - a recomputed value diverged from what the receipt declares, or a pinned key did not match the embedded one. |

`bernstein verify receipt` additionally offers `--require-provenance`, which
turns an integrity-only pass into exit `3` rather than `0` - an operational
convenience layered on top of this contract, not part of the base format.

## Worked example (test vectors)

[`docs/assets/demo-run/run-receipt.json`](../assets/demo-run/run-receipt.json)
is a real receipt from a recorded demo run, paired with
[`run-receipt.pub.pem`](../assets/demo-run/run-receipt.pub.pem), the Ed25519
public key that signed it.
[`run-receipt.tampered.json`](../assets/demo-run/run-receipt.tampered.json)
is the same receipt with one field added to the first journal event after
signing - every embedded row after it is untouched, so the divergence is
localized to step `0`.

```bash
python tools/verify_run_receipt.py \
  --receipt docs/assets/demo-run/run-receipt.json \
  --public-key docs/assets/demo-run/run-receipt.pub.pem
# OVERALL: OK (provenance)  -- exit 0

python tools/verify_run_receipt.py \
  --receipt docs/assets/demo-run/run-receipt.tampered.json \
  --public-key docs/assets/demo-run/run-receipt.pub.pem
# [FAIL] journal - journal step 0: event_hash mismatch
# OVERALL: TAMPER DETECTED  -- exit 2
```

`tests/unit/test_run_receipt_format_vectors.py` runs both invocations in CI
on every push, so this worked example cannot rot into prose that no longer
matches the reference verifier.
