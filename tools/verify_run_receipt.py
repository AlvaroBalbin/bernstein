#!/usr/bin/env python3
"""Standalone verifier for a bernstein signed run receipt.

This script has **zero dependencies on the bernstein package**. Its only
third-party import is :mod:`cryptography`, the library an external verifier
already runs to check an Ed25519 signature. Everything else is stdlib.

The point of the strict isolation (mirroring ``tools/verify_audit_dsse.py``
and ``tools/verify_audit_receipt.py``) is that the run-receipt wire format is
documented well enough to reimplement without the bernstein source tree: see
[docs/security/run-receipt-format.md](../docs/security/run-receipt-format.md)
for the field-by-field spec this script follows. Any drift between the two is
caught by ``tests/unit/test_run_receipt_format_vectors.py``, which runs this
script against the committed valid/tampered test vectors.

What it checks, in order:

* ``journal``  - every embedded row's chain hash recomputes from genesis, and
                 the declared ``head_hash`` / ``event_count`` match.
* ``spine``    - every embedded entry's ``entry_hash`` and ``prev_hash`` link
                 recompute without any HMAC key, and the declared
                 ``head_hash`` / ``entry_count`` match.
* ``audit``    - (only when the receipt embeds ``audit_range``) its
                 ``head_sha256`` recomputes from the embedded events.
* ``binding``  - the signed subject digest recomputes from the heads above.
* ``signature``- the Ed25519 signature verifies over the DSSE PAE encoding of
                 the binding, against the embedded JWK (optionally pinned).

Usage::

    python tools/verify_run_receipt.py --receipt /path/to/run-receipt.json \\
        [--public-key /path/to/trusted.pub.pem] [--verbose]

Exit codes:

* 0 - the receipt verifies. A pass is *integrity-only* (the file is
      internally self-consistent) unless ``--public-key`` was supplied and
      matched the embedded key, in which case it is *provenance* (the
      receipt was signed by that specific key).
* 1 - malformed input: unreadable file, or a required field/range missing.
* 2 - tamper detected: a recompute or the signature diverged from what the
      receipt declares, or a ``--public-key`` pin did not match the embedded
      key.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import io

# Wire-format constants re-declared from the bernstein run-receipt module.
# Any drift is caught by tests/unit/test_run_receipt_format_vectors.py.
# DO NOT import from the bernstein package here.
RUN_RECEIPT_TYPE = "https://bernstein.run/attestations/run-receipt/v1"
RUN_RECEIPT_PAYLOAD_TYPE = "application/vnd.bernstein.run-receipt+json"

_WALL_CLOCK_FIELDS = frozenset({"ts", "elapsed_s", "index", "prev_hash", "payload_hash", "event_hash"})
_SPINE_REQUIRED_FIELDS = (
    "v",
    "prev_hash",
    "artifact_path",
    "content_hash",
    "actor",
    "step_id",
    "model",
    "timestamp",
    "entry_hash",
)
_SPINE_OPTIONAL_FIELDS = ("traceparent", "tracestate", "baggage")
_GENESIS = ""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """Outcome of a single verification stage."""

    name: str
    ok: bool
    detail: str = ""


@dataclass
class VerifyResult:
    """Aggregate outcome across every stage that ran."""

    checks: list[CheckResult] = field(default_factory=list)
    status: str = "ok"  # "ok" | "malformed" | "tampered"

    @property
    def ok(self) -> bool:
        """True iff every stage that ran reported success."""
        return self.status == "ok" and all(c.ok for c in self.checks)


# ---------------------------------------------------------------------------
# Canonical primitives - re-implemented from the run-receipt format spec
# ---------------------------------------------------------------------------


def _canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON bytes (sorted keys, compact separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding."""
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _payload_hash(event_type: str, payload: dict[str, Any]) -> str:
    """SHA-256 of the canonical, timing-excluded journal-row payload."""
    projected = {k: v for k, v in payload.items() if k not in _WALL_CLOCK_FIELDS}
    projected["event"] = event_type
    return hashlib.sha256(_canonical_json_bytes(projected)).hexdigest()


def compute_event_hash(*, prev_hash: str, event_type: str, payload_hash: str, index: int) -> str:
    """``event_hash = H(prev_hash, event_type, payload_hash, index)``."""
    preimage = _canonical_json_bytes(
        {"prev_hash": prev_hash, "event_type": event_type, "payload_hash": payload_hash, "index": index},
    )
    return hashlib.sha256(preimage).hexdigest()


def compute_entry_hash(row: dict[str, Any]) -> str:
    """``entry_hash = H(prev_hash, artifact_path, content_hash, actor, step_id, model, timestamp, ...)``."""
    fields: dict[str, Any] = {
        "prev_hash": str(row["prev_hash"]),
        "artifact_path": str(row["artifact_path"]),
        "content_hash": str(row["content_hash"]),
        "actor": str(row["actor"]),
        "step_id": str(row["step_id"]),
        "model": str(row["model"]),
        "timestamp": int(row["timestamp"]),
    }
    for optional in _SPINE_OPTIONAL_FIELDS:
        value = row.get(optional)
        if value is not None:
            fields[optional] = value
    return hashlib.sha256(_canonical_json_bytes(fields)).hexdigest()


def _events_jsonl_bytes(events: list[dict[str, Any]]) -> bytes:
    """Canonical JSONL for an event range (sorted keys, ``\\n`` newlines)."""
    if not events:
        return b""
    parts = [json.dumps(e, sort_keys=True, separators=(",", ":")) for e in events]
    return ("\n".join(parts) + "\n").encode("utf-8")


def _public_key_from_jwk(jwk: dict[str, Any]) -> Any:
    """Decode an OKP/Ed25519 JWK (RFC 8037) into an Ed25519PublicKey."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        msg = f"expected kty=OKP, crv=Ed25519; got kty={jwk.get('kty')!r} crv={jwk.get('crv')!r}"
        raise ValueError(msg)
    x = jwk.get("x")
    if not isinstance(x, str):
        msg = "JWK 'x' missing or not a string"
        raise ValueError(msg)
    raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    if len(raw) != 32:
        msg = f"Ed25519 public key must be 32 bytes (got {len(raw)})"
        raise ValueError(msg)
    return Ed25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# Chain walks
# ---------------------------------------------------------------------------


def walk_journal(events: list[dict[str, Any]]) -> tuple[str, int | None, str]:
    """Recompute the journal chain over embedded rows. Returns (head, divergent_index, error)."""
    prev = _GENESIS
    for i, row in enumerate(events):
        event_type = str(row.get("event", ""))
        payload = {k: v for k, v in row.items() if k not in _WALL_CLOCK_FIELDS}
        expected_payload_hash = _payload_hash(event_type, payload)
        expected_hash = compute_event_hash(
            prev_hash=prev,
            event_type=event_type,
            payload_hash=expected_payload_hash,
            index=i,
        )
        stored_hash = str(row.get("event_hash", ""))
        stored_prev = str(row.get("prev_hash", ""))
        if stored_prev != prev:
            return prev, i, f"journal step {i}: prev_hash break"
        if stored_hash != expected_hash:
            return prev, i, f"journal step {i}: event_hash mismatch"
        prev = stored_hash
    return prev, None, ""


def walk_spine(entries: list[dict[str, Any]]) -> tuple[str, int | None, str]:
    """Recompute the spine chain over embedded entries. Returns (head, divergent_index, error)."""
    prev = _GENESIS
    for i, row in enumerate(entries):
        missing = [f for f in _SPINE_REQUIRED_FIELDS if f not in row]
        if missing:
            return prev, i, f"spine entry {i}: missing fields {sorted(missing)}"
        if str(row["prev_hash"]) != prev:
            return prev, i, f"spine entry {i}: prev_hash break"
        try:
            expected = compute_entry_hash(row)
        except (TypeError, ValueError):
            return prev, i, f"spine entry {i}: unhashable field types"
        if str(row["entry_hash"]) != expected:
            return prev, i, f"spine entry {i}: entry_hash mismatch"
        prev = str(row["entry_hash"])
    return prev, None, ""


def _binding_block(
    *,
    run_id: str,
    journal_head: str,
    journal_count: int,
    spine_head: str,
    spine_count: int,
    audit_head_sha256: str | None,
) -> dict[str, Any]:
    """The subject binding: one canonical block over every recomputed head."""
    block: dict[str, Any] = {
        "journal_event_count": journal_count,
        "journal_head": journal_head,
        "run_id": run_id,
        "spine_entry_count": spine_count,
        "spine_head": spine_head,
    }
    if audit_head_sha256 is not None:
        block["audit_range_head_sha256"] = audit_head_sha256
    return block


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def run_verify(
    *,
    receipt_path: Path,
    pinned_pem: bytes | None,
    verbose: bool,
    stream: io.TextIOBase,
) -> tuple[VerifyResult, str | None]:
    """Run every stage and emit human-readable output.

    Returns ``(result, tier)`` where ``tier`` is ``"provenance"`` when a pin
    was supplied and matched, ``"integrity-only"`` on an unpinned pass, or
    ``None`` when verification did not pass.
    """
    result = VerifyResult()

    def _emit(check: CheckResult) -> None:
        result.checks.append(check)
        status = "PASS" if check.ok else "FAIL"
        line = f"[{status}] {check.name}"
        if check.detail and (not check.ok or verbose):
            line += f" - {check.detail}"
        print(line, file=stream)

    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        result.status = "malformed"
        _emit(CheckResult("receipt_load", ok=False, detail=str(exc)))
        print("OVERALL: MALFORMED", file=stream)
        return result, None
    if not isinstance(receipt, dict):
        result.status = "malformed"
        _emit(CheckResult("receipt_load", ok=False, detail="receipt is not a JSON object"))
        print("OVERALL: MALFORMED", file=stream)
        return result, None

    run_id = str(receipt.get("run_id", ""))
    journal_block = receipt.get("journal")
    spine_block = receipt.get("spine")
    signing = receipt.get("signing")
    if (
        not run_id
        or receipt.get("receipt_type") != RUN_RECEIPT_TYPE
        or not isinstance(journal_block, dict)
        or not isinstance(journal_block.get("events"), list)
        or not isinstance(spine_block, dict)
        or not isinstance(spine_block.get("entries"), list)
        or not isinstance(signing, dict)
        or signing.get("payload_type") != RUN_RECEIPT_PAYLOAD_TYPE
    ):
        result.status = "malformed"
        _emit(CheckResult("structure", ok=False, detail="missing run_id/receipt_type/journal/spine/signing fields"))
        print("OVERALL: MALFORMED", file=stream)
        return result, None

    events: list[dict[str, Any]] = journal_block["events"]
    entries: list[dict[str, Any]] = spine_block["entries"]
    if not events or not all(isinstance(e, dict) for e in events):
        result.status = "malformed"
        _emit(CheckResult("structure", ok=False, detail="journal.events is empty or contains a non-object row"))
        print("OVERALL: MALFORMED", file=stream)
        return result, None
    if not all(isinstance(e, dict) for e in entries):
        result.status = "malformed"
        _emit(CheckResult("structure", ok=False, detail="spine.entries contains a non-object row"))
        print("OVERALL: MALFORMED", file=stream)
        return result, None

    journal_head, journal_divergent, journal_error = walk_journal(events)
    if journal_divergent is not None:
        result.status = "tampered"
        _emit(CheckResult("journal", ok=False, detail=journal_error))
    elif journal_head != str(journal_block.get("head_hash", "")) or journal_block.get("event_count") != len(events):
        result.status = "tampered"
        _emit(
            CheckResult("journal", ok=False, detail="declared head_hash/event_count does not match the embedded rows")
        )
    else:
        _emit(CheckResult("journal", ok=True, detail=f"{len(events)} events, head={journal_head[:16]}…"))

    spine_head, spine_divergent, spine_error = walk_spine(entries)
    if spine_divergent is not None:
        result.status = "tampered"
        _emit(CheckResult("spine", ok=False, detail=spine_error))
    elif spine_head != str(spine_block.get("head_hash", "")) or spine_block.get("entry_count") != len(entries):
        result.status = "tampered"
        _emit(
            CheckResult("spine", ok=False, detail="declared head_hash/entry_count does not match the embedded entries")
        )
    else:
        _emit(CheckResult("spine", ok=True, detail=f"{len(entries)} entries, head={spine_head[:16]}…"))

    audit_head: str | None = None
    audit_block = receipt.get("audit_range")
    if audit_block is not None:
        if not isinstance(audit_block, dict) or not isinstance(audit_block.get("events"), list):
            result.status = "malformed"
            _emit(CheckResult("audit", ok=False, detail="audit_range.events missing or not a list"))
            print("OVERALL: MALFORMED", file=stream)
            return result, None
        audit_events: list[dict[str, Any]] = audit_block["events"]
        recomputed_audit_head = hashlib.sha256(_events_jsonl_bytes(audit_events)).hexdigest()
        if recomputed_audit_head != str(audit_block.get("head_sha256", "")) or audit_block.get("event_count") != len(
            audit_events
        ):
            result.status = "tampered"
            _emit(
                CheckResult(
                    "audit", ok=False, detail="declared head_sha256/event_count does not match the embedded events"
                )
            )
        else:
            audit_head = recomputed_audit_head
            _emit(CheckResult("audit", ok=True, detail=f"{len(audit_events)} events, head={audit_head[:16]}…"))

    if result.status != "ok":
        print("OVERALL: TAMPER DETECTED", file=stream)
        return result, None

    binding = _binding_block(
        run_id=run_id,
        journal_head=journal_head,
        journal_count=len(events),
        spine_head=spine_head,
        spine_count=len(entries),
        audit_head_sha256=audit_head,
    )
    binding_bytes = _canonical_json_bytes(binding)
    recomputed_subject = hashlib.sha256(binding_bytes).hexdigest()
    stated_subject = str(((receipt.get("subject") or {}).get("digest") or {}).get("sha256", ""))
    if stated_subject != recomputed_subject:
        result.status = "tampered"
        _emit(
            CheckResult(
                "binding",
                ok=False,
                detail="signed subject does not match the digest recomputed from the embedded ranges",
            )
        )
        print("OVERALL: TAMPER DETECTED", file=stream)
        return result, None
    _emit(CheckResult("binding", ok=True, detail=f"subject={recomputed_subject[:16]}…"))

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    jwk = signing.get("public_key_jwk")
    if not isinstance(jwk, dict):
        result.status = "malformed"
        _emit(CheckResult("signature", ok=False, detail="signing.public_key_jwk missing or not an object"))
        print("OVERALL: MALFORMED", file=stream)
        return result, None
    try:
        public_key = _public_key_from_jwk(jwk)
    except ValueError as exc:
        result.status = "malformed"
        _emit(CheckResult("signature", ok=False, detail=f"embedded JWK is not a usable Ed25519 key: {exc}"))
        print("OVERALL: MALFORMED", file=stream)
        return result, None

    tier = "integrity-only"
    if pinned_pem is not None:
        pinned = serialization.load_pem_public_key(pinned_pem)
        if not isinstance(pinned, Ed25519PublicKey):
            result.status = "malformed"
            _emit(
                CheckResult(
                    "signature", ok=False, detail=f"pinned --public-key is not Ed25519 (got {type(pinned).__name__})"
                )
            )
            print("OVERALL: MALFORMED", file=stream)
            return result, None
        raw_pin = pinned.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        raw_emb = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if raw_pin != raw_emb:
            result.status = "tampered"
            _emit(
                CheckResult("signature", ok=False, detail="embedded receipt key does not match the pinned --public-key")
            )
            print("OVERALL: TAMPER DETECTED", file=stream)
            return result, None
        tier = "provenance"

    sig_b64 = signing.get("signature_b64")
    if not isinstance(sig_b64, str):
        result.status = "malformed"
        _emit(CheckResult("signature", ok=False, detail="signing.signature_b64 missing"))
        print("OVERALL: MALFORMED", file=stream)
        return result, None
    try:
        signature = base64.b64decode(sig_b64, validate=True)
        public_key.verify(signature, pae(RUN_RECEIPT_PAYLOAD_TYPE, binding_bytes))
    except (InvalidSignature, ValueError):
        result.status = "tampered"
        _emit(
            CheckResult(
                "signature", ok=False, detail="Ed25519 signature does not verify over the recomputed subject binding"
            )
        )
        print("OVERALL: TAMPER DETECTED", file=stream)
        return result, None

    _emit(CheckResult("signature", ok=True, detail=f"verified ({tier})"))
    print(f"OVERALL: OK ({tier})", file=stream)
    return result, tier


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Verify a bernstein run receipt without importing the bernstein package.",
    )
    parser.add_argument("--receipt", required=True, type=Path, help="Path to the run receipt JSON.")
    parser.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help="Optional trusted Ed25519 public key PEM to pin; embedded key must match (provenance tier).",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Print PASS-line details.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 verified, 1 malformed, 2 tamper detected."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.receipt.is_file():
        print(f"ERROR: not a file: {args.receipt}", file=sys.stderr)
        return 1

    pinned_pem: bytes | None = None
    if args.public_key is not None:
        if not args.public_key.is_file():
            print(f"ERROR: not a file: {args.public_key}", file=sys.stderr)
            return 1
        pinned_pem = args.public_key.read_bytes()

    result, _tier = run_verify(
        receipt_path=args.receipt,
        pinned_pem=pinned_pem,
        verbose=args.verbose,
        stream=sys.stdout,
    )
    if result.ok:
        return 0
    return 1 if result.status == "malformed" else 2


if __name__ == "__main__":
    sys.exit(main())
