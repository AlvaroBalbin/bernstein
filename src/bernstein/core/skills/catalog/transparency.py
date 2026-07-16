"""Merkle transparency log for skill catalog states (issue #2527).

The signed skills catalog already verifies an entry's Ed25519 signature at
install, pins the manifest digest in ``skills.lock``, and emits HMAC-chained
audit events. That defends the *bytes an install happened to receive*; it does
not defend against a publisher (or an attacker holding the signing key) that
serves different signed catalog contents to different installs, or that
rewrites a published state after the fact.

This module makes the catalog's history append-only. Each published catalog
state is a leaf over its canonical bytes; the leaves form an RFC-6962 Merkle
tree whose head (``tree_size``, ``root_hash``) is signed with the install's
existing Ed25519 identity. An install then verifies:

* an **inclusion proof** that the fetched state is a leaf under the signed
  head (so the receipt itself proves *what* was installed), and
* a **consistency proof** that the signed head extends the last head the
  install recorded in ``skills.lock`` (so a rewrite of an already-recorded
  state -- a split view -- is detected, which signature checking alone cannot
  do).

Killer shape: the signed head *is* the catalog's identity. Strip the Merkle
chain and the inclusion/consistency proofs and the receipt verifies nothing --
the feature collapses to a plain registry. The proofs are the artefact.

The hashing is RFC-6962: leaves are domain-separated with a ``0x00`` tag and
internal nodes with a ``0x01`` tag, so a leaf digest can never be reinterpreted
as an internal-node digest (second-preimage hardening). The Merkle-Tree-Hash,
audit path, and consistency proof follow RFC-6962 sections 2.1.1 and 2.1.2
verbatim, so two independent builders given the same sequence of states compute
byte-identical heads.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bernstein.core.skills.catalog.signature import (
    sign_payload,
    verify_payload,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

__all__ = [
    "GENESIS_ROOT",
    "CatalogLogView",
    "InclusionReceipt",
    "SignedTreeHead",
    "TransparencyLog",
    "TransparencyVerificationError",
    "build_catalog_envelope",
    "build_inclusion_receipt",
    "canonical_state_bytes",
    "leaf_hash_for_state",
    "parse_catalog_envelope",
    "sign_tree_head",
    "sth_canonical_bytes",
    "verify_consistency",
    "verify_inclusion",
    "verify_tree_head",
]

#: Domain-separation tags (RFC-6962). A leaf and an internal node can never
#: collide because their pre-images start with disjoint one-byte tags.
_LEAF_TAG = b"\x00"
_INTERNAL_TAG = b"\x01"

#: Merkle-Tree-Hash of the empty log (RFC-6962: ``MTH({}) = SHA-256()``).
GENESIS_ROOT = hashlib.sha256(b"").hexdigest()


class TransparencyVerificationError(RuntimeError):
    """Raised when an inclusion or consistency proof fails to verify.

    The message names the specific failure (leaf mismatch, root mismatch,
    malformed proof) so a refusal receipt records *why* an install was
    refused, not merely that it was.
    """


# ---------------------------------------------------------------------------
# Hash primitives (RFC-6962)
# ---------------------------------------------------------------------------


def _leaf_hash(data: bytes) -> str:
    """Return ``H(0x00 || data)`` -- the Merkle leaf digest of *data*."""
    return hashlib.sha256(_LEAF_TAG + data).hexdigest()


def _node_hash(left: str, right: str) -> str:
    """Return ``H(0x01 || left || right)`` for two hex child digests.

    The children are decoded from hex to their raw 32-byte form so the
    concatenation is fixed-width and unambiguous.
    """
    return hashlib.sha256(_INTERNAL_TAG + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def _largest_power_of_two_below(n: int) -> int:
    """Return the largest power of two strictly less than *n* (``n >= 2``)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def _mth(leaves: Sequence[str]) -> str:
    """Merkle-Tree-Hash over a sequence of leaf digests (RFC-6962 2.1.1)."""
    n = len(leaves)
    if n == 0:
        return GENESIS_ROOT
    if n == 1:
        return leaves[0]
    k = _largest_power_of_two_below(n)
    return _node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def _inclusion_path(m: int, leaves: Sequence[str]) -> list[str]:
    """RFC-6962 ``PATH(m, D[n])`` -- the audit path for leaf ``m``."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _largest_power_of_two_below(n)
    if m < k:
        return [*_inclusion_path(m, leaves[:k]), _mth(leaves[k:])]
    return [*_inclusion_path(m - k, leaves[k:]), _mth(leaves[:k])]


def _consistency_subproof(m: int, leaves: Sequence[str], b: bool) -> list[str]:
    """RFC-6962 ``SUBPROOF(m, D[n], b)`` -- the consistency sub-proof."""
    n = len(leaves)
    if m == n:
        if b:
            return []
        return [_mth(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return [*_consistency_subproof(m, leaves[:k], b), _mth(leaves[k:])]
    return [*_consistency_subproof(m - k, leaves[k:], False), _mth(leaves[:k])]


def _consistency_path(m: int, leaves: Sequence[str]) -> list[str]:
    """RFC-6962 ``PROOF(m, D[n])`` -- consistency proof for old size ``m``."""
    if m <= 0 or m > len(leaves):
        raise TransparencyVerificationError(
            f"consistency proof requires 0 < old_size <= new_size (got old={m}, new={len(leaves)})",
        )
    if m == len(leaves):
        return []
    return _consistency_subproof(m, leaves, True)


# ---------------------------------------------------------------------------
# Canonical state bytes + leaf
# ---------------------------------------------------------------------------


def canonical_state_bytes(state: dict[str, Any]) -> bytes:
    """Return the canonical byte encoding of a catalog *state*.

    The state is the catalog payload without any transparency or revocation
    envelope (those are metadata *about* the state, not part of it): passing
    :meth:`bernstein.core.skills.catalog.manifest.SkillCatalog.to_dict` output
    yields the leaf pre-image, so the leaf is stable across re-serialisation.
    """
    return json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")


def leaf_hash_for_state(state: dict[str, Any]) -> str:
    """Return the Merkle leaf digest for a catalog *state* dict."""
    return _leaf_hash(canonical_state_bytes(state))


# ---------------------------------------------------------------------------
# Signed tree head
# ---------------------------------------------------------------------------


def sth_canonical_bytes(tree_size: int, root_hash: str) -> bytes:
    """Return the canonical bytes signed for a Signed-Tree-Head."""
    return json.dumps(
        {"root_hash": root_hash, "tree_size": tree_size},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class SignedTreeHead:
    """A catalog log head (``tree_size``, ``root_hash``) plus its signature.

    The signature is a detached Ed25519 signature over
    :func:`sth_canonical_bytes`, produced with the install's existing signing
    identity. A head without a verifying signature proves nothing.
    """

    tree_size: int
    root_hash: str
    signature: str

    def canonical_bytes(self) -> bytes:
        """Return the signed pre-image for this head."""
        return sth_canonical_bytes(self.tree_size, self.root_hash)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the wire format."""
        return {
            "tree_size": self.tree_size,
            "root_hash": self.root_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SignedTreeHead:
        """Parse a signed head from an untrusted dict.

        Raises:
            TransparencyVerificationError: If any field is missing or the
                wrong type.
        """
        if not isinstance(raw, dict):
            raise TransparencyVerificationError(
                f"signed head must be an object, got {type(raw).__name__}",
            )
        size = raw.get("tree_size")
        root = raw.get("root_hash")
        sig = raw.get("signature")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise TransparencyVerificationError("signed head tree_size must be a non-negative integer")
        if not isinstance(root, str) or not root:
            raise TransparencyVerificationError("signed head root_hash must be a non-empty string")
        if not isinstance(sig, str) or not sig:
            raise TransparencyVerificationError("signed head signature must be a non-empty string")
        return cls(tree_size=size, root_hash=root, signature=sig)


def sign_tree_head(tree_size: int, root_hash: str, private_key_pem: str) -> SignedTreeHead:
    """Sign a log head with an Ed25519 private key."""
    signature = sign_payload(sth_canonical_bytes(tree_size, root_hash), private_key_pem)
    return SignedTreeHead(tree_size=tree_size, root_hash=root_hash, signature=signature)


def verify_tree_head(head: SignedTreeHead, public_key_pem: str | None) -> bool:
    """Return True iff *head*'s signature verifies against *public_key_pem*."""
    outcome = verify_payload(
        head.canonical_bytes(),
        head.signature,
        public_key_pem,
        allow_unverified=True,
    )
    return outcome.verified


# ---------------------------------------------------------------------------
# Inclusion / consistency verification (stateless, offline)
# ---------------------------------------------------------------------------


def verify_inclusion(
    *,
    leaf_hash: str,
    leaf_index: int,
    tree_size: int,
    proof: Sequence[str],
    root_hash: str,
) -> bool:
    """Verify an RFC-6962 inclusion proof, returning True on success.

    Reconstructs the tree root from *leaf_hash* at *leaf_index* within a tree
    of *tree_size* leaves using *proof*, and compares it to *root_hash*. Any
    structural inconsistency (index out of range, wrong proof length) returns
    False rather than raising, so a caller can turn it into a refusal.
    """
    if leaf_index < 0 or tree_size <= 0 or leaf_index >= tree_size:
        return False
    if tree_size == 1:
        return len(proof) == 0 and leaf_hash == root_hash

    fn = leaf_index
    sn = tree_size - 1
    node = leaf_hash
    idx = 0
    proof = list(proof)
    while sn > 0:
        if idx >= len(proof):
            return False
        if fn & 1 or fn == sn:
            node = _node_hash(proof[idx], node)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            node = _node_hash(node, proof[idx])
        idx += 1
        fn >>= 1
        sn >>= 1
    return idx == len(proof) and node == root_hash


def verify_consistency(
    *,
    old_size: int,
    old_root: str,
    new_size: int,
    new_root: str,
    proof: Sequence[str],
) -> bool:
    """Verify an RFC-6962 consistency proof, returning True on success.

    Proves that a log of *new_size* leaves with root *new_root* is an
    append-only extension of the earlier log of *old_size* leaves with root
    *old_root*. A rewrite of any already-committed leaf breaks this proof --
    that is the split-view / catalog-rewrite detection signature checking
    alone cannot provide.
    """
    if old_size < 0 or new_size < old_size:
        return False
    if old_size == 0:
        # Everything is consistent with the empty tree.
        return True
    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root

    proof = list(proof)
    # RFC-6962 6.2.  If old_size is an exact power of two the proof omits the
    # old root; prepend it so the two algorithms share one loop.
    if _is_power_of_two(old_size):
        proof = [old_root, *proof]

    if not proof:
        return False

    fn = old_size - 1
    sn = new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = proof[0]
    sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _node_hash(c, fr)
            sr = _node_hash(c, sr)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    return sn == 0 and fr == old_root and sr == new_root


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


# ---------------------------------------------------------------------------
# Inclusion receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InclusionReceipt:
    """The proof that an installed entry came from a committed catalog state.

    This is the artefact the receipt *is*: ``entry_digest`` (what was
    installed), the ``leaf`` (the catalog state) and its ``inclusion_proof``
    against the signed ``head``, and the ``consistency_proof`` binding that
    head to the previously-recorded one. A verifier holding only this receipt
    and the signer public key can confirm, offline, what was installed and
    from which catalog history -- with no access to the publisher.
    """

    entry_digest: str
    leaf_index: int
    leaf_hash: str
    head: SignedTreeHead
    inclusion_proof: tuple[str, ...]
    prev_tree_size: int
    prev_root_hash: str
    consistency_proof: tuple[str, ...]

    def verify(self, public_key_pem: str | None) -> None:
        """Verify the whole receipt or raise :class:`TransparencyVerificationError`.

        Checks, in order: the head signature, the inclusion of the leaf under
        the head, and (when a prior head is recorded) the consistency of the
        head with that prior head.
        """
        if not verify_tree_head(self.head, public_key_pem):
            raise TransparencyVerificationError("signed log head does not verify against signer key")
        if not verify_inclusion(
            leaf_hash=self.leaf_hash,
            leaf_index=self.leaf_index,
            tree_size=self.head.tree_size,
            proof=self.inclusion_proof,
            root_hash=self.head.root_hash,
        ):
            raise TransparencyVerificationError(
                f"inclusion proof failed for leaf {self.leaf_index} under head "
                f"size={self.head.tree_size} root={self.head.root_hash[:12]}...",
            )
        if self.prev_tree_size > 0 and not verify_consistency(
            old_size=self.prev_tree_size,
            old_root=self.prev_root_hash,
            new_size=self.head.tree_size,
            new_root=self.head.root_hash,
            proof=self.consistency_proof,
        ):
            raise TransparencyVerificationError(
                "consistency proof failed: the catalog head does not extend the "
                f"head recorded at size={self.prev_tree_size} (rewrite / split-view detected)",
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return {
            "entry_digest": self.entry_digest,
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash,
            "head": self.head.to_dict(),
            "inclusion_proof": list(self.inclusion_proof),
            "prev_tree_size": self.prev_tree_size,
            "prev_root_hash": self.prev_root_hash,
            "consistency_proof": list(self.consistency_proof),
        }


# ---------------------------------------------------------------------------
# Append-only builder
# ---------------------------------------------------------------------------


class TransparencyLog:
    """Append-only Merkle transparency log over catalog-state leaves.

    A publisher appends each catalog state; a builder replaying the same
    ordered states computes a byte-identical head. Proofs are derived from the
    committed leaves, so the log is self-verifying offline.
    """

    def __init__(self, leaves: Iterable[str] | None = None) -> None:
        self._leaves: list[str] = list(leaves) if leaves is not None else []

    @classmethod
    def from_states(cls, states: Iterable[dict[str, Any]]) -> TransparencyLog:
        """Build a log from an ordered iterable of catalog-state dicts."""
        log = cls()
        for state in states:
            log.append_state(state)
        return log

    def append_state(self, state: dict[str, Any]) -> int:
        """Append a catalog state's leaf; return its zero-based index."""
        return self.append_leaf(leaf_hash_for_state(state))

    def append_leaf(self, leaf_hash: str) -> int:
        """Append a precomputed leaf digest; return its zero-based index."""
        self._leaves.append(leaf_hash)
        return len(self._leaves) - 1

    @property
    def size(self) -> int:
        """Number of leaves committed to the log."""
        return len(self._leaves)

    @property
    def root(self) -> str:
        """Current Merkle-Tree-Hash of the log."""
        return _mth(self._leaves)

    @property
    def leaves(self) -> tuple[str, ...]:
        """The committed leaf digests, in append order."""
        return tuple(self._leaves)

    def leaf_at(self, index: int) -> str:
        """Return the leaf digest at *index*."""
        return self._leaves[index]

    def signed_head(self, private_key_pem: str) -> SignedTreeHead:
        """Return the current head signed with *private_key_pem*."""
        return sign_tree_head(self.size, self.root, private_key_pem)

    def inclusion_proof(self, index: int) -> list[str]:
        """Return the audit path proving leaf *index* is under the current head."""
        if index < 0 or index >= self.size:
            raise TransparencyVerificationError(
                f"leaf index {index} out of range for log of size {self.size}",
            )
        return _inclusion_path(index, self._leaves)

    def consistency_proof(self, old_size: int) -> list[str]:
        """Return a consistency proof from *old_size* to the current head."""
        return _consistency_path(old_size, self._leaves)


# ---------------------------------------------------------------------------
# Catalog transparency envelope (published alongside a catalog state)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CatalogLogView:
    """A client's view of the log as published in a catalog's envelope.

    ``leaves`` is the ordered list of committed leaf digests up to ``head``;
    ``leaf_index`` is the position of *this* catalog state's leaf. From the
    leaves a client derives inclusion and consistency proofs itself and checks
    them against the signed head, so verification is fully offline.
    """

    leaf_index: int
    leaves: tuple[str, ...]
    head: SignedTreeHead

    def as_log(self) -> TransparencyLog:
        """Return a :class:`TransparencyLog` over the committed leaves."""
        return TransparencyLog(self.leaves)


def build_catalog_envelope(
    log: TransparencyLog,
    leaf_index: int,
    private_key_pem: str,
) -> dict[str, Any]:
    """Build the ``transparency`` envelope a publisher ships with a catalog."""
    head = log.signed_head(private_key_pem)
    return {
        "leaf_index": leaf_index,
        "leaves": list(log.leaves),
        "signed_head": head.to_dict(),
    }


def parse_catalog_envelope(raw: Any) -> CatalogLogView:
    """Parse and structurally validate a catalog transparency envelope.

    Raises:
        TransparencyVerificationError: If the envelope is malformed, or the
            published head does not match the published leaves (size / root).
    """
    if not isinstance(raw, dict):
        raise TransparencyVerificationError(
            f"transparency envelope must be an object, got {type(raw).__name__}",
        )
    leaf_index = raw.get("leaf_index")
    leaves_raw = raw.get("leaves")
    head = SignedTreeHead.from_dict(raw.get("signed_head"))
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool) or leaf_index < 0:
        raise TransparencyVerificationError("transparency envelope leaf_index must be a non-negative integer")
    if not isinstance(leaves_raw, list) or not all(isinstance(x, str) and x for x in leaves_raw):
        raise TransparencyVerificationError("transparency envelope leaves must be a list of hex strings")
    leaves = tuple(leaves_raw)
    if leaf_index >= len(leaves):
        raise TransparencyVerificationError(
            f"transparency envelope leaf_index {leaf_index} is out of range for {len(leaves)} leaves",
        )
    log = TransparencyLog(leaves)
    if head.tree_size != log.size:
        raise TransparencyVerificationError(
            f"published head size {head.tree_size} does not match {log.size} leaves",
        )
    if head.root_hash != log.root:
        raise TransparencyVerificationError("published head root does not match the published leaves")
    return CatalogLogView(leaf_index=leaf_index, leaves=leaves, head=head)


def build_inclusion_receipt(
    view: CatalogLogView,
    *,
    entry_digest: str,
    state_leaf: str,
    prev_tree_size: int = 0,
    prev_root_hash: str = "",
) -> InclusionReceipt:
    """Assemble an :class:`InclusionReceipt` for an install against *view*.

    The receipt binds *entry_digest* (what is being installed) to the catalog
    state leaf, its inclusion proof under the signed head, and (when a prior
    head is recorded) the consistency proof from that prior head. It does not
    verify the head signature here -- :meth:`InclusionReceipt.verify` does that
    against the signer key -- but it does refuse to build a receipt whose
    ``state_leaf`` is not the committed leaf at ``leaf_index`` (a fetched state
    that is not the one the envelope claims).

    Raises:
        TransparencyVerificationError: If ``state_leaf`` does not match the
            committed leaf at ``view.leaf_index``.
    """
    committed = view.leaves[view.leaf_index]
    if state_leaf != committed:
        raise TransparencyVerificationError(
            "fetched catalog state leaf does not match the leaf committed at "
            f"index {view.leaf_index} (state / envelope mismatch)",
        )
    log = view.as_log()
    inclusion = tuple(log.inclusion_proof(view.leaf_index))
    consistency: tuple[str, ...] = ()
    if prev_tree_size > 0:
        consistency = tuple(_consistency_path(prev_tree_size, list(view.leaves)))
    return InclusionReceipt(
        entry_digest=entry_digest,
        leaf_index=view.leaf_index,
        leaf_hash=state_leaf,
        head=view.head,
        inclusion_proof=inclusion,
        prev_tree_size=prev_tree_size,
        prev_root_hash=prev_root_hash,
        consistency_proof=consistency,
    )
