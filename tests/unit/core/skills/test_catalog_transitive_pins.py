"""Transitive-source pinning tests for the skill catalog (issue #2527).

Acceptance: an entry referencing a transitive source without a pinned digest
fails verify with a named error; a fully-pinned entry validates and its pins
are covered by the entry signature.
"""

from __future__ import annotations

import pytest

from bernstein.core.skills.catalog import (
    SkillCatalogValidationError,
    SkillSourceRef,
    SkillSourceSpec,
    UnpinnedTransitiveSourceError,
    generate_signer_keypair,
    sign_entry,
    validate_catalog,
    verify_entry,
)
from bernstein.core.skills.catalog.manifest import SkillCatalogEntry
from bernstein.core.skills.catalog.signature import attach_signature


def _payload(references: list[dict[str, object]] | None) -> dict[str, object]:
    entry: dict[str, object] = {
        "id": "code-review",
        "name": "code-review",
        "version": "1.0.0",
        "description": "Review code.",
        "source": {"kind": "github", "repo": "acme/code-review", "tag": "v1.0.0"},
        "content_digest": "f" * 64,
        "verified": True,
    }
    if references is not None:
        entry["references"] = references
    return {
        "version": 1,
        "generated_at": "2026-05-21T00:00:00Z",
        "entries": [entry],
    }


def test_entry_with_pinned_reference_validates() -> None:
    catalog = validate_catalog(
        _payload(
            [
                {
                    "source": {"kind": "npm", "package": "left-pad", "version": "1.3.0"},
                    "digest": "a" * 64,
                }
            ]
        )
    )
    entry = catalog.entries[0]
    assert len(entry.references) == 1
    assert entry.references[0].digest == "a" * 64
    assert entry.references[0].source.kind == "npm"


def test_entry_without_references_still_validates() -> None:
    catalog = validate_catalog(_payload(None))
    assert catalog.entries[0].references == ()


def test_reference_missing_digest_fails_with_named_error() -> None:
    with pytest.raises(UnpinnedTransitiveSourceError, match="no pinned digest"):
        validate_catalog(_payload([{"source": {"kind": "git", "url": "https://example.com/x.git", "ref": "main"}}]))


def test_reference_bad_digest_fails_with_named_error() -> None:
    with pytest.raises(UnpinnedTransitiveSourceError, match="64-char lowercase hex"):
        validate_catalog(
            _payload(
                [
                    {
                        "source": {"kind": "npm", "package": "left-pad", "version": "1.3.0"},
                        "digest": "not-a-hex-digest",
                    }
                ]
            )
        )


def test_reference_unknown_field_rejected() -> None:
    with pytest.raises(SkillCatalogValidationError):
        validate_catalog(
            _payload(
                [
                    {
                        "source": {"kind": "npm", "package": "left-pad", "version": "1.3.0"},
                        "digest": "a" * 64,
                        "rogue": "x",
                    }
                ]
            )
        )


def test_references_are_covered_by_entry_signature() -> None:
    """Adding/altering a reference must invalidate the entry signature."""
    priv, pub = generate_signer_keypair()
    ref = SkillSourceRef(
        source=SkillSourceSpec(kind="npm", package="left-pad", version="1.3.0"),
        digest="a" * 64,
    )
    entry = SkillCatalogEntry(
        id="code-review",
        name="code-review",
        version="1.0.0",
        description="Review code.",
        source=SkillSourceSpec(kind="github", repo="acme/code-review", tag="v1.0.0"),
        content_digest="f" * 64,
        references=(ref,),
    )
    signed = attach_signature(entry, sign_entry(entry, priv))
    assert verify_entry(signed, pub).verified

    # Tamper with the pinned digest: the signature must no longer verify.
    tampered_ref = SkillSourceRef(source=ref.source, digest="b" * 64)
    tampered = SkillCatalogEntry(
        id=signed.id,
        name=signed.name,
        version=signed.version,
        description=signed.description,
        source=signed.source,
        content_digest=signed.content_digest,
        signature=signed.signature,
        references=(tampered_ref,),
    )
    assert not verify_entry(tampered, pub, allow_unverified=True).verified
