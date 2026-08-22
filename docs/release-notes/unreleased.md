# Unreleased

Changes merged to `main` that are not yet part of a tagged release. Each
tagged release has its own page in this directory; this page carries what has
landed since the newest one.

Cutting a version empties this page: every entry the tag ships moves onto that
version's page in the release PR itself. `tests/unit/test_unreleased_notes_rotation.py`
holds the page to that — an entry naming an issue or PR a tagged release page
already documents fails the build. An entry that cites released work as context
rather than as its own attribution is exempted by hand there, with the reason.

## Added

- `bernstein run` on a TTY now says it is waiting for the first agent instead of sitting silent (#4257). The wait is bounded and returns as soon as an agent registers, so a fast start stays exactly as quiet as before: the transient status appears only once a poll has already failed to produce a verdict, and clears before the dashboard or the Rich fallback renders. The non-interactive detach path is unchanged.
- The signed run receipt now has a normative field-by-field format spec (`docs/security/run-receipt-format.md`) and a stdlib-only reference verifier, `tools/verify_run_receipt.py` (#4204). An operator handing a receipt to a third party can point them at the spec and the script instead of `src/`; both are exercised in CI against a committed valid receipt and a committed tampered copy.
