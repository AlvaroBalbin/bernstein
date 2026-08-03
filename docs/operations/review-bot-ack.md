# Review-bot acknowledgement protocol

This page documents the pre-merge gate and post-merge sweeper that
ensure review-bot findings on PRs are processed. The bots the gate
tracks are the `REVIEW_BOT_LOGINS` set in `scripts/review_bot_ack.py`
(currently `baz-reviewer[bot]`); retiring or adding a bot is a change
to that set.

## Why

Automated review tools regularly flag legitimate correctness and
security issues that hand-reviews miss. Treating their output as
advisory means real defects ship to `main`. This protocol makes the
findings part of the merge gate.

## The gate

`.github/workflows/review-bot-ack.yml` runs on every PR event and on
every review submission. It calls `scripts/review_bot_ack.py`, which:

1. Fetches inline review-comment threads (`pulls/<n>/comments`) and
   top-level issue comments (`issues/<n>/comments`) authored by the
   configured review-bot accounts (`REVIEW_BOT_LOGINS`).
2. Classifies each comment into `must-address` or `informational`.
   A structured finding marker, when the body carries one, is
   authoritative; prose severity headings are the fallback. See
   [Finding taxonomy](#finding-taxonomy).
3. Confirms every `must-address` finding is either:
   - Fixed in a commit on the PR branch whose message contains
     `bot-ack: <comment-id>` or `addresses: <comment-id>`, OR
   - Acknowledged in the PR body with
     `<!-- bot-ack: <comment-id> reason=<short-reason> -->`.
4. Upserts a sticky summary comment on the PR (marker:
   `<!-- review-bot-ack-summary: managed -->`) listing open findings.
5. Exits non-zero if any `must-address` finding is unresolved; that
   non-zero exit fails the `review-bot-ack` check and blocks merge.

### Finding taxonomy

A reviewer that states its category in a machine-readable marker is
graded from that marker, not from the surrounding prose:

```
<!--
_Finding type:_ `Logical Bugs`
-->
```

The marker is plural (`_Finding types:_`) when one finding spans
several categories, and the strictest category wins.

| Finding type | Bucket | Why |
|---|---|---|
| `Logical Bugs` | `must-address` | Correctness defect in the change under review. |
| `Breaking Changes` | `must-address` | Compatibility or contract break for existing callers. |
| `Verifiable Architecture & Design Review` | `must-address` | Design-level correctness, e.g. a poll loop that runs past its configured deadline. |
| anything reading as security | `must-address` | Matched on the category name so a renamed or new security category cannot arrive as informational. |
| `AI Coding Guidelines` | `informational` | Convention and guideline adherence. |
| `Naming and Typos` | `informational` | Wording, spelling, identifier names. |
| unmapped category | `must-address` | Fails closed: an untriaged category blocks rather than passing silently. |

Two rules cut across the table:

- **Severity escalates.** A finding the reviewer grades `high` is
  `must-address` whatever its category. Category alone under-reads - a
  user-controlled path reaching `unlink()` with no containment check
  was filed under `AI Coding Guidelines` and graded `high`.
- **Blocking is not a veto.** A `must-address` finding is cleared by a
  fixup commit naming it or by a `bot-ack` marker in the PR body, so
  the effect is that a human states a position on each one.

Bodies with no marker fall back to the prose severity headings other
bots embed (`**Potential issue**`, `**bug:**`, `**security:**`,
`nit:`, `**note**`), classified the same two ways.

When the reviewer introduces a category not in the table, the gate
blocks on it until `MUST_ADDRESS_FINDING_TYPES` /
`INFORMATIONAL_FINDING_TYPES` in `scripts/review_bot_ack.py` are
updated to place it.

### Skipping nit/style findings

Informational findings are not gated. The single line
`<!-- bot-ack: nit-batch-skipped -->` in the PR body is a
documentation hint for human reviewers; the gate does not require it.

## The sweeper

`.github/workflows/review-bot-sweep.yml` runs daily at 06:00 UTC and
on `workflow_dispatch`. It walks merged PRs from the configurable
look-back window (default 30 days) and runs the same classifier. Any
PR with unresolved `must-address` findings is reported in a manifest;
the workflow opens a consolidated follow-up PR
(`fix(review): apply deferred review-bot findings`) carrying that
manifest. The workflow authenticates with `GITHUB_TOKEN`.

## Shepherd checklist

Shepherds:

1. Watch CI to green.
2. Fetch all configured review-bot artefacts via the three `gh api`
   endpoints the gate reads: `pulls/<n>/comments`,
   `issues/<n>/comments`, and `pulls/<n>/reviews`.
3. Classify the two comment endpoints into must-address vs
   informational. `pulls/<n>/reviews` carries no severity; it feeds
   only the per-bot review coverage for the head commit.
4. Apply must-address fixes in a fixup commit (`bot-ack: <id>` in
   the message) or add a `bot-ack` marker to the PR body with a
   short reason.
5. Push, re-watch CI, then `gh pr merge --auto --squash`.

## Files

- `.github/workflows/review-bot-ack.yml` - pre-merge gate.
- `.github/workflows/review-bot-sweep.yml` - daily post-merge sweep.
- `scripts/review_bot_ack.py` - classifier + acknowledgement check.
- `scripts/review_bot_sweep.py` - sweep + manifest renderer.
- `tests/unit/test_review_bot_ack_workflow_yaml.py` - structural and
  classifier assertions.
- `tests/unit/scripts/test_review_bot_ack_finding_taxonomy.py` - the
  finding-type taxonomy, pinned against captured finding bodies.
- `tests/unit/scripts/test_review_bot_ack_run_detection.py` - per-bot
  review coverage for the head commit.
