# Translated READMEs

`README.md` is the only document that states what the project does, what it
guarantees, and how to install it. Translating it is the easy half. Keeping a
translation true is the half that decides whether the translation helps anyone:
a stale install command in a translated file is worse than no translated file —
it is a documented instruction that fails, in a file nobody re-reads.

So the translations are gated the same way the generated agent files are. Each
translated section carries the content hash of the English section it mirrors,
and the **Repo hygiene** CI job fails when an English section changes and its
translation does not, naming the language and the heading.

```bash
uv run python scripts/check_readme_translations.py            # verify (what CI runs)
uv run python scripts/check_readme_translations.py --update   # rebind after translating
```

## What the gate checks

| check | why |
|---|---|
| every English section has a binding in every translation | a section nobody translated is drift too |
| the recorded hash matches the English section today | the case the gate exists for |
| the section count matches | a merged or dropped section breaks the mapping the bindings rely on |
| fenced code blocks are byte-identical, in order | a translated command is not a rough edge, it is an instruction that fails |
| the set of inline commands, flags and paths matches | the same rule inside a sentence, where it is easier to slip through |
| the language links line matches `languages.json` | adding a language is a data change; the line follows the data |

**What it does not check:** that a translation says what the English says. No
offline check can. The binding proves someone rebound the file after the
English moved — which is the failure that actually happens — not that the
prose is right. Review the prose the way you would review any other change.

## What is deliberately not drift

Two normalisations decide what counts as a change, and both exist because a
gate that cries wolf gets disabled within a month:

- **Whitespace is collapsed.** Rewrapping an English paragraph does not change
  what it says.
- **Link targets are masked.** This repository has twice rewritten every link
  in the README mechanically — relative to absolute, so the packaged
  description renders on PyPI — without changing a word of prose. Invalidating
  every translation over that would teach the next person to run `--update`
  without reading, which is how a gate becomes a rubber stamp. Link *text* is
  prose, and is tracked.

## Adding a language

1. Add an entry to `docs/i18n/languages.json`:

   ```json
   { "tag": "ja", "name": "日本語" }
   ```

   Use IETF language tags, with the script subtag where it decides legibility —
   `zh-Hans`, not `zh-CN`.

2. Copy `README.md` to `README.<tag>.md` and translate the prose. Keep every
   heading in the same order and at the same level; copy code blocks, command
   names, flags, paths, badges and the logo block verbatim.

3. Run `uv run python scripts/check_readme_translations.py --update`. It writes
   the binding block into the new file and refreshes the language links line in
   every README, including the English one.

4. Commit the new file together with the regenerated bindings.

No code changes are needed for step 1 to take effect: the language set is data,
and the gate reads it.

## When CI says a translation is stale

The failure names the language and the exact heading:

```
error: es: section "install in 30 seconds" is stale - the English text changed and README.es.md did not
```

Translate that section, then rebind. Running `--update` without translating
makes the gate pass and the file wrong — it is the one way to defeat this
check, and it is visible in the diff, which is where it belongs.
