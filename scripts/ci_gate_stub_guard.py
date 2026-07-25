#!/usr/bin/env python3
"""Decide whether ``ci-gate-stub.yml`` may publish the ``CI gate`` context.

Background
----------
Branch protection on ``main`` requires a single context named ``CI gate``.
Two workflows can produce a check run with that name:

* ``ci.yml::ci-gate`` - the real aggregator, which runs after the test
  matrix and rolls up ``needs.*.result``.
* ``ci-gate-stub.yml`` - a synthetic success for pull requests whose diff
  is entirely contained in ``ci.yml``'s ``paths-ignore`` list. Without it,
  such pull requests wait forever for a context that will never report.

``paths`` and ``paths-ignore`` filters are evaluated per file with OR
semantics: a workflow runs when *at least one* changed file matches. That
means the stub's ``paths:`` mirror also fires on a mixed diff (some files
ignored, some not), where ``ci.yml`` runs too. Both then publish ``CI
gate``, and the cheap synthetic one can report success minutes before the
real test matrix has finished - satisfying branch protection on code that
was never tested.

No ``on:`` filter can express "every changed file is ignored", so the
decision has to be made inside the job. This module implements it.

The pattern list is read from ``ci.yml`` itself rather than duplicated, so
the stub cannot drift away from the filter it is standing in for.

Semantics
---------
Mirrors GitHub's filter-pattern matching:

* ``*`` matches zero or more characters but does not cross ``/``
* ``**`` matches zero or more characters including ``/``
* ``?`` matches zero or one of the preceding character
* ``+`` matches one or more of the preceding character
* ``[]`` matches a character range
* a leading ``!`` negates, and later patterns override earlier ones

A file is "ignored" when the last pattern that matches it is positive. The
stub may publish ``CI gate`` only when every changed file is ignored.

Usage
-----
    python3 scripts/ci_gate_stub_guard.py --changed-paths changed-paths.txt

Writes ``all_ignored=true|false`` to ``$GITHUB_OUTPUT`` when set, and
prints a per-file classification to the log. Exits non-zero only on an
input error, never to signal the verdict: the verdict is the output.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - runner without pyyaml
    print("::error::pyyaml is not available on this runner")
    sys.exit(2)

CI_WORKFLOW = Path(".github/workflows/ci.yml")


def _translate(pattern: str) -> re.Pattern[str]:
    """Compile one GitHub filter pattern into an anchored regex."""
    out: list[str] = [r"\A"]
    i = 0
    end = len(pattern)
    while i < end:
        char = pattern[i]
        if char == "*":
            if pattern.startswith("**", i):
                out.append(".*")
                i += 2
            else:
                # A single `*` does not cross a path separator.
                out.append("[^/]*")
                i += 1
            continue
        if char in "?+":
            # Quantifiers apply to the preceding element, same as regex.
            out.append(char)
            i += 1
            continue
        if char == "[":
            close = pattern.find("]", i)
            if close != -1:
                out.append(pattern[i : close + 1])
                i = close + 1
                continue
        if char == "\\" and i + 1 < end:
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(re.escape(char))
        i += 1
    out.append(r"\Z")
    return re.compile("".join(out))


def load_paths_ignore(ci_workflow: Path = CI_WORKFLOW) -> list[str]:
    """Read ``on.pull_request.paths-ignore`` out of ``ci.yml``."""
    doc = yaml.safe_load(ci_workflow.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        msg = f"{ci_workflow} did not parse to a mapping"
        raise ValueError(msg)
    # PyYAML 1.1 parses a bare `on:` key as the boolean True.
    on = doc.get(True, doc.get("on"))
    if not isinstance(on, dict):
        msg = f"{ci_workflow} has no `on:` mapping"
        raise ValueError(msg)
    pull_request = on.get("pull_request")
    if not isinstance(pull_request, dict):
        msg = f"{ci_workflow} has no `on.pull_request:` mapping"
        raise ValueError(msg)
    patterns = pull_request.get("paths-ignore")
    if not isinstance(patterns, list) or not patterns:
        msg = f"{ci_workflow} has no `on.pull_request.paths-ignore:` list"
        raise ValueError(msg)
    return [str(entry) for entry in patterns]


def is_ignored(path: str, patterns: Sequence[str]) -> bool:
    """Return True when ``path`` is excluded by the filter ``patterns``.

    Later patterns override earlier ones, so a trailing ``!foo`` un-ignores
    a file an earlier positive pattern captured.
    """
    ignored = False
    for raw in patterns:
        negated = raw.startswith("!")
        pattern = raw[1:] if negated else raw
        if _translate(pattern).match(path):
            ignored = not negated
    return ignored


def all_paths_ignored(paths: Iterable[str], patterns: Sequence[str]) -> bool:
    """Return True only when every changed path is ignored by ``patterns``.

    An empty diff returns False. The stub exists to unblock a diff it can
    prove is inert; a diff it cannot see is not such a diff, and failing
    closed leaves the pull request waiting for the real gate rather than
    handing it a synthetic success.
    """
    materialised = [p for p in paths if p]
    if not materialised:
        return False
    return all(is_ignored(path, patterns) for path in materialised)


def read_changed_paths(source: Path) -> list[str]:
    text = source.read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--changed-paths",
        type=Path,
        required=True,
        help="File containing the pull request's changed paths, one per line.",
    )
    parser.add_argument(
        "--ci-workflow",
        type=Path,
        default=CI_WORKFLOW,
        help="Workflow whose `on.pull_request.paths-ignore` list is authoritative.",
    )
    args = parser.parse_args(argv)

    patterns = load_paths_ignore(args.ci_workflow)
    changed = read_changed_paths(args.changed_paths)

    print(f"Changed paths ({len(changed)}):")
    for path in changed:
        marker = "ignored    " if is_ignored(path, patterns) else "NOT ignored"
        print(f"  {marker}  {path}")

    verdict = all_paths_ignored(changed, patterns)
    print(f"\nall_ignored={str(verdict).lower()}")
    if verdict:
        print("Every changed path is ignored by ci.yml, so the real CI gate will never report.")
        print("The stub publishes the `CI gate` context for this pull request.")
    else:
        print("At least one changed path is not ignored by ci.yml, so the real CI gate will report.")
        print("The stub must not publish the `CI gate` context for this pull request.")

    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"all_ignored={str(verdict).lower()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
