"""Tests for the docs requirements pin gate (#3995).

Every case that exercises the *check* builds its own ``.in``/``.txt`` pair
in a tmp dir. None of those read the real ``docs/`` files: the drift that
motivated this gate is fixed by #3979, so a test asserting against the real
tree would pass from that moment on and never fail again regardless of
whether the check still works.

The one exception is ``TestTheDocumentedRegenerationCommandMatchesTheOneWePrint``,
which reads the real files on purpose. Its claim is about those two files
specifically and cannot go stale the way a pin can - see that class.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.check_docs_requirements_pins import (
    REGEN_COMMAND,
    check,
    find_violations,
    parse_in_file,
    parse_pins,
)

# A compiled line carries its hashes on indented continuations. Included
# verbatim in the fixtures because "indented lines are not pins" is a real
# parsing rule, not an incidental formatting detail.
_HASH_TAIL = " \\\n    --hash=sha256:" + "0" * 64


def write_pair(tmp_path: Path, in_text: str, txt_text: str) -> tuple[Path, Path]:
    in_path = tmp_path / "requirements.in"
    txt_path = tmp_path / "requirements.txt"
    in_path.write_text(in_text, encoding="utf-8", newline="")
    txt_path.write_text(txt_text, encoding="utf-8", newline="")
    return in_path, txt_path


class TestTheGateCatchesTheDriftItWasBuiltFor:
    def test_a_pin_above_its_cap_is_a_violation_naming_the_package(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # This is #3995 in miniature: a cap with a reason, and a compiled
        # file that resolved the exact release the cap excludes.
        in_path, txt_path = write_pair(
            tmp_path,
            "# Cap below 1.2.3: that release adds a third-party fork dependency.\nmkdocs-redirects>=1.2,<1.2.3\n",
            f"mkdocs-redirects==1.2.3{_HASH_TAIL}\n",
        )
        assert check(in_path, txt_path) == 1
        out = capsys.readouterr().out
        # The package name is the whole point - "files differ" costs a bisect.
        assert "mkdocs-redirects" in out
        assert "1.2.3" in out
        # And the way out has to be in the failure, not in someone's memory.
        assert "pip-compile" in out

    def test_a_pin_inside_its_bounds_passes(self, tmp_path: Path) -> None:
        in_path, txt_path = write_pair(
            tmp_path,
            "mkdocs-redirects>=1.2,<1.2.3\n",
            f"mkdocs-redirects==1.2.2{_HASH_TAIL}\n",
        )
        assert check(in_path, txt_path) == 0

    def test_the_exact_boundary_version_is_excluded(self, tmp_path: Path) -> None:
        # `<1.2.3` must reject 1.2.3 itself. An off-by-one here would have
        # let the original drift through while still looking like a gate.
        in_path, txt_path = write_pair(tmp_path, "pkg<1.2.3\n", f"pkg==1.2.3{_HASH_TAIL}\n")
        assert check(in_path, txt_path) == 1

    def test_a_directly_declared_requirement_missing_from_the_pins_is_a_violation(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A dropped direct dependency is drift too: the docs build stops
        # installing something the .in file says it needs.
        in_path, txt_path = write_pair(
            tmp_path,
            "mkdocs>=1.6.1,<2\nmkdocs-minify-plugin>=0.8,<1\n",
            f"mkdocs==1.6.1{_HASH_TAIL}\n",
        )
        assert check(in_path, txt_path) == 1
        assert "mkdocs-minify-plugin" in capsys.readouterr().out


class TestParsingTheCompiledFormat:
    def test_hash_continuation_lines_are_not_mistaken_for_pins(self) -> None:
        pins = parse_pins(f"babel==2.18.0{_HASH_TAIL}\n    --hash=sha256:" + "1" * 64 + "\n    # via mkdocs-material\n")
        assert pins == {"babel": "2.18.0"}

    def test_extras_are_stripped_when_matching(self, tmp_path: Path) -> None:
        # The committed file is compiled with --strip-extras, so the .in
        # declares `mkdocs-material[imaging]` and the .txt pins the bare name.
        # Matching on the raw string would report a false violation forever.
        in_path, txt_path = write_pair(
            tmp_path,
            "mkdocs-material[imaging]>=9.7.6,<10\n",
            f"mkdocs-material==9.7.6{_HASH_TAIL}\n",
        )
        assert check(in_path, txt_path) == 0

    def test_names_are_compared_canonically(self, tmp_path: Path) -> None:
        # PEP 503: Foo_Bar and foo-bar are the same project.
        in_path, txt_path = write_pair(tmp_path, "Mkdocs_Redirects<1.2.3\n", f"mkdocs-redirects==1.2.2{_HASH_TAIL}\n")
        assert check(in_path, txt_path) == 0

    def test_comments_blank_lines_and_option_lines_are_skipped(self) -> None:
        requirements = parse_in_file(
            "# a comment\n"
            "\n"
            "-r other.in\n"
            "--index-url https://example.invalid/simple\n"
            "mkdocs>=1.6.1,<2  # trailing comment\n"
        )
        assert [r.name for r in requirements] == ["mkdocs"]

    def test_a_version_the_resolver_could_not_produce_is_reported_not_crashed(self, tmp_path: Path) -> None:
        in_path, txt_path = write_pair(tmp_path, "pkg<2\n", "pkg==not-a-version\n")
        assert check(in_path, txt_path) == 1


class TestTheGateRefusesRatherThanPassingOnBadInput:
    def test_an_empty_compiled_file_is_an_error_not_a_pass(self, tmp_path: Path) -> None:
        # The failure that matters most: if the .txt cannot be parsed, every
        # requirement looks "missing" and a naive check reports success on an
        # empty violation list. Refuse instead - this gate exists precisely
        # because a check that reports OK without checking is worse than none.
        in_path, txt_path = write_pair(tmp_path, "mkdocs>=1.6.1,<2\n", "# nothing here\n")
        assert check(in_path, txt_path) == 2

    def test_a_missing_file_is_an_error(self, tmp_path: Path) -> None:
        assert check(tmp_path / "absent.in", tmp_path / "absent.txt") == 2

    def test_an_unparseable_requirement_is_an_error(self, tmp_path: Path) -> None:
        in_path, txt_path = write_pair(tmp_path, "not a requirement!!\n", "pkg==1.0\n")
        assert check(in_path, txt_path) == 2


class TestMarkers:
    def test_a_marker_guarded_requirement_absent_from_the_pins_is_not_a_violation(self) -> None:
        # A Python-version guard can legitimately exclude a requirement from
        # the resolution. Absence is only a finding when it applies always.
        requirements = parse_in_file('tomli>=2; python_version < "3.11"\n')
        assert find_violations(requirements, {"mkdocs": "1.6.1"}) == []

    def test_a_marker_guarded_requirement_that_IS_pinned_is_still_bounds_checked(self) -> None:
        # Present means it was resolved, so the cap applies to it as normal.
        requirements = parse_in_file('tomli>=2,<3; python_version < "3.11"\n')
        violations = find_violations(requirements, {"tomli": "3.1.0"})
        assert [v.name for v in violations] == ["tomli"]


class TestTheDocumentedRegenerationCommandMatchesTheOneWePrint:
    """The one place reading the real files is right.

    Everything above uses tmp dirs because pins change. These two claims do
    not: the command in the ``.in`` header and the command this gate prints
    on failure must be the same command, forever. They were NOT the same
    before this gate existed - the header omitted ``--strip-extras`` while
    the committed ``.txt`` recorded having used it, which is the second
    drift #3995 turned up.

    That mattered concretely. Following the header regenerates a ``.txt``
    with extras left in, and this gate then reports ``mkdocs-material ...
    no pin was found`` - sending the reader after a dropped dependency that
    was never dropped.

    Pinning it here rather than trusting review, for the reason the whole
    PR is about: a documented instruction with nothing checking it drifts
    from the real one and stays drifted.
    """

    REPO_ROOT = Path(__file__).resolve().parents[2]

    # The sentence the command block follows. Anchoring on it is what keeps
    # this scoped to the command instead of the whole comment block.
    COMMAND_MARKER = "Regenerate after any change here with:"

    def documented_command(self) -> str:
        """The regeneration command from the ``.in`` header, and nothing else.

        Scoped deliberately. An earlier version of this test matched against
        every comment line in the file, which made it unfailable: the prose
        two lines below the command explains why ``--strip-extras`` matters
        and therefore *contains the string the assertion looked for*. Delete
        the flag from the command and the test stayed green, because the
        sentence warning you not to delete it kept the substring alive.

        That is this PR's own subject one level up - a check reporting green
        without checking - so it is worth stating rather than quietly fixing.
        """
        lines = (self.REPO_ROOT / "docs" / "requirements.in").read_text(encoding="utf-8").splitlines()
        start = next(
            (index for index, line in enumerate(lines) if self.COMMAND_MARKER in line),
            None,
        )
        assert start is not None, (
            f"docs/requirements.in no longer contains {self.COMMAND_MARKER!r}, so this test "
            f"cannot find the command it is meant to check. Re-anchor it rather than deleting it."
        )
        collected: list[str] = []
        for line in lines[start + 1 :]:
            if not line.startswith("#"):
                break
            body = line[1:]
            if body.strip() == "":
                # A blank comment line closes the block once it has started.
                if collected:
                    break
                continue
            if not body.startswith("   "):
                # Back to unindented prose: the command is over.
                break
            collected.append(body.strip().rstrip("\\").strip())
        assert collected, "found the marker but no indented command block under it"
        return " ".join(collected)

    @pytest.mark.parametrize(
        "flag",
        ["--generate-hashes", "--strip-extras", "--output-file", "pip-compile"],
        ids=["hashes", "strip-extras", "output-file", "compiler"],
    )
    def test_every_flag_the_gate_prints_is_in_the_documented_command(self, flag: str) -> None:
        assert flag in REGEN_COMMAND, f"{flag} vanished from the printed command"
        assert flag in self.documented_command(), (
            f"docs/requirements.in's command block no longer documents {flag}, so following it "
            f"produces a file this gate will misdiagnose. Keep it in step with REGEN_COMMAND."
        )

    def test_the_extraction_excludes_the_prose_around_the_command(self) -> None:
        """The control. Without this, the scoping could silently stop working.

        If ``documented_command`` ever went back to returning the whole
        comment block, every assertion above would pass for the wrong reason
        again and nothing would say so.
        """
        command = self.documented_command()
        raw = (self.REPO_ROOT / "docs" / "requirements.in").read_text(encoding="utf-8")
        # The explanatory sentence mentions the flag and must NOT be what the
        # assertions are matching against.
        assert "not optional" in raw, "the explanatory prose is gone; re-point this control at whatever replaced it"
        assert "not optional" not in command
        # And the command really is a command, not an empty string that would
        # make every `in` assertion above fail loudly rather than pass quietly.
        assert command.startswith("uv run")

    def test_the_compiled_file_records_the_same_invocation_it_documents(self) -> None:
        # The .txt header is pip-compile's own record of how it was called.
        # If it and the .in command disagree, one of them is lying about how
        # to reproduce the file - which is exactly what this gate found.
        txt_header = "\n".join(
            line
            for line in (self.REPO_ROOT / "docs" / "requirements.txt").read_text(encoding="utf-8").splitlines()[:12]
            if line.startswith("#")
        )
        assert "--strip-extras" in txt_header
        assert "--strip-extras" in self.documented_command()
