"""A translated README has to fail loudly when the English one moves on.

The English `README.md` states what the project does, what it guarantees, and
how to install it. A translation of it rots at the first release that changes
an install command, and a stale install command in a translated file is worse
than no translated file: it is a documented instruction that fails, in a file
nobody re-reads.

`scripts/check_readme_translations.py` is the gate. These tests drive it
against synthetic README pairs in a temporary directory - so a failure here
describes the gate rather than today's translations - plus one test that runs
it against the repository as committed.

The two normalisations are tested as behaviour, not as implementation: a
rewrap and a mechanical link rewrite must NOT invalidate a translation, because
a gate that cries wolf on either gets disabled within a month, and this
repository has done the link rewrite twice already.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_readme_translations.py"

ENGLISH_FIXTURE = """<!-- language-links -->
<!-- /language-links -->

### install in 30 seconds

Install it, then run it:

```bash
pipx install bernstein
```

See the [install guide](https://example.invalid/install.md) for the rest.

### prove a run

Determinism is something you check. Run with `BERNSTEIN_AUDIT=1` and verify.
"""

TRANSLATION_FIXTURE = """<!-- language-links -->
<!-- /language-links -->

### instalar en 30 segundos

Instálalo y ejecútalo:

```bash
pipx install bernstein
```

Consulta la [guía de instalación](https://example.invalid/install.md) para lo demás.

### probar una ejecución

El determinismo se comprueba. Ejecuta con `BERNSTEIN_AUDIT=1` y verifica.
"""


@pytest.fixture
def gate() -> Any:
    """Load scripts/check_readme_translations.py without executing main()."""
    name = "check_readme_translations_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before execution because `@dataclass` resolves its own module
    # out of sys.modules while the class body runs.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def sandbox(gate: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the gate at a synthetic English/Spanish pair under tmp_path."""
    (tmp_path / "docs" / "i18n").mkdir(parents=True)
    (tmp_path / "docs" / "i18n" / "languages.json").write_text(
        json.dumps({"languages": [{"tag": "es", "name": "Español"}]}), encoding="utf-8"
    )
    (tmp_path / "README.md").write_text(ENGLISH_FIXTURE, encoding="utf-8")
    (tmp_path / "README.es.md").write_text(TRANSLATION_FIXTURE, encoding="utf-8")

    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(gate, "ENGLISH", tmp_path / "README.md")
    monkeypatch.setattr(gate, "LANGUAGES", tmp_path / "docs" / "i18n" / "languages.json")

    assert gate.update() == ["README.es.md"]
    assert gate.verify() == [], "the fixture pair should start bound and clean"
    return tmp_path


def test_the_committed_translations_match_the_english_readme(gate: Any) -> None:
    """The gate itself, run against the repository as committed."""
    assert gate.verify() == []


def test_an_edited_english_section_names_the_language_and_the_heading(sandbox: Path, gate: Any) -> None:
    """ "Translations are out of date" is not an acceptable failure message.

    The operator must not have to diff every translated file to find the one
    paragraph that moved.
    """
    english = sandbox / "README.md"
    english.write_text(
        english.read_text(encoding="utf-8").replace("pipx install bernstein", "uv tool install bernstein"),
        encoding="utf-8",
    )

    problems = gate.verify()

    assert len(problems) >= 1
    stale = [problem for problem in problems if "stale" in problem]
    assert stale, problems
    assert "es:" in stale[0]
    assert "install in 30 seconds" in stale[0]


def test_a_translated_command_is_caught(sandbox: Path, gate: Any) -> None:
    """A translated flag is not a rough edge, it is an instruction that fails."""
    spanish = sandbox / "README.es.md"
    spanish.write_text(
        spanish.read_text(encoding="utf-8").replace("pipx install bernstein", "pipx instalar bernstein"),
        encoding="utf-8",
    )

    problems = gate.verify()

    assert any("fenced code block" in problem for problem in problems), problems


def test_a_translated_inline_command_is_caught(sandbox: Path, gate: Any) -> None:
    """The same rule inside a sentence, where it is easier to slip through."""
    spanish = sandbox / "README.es.md"
    spanish.write_text(
        spanish.read_text(encoding="utf-8").replace("`BERNSTEIN_AUDIT=1`", "`AUDITORIA_BERNSTEIN=1`"),
        encoding="utf-8",
    )

    problems = gate.verify()

    assert any("copied, not translated" in problem for problem in problems), problems
    assert any("BERNSTEIN_AUDIT=1" in problem for problem in problems), problems


def test_reordering_commands_within_a_sentence_is_allowed(sandbox: Path, gate: Any) -> None:
    """Clauses move when a sentence is translated; the command set does not.

    Chinese puts the environment variable before the verb where English puts it
    after. Requiring English word order would make a correct translation fail.
    """
    spanish = sandbox / "README.es.md"
    spanish.write_text(
        spanish.read_text(encoding="utf-8").replace(
            "Ejecuta con `BERNSTEIN_AUDIT=1` y verifica.",
            "Con `BERNSTEIN_AUDIT=1`, ejecuta y verifica.",
        ),
        encoding="utf-8",
    )

    assert gate.verify() == []


def test_rewrapping_the_english_does_not_invalidate_a_translation(sandbox: Path, gate: Any) -> None:
    """A reformat says nothing new, and a gate that fires on it gets disabled."""
    english = sandbox / "README.md"
    english.write_text(
        english.read_text(encoding="utf-8").replace(
            "Determinism is something you check. Run with",
            "Determinism is something you check.\nRun with",
        ),
        encoding="utf-8",
    )

    assert gate.verify() == []


def test_rewriting_a_link_target_does_not_invalidate_a_translation(sandbox: Path, gate: Any) -> None:
    """This repository has rewritten every README link twice, mechanically.

    Relative to absolute, for PyPI, without changing a word of prose. Making
    every translation stale over that teaches the next person to run --update
    without reading, which is how a gate becomes a rubber stamp.
    """
    english = sandbox / "README.md"
    english.write_text(
        english.read_text(encoding="utf-8").replace(
            "https://example.invalid/install.md", "https://github.example/blob/main/install.md"
        ),
        encoding="utf-8",
    )

    assert gate.verify() == []


def test_link_text_is_prose_and_is_tracked(sandbox: Path, gate: Any) -> None:
    """Masking the target must not mask what the reader actually reads."""
    english = sandbox / "README.md"
    english.write_text(
        english.read_text(encoding="utf-8").replace("[install guide]", "[installation handbook]"),
        encoding="utf-8",
    )

    assert any("stale" in problem for problem in gate.verify())


def test_a_new_english_section_is_reported_as_unbound(sandbox: Path, gate: Any) -> None:
    """A section nobody translated is drift too, and a different kind of it."""
    english = sandbox / "README.md"
    english.write_text(
        english.read_text(encoding="utf-8") + "\n### everyday commands\n\nA new section.\n", encoding="utf-8"
    )

    problems = gate.verify()

    assert any("everyday commands" in problem for problem in problems), problems


def test_a_missing_translation_file_is_reported(sandbox: Path, gate: Any) -> None:
    """A language in the config with no file is a promise the repo does not keep."""
    (sandbox / "README.es.md").unlink()

    assert any("does not exist" in problem for problem in gate.verify())


def test_the_language_links_line_is_generated_from_the_config(sandbox: Path, gate: Any) -> None:
    """Adding a language is a data change, so the links line follows the data."""
    config = sandbox / "docs" / "i18n" / "languages.json"
    config.write_text(
        json.dumps({"languages": [{"tag": "es", "name": "Español"}, {"tag": "ja", "name": "日本語"}]}),
        encoding="utf-8",
    )

    problems = gate.verify()

    assert any("language links line" in problem for problem in problems), problems
    assert any("README.ja.md" in problem or "ja:" in problem for problem in problems), problems


def test_the_english_file_names_itself_without_linking_to_itself(gate: Any) -> None:
    """The reader is already there; a self-link is noise on the front page."""
    line = gate.language_line("en")

    assert "**English**" in line
    assert "README.md" not in line
    assert "README.zh-Hans.md" in line


def test_the_binding_block_is_invisible_on_a_rendered_page(gate: Any) -> None:
    """It has to be diffable without being visible noise on GitHub."""
    text = (REPO_ROOT / "README.es.md").read_text(encoding="utf-8")

    assert text.lstrip().startswith("<!--")
    assert gate.BINDING_START in text
    # ...and it is not the language-links comment, which is a separate marker.
    assert gate.LINKS_START in text


def test_the_language_links_block_is_not_read_as_the_project_overview(tmp_path: Path) -> None:
    """`agents-md sync` takes its Overview from the README's first paragraph.

    The links line is a link strip one link short of the nav heuristic while
    only two languages are configured, so without an explicit skip the
    generated AGENTS.md/CLAUDE.md open with a language switcher instead of a
    description of the project - and every agent reading them starts from that.
    """
    from bernstein.core.knowledge.agents_md_generator import _first_paragraph

    readme = tmp_path / "README.md"
    readme.write_text(
        '<div align="center">\n\n'
        "<!-- language-links -->\n"
        "**English** &middot; [简体中文](https://example.invalid/README.zh-Hans.md)\n"
        "<!-- /language-links -->\n\n"
        "</div>\n\n---\n\n"
        "Bernstein is a deterministic orchestrator for CLI coding agents.\n",
        encoding="utf-8",
    )

    assert _first_paragraph(readme) == "Bernstein is a deterministic orchestrator for CLI coding agents."
