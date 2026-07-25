"""Issue #3015 - a single, coherent completion instruction per role.

The fix routes task completion through the first-class ``bernstein task
complete`` CLI. It must not leave a role's prompt carrying TWO conflicting
completion instructions (a CLI line *and* a raw-curl ``/complete`` POST) - that
would reproduce, or worsen, the quoting/decision confusion #3015 is about.

These tests assemble the **live** agent prompt exactly as production does
(``spawner_core._render_prompt`` for the role body + the appended
``_render_auth_section``) and assert that every role - manager and workers -
sees the CLI and nothing that tells it to hand-build a completion curl.

Issue #3035 found a second, SEPARATE surface this guard did not cover: the
injected skill set written into every worktree's ``.claude/skills/`` by
``inject_skills(...)`` (``_ALWAYS_INJECT`` + ``ROLE_SKILL_MAP``). That set is
built from its own templates via ``render_skill_template``, not from
``_render_prompt``/``_render_auth_section`` - so the raw curl baked into the
bundled ``bernstein-completion-protocol.md`` shipped to every spawned agent
without this guard ever seeing it. ``TestInjectedSkillCompletionCoherence``
below closes that gap.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from bernstein.core.models import Task

from bernstein import _BUNDLED_TEMPLATES_DIR
from bernstein.adapters.skills_injector import _ALWAYS_INJECT, ROLE_SKILL_MAP, inject_skills
from bernstein.core.agents.spawner_core import _render_auth_section, _render_prompt

# curl POST to a /tasks/<id>/complete endpoint on a single line - the fragile
# shape the issue calls out. Matches the inline instructions block and the
# batch prompt whether or not they also carry the JSON body.
_RAW_CURL_COMPLETE = re.compile(r"curl[^\n]*/tasks/\S*?/complete", re.IGNORECASE)

_ROLES = ["manager", "backend", "qa", "security", "reviewer", "docs"]


def _live_prompt(role: str, tmp_path: Path) -> str:
    """Assemble the prompt for *role* the way the production spawner does."""
    workdir = tmp_path / role
    (workdir / ".sdd").mkdir(parents=True, exist_ok=True)
    roles_dir = _BUNDLED_TEMPLATES_DIR / "roles"
    task = Task(id="T-1", title="Do the thing", description="A task body.", role=role)
    body = _render_prompt([task], roles_dir, workdir)
    auth = _render_auth_section(workdir / ".sdd" / "runtime" / "agent_tokens" / "s.token")
    return body + auth


class TestPromptCompletionCoherence:
    @pytest.mark.parametrize("role", _ROLES)
    def test_role_prompt_has_single_cli_completion(self, role: str, tmp_path: Path) -> None:
        prompt = _live_prompt(role, tmp_path)
        # The one and only completion instruction is the CLI front door.
        assert "bernstein task complete" in prompt, f"{role}: CLI completion instruction missing"
        # No competing raw-curl completion anywhere in the same prompt.
        match = _RAW_CURL_COMPLETE.search(prompt)
        assert match is None, f"{role}: raw-curl completion still present -> {match and match.group(0)!r}"

    @pytest.mark.parametrize("role", _ROLES)
    def test_role_prompt_has_no_result_summary_json_body(self, role: str, tmp_path: Path) -> None:
        """No hand-quoted JSON completion body should remain in the live prompt."""
        prompt = _live_prompt(role, tmp_path)
        assert '"result_summary"' not in prompt, f"{role}: hand-quoted result_summary JSON body still present"


def _injected_skills(role: str, tmp_path: Path) -> dict[str, str]:
    """Write the REAL injected skill set for *role* and return {filename: content}.

    Mirrors what ``AgentSpawner`` does for every spawned agent: ``inject_skills``
    copies ``_ALWAYS_INJECT`` plus ``ROLE_SKILL_MAP.get(role, [])`` from the
    shipped ``templates/skills/`` directory into ``workdir/.claude/skills/``,
    rendering the same ``{{COMPLETE_CMDS}}``-style placeholders the live prompt
    path renders separately.
    """
    workdir = tmp_path / f"{role}-skills"
    workdir.mkdir(parents=True, exist_ok=True)
    roles_dir = _BUNDLED_TEMPLATES_DIR / "roles"
    task = Task(id="T-1", title="Do the thing", description="A task body.", role=role)

    inject_skills(
        workdir=workdir,
        role=role,
        tasks=[task],
        session_id=f"{role}-session",
        templates_dir=roles_dir,
    )

    skills_dir = workdir / ".claude" / "skills"
    if not skills_dir.is_dir():
        return {}
    return {p.name: p.read_text(encoding="utf-8") for p in skills_dir.glob("*.md")}


class TestInjectedSkillCompletionCoherence:
    """Issue #3035 - the injected skill set must be as coherent as the prompt.

    #3021/#3015 fixed the live *rendered prompt* and added
    ``TestPromptCompletionCoherence`` above to guard it - but never looked at
    the SEPARATE skill files ``inject_skills`` writes into
    ``workdir/.claude/skills/``. The always-injected
    ``bernstein-completion-protocol.md`` kept a raw, unauthenticated curl to a
    hardcoded ``127.0.0.1:8052`` that shipped to every spawned agent (manager
    and every worker role) unnoticed. This covers the full injected set -
    ``_ALWAYS_INJECT`` plus each role's ``ROLE_SKILL_MAP`` entries - the same
    way the prompt guard covers the full rendered prompt.
    """

    @pytest.mark.parametrize("role", _ROLES)
    def test_injected_skill_set_has_no_raw_curl_completion(self, role: str, tmp_path: Path) -> None:
        skills = _injected_skills(role, tmp_path)

        # Every always-injected skill must actually have landed - a silently
        # skipped write would make the "no curl" sweep below vacuous.
        expected = set(_ALWAYS_INJECT) | set(ROLE_SKILL_MAP.get(role, []))
        missing = expected - set(skills)
        assert not missing, f"{role}: expected injected skills missing on disk: {sorted(missing)}"

        for filename, content in skills.items():
            match = _RAW_CURL_COMPLETE.search(content)
            assert match is None, (
                f"{role}: raw-curl completion in injected skill {filename} -> {match and match.group(0)!r}"
            )

    @pytest.mark.parametrize("role", _ROLES)
    def test_injected_completion_skill_uses_the_cli(self, role: str, tmp_path: Path) -> None:
        skills = _injected_skills(role, tmp_path)
        completion = skills["bernstein-completion-protocol.md"]
        assert "bernstein task complete" in completion, f"{role}: CLI completion instruction missing"
