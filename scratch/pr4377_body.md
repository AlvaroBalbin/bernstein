Fixes #4377

### Problem
Bernstein assembles agent prompts from multiple sources (role templates, skills, project context, lessons, memory, tasks, predecessor diffs, etc.) without an explicit budget check at spawn time. On large repos or tasks with extensive context, the assembled system prompt can silently consume a huge fraction of the model's context window.

### Changes
1. **Budget Defaults**: Added `spawn_prompt_budget_pct = 25.0` and `spawn_prompt_budget_abs = 32_768` to `TokenDefaults` in `src/bernstein/core/defaults.py`.
2. **Prompt Budget Analyzer**: Created `src/bernstein/core/agents/spawn_prompt_budget.py` with `check_spawn_prompt_budget()` to estimate section token consumption against the resolved context limit and log actionable per-source attribution warnings when over budget.
3. **Integration**: Integrated budget checking into `_render_prompt` in `src/bernstein/core/agents/spawn_prompt.py`.
4. **Session Metrics**: Added `spawn_prompt_tokens`, `spawn_prompt_utilization_pct`, and `spawn_prompt_over_budget` fields to `AgentSession` in `src/bernstein/core/tasks/models.py`.
5. **Tests**: Added `tests/unit/core/agents/test_spawn_prompt_budget.py` (6 unit tests).
