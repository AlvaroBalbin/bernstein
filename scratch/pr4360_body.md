Fixes #4360

### Problem
`bernstein status` reported three different live-agent counts for the same run (e.g. on a run with one dead manager and one working backend, `summary.agents` reported 0, `agents.count` reported 2, and the human CLI line reported `Active agents: 2`).

### Changes
1. Added unified helper `is_agent_alive(agent_or_status)` in `src/bernstein/core/tasks/lifecycle.py`.
2. Updated `GET /status`, `GET /dashboard/data`, `_health_components`, and `_status_agent_items` in `src/bernstein/core/routes/status_dashboard.py` to use `is_agent_alive` and populate fallback snapshots when in-memory agents are empty.
3. Updated `create_summary_table` and `create_summary_plain` in `src/bernstein/cli/ui.py` to count active agents via `is_agent_alive`.
4. Added `tests/unit/test_status_agent_counts.py` asserting that `summary.agents`, `agents.count`, and the rendered CLI line all consistently report `1`.
