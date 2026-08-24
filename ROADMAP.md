# Roadmap

The roadmap is tracked live, not in this file:

- [Milestones](https://github.com/sipyourdrink-ltd/bernstein/milestones)
  — what ships in each release, and when.
- [Project board](https://github.com/orgs/sipyourdrink-ltd/projects/1)
  — current state of every tracked issue.

## Release cadence

Two tracks ship from `main`:

- **Patch** (`v3.x.y`) — cut roughly every 3 days from whatever merged
  work has accumulated. Queue-driven, no dedicated milestone.
- **Minor** (`v3.x.0`) — cut on a roughly 2-week cadence, or sooner when
  a substantial feature is ready. Each minor gets a milestone with a due
  date that reflects that.

A milestone holds the issues actually targeted for that release, not
every open issue. Small and priority-labelled issues stay in the nearer
milestone; larger or not-yet-prioritized issues move to the next one
out. Advanced-tier work (lineage, audit-chain, verifiability, replay)
can still land in an earlier minor once the surface it depends on is
mature enough — milestone is about target release, not a hard gate.

An open issue with no milestone yet is untriaged, not deprioritized.
