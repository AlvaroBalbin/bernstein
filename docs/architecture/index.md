---
title: Architecture and internals
description: How Bernstein is built - system design, core concepts, orchestration internals, and the ADR trail.
search:
  boost: 2
---

# Architecture and internals

How Bernstein works under the hood, for readers extending it or
deciding whether its design fits their constraints.

- **System** - Top-level architecture, task lifecycle, model routing, state persistence. [Architecture](ARCHITECTURE.md).
- **Concepts** - The building blocks: fingerprint memoization, lineage trail, spec-as-test. [Artifact lineage trail](../concepts/artifact-lineage.md).
- **Orchestration internals** - Task DAG, run actor, worker coordination, failure taxonomy. [Task DAG](../orchestration/task-dag.md).
- **Decisions (ADRs)** - Why the orchestrator is deterministic, file-based, and LLM-free at the core. [Why deterministic](WHY_DETERMINISTIC.md).
