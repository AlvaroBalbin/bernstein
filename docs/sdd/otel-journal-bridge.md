# Journal-anchored OTLP bridge

The OTLP bridge keeps the run journal as the only source of orchestrator span
identity. `otel_projection.project_spans` remains the canonical batch
projection; `otel_bridge.IncrementalSpanProjector` mirrors it as journal rows
append, with equality between incremental and batch output enforced by tests.

The bridge bypasses `Tracer.start_span` and constructs SDK `ReadableSpan`
objects with journal-derived trace, span, and parent ids. `EventJournal`
delivers observer callbacks under its append lock so concurrent writers cannot
reorder the incremental projection. A `BatchSpanProcessor` moves OTLP/gRPC I/O
off the journal append path.

Every wire span carries its journal entry hash, run id, and the first-entry
projection anchor. The trace id is derived from that anchor. At completion,
the `otel.projection` audit event records the same trace id and the final
journal head, providing the stable join that Phase 3 span verification uses.

Export is disabled unless `BERNSTEIN_OTEL_ENDPOINT` is configured. The live
GenAI convention attributes are independently controlled by
`BERNSTEIN_OTEL_GENAI_STABILITY`; this flag never affects span identity or
ordering. Completed runs use the same bridge through
`bernstein telemetry export-otel --run <id>`.
