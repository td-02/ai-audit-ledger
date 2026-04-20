# OTel Mapping

The Go SDK does not depend on the upstream OpenTelemetry SDK in this first scaffold, but its transport model is intentionally OTel-shaped:

- one AI decision maps to one audit emission
- trace context is carried as `trace_id` and optional `span_id`
- exporter semantics use a dedicated transport component rather than app-specific HTTP calls
- the ledger ingestion endpoint is the collector boundary

The next integration step is to wrap this emitter in a real OpenTelemetry exporter so application teams can install it alongside existing tracing setup with no code-path changes in business handlers.
