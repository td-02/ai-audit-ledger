# OTel Mapping

The Go SDK now supports native OpenTelemetry span emission for each `AuditRecord`.

## Mapping model

- one AI decision maps to one span: `ai.audit.record`
- trace context is carried in `application.trace_id` and optional `application.span_id`
- decision, policy, chain, and signature metadata are emitted as span attributes
- SDK supports multi-export fanout:
  - `LedgerHTTPExporter` for direct ledger append
  - `OTelSpanExporter` for native OTel pipelines

## OTLP setup helper

`NewOTLPSpanPipeline` provisions an OTLP/HTTP exporter-backed tracer provider and returns an `OTelSpanExporter` for the audit emitter. This allows drop-in integration with existing collector deployments.
