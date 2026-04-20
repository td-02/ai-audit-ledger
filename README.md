# AI Audit Ledger

AI Audit Ledger is a tamper-evident compliance system for AI decisions. It captures every application AI call as an audit record, emits it over OpenTelemetry-compatible plumbing, persists it into a cryptographically chained ledger, and produces regulator-facing compliance reports.

## Architecture

1. An application calls an LLM through an SDK wrapper.
2. The SDK intercepts the request and response metadata, builds an `AuditRecord`, signs it, and emits it through an OpenTelemetry-style exporter.
3. The ledger collector validates the record and appends it to an immutable chain.
4. The ledger server batches records into Merkle roots for efficient verification.
5. The reporting pipeline verifies the chain and renders compliance reports.

## Repository layout

- `schema/`: canonical product schema for `AuditRecord`
- `docs/`: architecture, phases, and report format
- `crates/ledger-core`: shared Rust primitives for hashing, chaining, and verification
- `crates/ledger-server`: Rust HTTP ingestion and append-only ledger service
- `crates/report-cli`: Rust CLI for verification and compliance report generation
- `sdk/go`: Go SDK and OpenTelemetry exporter implementation
- `examples/go-app`: example application emitting AI audit events

## Phase plan

1. Define the schema, repo structure, and developer workflow.
2. Implement the Rust ledger core and ingestion service skeleton.
3. Implement the Go SDK/exporter path from app call to ledger append.
4. Implement report generation and end-to-end verification.

## Current status

The repo is scaffolded in incremental phases. Rust is not installed in the current environment, so Rust code is authored but not compiled here yet.

