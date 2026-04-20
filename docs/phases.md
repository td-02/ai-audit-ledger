# Delivery Phases

## Phase 1

Define the canonical schema, repo layout, and architecture documents.

## Phase 2

Build the Rust ledger core:

- canonical hashing
- Ed25519 signature verification
- append-only chain validation
- Merkle batch root generation

Build the Rust ledger server:

- `POST /v1/records`
- `GET /v1/records/{id}`
- `GET /v1/chain/head`
- `GET /v1/proofs/{batch_id}`

## Phase 3

Build the Go SDK:

- AI call wrapper
- `AuditRecord` construction
- local signing
- exporter transport

Build a sample app that emits records into the ledger.

## Phase 4

Build the report CLI:

- chain verification
- report assembly
- exception summary
- signed compliance artifact generation

