# System Architecture Flow

## End-to-end path

1. Application code invokes an AI model through the Go SDK wrapper.
2. The wrapper captures the prompt, model identifier, tool usage, policy context, latency, and outcome.
3. The SDK constructs an `AuditRecord` with:
   - deterministic record hash
   - previous record hash
   - actor and tenant identifiers
   - decision metadata
   - evidence pointers
4. The SDK signs the record payload with an Ed25519 private key.
5. The exporter sends the record to the ledger collector over an OTel-aligned envelope.
6. The ledger server validates the signature, sequence, and hash links.
7. The accepted record is atomically appended to storage.
8. A background Merkle accumulator batches record hashes into signed roots.
9. The reporting pipeline verifies the full chain and selected Merkle proofs.
10. A compliance report is rendered from verified records, policy labels, and exceptions.

## Design choices

### Rust ledger server

The ledger is correctness-critical. Rust keeps the append and verification path memory-safe while making ownership and mutation boundaries explicit.

### Merkle tree plus Ed25519 chain

The per-record chain makes localized tampering obvious. The Merkle layer adds efficient batch verification, anchoring, and report-time proof generation.

### OpenTelemetry wire model

Engineering teams already ship spans and events. Treating an audit emission as a specialized exporter reduces adoption friction and lets this system fit existing observability rollouts.

### Open core licensing

The repo is structured so the protocol and core primitives can remain open while cloud-only commercial control points stay separable.

