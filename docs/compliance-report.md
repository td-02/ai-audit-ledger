# Compliance Report Flow

The report layer is verifier-first rather than dashboard-first.

## Inputs

- append-only `ledger.jsonl` file
- canonical `AuditRecord` schema
- chain and Merkle verification routines from `ledger-core`

## Verification steps

1. Read every record in order.
2. Recompute each canonical record hash.
3. Validate the `previous_hash` link against the prior accepted record.
4. Recompute the ledger-wide Merkle root.
5. Generate a Merkle proof for each record and verify proof validity against the root.
6. Extract policy, outcome, and exception summaries.
7. Render a machine-readable compliance artifact.

## Output shape

The current CLI outputs a signed JSON report artifact containing:

- tenant identifier
- total verified record count
- chain head sequence and hash
- Merkle root
- number of generated Merkle proofs and pass/fail verification status
- full Merkle proofs for each record hash
- explainability coverage (`explainability_records`, `explainability_coverage_pct`)
- top explanatory factors with occurrence count and average weight
- observed policy identifiers
- observed decision outcomes
- exception list

## CLI

Generate signed report:

`report-cli generate <ledger.jsonl> <report.json> <private_key_hex> <public_key_id>`

Verify signed report:

`report-cli verify <report.json> <public_key_hex>`

This is the bridge from engineering evidence to auditor-facing artifacts.
