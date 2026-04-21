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

The current CLI outputs a JSON report containing:

- tenant identifier
- total verified record count
- chain head sequence and hash
- Merkle root
- number of generated Merkle proofs and pass/fail verification status
- observed policy identifiers
- observed decision outcomes
- exception list

This is the bridge from engineering evidence to auditor-facing artifacts.
