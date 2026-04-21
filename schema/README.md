# AuditRecord schema

The canonical machine-readable schema is:

- `auditrecord.schema.json` (current `version: v1`)

Reference example:

- `auditrecord.example.json`

Explainability contract:

- `explanation.rationale_summary` is required.
- `explanation.key_factors[]` captures weighted drivers used to reach the decision.
- `explanation.policy_trace[]` links explanation to concrete policy rules.

Versioning policy:

- Backward-compatible additions are published as minor schema updates.
- Breaking changes require a new top-level schema version (for example `v2`) and migration notes.
