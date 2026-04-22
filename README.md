# AI Audit Ledger

> Tamper-evident compliance logging for every AI decision. Ed25519-signed, Merkle-chained, OTel-compatible. Built for regulated industries.

---

## Why this exists

When an AI model approves a loan, flags fraud, or routes a medical triage — regulators will ask: *"Can you prove that decision hasn't been altered, and that it followed your stated policy at the time?"*

Most teams can't answer that. Their logs are mutable, unsigned, and not linked to anything verifiable.

**AI Audit Ledger** is the open-source infrastructure layer that changes this. Every LLM call your application makes is captured as a signed `AuditRecord`, appended to a cryptographically chained ledger, and Merkle-batched for efficient audit verification.

---

## How it works

```
Your App (Go SDK)
  │
  ├─ wraps your LLM call with emitter.CaptureCall(...)
  ├─ hashes prompt + response, captures policy context + latency
  ├─ signs the AuditRecord with Ed25519
  │
  └─► Ledger Server (Rust / Axum)
        ├─ verifies signature
        ├─ verifies chain link (previous_hash + sequence)
        ├─ appends to append-only JSONL store
        └─ batches record hashes into Merkle root
              │
              └─► report-cli  →  compliance report
```

**One line wraps a full LLM call:**

```go
record, err := emitter.CaptureCall(ctx, audit.CallMetadata{
    TenantID:     "bank-prod",
    AppName:      "loan-underwriter",
    ActorID:      "customer-9182",
    ModelName:    "gpt-4.1",
    ProviderName: "openai",
    Action:       "loan_decision",
    Category:     "credit",
    PolicyIDs:    []string{"loan-policy-v3", "ecoa-review-rule"},
    RiskLevel:    "medium",
}, func(ctx context.Context) (audit.AIResponse, error) {
    // your actual LLM call here
    return audit.AIResponse{
        Outcome:      "approved",
        Summary:      "Application approved within policy limits.",
        Prompt:       prompt,
        ResponseBody: response,
        ToolCalls:    []string{"fraud_check", "kyc_profile"},
    }, nil
})
```

The SDK intercepts the call, builds the `AuditRecord`, signs it, and ships it to the ledger server — all transparent to your business logic.

The `AuditRecord` captures both:
- what decision was made (`decision.outcome`, policy context)
- why it was made (`explanation.rationale_summary`, weighted factors, confidence, policy trace)

---

## Security model

Every `AuditRecord` carries:

- **Ed25519 signature** over the canonical JSON payload — proves the record came from a trusted SDK instance and hasn't been modified
- **SHA-256 record hash** — deterministically computed from the payload before signing
- **Previous hash chain link** — each record commits to the hash of the prior record; tampering breaks every subsequent link
- **Merkle root batching** — groups of record hashes are reduced to a single root for efficient proof generation at audit time

The ledger server rejects any record that fails signature verification, has a mismatched record hash, or breaks the chain link. The genesis record uses `"GENESIS"` as `previous_hash` at `sequence: 0`.

---

## AuditRecord schema

The canonical unit is the `AuditRecord`. Key fields:

| Field | Description |
|---|---|
| `record_id` | Stable UUID for the record |
| `tenant_id` | Tenant or org identifier |
| `application` | App name, environment, actor ID, OTel trace/span IDs |
| `model` | Provider, model name, temperature, tool calls used |
| `decision` | Category, action, outcome, prompt hash, response hash |
| `policy` | Applied policy IDs, risk level, human review flag |
| `timing` | `started_at`, `completed_at`, `latency_ms` |
| `chain` | Sequence number, previous hash, record hash, Merkle batch ID |
| `signature` | Algorithm (`Ed25519`), public key ID, base64 signature |
| `evidence` | Array of URI + digest pointers to prompt/response artifacts |

Full JSON Schema: [`schema/auditrecord.schema.json`](schema/auditrecord.schema.json)  
Example record: [`schema/auditrecord.example.json`](schema/auditrecord.example.json)

---

## Repository layout

```
├── schema/                  # Canonical AuditRecord JSON Schema + example
├── docs/                    # Architecture, OTel mapping, compliance report format, phases
├── crates/
│   ├── ledger-core/         # Rust: SHA-256 chaining, Ed25519 verification, Merkle tree
│   ├── ledger-server/       # Rust: Axum HTTP ingestion + append-only ledger service
│   └── report-cli/          # Rust: chain verification + compliance report generation
├── sdk/go/audit/            # Go: AuditRecord types, builder, Ed25519 signer, OTel exporter
└── examples/go-app/         # Go: end-to-end example (loan underwriter → bank-prod ledger)
```

---

## Getting started

**Run the ledger server (Rust):**

```bash
cargo build --release
mkdir -p data
./target/release/ledger-server
# Listening on 127.0.0.1:8080
```

Or run with Docker Compose:

```bash
docker compose up --build ledger-server
```

**Run the example Go app:**

```bash
cd examples/go-app
go run main.go
# emitted record 1745123456789-trace-001 with hash sha256:...
```

## Quickstart (end-to-end in 5 minutes)

Terminal 1:

```bash
cargo run -p ledger-server
```

Terminal 2:

```bash
go run ./examples/go-app
```

Verify chain head:

```bash
curl http://127.0.0.1:8080/v1/chain/head
```

**API endpoints:**

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/records` | Append a signed AuditRecord |
| `GET` | `/v1/records/:id` | Retrieve a record by ID |
| `GET` | `/v1/chain/head` | Current head sequence, hash, and Merkle root |
| `GET` | `/v1/proofs/:record_id` | Merkle proof for a specific record |
| `GET` | `/v1/proofs/head` | Merkle proof for the current chain head |

## Sample output

`POST /v1/records`

```json
{
  "accepted": true,
  "sequence": 42,
  "merkle_root": "sha256:8dff5b4c5ef4d50d78d0ff0a9f7b5e10e1b9e9d9f1cc1b2b655a4f39f13c5b43"
}
```

`GET /v1/proofs/head`

```json
{
  "record_id": "1745382544123456700-trace-001",
  "sequence": 42,
  "merkle_root": "sha256:8dff5b4c5ef4d50d78d0ff0a9f7b5e10e1b9e9d9f1cc1b2b655a4f39f13c5b43",
  "proof": {
    "leaf_index": 42,
    "leaf_value": "sha256:ec95b41ae9d8468c2f5e151f30b016493e730604bd51dbad8da8b6bd6b30a22c",
    "path": [
      {
        "hash": "sha256:b5c75fcbbe78f04f1a0f8b041aa4f4d18cc8af73a12306c2ad4ddfc4b3e4d7bf",
        "position": "Right"
      },
      {
        "hash": "sha256:77d64c1824d2f15ece33296a9e37265fe0e9f237f38ed91ef64f1b9f2ff12846",
        "position": "Left"
      }
    ],
    "root": "sha256:8dff5b4c5ef4d50d78d0ff0a9f7b5e10e1b9e9d9f1cc1b2b655a4f39f13c5b43"
  }
}
```

`outputs/report.json` (from `report-cli generate`)

```json
{
  "report": {
    "generated_at": "2026-04-22T11:15:43.196418Z",
    "tenant_id": "bank-prod",
    "record_count": 1,
    "head_sequence": 42,
    "head_hash": "sha256:ec95b41ae9d8468c2f5e151f30b016493e730604bd51dbad8da8b6bd6b30a22c",
    "merkle_root": "sha256:8dff5b4c5ef4d50d78d0ff0a9f7b5e10e1b9e9d9f1cc1b2b655a4f39f13c5b43",
    "proofs_generated": 1,
    "merkle_proof_validation_passed": true,
    "proofs": [
      {
        "leaf_index": 0,
        "leaf_value": "sha256:ec95b41ae9d8468c2f5e151f30b016493e730604bd51dbad8da8b6bd6b30a22c",
        "path": [],
        "root": "sha256:8dff5b4c5ef4d50d78d0ff0a9f7b5e10e1b9e9d9f1cc1b2b655a4f39f13c5b43"
      }
    ],
    "explainability_records": 1,
    "explainability_coverage_pct": 100.0,
    "top_explanatory_factors": [
      {
        "factor": "credit_score",
        "occurrences": 1,
        "avg_weight": 0.62
      },
      {
        "factor": "debt_to_income",
        "occurrences": 1,
        "avg_weight": 0.31
      }
    ],
    "policies_observed": [
      "loan-policy-v3"
    ],
    "outcomes": [
      "approved"
    ],
    "exceptions": []
  },
  "signature": {
    "algorithm": "Ed25519",
    "public_key_id": "report-key-1",
    "digest": "sha256:7108d8a8df98fce6400de0f6a84427f3f8edba0cd8ecef91aa8a80ecdeaf8df1",
    "signature": "base64:Y4R6xF0Mjbj8Ih8g2SYWVr4KxCV7W5PXhQ4D+ai3f3k3fQx7vUQ3uI2e+8C+K5kTFkS+J8Y4v43U1Kq7qxbhBw=="
  }
}
```

---

## Build and verify

### Rust

```bash
cargo check
cargo test
```

### Go

```bash
go build -buildvcs=false ./examples/go-app
```

### Signed compliance artifact

```bash
cargo run -p report-cli -- generate data/ledger.jsonl outputs/report.json <private_key_hex_64> report-key-1
cargo run -p report-cli -- verify outputs/report.json <public_key_hex_64>
```

---

## Build status

| Phase | Status | Description |
|---|---|---|
| 1 — Schema & structure | Done | AuditRecord schema, docs, repo layout |
| 2 — Rust ledger core |  Done | SHA-256 chaining, Ed25519 verification, Merkle tree, Axum server |
| 3 — Go SDK + exporter |  Done | Builder, signer, native OTel span exporter, end-to-end example |
| 4 — Report CLI |  In progress | Chain verification + regulator-facing compliance reports |

---

## Roadmap

- [ ] `report-cli`: full chain walk + Merkle proof generation
- [ ] Compliance report renderer (JSON + human-readable)
- [x] Ledger-backed sequence provider (`LedgerChainSequenceProvider`) for multi-record chains
- [ ] Multi-tenant key registry
- [ ] Anchoring: publish Merkle roots to a transparency log


---

## License

Apache-2.0 for core components in this repository.

BSL-1.1 for cloud-layer code under `cloud/`, converting to Apache-2.0 on the change date in `LICENSES/BSL-1.1.md`.

See `docs/licensing.md` for the exact boundary.

## Community

- Contribution guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Issue templates: `.github/ISSUE_TEMPLATE/`
- Security policy: `SECURITY.md`
