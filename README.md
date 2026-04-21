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
- [ ] Persistent sequence provider (replace `StaticSequenceProvider` with ledger-backed)
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
