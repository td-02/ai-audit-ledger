use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use ledger_core::{
    chain::verify_chain_link,
    merkle::{build_merkle_proof, compute_merkle_root, MerkleProof},
    record::AuditRecord,
};
use serde::Serialize;
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    sync::Mutex,
};
use tower_http::trace::TraceLayer;

#[derive(Clone)]
struct AppState {
    storage: Arc<Mutex<LedgerStore>>,
}

#[derive(Debug)]
struct LedgerStore {
    path: PathBuf,
    records: Vec<AuditRecord>,
}

#[derive(Serialize)]
struct AppendResponse {
    accepted: bool,
    sequence: u64,
    merkle_root: String,
}

#[derive(Serialize)]
struct ChainHeadResponse {
    head_sequence: Option<u64>,
    head_hash: Option<String>,
    merkle_root: String,
}

#[derive(Serialize)]
struct RecordProofResponse {
    record_id: String,
    sequence: u64,
    merkle_root: String,
    proof: MerkleProof,
}

#[derive(Serialize)]
struct HeadProofResponse {
    record_id: String,
    sequence: u64,
    merkle_root: String,
    proof: MerkleProof,
}

impl LedgerStore {
    async fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut records = Vec::new();
        if let Ok(content) = fs::read_to_string(&path).await {
            for line in content.lines().filter(|line| !line.trim().is_empty()) {
                records.push(serde_json::from_str(line)?);
            }
        }
        Ok(Self { path, records })
    }

    fn head_hash(&self) -> Option<&str> {
        self.records.last().map(|r| r.chain.record_hash.as_str())
    }

    fn merkle_root(&self) -> String {
        let leaves: Vec<String> = self
            .records
            .iter()
            .map(|record| record.chain.record_hash.clone())
            .collect();
        compute_merkle_root(&leaves)
    }

    fn proof_by_record_id(&self, record_id: &str) -> Option<RecordProofResponse> {
        let leaf_index = self
            .records
            .iter()
            .position(|record| record.record_id == record_id)?;
        let leaves = self
            .records
            .iter()
            .map(|record| record.chain.record_hash.clone())
            .collect::<Vec<_>>();
        let proof = build_merkle_proof(&leaves, leaf_index)?;
        let record = &self.records[leaf_index];
        Some(RecordProofResponse {
            record_id: record.record_id.clone(),
            sequence: record.chain.sequence,
            merkle_root: self.merkle_root(),
            proof,
        })
    }

    fn head_proof(&self) -> Option<HeadProofResponse> {
        if self.records.is_empty() {
            return None;
        }
        let leaf_index = self.records.len() - 1;
        let leaves = self
            .records
            .iter()
            .map(|record| record.chain.record_hash.clone())
            .collect::<Vec<_>>();
        let proof = build_merkle_proof(&leaves, leaf_index)?;
        let record = &self.records[leaf_index];
        Some(HeadProofResponse {
            record_id: record.record_id.clone(),
            sequence: record.chain.sequence,
            merkle_root: self.merkle_root(),
            proof,
        })
    }

    async fn append(&mut self, record: AuditRecord) -> Result<()> {
        verify_chain_link(&record, self.head_hash())?;
        let encoded = serde_json::to_string(&record)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .with_context(|| format!("opening ledger file {}", self.path.display()))?;
        file.write_all(encoded.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        self.records.push(record);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info,ledger_server=debug")
        .init();

    let storage = LedgerStore::load("data/ledger.jsonl").await?;
    let state = AppState {
        storage: Arc::new(Mutex::new(storage)),
    };

    let app = Router::new()
        .route("/v1/records", post(post_record))
        .route("/v1/records/:record_id", get(get_record))
        .route("/v1/chain/head", get(get_chain_head))
        .route("/v1/proofs/:record_id", get(get_record_proof))
        .route("/v1/proofs/head", get(get_head_proof))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    tracing::info!("ledger server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn post_record(
    State(state): State<AppState>,
    Json(record): Json<AuditRecord>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut storage = state.storage.lock().await;
    storage
        .append(record.clone())
        .await
        .map_err(internal_error)?;
    Ok(Json(AppendResponse {
        accepted: true,
        sequence: record.chain.sequence,
        merkle_root: storage.merkle_root(),
    }))
}

async fn get_record(
    AxumPath(record_id): AxumPath<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let storage = state.storage.lock().await;
    let record = storage
        .records
        .iter()
        .find(|record| record.record_id == record_id)
        .cloned()
        .ok_or_else(|| (StatusCode::NOT_FOUND, "record not found".to_string()))?;
    Ok(Json(record))
}

async fn get_chain_head(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let storage = state.storage.lock().await;
    let head = storage.records.last();
    Ok(Json(ChainHeadResponse {
        head_sequence: head.map(|record| record.chain.sequence),
        head_hash: head.map(|record| record.chain.record_hash.clone()),
        merkle_root: storage.merkle_root(),
    }))
}

async fn get_record_proof(
    AxumPath(record_id): AxumPath<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let storage = state.storage.lock().await;
    let proof = storage
        .proof_by_record_id(&record_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "record proof not found".to_string()))?;
    Ok(Json(proof))
}

async fn get_head_proof(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let storage = state.storage.lock().await;
    let proof = storage.head_proof().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "head proof not available".to_string(),
        )
    })?;
    Ok(Json(proof))
}

fn internal_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::LedgerStore;
    use ledger_core::{
        chain::compute_record_hash,
        record::{
            ApplicationContext, AuditRecord, ChainContext, DecisionContext, EvidencePointer,
            ModelContext, PolicyContext, SignatureEnvelope, TimingContext,
        },
    };
    use std::path::PathBuf;

    fn make_record(sequence: u64, previous_hash: String, record_id: &str) -> AuditRecord {
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-02-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        let completed_at = chrono::DateTime::parse_from_rfc3339("2026-02-01T00:00:01Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        let mut record = AuditRecord {
            version: "v1".to_string(),
            record_id: record_id.to_string(),
            tenant_id: "tenant-1".to_string(),
            application: ApplicationContext {
                name: "app".to_string(),
                environment: "test".to_string(),
                actor_id: "actor-1".to_string(),
                trace_id: format!("trace-{record_id}"),
                span_id: None,
            },
            model: ModelContext {
                provider: "openai".to_string(),
                name: "gpt-x".to_string(),
                temperature: None,
                tool_calls: vec![],
            },
            decision: DecisionContext {
                category: "risk".to_string(),
                action: "review".to_string(),
                outcome: "approved".to_string(),
                summary: None,
                prompt_hash: None,
                response_hash: None,
            },
            explanation: None,
            policy: PolicyContext {
                policy_ids: vec!["policy-a".to_string()],
                risk_level: "low".to_string(),
                requires_human_review: Some(false),
            },
            timing: TimingContext {
                started_at,
                completed_at,
                latency_ms: 1000,
            },
            chain: ChainContext {
                sequence,
                previous_hash,
                record_hash: String::new(),
                merkle_batch_id: None,
            },
            signature: SignatureEnvelope {
                algorithm: "Ed25519".to_string(),
                public_key_id: "test-key".to_string(),
                signature: "base64:unused".to_string(),
            },
            evidence: vec![EvidencePointer {
                kind: "prompt".to_string(),
                uri: "memory://prompt".to_string(),
                digest: None,
            }],
        };
        record.chain.record_hash = compute_record_hash(&record).expect("hash");
        record
    }

    #[test]
    fn proof_by_record_id_returns_merkle_proof() {
        let first = make_record(0, "GENESIS".to_string(), "r1");
        let second = make_record(1, first.chain.record_hash.clone(), "r2");
        let store = LedgerStore {
            path: PathBuf::from("data/test-ledger.jsonl"),
            records: vec![first, second],
        };

        let proof = store.proof_by_record_id("r1").expect("proof");
        assert_eq!(proof.record_id, "r1");
        assert!(proof.merkle_root.starts_with("sha256:"));
        assert!(!proof.proof.path.is_empty());
    }

    #[test]
    fn head_proof_returns_latest_record_proof() {
        let first = make_record(0, "GENESIS".to_string(), "r1");
        let second = make_record(1, first.chain.record_hash.clone(), "r2");
        let store = LedgerStore {
            path: PathBuf::from("data/test-ledger.jsonl"),
            records: vec![first, second],
        };

        let proof = store.head_proof().expect("proof");
        assert_eq!(proof.record_id, "r2");
        assert_eq!(proof.sequence, 1);
    }
}
