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
use ledger_core::{chain::verify_chain_link, merkle::compute_merkle_root, record::AuditRecord};
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

fn internal_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, error.to_string())
}
