use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub version: String,
    pub record_id: String,
    pub tenant_id: String,
    pub application: ApplicationContext,
    pub model: ModelContext,
    pub decision: DecisionContext,
    #[serde(default)]
    pub explanation: Option<ExplanationContext>,
    pub policy: PolicyContext,
    pub timing: TimingContext,
    pub chain: ChainContext,
    pub signature: SignatureEnvelope,
    pub evidence: Vec<EvidencePointer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationContext {
    pub name: String,
    pub environment: String,
    pub actor_id: String,
    pub trace_id: String,
    pub span_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelContext {
    pub provider: String,
    pub name: String,
    pub temperature: Option<f64>,
    #[serde(default)]
    pub tool_calls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionContext {
    pub category: String,
    pub action: String,
    pub outcome: String,
    pub summary: Option<String>,
    pub prompt_hash: Option<String>,
    pub response_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationContext {
    pub rationale_summary: String,
    #[serde(default)]
    pub key_factors: Vec<ExplanationFactor>,
    pub confidence_score: Option<f64>,
    #[serde(default)]
    pub alternative_outcomes: Vec<String>,
    #[serde(default)]
    pub policy_trace: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationFactor {
    pub name: String,
    pub weight: f64,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub policy_ids: Vec<String>,
    pub risk_level: String,
    pub requires_human_review: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingContext {
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainContext {
    pub sequence: u64,
    pub previous_hash: String,
    pub record_hash: String,
    pub merkle_batch_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub public_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePointer {
    pub kind: String,
    pub uri: String,
    pub digest: Option<String>,
}
