package audit

import "time"

type AuditRecord struct {
	Version     string              `json:"version"`
	RecordID    string              `json:"record_id"`
	TenantID    string              `json:"tenant_id"`
	Application ApplicationContext  `json:"application"`
	Model       ModelContext        `json:"model"`
	Decision    DecisionContext     `json:"decision"`
	Explanation *ExplanationContext `json:"explanation,omitempty"`
	Policy      PolicyContext       `json:"policy"`
	Timing      TimingContext       `json:"timing"`
	Chain       ChainContext        `json:"chain"`
	Signature   SignatureEnvelope   `json:"signature"`
	Evidence    []EvidencePointer   `json:"evidence"`
}

type ApplicationContext struct {
	Name        string  `json:"name"`
	Environment string  `json:"environment"`
	ActorID     string  `json:"actor_id"`
	TraceID     string  `json:"trace_id"`
	SpanID      *string `json:"span_id,omitempty"`
}

type ModelContext struct {
	Provider    string   `json:"provider"`
	Name        string   `json:"name"`
	Temperature *float64 `json:"temperature,omitempty"`
	ToolCalls   []string `json:"tool_calls,omitempty"`
}

type DecisionContext struct {
	Category     string  `json:"category"`
	Action       string  `json:"action"`
	Outcome      string  `json:"outcome"`
	Summary      *string `json:"summary,omitempty"`
	PromptHash   *string `json:"prompt_hash,omitempty"`
	ResponseHash *string `json:"response_hash,omitempty"`
}

type ExplanationContext struct {
	RationaleSummary    string              `json:"rationale_summary"`
	KeyFactors          []ExplanationFactor `json:"key_factors"`
	ConfidenceScore     *float64            `json:"confidence_score,omitempty"`
	AlternativeOutcomes []string            `json:"alternative_outcomes,omitempty"`
	PolicyTrace         []string            `json:"policy_trace,omitempty"`
}

type ExplanationFactor struct {
	Name     string  `json:"name"`
	Weight   float64 `json:"weight"`
	Evidence *string `json:"evidence,omitempty"`
}

type PolicyContext struct {
	PolicyIDs           []string `json:"policy_ids"`
	RiskLevel           string   `json:"risk_level"`
	RequiresHumanReview bool     `json:"requires_human_review"`
}

type TimingContext struct {
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	LatencyMS   int64     `json:"latency_ms"`
}

type ChainContext struct {
	Sequence      uint64  `json:"sequence"`
	PreviousHash  string  `json:"previous_hash"`
	RecordHash    string  `json:"record_hash"`
	MerkleBatchID *string `json:"merkle_batch_id,omitempty"`
}

type SignatureEnvelope struct {
	Algorithm   string `json:"algorithm"`
	PublicKeyID string `json:"public_key_id"`
	Signature   string `json:"signature"`
}

type EvidencePointer struct {
	Kind   string  `json:"kind"`
	URI    string  `json:"uri"`
	Digest *string `json:"digest,omitempty"`
}

type CallMetadata struct {
	TenantID            string
	AppName             string
	Environment         string
	ActorID             string
	TraceID             string
	ModelName           string
	ProviderName        string
	Action              string
	Category            string
	PolicyIDs           []string
	RiskLevel           string
	RequiresHumanReview bool
}

type AIResponse struct {
	Outcome             string
	Summary             string
	Prompt              string
	ResponseBody        string
	ToolCalls           []string
	RationaleSummary    string
	KeyFactors          []ExplanationFactor
	ConfidenceScore     *float64
	AlternativeOutcomes []string
	PolicyTrace         []string
}
