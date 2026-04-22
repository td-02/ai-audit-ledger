package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type SequenceProvider interface {
	Next(ctx context.Context, tenantID string) (sequence uint64, previousHash string, err error)
}

type StaticSequenceProvider struct {
	Sequence     uint64
	PreviousHash string
}

func (s StaticSequenceProvider) Next(context.Context, string) (uint64, string, error) {
	return s.Sequence, s.PreviousHash, nil
}

type Builder struct {
	Signer           Signer
	SequenceProvider SequenceProvider
}

func (b Builder) Build(ctx context.Context, meta CallMetadata, response AIResponse) (*AuditRecord, error) {
	started := time.Now().UTC()
	completed := time.Now().UTC()
	return b.BuildWithTiming(ctx, meta, response, started, completed)
}

func (b Builder) BuildWithTiming(
	ctx context.Context,
	meta CallMetadata,
	response AIResponse,
	started time.Time,
	completed time.Time,
) (*AuditRecord, error) {
	if completed.Before(started) {
		completed = started
	}

	sequence, previousHash, err := b.SequenceProvider.Next(ctx, meta.TenantID)
	if err != nil {
		return nil, err
	}

	summary := response.Summary
	record := &AuditRecord{
		Version:  "v1",
		RecordID: fmt.Sprintf("%d-%s", time.Now().UnixNano(), meta.TraceID),
		TenantID: meta.TenantID,
		Application: ApplicationContext{
			Name:        meta.AppName,
			Environment: meta.Environment,
			ActorID:     meta.ActorID,
			TraceID:     meta.TraceID,
		},
		Model: ModelContext{
			Provider:  meta.ProviderName,
			Name:      meta.ModelName,
			ToolCalls: response.ToolCalls,
		},
		Decision: DecisionContext{
			Category:     meta.Category,
			Action:       meta.Action,
			Outcome:      response.Outcome,
			Summary:      &summary,
			PromptHash:   ptr(sha256Text(response.Prompt)),
			ResponseHash: ptr(sha256Text(response.ResponseBody)),
		},
		Explanation: &ExplanationContext{
			RationaleSummary:    response.RationaleSummary,
			KeyFactors:          append([]ExplanationFactor{}, response.KeyFactors...),
			ConfidenceScore:     response.ConfidenceScore,
			AlternativeOutcomes: response.AlternativeOutcomes,
			PolicyTrace:         response.PolicyTrace,
		},
		Policy: PolicyContext{
			PolicyIDs:           meta.PolicyIDs,
			RiskLevel:           meta.RiskLevel,
			RequiresHumanReview: meta.RequiresHumanReview,
		},
		Timing: TimingContext{
			StartedAt:   started,
			CompletedAt: completed,
			LatencyMS:   completed.Sub(started).Milliseconds(),
		},
		Chain: ChainContext{
			Sequence:     sequence,
			PreviousHash: previousHash,
		},
		Evidence: []EvidencePointer{
			{Kind: "prompt", URI: fmt.Sprintf("memory://prompt/%s", meta.TraceID), Digest: ptr(sha256Text(response.Prompt))},
			{Kind: "response", URI: fmt.Sprintf("memory://response/%s", meta.TraceID), Digest: ptr(sha256Text(response.ResponseBody))},
		},
	}

	if err := b.Signer.SignRecord(record); err != nil {
		return nil, err
	}
	return record, nil
}

func canonicalPayload(record *AuditRecord) ([]byte, error) {
	type canonicalChain struct {
		PreviousHash string `json:"previous_hash"`
		Sequence     uint64 `json:"sequence"`
	}
	type canonicalAuditPayload struct {
		Application ApplicationContext  `json:"application"`
		Chain       canonicalChain      `json:"chain"`
		Decision    DecisionContext     `json:"decision"`
		Explanation *ExplanationContext `json:"explanation"`
		Evidence    []EvidencePointer   `json:"evidence"`
		Model       ModelContext        `json:"model"`
		Policy      PolicyContext       `json:"policy"`
		RecordID    string              `json:"record_id"`
		TenantID    string              `json:"tenant_id"`
		Timing      TimingContext       `json:"timing"`
		Version     string              `json:"version"`
	}
	payload := canonicalAuditPayload{
		Application: record.Application,
		Chain: canonicalChain{
			PreviousHash: record.Chain.PreviousHash,
			Sequence:     record.Chain.Sequence,
		},
		Decision:    record.Decision,
		Explanation: record.Explanation,
		Evidence:    record.Evidence,
		Model:       record.Model,
		Policy:      record.Policy,
		RecordID:    record.RecordID,
		TenantID:    record.TenantID,
		Timing:      record.Timing,
		Version:     record.Version,
	}
	return json.Marshal(payload)
}

func sha256Text(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ptr[T any](v T) *T {
	return &v
}
