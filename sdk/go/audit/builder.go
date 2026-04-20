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
	completed := started.Add(50 * time.Millisecond)

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
		Policy: PolicyContext{
			PolicyIDs:           meta.PolicyIDs,
			RiskLevel:           meta.RiskLevel,
			RequiresHumanReview: false,
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
	payload := map[string]any{
		"application": record.Application,
		"chain": map[string]any{
			"previous_hash": record.Chain.PreviousHash,
			"sequence":      record.Chain.Sequence,
		},
		"decision":  record.Decision,
		"evidence":  record.Evidence,
		"model":     record.Model,
		"policy":    record.Policy,
		"record_id": record.RecordID,
		"tenant_id": record.TenantID,
		"timing":    record.Timing,
		"version":   record.Version,
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
