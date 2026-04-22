package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type noopExporter struct{}

func (noopExporter) Export(context.Context, *AuditRecord) error { return nil }

type failingExporter struct {
	msg string
}

func (f failingExporter) Export(context.Context, *AuditRecord) error {
	return errors.New(f.msg)
}

func sampleMeta() CallMetadata {
	return CallMetadata{
		TenantID:            "tenant-a",
		AppName:             "app",
		Environment:         "test",
		ActorID:             "actor-1",
		TraceID:             "trace-1",
		ModelName:           "gpt-test",
		ProviderName:        "openai",
		Action:              "loan_decision",
		Category:            "credit",
		PolicyIDs:           []string{"policy-a"},
		RiskLevel:           "low",
		RequiresHumanReview: true,
	}
}

func sampleResponse() AIResponse {
	confidence := 0.9
	return AIResponse{
		Outcome:             "approved",
		Summary:             "approved under policy",
		Prompt:              "evaluate",
		ResponseBody:        "approved",
		ToolCalls:           []string{"tool-a"},
		RationaleSummary:    "score and dti passed",
		KeyFactors:          []ExplanationFactor{{Name: "credit_score", Weight: 0.62}},
		ConfidenceScore:     &confidence,
		AlternativeOutcomes: []string{"manual_review"},
		PolicyTrace:         []string{"policy-a.rule-1"},
	}
}

func testSigner() Signer {
	seed := sha256.Sum256([]byte("audit-test-seed"))
	return Signer{
		PublicKeyID: "test-key",
		PrivateKey:  ed25519.NewKeyFromSeed(seed[:]),
	}
}

func TestSignRecordHashesCanonicalBytes(t *testing.T) {
	builder := Builder{
		Signer: testSigner(),
		SequenceProvider: StaticSequenceProvider{
			Sequence:     0,
			PreviousHash: "GENESIS",
		},
	}
	record, err := builder.Build(context.Background(), sampleMeta(), sampleResponse())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	payload, err := canonicalPayload(record)
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	sum := sha256.Sum256(payload)
	expected := "sha256:" + hex.EncodeToString(sum[:])
	if record.Chain.RecordHash != expected {
		t.Fatalf("record hash mismatch got=%s expected=%s", record.Chain.RecordHash, expected)
	}
}

func TestCaptureCallMeasuresActualLatency(t *testing.T) {
	emitter := Emitter{
		Builder: Builder{
			Signer: testSigner(),
			SequenceProvider: StaticSequenceProvider{
				Sequence:     0,
				PreviousHash: "GENESIS",
			},
		},
		Exporter: noopExporter{},
	}

	record, err := emitter.CaptureCall(context.Background(), sampleMeta(), func(context.Context) (AIResponse, error) {
		time.Sleep(20 * time.Millisecond)
		return sampleResponse(), nil
	})
	if err != nil {
		t.Fatalf("capture call: %v", err)
	}
	if record.Timing.LatencyMS < 15 {
		t.Fatalf("latency too small got=%dms", record.Timing.LatencyMS)
	}
	if record.Policy.RequiresHumanReview != true {
		t.Fatalf("requires_human_review not propagated")
	}
}

func TestMultiExporterAggregatesErrors(t *testing.T) {
	m := MultiExporter{
		Exporters: []Exporter{
			failingExporter{msg: "ledger down"},
			noopExporter{},
			failingExporter{msg: "otlp unavailable"},
		},
	}
	err := m.Export(context.Background(), &AuditRecord{})
	if err == nil {
		t.Fatalf("expected joined error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ledger down") || !strings.Contains(msg, "otlp unavailable") {
		t.Fatalf("missing exporter errors in joined message: %s", msg)
	}
}

func TestLedgerChainSequenceProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"head_sequence":7,"head_hash":"sha256:abc","merkle_root":"sha256:def"}`))
	}))
	defer server.Close()

	provider := LedgerChainSequenceProvider{Endpoint: server.URL}
	sequence, previousHash, err := provider.Next(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if sequence != 8 || previousHash != "sha256:abc" {
		t.Fatalf("unexpected sequence response seq=%d prev=%s", sequence, previousHash)
	}
}
