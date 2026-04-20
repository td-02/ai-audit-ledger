package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/TAPESH/ai-audit-ledger/sdk/go/audit"
)

func main() {
	ctx := context.Background()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	emitter := audit.Emitter{
		Builder: audit.Builder{
			Signer: audit.Signer{
				PublicKeyID: "demo-key-1",
				PrivateKey:  privateKey,
			},
			SequenceProvider: audit.StaticSequenceProvider{
				Sequence:     0,
				PreviousHash: "GENESIS",
			},
		},
		Exporter: audit.OTLPAuditExporter{
			Endpoint: "http://127.0.0.1:8080",
		},
	}

	record, err := emitter.CaptureCall(ctx, audit.CallMetadata{
		TenantID:     "bank-prod",
		AppName:      "loan-underwriter",
		Environment:  "prod",
		ActorID:      "customer-9182",
		TraceID:      "trace-001",
		ModelName:    "gpt-4.1",
		ProviderName: "openai",
		Action:       "loan_decision",
		Category:     "credit",
		PolicyIDs:    []string{"loan-policy-v3", "ecoa-review-rule"},
		RiskLevel:    "medium",
	}, func(context.Context) (audit.AIResponse, error) {
		return audit.AIResponse{
			Outcome:      "approved",
			Summary:      "Application approved within policy limits.",
			Prompt:       "Evaluate this application against credit policy.",
			ResponseBody: `{"result":"approved"}`,
			ToolCalls:    []string{"fraud_check", "kyc_profile"},
		}, nil
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("emitted record %s with hash %s\n", record.RecordID, record.Chain.RecordHash)
}
