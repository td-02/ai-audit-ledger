package audit

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const defaultInstrumentationName = "github.com/td-02/ai-audit-ledger/sdk/go/audit"

// OTelSpanExporter emits one OpenTelemetry span per audit record. It can be
// used with any existing app-level TracerProvider.
type OTelSpanExporter struct {
	Tracer trace.Tracer
}

func NewOTelSpanExporter(tracer trace.Tracer) OTelSpanExporter {
	return OTelSpanExporter{Tracer: tracer}
}

func (e OTelSpanExporter) Export(ctx context.Context, record *AuditRecord) error {
	tracer := e.Tracer
	if tracer == nil {
		tracer = otel.Tracer(defaultInstrumentationName)
	}

	spanCtx, span := tracer.Start(
		ctx,
		"ai.audit.record",
		trace.WithTimestamp(record.Timing.StartedAt),
		trace.WithSpanKind(trace.SpanKindInternal),
	)

	attrs := []attribute.KeyValue{
		attribute.String("audit.record_id", record.RecordID),
		attribute.String("audit.tenant_id", record.TenantID),
		attribute.String("audit.chain.record_hash", record.Chain.RecordHash),
		attribute.String("audit.chain.previous_hash", record.Chain.PreviousHash),
		attribute.Int64("audit.chain.sequence", int64(record.Chain.Sequence)),
		attribute.String("audit.signature.algorithm", record.Signature.Algorithm),
		attribute.String("audit.signature.public_key_id", record.Signature.PublicKeyID),
		attribute.String("audit.application.name", record.Application.Name),
		attribute.String("audit.application.environment", record.Application.Environment),
		attribute.String("audit.application.actor_id", record.Application.ActorID),
		attribute.String("audit.application.trace_id", record.Application.TraceID),
		attribute.String("audit.model.provider", record.Model.Provider),
		attribute.String("audit.model.name", record.Model.Name),
		attribute.String("audit.decision.category", record.Decision.Category),
		attribute.String("audit.decision.action", record.Decision.Action),
		attribute.String("audit.decision.outcome", record.Decision.Outcome),
		attribute.StringSlice("audit.policy.ids", record.Policy.PolicyIDs),
		attribute.String("audit.policy.risk_level", record.Policy.RiskLevel),
		attribute.Int64("audit.timing.latency_ms", record.Timing.LatencyMS),
	}

	if record.Application.SpanID != nil {
		attrs = append(attrs, attribute.String("audit.application.span_id", *record.Application.SpanID))
	}
	if record.Decision.PromptHash != nil {
		attrs = append(attrs, attribute.String("audit.decision.prompt_hash", *record.Decision.PromptHash))
	}
	if record.Decision.ResponseHash != nil {
		attrs = append(attrs, attribute.String("audit.decision.response_hash", *record.Decision.ResponseHash))
	}
	if record.Chain.MerkleBatchID != nil {
		attrs = append(attrs, attribute.String("audit.chain.merkle_batch_id", *record.Chain.MerkleBatchID))
	}

	span.SetAttributes(attrs...)
	span.SetStatus(codes.Ok, "audit record emitted")
	span.End(trace.WithTimestamp(record.Timing.CompletedAt))

	_ = spanCtx
	return nil
}

// OTLPSpanPipeline provisions an OTLP/HTTP pipeline and an exporter that emits
// audit records as spans into that pipeline.
type OTLPSpanPipeline struct {
	Exporter OTelSpanExporter
	shutdown func(context.Context) error
}

func (p *OTLPSpanPipeline) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

func NewOTLPSpanPipeline(ctx context.Context, serviceName, endpoint string) (*OTLPSpanPipeline, error) {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")),
	}
	if strings.HasPrefix(endpoint, "http://") {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	traceExporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(
		ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
	)
	if err != nil {
		return nil, err
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)

	tracer := provider.Tracer(defaultInstrumentationName)
	return &OTLPSpanPipeline{
		Exporter: NewOTelSpanExporter(tracer),
		shutdown: provider.Shutdown,
	}, nil
}
