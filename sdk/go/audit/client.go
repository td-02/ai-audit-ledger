package audit

import (
	"context"
	"time"
)

type Emitter struct {
	Builder  Builder
	Exporter Exporter
}

func (e Emitter) CaptureCall(ctx context.Context, meta CallMetadata, invoke func(context.Context) (AIResponse, error)) (*AuditRecord, error) {
	started := time.Now().UTC()
	response, err := invoke(ctx)
	completed := time.Now().UTC()
	if err != nil {
		return nil, err
	}
	record, err := e.Builder.BuildWithTiming(ctx, meta, response, started, completed)
	if err != nil {
		return nil, err
	}
	if err := e.Exporter.Export(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}
