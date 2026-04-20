package audit

import "context"

type Emitter struct {
	Builder  Builder
	Exporter Exporter
}

func (e Emitter) CaptureCall(ctx context.Context, meta CallMetadata, invoke func(context.Context) (AIResponse, error)) (*AuditRecord, error) {
	response, err := invoke(ctx)
	if err != nil {
		return nil, err
	}
	record, err := e.Builder.Build(ctx, meta, response)
	if err != nil {
		return nil, err
	}
	if err := e.Exporter.Export(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}
