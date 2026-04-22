package audit

import (
	"context"
	"errors"
)

type MultiExporter struct {
	Exporters []Exporter
}

func (m MultiExporter) Export(ctx context.Context, record *AuditRecord) error {
	var errs []error
	for _, exporter := range m.Exporters {
		if err := exporter.Export(ctx, record); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
