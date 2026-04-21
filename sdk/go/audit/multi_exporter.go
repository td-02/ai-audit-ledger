package audit

import "context"

type MultiExporter struct {
	Exporters []Exporter
}

func (m MultiExporter) Export(ctx context.Context, record *AuditRecord) error {
	for _, exporter := range m.Exporters {
		if err := exporter.Export(ctx, record); err != nil {
			return err
		}
	}
	return nil
}
