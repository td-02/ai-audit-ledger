package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type Exporter interface {
	Export(ctx context.Context, record *AuditRecord) error
}

type LedgerHTTPExporter struct {
	Endpoint   string
	HTTPClient *http.Client
}

func (e LedgerHTTPExporter) Export(ctx context.Context, record *AuditRecord) error {
	client := e.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	body, err := json.Marshal(record)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint+"/v1/records", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("ledger rejected audit record with status %d", resp.StatusCode)
	}
	return nil
}

// Backward-compatible alias from the initial scaffold.
type OTLPAuditExporter = LedgerHTTPExporter
