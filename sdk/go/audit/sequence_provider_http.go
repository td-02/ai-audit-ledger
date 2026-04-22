package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type LedgerChainSequenceProvider struct {
	Endpoint   string
	HTTPClient *http.Client
}

type chainHeadResponse struct {
	HeadSequence *uint64 `json:"head_sequence"`
	HeadHash     *string `json:"head_hash"`
	MerkleRoot   string  `json:"merkle_root"`
}

func (p LedgerChainSequenceProvider) Next(ctx context.Context, _ string) (uint64, string, error) {
	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	endpoint := strings.TrimRight(p.Endpoint, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/chain/head", nil)
	if err != nil {
		return 0, "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return 0, "", fmt.Errorf("ledger head query failed with status %d", resp.StatusCode)
	}

	var head chainHeadResponse
	if err := json.NewDecoder(resp.Body).Decode(&head); err != nil {
		return 0, "", err
	}
	if head.HeadSequence == nil || head.HeadHash == nil {
		return 0, "GENESIS", nil
	}
	return *head.HeadSequence + 1, *head.HeadHash, nil
}
