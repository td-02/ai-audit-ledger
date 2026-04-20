package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type Signer struct {
	PublicKeyID string
	PrivateKey  ed25519.PrivateKey
}

func (s Signer) SignRecord(record *AuditRecord) error {
	payload, err := canonicalPayload(record)
	if err != nil {
		return err
	}
	record.Chain.RecordHash = hashJSON(payload)
	record.Signature = SignatureEnvelope{
		Algorithm:   "Ed25519",
		PublicKeyID: s.PublicKeyID,
		Signature:   "base64:" + base64.StdEncoding.EncodeToString(ed25519.Sign(s.PrivateKey, payload)),
	}
	return nil
}

func hashJSON(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(sum[:]))
}
