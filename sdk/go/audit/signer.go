package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	sum := sha256.Sum256(payload)
	record.Chain.RecordHash = fmt.Sprintf("sha256:%s", hex.EncodeToString(sum[:]))
	record.Signature = SignatureEnvelope{
		Algorithm:   "Ed25519",
		PublicKeyID: s.PublicKeyID,
		Signature:   "base64:" + base64.StdEncoding.EncodeToString(ed25519.Sign(s.PrivateKey, payload)),
	}
	return nil
}
