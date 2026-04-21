use anyhow::{anyhow, bail, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::record::AuditRecord;

pub fn canonical_payload(record: &AuditRecord) -> Value {
    json!({
        "application": record.application,
        "chain": {
            "previous_hash": record.chain.previous_hash,
            "sequence": record.chain.sequence
        },
        "decision": record.decision,
        "evidence": record.evidence,
        "model": record.model,
        "policy": record.policy,
        "record_id": record.record_id,
        "tenant_id": record.tenant_id,
        "timing": record.timing,
        "version": record.version
    })
}

pub fn compute_record_hash(record: &AuditRecord) -> Result<String> {
    let canonical = serde_json::to_vec(&canonical_payload(record))?;
    let digest = Sha256::digest(canonical);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

pub fn verify_chain_link(record: &AuditRecord, previous_record_hash: Option<&str>) -> Result<()> {
    let computed = compute_record_hash(record)?;
    if record.chain.record_hash != computed {
        bail!("record hash mismatch");
    }

    match previous_record_hash {
        Some(expected_previous) if expected_previous != record.chain.previous_hash => {
            bail!("previous hash mismatch")
        }
        None if record.chain.sequence != 0 => bail!("first record must start at sequence 0"),
        None if record.chain.previous_hash != "GENESIS" => {
            bail!("first record must use GENESIS previous hash")
        }
        _ => Ok(()),
    }
}

pub fn verify_signature(record: &AuditRecord, public_key_bytes: &[u8]) -> Result<()> {
    let payload = serde_json::to_vec(&canonical_payload(record))?;
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .try_into()
            .map_err(|_| anyhow!("public key must be 32 bytes"))?,
    )?;
    let signature_raw = record
        .signature
        .signature
        .strip_prefix("base64:")
        .unwrap_or(&record.signature.signature);
    let signature =
        Signature::from_slice(&base64::engine::general_purpose::STANDARD.decode(signature_raw)?)?;
    verifying_key.verify(&payload, &signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{
        ApplicationContext, ChainContext, DecisionContext, EvidencePointer, ModelContext,
        PolicyContext, SignatureEnvelope, TimingContext,
    };
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::Digest;

    fn sample_record() -> AuditRecord {
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let completed_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:01Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        AuditRecord {
            version: "v1".to_string(),
            record_id: "rec-1".to_string(),
            tenant_id: "tenant-a".to_string(),
            application: ApplicationContext {
                name: "app".to_string(),
                environment: "test".to_string(),
                actor_id: "actor-1".to_string(),
                trace_id: "trace-1".to_string(),
                span_id: Some("span-1".to_string()),
            },
            model: ModelContext {
                provider: "openai".to_string(),
                name: "gpt-x".to_string(),
                temperature: Some(0.2),
                tool_calls: vec!["tool-a".to_string()],
            },
            decision: DecisionContext {
                category: "risk".to_string(),
                action: "approve".to_string(),
                outcome: "allowed".to_string(),
                summary: Some("ok".to_string()),
                prompt_hash: Some("sha256:prompt".to_string()),
                response_hash: Some("sha256:response".to_string()),
            },
            policy: PolicyContext {
                policy_ids: vec!["policy-1".to_string()],
                risk_level: "low".to_string(),
                requires_human_review: Some(false),
            },
            timing: TimingContext {
                started_at,
                completed_at,
                latency_ms: 1000,
            },
            chain: ChainContext {
                sequence: 0,
                previous_hash: "GENESIS".to_string(),
                record_hash: String::new(),
                merkle_batch_id: None,
            },
            signature: SignatureEnvelope {
                algorithm: "Ed25519".to_string(),
                public_key_id: "key-1".to_string(),
                signature: "base64:placeholder".to_string(),
            },
            evidence: vec![EvidencePointer {
                kind: "prompt".to_string(),
                uri: "memory://prompt".to_string(),
                digest: Some("sha256:abc".to_string()),
            }],
        }
    }

    fn sign_record(record: &mut AuditRecord) -> [u8; 32] {
        let secret_bytes: [u8; 32] = sha2::Sha256::digest(b"ledger-core-test-key").into();
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let payload = serde_json::to_vec(&canonical_payload(record)).expect("serialize payload");
        let signature = signing_key.sign(&payload);
        record.signature.signature = format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        );
        verifying_key.to_bytes()
    }

    #[test]
    fn compute_record_hash_is_deterministic() {
        let mut first = sample_record();
        first.chain.record_hash = compute_record_hash(&first).expect("hash");
        let mut second = first.clone();
        second.chain.record_hash.clear();
        second.chain.record_hash = compute_record_hash(&second).expect("hash");
        assert_eq!(first.chain.record_hash, second.chain.record_hash);
    }

    #[test]
    fn verify_chain_link_accepts_valid_genesis_record() {
        let mut record = sample_record();
        record.chain.record_hash = compute_record_hash(&record).expect("hash");
        let result = verify_chain_link(&record, None);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_chain_link_rejects_wrong_previous_hash() {
        let mut record = sample_record();
        record.chain.sequence = 1;
        record.chain.previous_hash = "sha256:expected".to_string();
        record.chain.record_hash = compute_record_hash(&record).expect("hash");
        let err =
            verify_chain_link(&record, Some("sha256:different")).expect_err("must reject link");
        assert!(err.to_string().contains("previous hash mismatch"));
    }

    #[test]
    fn verify_chain_link_rejects_hash_mismatch() {
        let mut record = sample_record();
        record.chain.record_hash = "sha256:not-actual".to_string();
        let err = verify_chain_link(&record, None).expect_err("must reject hash mismatch");
        assert!(err.to_string().contains("record hash mismatch"));
    }

    #[test]
    fn verify_signature_accepts_valid_signature() {
        let mut record = sample_record();
        record.chain.record_hash = compute_record_hash(&record).expect("hash");
        let public_key = sign_record(&mut record);
        let result = verify_signature(&record, &public_key);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_signature_rejects_tampered_payload() {
        let mut record = sample_record();
        record.chain.record_hash = compute_record_hash(&record).expect("hash");
        let public_key = sign_record(&mut record);
        record.decision.outcome = "denied".to_string();
        let err = verify_signature(&record, &public_key).expect_err("must reject tampering");
        assert!(err.to_string().contains("signature error"));
    }
}
