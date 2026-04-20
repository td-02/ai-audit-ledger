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
    let signature = Signature::from_slice(
        &base64::engine::general_purpose::STANDARD.decode(signature_raw)?,
    )?;
    verifying_key.verify(&payload, &signature)?;
    Ok(())
}

