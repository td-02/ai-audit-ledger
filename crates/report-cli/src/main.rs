use std::{env, fs};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ledger_core::{
    chain::verify_chain_link,
    merkle::{build_merkle_proof, compute_merkle_root, verify_merkle_proof, MerkleProof},
    record::{AuditRecord, ExplanationContext},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
struct ComplianceReport {
    generated_at: chrono::DateTime<chrono::Utc>,
    tenant_id: String,
    record_count: usize,
    head_sequence: u64,
    head_hash: String,
    merkle_root: String,
    proofs_generated: usize,
    merkle_proof_validation_passed: bool,
    proofs: Vec<MerkleProof>,
    explainability_records: usize,
    explainability_coverage_pct: f64,
    top_explanatory_factors: Vec<FactorWeightSummary>,
    policies_observed: Vec<String>,
    outcomes: Vec<String>,
    exceptions: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct FactorWeightSummary {
    factor: String,
    occurrences: usize,
    avg_weight: f64,
}

#[derive(Serialize, Deserialize)]
struct ReportSignatureEnvelope {
    algorithm: String,
    public_key_id: String,
    digest: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct SignedComplianceReport {
    report: ComplianceReport,
    signature: ReportSignatureEnvelope,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        bail!(
            "usage:\n  report-cli generate <ledger.jsonl> <report.json> <private_key_hex> <public_key_id>\n  report-cli verify <report.json> <public_key_hex>"
        );
    }

    match args[1].as_str() {
        "generate" if args.len() == 6 => run_generate(&args[2], &args[3], &args[4], &args[5]),
        "verify" if args.len() == 4 => run_verify(&args[2], &args[3]),
        _ => bail!(
            "usage:\n  report-cli generate <ledger.jsonl> <report.json> <private_key_hex> <public_key_id>\n  report-cli verify <report.json> <public_key_hex>"
        ),
    }
}

fn run_generate(
    ledger_path: &str,
    output_path: &str,
    private_key_hex: &str,
    public_key_id: &str,
) -> Result<()> {
    let records = read_records(ledger_path)?;
    verify_records(&records)?;
    let report = build_report(&records)?;
    let signed = sign_report(&report, private_key_hex, public_key_id)?;
    fs::write(output_path, serde_json::to_vec_pretty(&signed)?)
        .with_context(|| format!("writing report to {}", output_path))?;
    Ok(())
}

fn run_verify(report_path: &str, public_key_hex: &str) -> Result<()> {
    let payload = fs::read_to_string(report_path)
        .with_context(|| format!("reading report file {}", report_path))?;
    let signed: SignedComplianceReport = serde_json::from_str(&payload)
        .with_context(|| format!("parsing report file {}", report_path))?;

    verify_signed_report(&signed, public_key_hex)?;
    verify_report_proofs(&signed.report)?;
    Ok(())
}

fn read_records(ledger_path: &str) -> Result<Vec<AuditRecord>> {
    let content = fs::read_to_string(ledger_path)
        .with_context(|| format!("reading ledger file {}", ledger_path))?;
    let mut records = Vec::new();
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        records.push(serde_json::from_str::<AuditRecord>(line)?);
    }
    if records.is_empty() {
        bail!("ledger is empty");
    }
    Ok(records)
}

fn verify_records(records: &[AuditRecord]) -> Result<()> {
    let mut previous_hash: Option<&str> = None;
    for record in records {
        verify_chain_link(record, previous_hash)?;
        previous_hash = Some(record.chain.record_hash.as_str());
    }
    Ok(())
}

fn build_report(records: &[AuditRecord]) -> Result<ComplianceReport> {
    let head = records.last().expect("records should be non-empty");
    let (proofs, merkle_proof_validation_passed) = build_and_verify_proofs(records)?;
    let (explainability_records, explainability_coverage_pct, top_explanatory_factors) =
        explainability_summary(records);

    let mut policies = std::collections::BTreeSet::new();
    let mut outcomes = std::collections::BTreeSet::new();
    let mut exceptions = Vec::new();

    for record in records {
        for policy_id in &record.policy.policy_ids {
            policies.insert(policy_id.clone());
        }
        outcomes.insert(record.decision.outcome.clone());
        if record.policy.requires_human_review.unwrap_or(false) {
            exceptions.push(format!("record {} requires human review", record.record_id));
        }
    }

    Ok(ComplianceReport {
        generated_at: chrono::Utc::now(),
        tenant_id: head.tenant_id.clone(),
        record_count: records.len(),
        head_sequence: head.chain.sequence,
        head_hash: head.chain.record_hash.clone(),
        merkle_root: compute_merkle_root(&record_hashes(records)),
        proofs_generated: proofs.len(),
        merkle_proof_validation_passed,
        proofs,
        explainability_records,
        explainability_coverage_pct,
        top_explanatory_factors,
        policies_observed: policies.into_iter().collect(),
        outcomes: outcomes.into_iter().collect(),
        exceptions,
    })
}

fn record_hashes(records: &[AuditRecord]) -> Vec<String> {
    records
        .iter()
        .map(|record| record.chain.record_hash.clone())
        .collect()
}

fn build_and_verify_proofs(records: &[AuditRecord]) -> Result<(Vec<MerkleProof>, bool)> {
    let leaves = record_hashes(records);
    let mut proofs = Vec::with_capacity(leaves.len());
    for (idx, _) in leaves.iter().enumerate() {
        let proof = build_merkle_proof(&leaves, idx)
            .ok_or_else(|| anyhow!("failed to build proof for leaf index {}", idx))?;
        if !verify_merkle_proof(&proof) {
            return Ok((proofs, false));
        }
        proofs.push(proof);
    }
    Ok((proofs, true))
}

fn explainability_summary(records: &[AuditRecord]) -> (usize, f64, Vec<FactorWeightSummary>) {
    let mut explainability_records = 0usize;
    let mut aggregate: std::collections::BTreeMap<String, (usize, f64)> =
        std::collections::BTreeMap::new();

    for record in records {
        if has_explanation(record.explanation.as_ref()) {
            explainability_records += 1;
        }
        if let Some(explanation) = &record.explanation {
            for factor in &explanation.key_factors {
                let entry = aggregate.entry(factor.name.clone()).or_insert((0, 0.0));
                entry.0 += 1;
                entry.1 += factor.weight;
            }
        }
    }

    let coverage = if records.is_empty() {
        0.0
    } else {
        (explainability_records as f64 / records.len() as f64) * 100.0
    };

    let mut top = aggregate
        .into_iter()
        .map(
            |(factor, (occurrences, total_weight))| FactorWeightSummary {
                factor,
                occurrences,
                avg_weight: total_weight / occurrences as f64,
            },
        )
        .collect::<Vec<_>>();
    top.sort_by(|a, b| {
        b.occurrences
            .cmp(&a.occurrences)
            .then_with(|| b.avg_weight.total_cmp(&a.avg_weight))
    });
    if top.len() > 5 {
        top.truncate(5);
    }

    (explainability_records, coverage, top)
}

fn has_explanation(explanation: Option<&ExplanationContext>) -> bool {
    let Some(explanation) = explanation else {
        return false;
    };
    !explanation.rationale_summary.trim().is_empty() && !explanation.key_factors.is_empty()
}

fn verify_report_proofs(report: &ComplianceReport) -> Result<()> {
    if report.proofs_generated != report.proofs.len() {
        bail!(
            "proof count mismatch: declared {} vs actual {}",
            report.proofs_generated,
            report.proofs.len()
        );
    }
    if report.proofs_generated != report.record_count {
        bail!(
            "proof count mismatch: proofs {} vs record_count {}",
            report.proofs_generated,
            report.record_count
        );
    }
    for proof in &report.proofs {
        if proof.root != report.merkle_root {
            bail!("proof root does not match report merkle_root");
        }
        if !verify_merkle_proof(proof) {
            bail!("invalid merkle proof detected");
        }
    }
    Ok(())
}

fn sign_report(
    report: &ComplianceReport,
    private_key_hex: &str,
    public_key_id: &str,
) -> Result<SignedComplianceReport> {
    let private_key = decode_hex_32(private_key_hex, "private key")?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let canonical = serde_json::to_vec(report)?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&canonical)));
    let signature = signing_key.sign(&canonical);

    Ok(SignedComplianceReport {
        report: ComplianceReport {
            generated_at: report.generated_at,
            tenant_id: report.tenant_id.clone(),
            record_count: report.record_count,
            head_sequence: report.head_sequence,
            head_hash: report.head_hash.clone(),
            merkle_root: report.merkle_root.clone(),
            proofs_generated: report.proofs_generated,
            merkle_proof_validation_passed: report.merkle_proof_validation_passed,
            proofs: report.proofs.clone(),
            explainability_records: report.explainability_records,
            explainability_coverage_pct: report.explainability_coverage_pct,
            top_explanatory_factors: report.top_explanatory_factors.clone(),
            policies_observed: report.policies_observed.clone(),
            outcomes: report.outcomes.clone(),
            exceptions: report.exceptions.clone(),
        },
        signature: ReportSignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            public_key_id: public_key_id.to_string(),
            digest,
            signature: format!(
                "base64:{}",
                base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
            ),
        },
    })
}

fn verify_signed_report(signed: &SignedComplianceReport, public_key_hex: &str) -> Result<()> {
    if signed.signature.algorithm != "Ed25519" {
        bail!("unsupported signature algorithm");
    }
    let public_key = decode_hex_32(public_key_hex, "public key")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)?;
    let canonical = serde_json::to_vec(&signed.report)?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&canonical)));
    if digest != signed.signature.digest {
        bail!("report digest mismatch");
    }

    let signature_raw = signed
        .signature
        .signature
        .strip_prefix("base64:")
        .unwrap_or(&signed.signature.signature);
    let signature =
        Signature::from_slice(&base64::engine::general_purpose::STANDARD.decode(signature_raw)?)?;
    verifying_key.verify(&canonical, &signature)?;
    Ok(())
}

fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("decoding {} hex", label))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{} must be 32 bytes (64 hex chars)", label))
}

#[cfg(test)]
mod tests {
    use super::{
        build_report, sign_report, verify_records, verify_report_proofs, verify_signed_report,
    };
    use ledger_core::{
        chain::compute_record_hash,
        record::{
            ApplicationContext, AuditRecord, ChainContext, DecisionContext, EvidencePointer,
            ModelContext, PolicyContext, SignatureEnvelope, TimingContext,
        },
    };

    fn make_record(
        sequence: u64,
        previous_hash: String,
        record_id: &str,
        outcome: &str,
        requires_human_review: bool,
    ) -> AuditRecord {
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-02-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        let completed_at = chrono::DateTime::parse_from_rfc3339("2026-02-01T00:00:01Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        let mut record = AuditRecord {
            version: "v1".to_string(),
            record_id: record_id.to_string(),
            tenant_id: "tenant-1".to_string(),
            application: ApplicationContext {
                name: "app".to_string(),
                environment: "test".to_string(),
                actor_id: "actor-1".to_string(),
                trace_id: format!("trace-{record_id}"),
                span_id: None,
            },
            model: ModelContext {
                provider: "openai".to_string(),
                name: "gpt-x".to_string(),
                temperature: None,
                tool_calls: vec![],
            },
            decision: DecisionContext {
                category: "risk".to_string(),
                action: "review".to_string(),
                outcome: outcome.to_string(),
                summary: None,
                prompt_hash: None,
                response_hash: None,
            },
            explanation: None,
            policy: PolicyContext {
                policy_ids: vec!["policy-a".to_string(), "policy-b".to_string()],
                risk_level: "medium".to_string(),
                requires_human_review: Some(requires_human_review),
            },
            timing: TimingContext {
                started_at,
                completed_at,
                latency_ms: 1000,
            },
            chain: ChainContext {
                sequence,
                previous_hash,
                record_hash: String::new(),
                merkle_batch_id: None,
            },
            signature: SignatureEnvelope {
                algorithm: "Ed25519".to_string(),
                public_key_id: "test-key".to_string(),
                signature: "base64:unused".to_string(),
            },
            evidence: vec![EvidencePointer {
                kind: "prompt".to_string(),
                uri: "memory://prompt".to_string(),
                digest: None,
            }],
        };
        record.chain.record_hash = compute_record_hash(&record).expect("hash");
        record
    }

    #[test]
    fn verify_records_accepts_valid_chain() {
        let first = make_record(0, "GENESIS".to_string(), "r1", "approved", false);
        let second = make_record(1, first.chain.record_hash.clone(), "r2", "approved", false);
        assert!(verify_records(&[first, second]).is_ok());
    }

    #[test]
    fn verify_records_rejects_broken_chain() {
        let first = make_record(0, "GENESIS".to_string(), "r1", "approved", false);
        let bad_second = make_record(1, "sha256:wrong".to_string(), "r2", "denied", false);
        let err = verify_records(&[first, bad_second]).expect_err("must reject chain");
        assert!(err.to_string().contains("previous hash mismatch"));
    }

    #[test]
    fn build_report_aggregates_policy_outcome_and_exceptions() {
        let first = make_record(0, "GENESIS".to_string(), "r1", "approved", false);
        let second = make_record(1, first.chain.record_hash.clone(), "r2", "denied", true);

        let report = build_report(&[first, second]).expect("report");
        assert_eq!(report.tenant_id, "tenant-1");
        assert_eq!(report.record_count, 2);
        assert_eq!(report.head_sequence, 1);
        assert_eq!(report.proofs_generated, 2);
        assert!(report.merkle_proof_validation_passed);
        assert_eq!(report.explainability_records, 0);
        assert_eq!(report.explainability_coverage_pct, 0.0);
        assert!(report.top_explanatory_factors.is_empty());
        assert_eq!(
            report.outcomes,
            vec!["approved".to_string(), "denied".to_string()]
        );
        assert_eq!(
            report.policies_observed,
            vec!["policy-a".to_string(), "policy-b".to_string()]
        );
        assert_eq!(report.exceptions.len(), 1);
        assert!(report.exceptions[0].contains("requires human review"));
        assert!(report.merkle_root.starts_with("sha256:"));
        assert_eq!(report.proofs.len(), 2);
    }

    #[test]
    fn signed_report_verifies_with_matching_public_key() {
        let first = make_record(0, "GENESIS".to_string(), "r1", "approved", false);
        let second = make_record(1, first.chain.record_hash.clone(), "r2", "approved", false);
        let report = build_report(&[first, second]).expect("report");

        let private_key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let signed = sign_report(&report, private_key_hex, "report-key-1").expect("sign");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            &hex::decode(private_key_hex)
                .expect("hex")
                .try_into()
                .expect("32-byte private key"),
        );
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

        assert!(verify_signed_report(&signed, &public_key_hex).is_ok());
        assert!(verify_report_proofs(&signed.report).is_ok());
    }

    #[test]
    fn signed_report_verification_fails_on_tamper() {
        let first = make_record(0, "GENESIS".to_string(), "r1", "approved", false);
        let second = make_record(1, first.chain.record_hash.clone(), "r2", "approved", false);
        let report = build_report(&[first, second]).expect("report");
        let private_key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let mut signed = sign_report(&report, private_key_hex, "report-key-1").expect("sign");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            &hex::decode(private_key_hex)
                .expect("hex")
                .try_into()
                .expect("32-byte private key"),
        );
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

        signed.report.head_hash = "sha256:tampered".to_string();
        assert!(verify_signed_report(&signed, &public_key_hex).is_err());
    }

    #[test]
    fn explainability_summary_tracks_coverage_and_factors() {
        let mut first = make_record(0, "GENESIS".to_string(), "r1", "approved", false);
        let second = make_record(1, first.chain.record_hash.clone(), "r2", "approved", false);
        first.explanation = Some(ledger_core::record::ExplanationContext {
            rationale_summary: "Low risk profile".to_string(),
            key_factors: vec![
                ledger_core::record::ExplanationFactor {
                    name: "credit_score".to_string(),
                    weight: 0.7,
                    evidence: None,
                },
                ledger_core::record::ExplanationFactor {
                    name: "debt_to_income".to_string(),
                    weight: 0.2,
                    evidence: None,
                },
            ],
            confidence_score: Some(0.89),
            alternative_outcomes: vec!["manual_review".to_string()],
            policy_trace: vec!["loan-policy-v3.rule-12".to_string()],
        });
        first.chain.record_hash = compute_record_hash(&first).expect("hash");

        let report = build_report(&[first, second]).expect("report");
        assert_eq!(report.explainability_records, 1);
        assert_eq!(report.explainability_coverage_pct, 50.0);
        assert!(!report.top_explanatory_factors.is_empty());
        assert_eq!(report.top_explanatory_factors[0].factor, "credit_score");
    }
}
