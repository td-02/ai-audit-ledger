use std::{env, fs};

use anyhow::{bail, Context, Result};
use ledger_core::{chain::verify_chain_link, merkle::compute_merkle_root, record::AuditRecord};
use serde::Serialize;

#[derive(Serialize)]
struct ComplianceReport {
    generated_at: chrono::DateTime<chrono::Utc>,
    tenant_id: String,
    record_count: usize,
    head_sequence: u64,
    head_hash: String,
    merkle_root: String,
    policies_observed: Vec<String>,
    outcomes: Vec<String>,
    exceptions: Vec<String>,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        bail!("usage: report-cli <ledger.jsonl> <report.json>");
    }

    let ledger_path = &args[1];
    let output_path = &args[2];
    let content = fs::read_to_string(ledger_path)
        .with_context(|| format!("reading ledger file {}", ledger_path))?;

    let mut records = Vec::new();
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        records.push(serde_json::from_str::<AuditRecord>(line)?);
    }
    if records.is_empty() {
        bail!("ledger is empty");
    }

    verify_records(&records)?;
    let report = build_report(&records);
    fs::write(output_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("writing report to {}", output_path))?;
    Ok(())
}

fn verify_records(records: &[AuditRecord]) -> Result<()> {
    let mut previous_hash: Option<&str> = None;
    for record in records {
        verify_chain_link(record, previous_hash)?;
        previous_hash = Some(record.chain.record_hash.as_str());
    }
    Ok(())
}

fn build_report(records: &[AuditRecord]) -> ComplianceReport {
    let head = records.last().expect("records should be non-empty");

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

    ComplianceReport {
        generated_at: chrono::Utc::now(),
        tenant_id: head.tenant_id.clone(),
        record_count: records.len(),
        head_sequence: head.chain.sequence,
        head_hash: head.chain.record_hash.clone(),
        merkle_root: compute_merkle_root(
            &records
                .iter()
                .map(|record| record.chain.record_hash.clone())
                .collect::<Vec<_>>(),
        ),
        policies_observed: policies.into_iter().collect(),
        outcomes: outcomes.into_iter().collect(),
        exceptions,
    }
}

#[cfg(test)]
mod tests {
    use super::{build_report, verify_records};
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

        let report = build_report(&[first, second]);
        assert_eq!(report.tenant_id, "tenant-1");
        assert_eq!(report.record_count, 2);
        assert_eq!(report.head_sequence, 1);
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
    }
}
