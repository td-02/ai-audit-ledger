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
