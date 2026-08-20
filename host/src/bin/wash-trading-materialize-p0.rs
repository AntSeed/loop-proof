use alloy_primitives::{Address, B256};
use anyhow::{bail, Context, Result};
use enforcement_core::{
    ClosedCycleInput, ClosureEvidence, FundingKind, LogRef, PositiveFundingEvidence, ReceiptRef,
    ReciprocalInput, RelayPathEvidence, SettlementEvidence, TransactionRef, BASE_CHAIN_ID,
    PREDICATE_VERSION,
};
use loop_host::rpc::Client;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::PathBuf,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofPlan {
    chain_id: u64,
    claims: Vec<PlannedClaim>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlannedClaim {
    claim_id: String,
    #[serde(rename = "type")]
    claim_type: String,
    subjects: Vec<Address>,
    selected_evidence: Vec<PlannedEvidence>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlannedEvidence {
    evidence_type: String,
    #[serde(default)]
    block_number: Option<u64>,
    #[serde(default)]
    transaction_index: Option<u64>,
    #[serde(default)]
    log_index: Option<u64>,
    #[serde(default)]
    deposit_log_index: Option<u64>,
    #[serde(default)]
    buyer: Option<Address>,
    #[serde(default)]
    funder: Option<Address>,
    #[serde(default)]
    seller_payment: Option<Box<PlannedEvidence>>,
    #[serde(default)]
    relay_forward: Option<Box<PlannedEvidence>>,
    #[serde(default)]
    funder_receipt: Option<Box<PlannedEvidence>>,
}

#[derive(Default)]
struct BlockTargets {
    receipts: BTreeSet<u64>,
    transactions: BTreeSet<u64>,
    logs: BTreeSet<u64>,
}

struct MaterializedEvidence {
    blocks: Vec<enforcement_core::EnforcementBlock>,
    block_positions: BTreeMap<u64, usize>,
    receipt_positions: BTreeMap<(u64, u64), usize>,
    transaction_positions: BTreeMap<(u64, u64), usize>,
    log_positions: BTreeMap<(u64, u64, u64), usize>,
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let args = env::args().skip(1).collect::<Vec<_>>();
    let plan_path = PathBuf::from(arg(&args, "--plan").context("missing --plan")?);
    let claim_id = arg(&args, "--claim-id").context("missing --claim-id")?;
    let output = PathBuf::from(arg(&args, "--output").context("missing --output")?);
    let plan: ProofPlan = serde_json::from_slice(
        &fs::read(&plan_path).with_context(|| format!("read {}", plan_path.display()))?,
    )
    .with_context(|| format!("decode {}", plan_path.display()))?;
    if plan.chain_id != BASE_CHAIN_ID {
        bail!("proof plan chain ID {} is not Base", plan.chain_id);
    }
    let claim = plan
        .claims
        .iter()
        .find(|claim| claim.claim_id == claim_id)
        .with_context(|| format!("claim {claim_id} not found"))?;
    if !matches!(
        claim.claim_type.as_str(),
        "P0_CLOSED_LOOP" | "P0_RECIPROCAL"
    ) {
        bail!("claim {} is not a P0 claim", claim.claim_id);
    }

    let client = Client::new(rpc_endpoints()?);
    let materialized = materialize_evidence(&client, &claim.selected_evidence)?;
    let planned_claim_id: B256 = claim
        .claim_id
        .parse()
        .with_context(|| format!("invalid claim ID {}", claim.claim_id))?;
    let (proof_type, input, verified_claim_id) = match claim.claim_type.as_str() {
        "P0_CLOSED_LOOP" => {
            let input = build_closed_cycle(claim, &materialized)?;
            let journal =
                enforcement_core::verify_closed_cycle(&input).map_err(anyhow::Error::msg)?;
            eprintln!(
                "verified closed-cycle claim {} with {:.6} USDC",
                journal.claim_id,
                journal.qualified_volume_raw as f64 / 1_000_000.0
            );
            (
                "P0_CLOSED_CYCLE",
                serde_json::to_value(input)?,
                journal.claim_id,
            )
        }
        "P0_RECIPROCAL" => {
            let input = build_reciprocal(claim, &materialized)?;
            let journal =
                enforcement_core::verify_reciprocal(&input).map_err(anyhow::Error::msg)?;
            eprintln!(
                "verified reciprocal claim {} with {} settlements",
                journal.claim_id,
                journal.settlement_count_a_to_b + journal.settlement_count_b_to_a
            );
            (
                "P0_RECIPROCAL",
                serde_json::to_value(input)?,
                journal.claim_id,
            )
        }
        _ => unreachable!(),
    };
    if verified_claim_id != planned_claim_id {
        bail!(
            "plan claim ID {} does not match verified claim {}",
            planned_claim_id,
            verified_claim_id
        );
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let package = serde_json::json!({
        "version": PREDICATE_VERSION,
        "kind": "antseed-wash-trading-proof-witness",
        "enforceable": true,
        "proofType": proof_type,
        "input": input,
    });
    fs::write(&output, format!("{}\n", serde_json::to_string(&package)?))?;
    eprintln!("wrote {}", output.display());
    Ok(())
}

fn materialize_evidence(
    client: &Client,
    evidence: &[PlannedEvidence],
) -> Result<MaterializedEvidence> {
    let atomic = evidence
        .iter()
        .flat_map(atomic_evidence)
        .collect::<Vec<_>>();
    let mut targets = BTreeMap::<u64, BlockTargets>::new();
    for entry in &atomic {
        let block = required(entry.block_number, "block number", entry)?;
        let transaction = required(entry.transaction_index, "transaction index", entry)?;
        let block_targets = targets.entry(block).or_default();
        block_targets.receipts.insert(transaction);
        if matches!(
            entry.evidence_type.as_str(),
            "USDC_FUNDING" | "NATIVE_FUNDING"
        ) {
            block_targets.transactions.insert(transaction);
        }
        if let Some(log_index) = entry.log_index {
            block_targets.logs.insert(log_index);
        }
        if let Some(log_index) = entry.deposit_log_index {
            block_targets.logs.insert(log_index);
        }
    }

    let mut blocks = Vec::with_capacity(targets.len());
    let mut block_positions = BTreeMap::new();
    let mut receipt_positions = BTreeMap::new();
    let mut transaction_positions = BTreeMap::new();
    let mut log_positions = BTreeMap::new();
    for (block_number, block_targets) in targets {
        let receipts = block_targets.receipts.into_iter().collect::<Vec<_>>();
        let transactions = block_targets.transactions.into_iter().collect::<Vec<_>>();
        let logs = block_targets.logs.into_iter().collect::<Vec<_>>();
        let (block, located_logs) =
            client.enforcement_block_evidence(block_number, &receipts, &transactions, &logs)?;
        let block_position = blocks.len();
        block_positions.insert(block_number, block_position);
        for (position, transaction_index) in receipts.iter().enumerate() {
            receipt_positions.insert((block_number, *transaction_index), position);
        }
        for (position, transaction_index) in transactions.iter().enumerate() {
            transaction_positions.insert((block_number, *transaction_index), position);
        }
        for ((transaction_index, block_log_index), local_index) in located_logs {
            log_positions.insert(
                (block_number, transaction_index, block_log_index),
                local_index,
            );
        }
        blocks.push(block);
    }
    Ok(MaterializedEvidence {
        blocks,
        block_positions,
        receipt_positions,
        transaction_positions,
        log_positions,
    })
}

fn build_closed_cycle(
    claim: &PlannedClaim,
    materialized: &MaterializedEvidence,
) -> Result<ClosedCycleInput> {
    let seller = *claim
        .subjects
        .first()
        .context("closed-cycle subject missing")?;
    let funding_entries = claim
        .selected_evidence
        .iter()
        .filter(|entry| {
            matches!(
                entry.evidence_type.as_str(),
                "USDC_FUNDING" | "NATIVE_FUNDING"
            )
        })
        .collect::<Vec<_>>();
    if funding_entries.len() < 3 {
        bail!("closed-cycle plan has fewer than three fundings");
    }
    let funder = funding_entries[0]
        .funder
        .context("funding funder missing")?;
    let mut linked_buyers = Vec::with_capacity(funding_entries.len());
    let mut fundings = Vec::with_capacity(funding_entries.len());
    for entry in funding_entries {
        if entry.funder != Some(funder) {
            bail!("closed-cycle plan mixes funders");
        }
        let buyer = entry.buyer.context("funding buyer missing")?;
        linked_buyers.push(buyer);
        let kind = if entry.evidence_type == "NATIVE_FUNDING" {
            FundingKind::Native {
                transaction: transaction_ref(entry, materialized)?,
                receipt: receipt_ref(entry, materialized)?,
            }
        } else if let Some(deposit_log_index) = entry.deposit_log_index {
            FundingKind::ProtocolDeposit {
                transfer: log_ref(
                    entry,
                    entry.log_index.context("funding transfer log missing")?,
                    materialized,
                )?,
                deposited: log_ref(entry, deposit_log_index, materialized)?,
            }
        } else {
            FundingKind::Usdc {
                transfer: log_ref(
                    entry,
                    entry.log_index.context("funding transfer log missing")?,
                    materialized,
                )?,
            }
        };
        fundings.push(PositiveFundingEvidence { buyer, kind });
    }
    linked_buyers.sort_unstable();
    linked_buyers.dedup();
    fundings.sort_unstable_by_key(|entry| entry.buyer);
    if linked_buyers.len() != fundings.len() {
        bail!("closed-cycle plan contains duplicate funded buyers");
    }

    let settlements = claim
        .selected_evidence
        .iter()
        .filter(|entry| entry.evidence_type == "SETTLEMENT")
        .map(|entry| {
            Ok(SettlementEvidence {
                settlement: log_ref(
                    entry,
                    entry.log_index.context("settlement log missing")?,
                    materialized,
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let direct = claim.selected_evidence.iter().find(|entry| {
        matches!(
            entry.evidence_type.as_str(),
            "DIRECT_SELLER_FUNDER" | "DIRECT_SELLER_BUYER"
        )
    });
    let relay = claim
        .selected_evidence
        .iter()
        .filter(|entry| entry.evidence_type == "RELAY_PATH")
        .collect::<Vec<_>>();
    let closure = if let Some(entry) = direct {
        ClosureEvidence::Direct {
            transfer: log_ref(
                entry,
                entry.log_index.context("closure log missing")?,
                materialized,
            )?,
        }
    } else if !relay.is_empty() {
        ClosureEvidence::Relay {
            paths: relay
                .into_iter()
                .map(|entry| {
                    let seller_payment = entry
                        .seller_payment
                        .as_deref()
                        .context("relay seller payment missing")?;
                    let relay_forward = entry
                        .relay_forward
                        .as_deref()
                        .context("relay forward missing")?;
                    let final_receipt = entry
                        .funder_receipt
                        .as_deref()
                        .context("relay receipt missing")?;
                    Ok(RelayPathEvidence {
                        seller_payment: log_ref(
                            seller_payment,
                            seller_payment
                                .log_index
                                .context("relay seller log missing")?,
                            materialized,
                        )?,
                        relay_forward: log_ref(
                            relay_forward,
                            relay_forward
                                .log_index
                                .context("relay forward log missing")?,
                            materialized,
                        )?,
                        final_receipt: log_ref(
                            final_receipt,
                            final_receipt
                                .log_index
                                .context("relay receipt log missing")?,
                            materialized,
                        )?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        }
    } else {
        bail!("closed-cycle plan has no closure evidence");
    };
    Ok(ClosedCycleInput {
        chain_id: BASE_CHAIN_ID,
        seller,
        funder,
        linked_buyers,
        blocks: materialized.blocks.clone(),
        fundings,
        settlements,
        closure,
    })
}

fn build_reciprocal(
    claim: &PlannedClaim,
    materialized: &MaterializedEvidence,
) -> Result<ReciprocalInput> {
    if claim.subjects.len() != 2 {
        bail!("reciprocal plan must have exactly two subjects");
    }
    let mut subjects = claim.subjects.clone();
    subjects.sort_unstable();
    let settlements = claim
        .selected_evidence
        .iter()
        .filter(|entry| entry.evidence_type == "RECIPROCAL_SETTLEMENT")
        .map(|entry| {
            Ok(SettlementEvidence {
                settlement: log_ref(
                    entry,
                    entry.log_index.context("reciprocal log missing")?,
                    materialized,
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ReciprocalInput {
        chain_id: BASE_CHAIN_ID,
        address_a: subjects[0],
        address_b: subjects[1],
        blocks: materialized.blocks.clone(),
        settlements,
    })
}

fn atomic_evidence(entry: &PlannedEvidence) -> Vec<&PlannedEvidence> {
    if entry.evidence_type != "RELAY_PATH" {
        return vec![entry];
    }
    [
        entry.seller_payment.as_deref(),
        entry.relay_forward.as_deref(),
        entry.funder_receipt.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn receipt_ref(entry: &PlannedEvidence, materialized: &MaterializedEvidence) -> Result<ReceiptRef> {
    let block_number = required(entry.block_number, "block number", entry)?;
    let transaction_index = required(entry.transaction_index, "transaction index", entry)?;
    Ok(ReceiptRef {
        block: *materialized
            .block_positions
            .get(&block_number)
            .context("materialized block missing")?,
        receipt: *materialized
            .receipt_positions
            .get(&(block_number, transaction_index))
            .context("materialized receipt missing")?,
    })
}

fn transaction_ref(
    entry: &PlannedEvidence,
    materialized: &MaterializedEvidence,
) -> Result<TransactionRef> {
    let block_number = required(entry.block_number, "block number", entry)?;
    let transaction_index = required(entry.transaction_index, "transaction index", entry)?;
    Ok(TransactionRef {
        block: *materialized
            .block_positions
            .get(&block_number)
            .context("materialized block missing")?,
        transaction: *materialized
            .transaction_positions
            .get(&(block_number, transaction_index))
            .context("materialized transaction missing")?,
    })
}

fn log_ref(
    entry: &PlannedEvidence,
    block_log_index: u64,
    materialized: &MaterializedEvidence,
) -> Result<LogRef> {
    let receipt = receipt_ref(entry, materialized)?;
    let block_number = required(entry.block_number, "block number", entry)?;
    let transaction_index = required(entry.transaction_index, "transaction index", entry)?;
    Ok(LogRef {
        block: receipt.block,
        receipt: receipt.receipt,
        log: *materialized
            .log_positions
            .get(&(block_number, transaction_index, block_log_index))
            .context("materialized log missing")?,
    })
}

fn required<T: Copy>(value: Option<T>, label: &str, entry: &PlannedEvidence) -> Result<T> {
    value.with_context(|| format!("{} evidence missing {label}", entry.evidence_type))
}

fn rpc_endpoints() -> Result<Vec<String>> {
    let value = env::var("BASE_RPC_URL").context("BASE_RPC_URL is not configured")?;
    let endpoints = value
        .split(',')
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        bail!("BASE_RPC_URL contains no endpoints");
    }
    Ok(endpoints)
}

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_evidence_flattens_without_state_proofs() {
        let atomic = |evidence_type: &str| PlannedEvidence {
            evidence_type: evidence_type.to_string(),
            block_number: Some(1),
            transaction_index: Some(0),
            log_index: Some(0),
            deposit_log_index: None,
            buyer: None,
            funder: None,
            seller_payment: None,
            relay_forward: None,
            funder_receipt: None,
        };
        let relay = PlannedEvidence {
            evidence_type: "RELAY_PATH".to_string(),
            block_number: None,
            transaction_index: None,
            log_index: None,
            deposit_log_index: None,
            buyer: None,
            funder: None,
            seller_payment: Some(Box::new(atomic("RELAY_SELLER_PAYMENT"))),
            relay_forward: Some(Box::new(atomic("RELAY_FORWARD"))),
            funder_receipt: Some(Box::new(atomic("RELAY_FUNDER_RECEIPT"))),
        };
        assert_eq!(atomic_evidence(&relay).len(), 3);
    }
}
