#[path = "../rpc.rs"]
mod rpc;

use alloy_primitives::{Address, B256};
use anyhow::{bail, Context, Result};
use rpc::Client;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::PathBuf,
};
use wash_predicate::{
    reciprocal::PairDepositEvidence, BuyerLedger, ClosedLoopInput, EvidenceBlock, FundingEvidence,
    FundingKind, LogRef, ReceiptRef, ReciprocalInput, ReturnPath, StateRead, TransactionRef,
    BASE_CHAIN_ID, BUYER_ACCOUNT_BALANCE_OFFSET, DEPOSITS_ADDRESS, DEPOSITS_BUYERS_SLOT,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofPlan {
    version: u64,
    kind: String,
    chain_id: u64,
    period: ProofPeriod,
    claims: Vec<PlannedClaim>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofPeriod {
    start_block: u64,
    end_block_exclusive: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlannedClaim {
    claim_id: String,
    #[serde(rename = "type")]
    claim_type: String,
    subjects: Vec<Address>,
    #[serde(default)]
    closure_type: Option<String>,
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
}

struct MaterializedEvidence {
    blocks: Vec<EvidenceBlock>,
    block_positions: BTreeMap<u64, usize>,
    receipt_positions: BTreeMap<(u64, u64), usize>,
    transaction_positions: BTreeMap<(u64, u64), usize>,
    log_positions: BTreeMap<(u64, u64), usize>,
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let plan_path = PathBuf::from(arg(&args, "--plan").context("missing --plan")?);
    let claim_id = arg(&args, "--claim-id").context("missing --claim-id")?;
    let output = PathBuf::from(arg(&args, "--output").context("missing --output")?);
    let plan: ProofPlan = serde_json::from_slice(
        &fs::read(&plan_path).with_context(|| format!("read {}", plan_path.display()))?,
    )
    .with_context(|| format!("decode {}", plan_path.display()))?;
    if plan.version != 2
        || plan.kind != "antseed-wash-trading-proof-plan"
        || plan.chain_id != BASE_CHAIN_ID
    {
        bail!("unsupported proof plan");
    }
    let claim = plan
        .claims
        .iter()
        .find(|claim| claim.claim_id.eq_ignore_ascii_case(&claim_id))
        .with_context(|| format!("claim {claim_id} not found"))?;
    if !matches!(
        claim.claim_type.as_str(),
        "P0_CLOSED_LOOP" | "P0_RECIPROCAL"
    ) {
        bail!("claim {} is not a supported P0 claim", claim.claim_id);
    }

    let client = Client::new(&rpc_endpoints()?);
    if plan.period.start_block == 0 || plan.period.start_block >= plan.period.end_block_exclusive {
        bail!("invalid proof period");
    }
    let period_end_block = plan.period.end_block_exclusive - 1;
    let materialized = materialize_evidence(
        &client,
        &claim.selected_evidence,
        plan.period.start_block,
        period_end_block,
    )?;
    let (input, journal) = match claim.claim_type.as_str() {
        "P0_CLOSED_LOOP" => {
            let input = build_closed_loop(
                &client,
                claim,
                &materialized,
                plan.period.start_block,
                period_end_block,
            )?;
            let journal = wash_predicate::verify_closed_loop(&input).map_err(anyhow::Error::msg)?;
            (serde_json::to_value(input)?, journal)
        }
        "P0_RECIPROCAL" => {
            let input = build_reciprocal(
                &client,
                claim,
                &materialized,
                plan.period.start_block,
                period_end_block,
            )?;
            let journal = wash_predicate::verify_reciprocal(&input).map_err(anyhow::Error::msg)?;
            (serde_json::to_value(input)?, journal)
        }
        _ => unreachable!(),
    };
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_vec(&input)?)?;
    eprintln!(
        "materialized source claim {} as evidence-bound claim {}",
        claim.claim_id, journal.claim_id
    );
    eprintln!("wrote {}", output.display());
    Ok(())
}

fn materialize_evidence(
    client: &Client,
    evidence: &[PlannedEvidence],
    _period_start_block: u64,
    period_end_block: u64,
) -> Result<MaterializedEvidence> {
    let atomic = evidence
        .iter()
        .flat_map(atomic_evidence)
        .collect::<Vec<_>>();
    let mut targets = BTreeMap::<u64, BlockTargets>::new();
    targets.entry(period_end_block).or_default();
    for entry in &atomic {
        let block = required(entry.block_number, "block number", entry)?;
        let transaction = required(entry.transaction_index, "transaction index", entry)?;
        let block_targets = targets.entry(block).or_default();
        block_targets.receipts.insert(transaction);
        if requires_transaction_proof(entry) {
            block_targets.transactions.insert(transaction);
        }
    }

    let mut blocks = Vec::with_capacity(targets.len());
    let mut block_positions = BTreeMap::new();
    let mut receipt_positions = BTreeMap::new();
    let mut transaction_positions = BTreeMap::new();
    let mut log_positions = BTreeMap::new();
    let targets = targets
        .into_iter()
        .map(|(block_number, block_targets)| {
            (
                block_number,
                block_targets.receipts.into_iter().collect::<Vec<_>>(),
                block_targets.transactions.into_iter().collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let concurrency = env::var("LOOP_RPC_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4);
    let evidence = client.block_evidence_many(&targets, concurrency)?;
    for ((block_number, _, _), (block, located_logs)) in targets.into_iter().zip(evidence) {
        let block_position = blocks.len();
        block_positions.insert(block_number, block_position);
        for (position, proof) in block.receipts.iter().enumerate() {
            receipt_positions.insert((block_number, proof.tx_index), position);
        }
        for (position, proof) in block.transactions.iter().enumerate() {
            transaction_positions.insert((block_number, proof.tx_index), position);
        }
        for (block_log_index, local_index) in located_logs {
            log_positions.insert((block_number, block_log_index), local_index);
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

fn build_closed_loop(
    client: &Client,
    claim: &PlannedClaim,
    materialized: &MaterializedEvidence,
    period_start_block: u64,
    period_end_block: u64,
) -> Result<ClosedLoopInput> {
    if claim.subjects.len() != 1 {
        bail!("closed-loop plan must have exactly one subject");
    }
    let seller = claim.subjects[0];
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
    let funder = funding_entries
        .first()
        .and_then(|entry| entry.funder)
        .context("closed-loop plan has no attributed funding")?;
    if funding_entries
        .iter()
        .any(|entry| entry.funder != Some(funder))
    {
        bail!("closed-loop plan mixes funders");
    }

    let mut buyers = funding_entries
        .iter()
        .map(|entry| entry.buyer.context("funding buyer missing"))
        .collect::<Result<Vec<_>>>()?;
    buyers.sort_unstable();
    buyers.dedup();
    let mut fundings = funding_entries
        .iter()
        .map(|entry| funding_evidence(entry, materialized))
        .collect::<Result<Vec<_>>>()?;
    fundings.sort_unstable_by_key(|entry| entry.buyer);

    let settlements = claim
        .selected_evidence
        .iter()
        .filter(|entry| entry.evidence_type == "SETTLEMENT")
        .map(|entry| {
            log_ref(
                entry,
                required(entry.log_index, "settlement log index", entry)?,
                materialized,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let returns = build_return_paths(claim, seller, funder, materialized)?;
    let ledgers = if funding_entries[0].evidence_type == "NATIVE_FUNDING" {
        Vec::new()
    } else {
        buyers
            .iter()
            .map(|buyer| buyer_ledger(client, materialized, *buyer, period_end_block))
            .collect::<Result<Vec<_>>>()?
    };
    Ok(ClosedLoopInput {
        chain_id: BASE_CHAIN_ID,
        period_start_block,
        period_end_block,
        source_claim_id: claim.claim_id.parse().context("invalid source claim ID")?,
        seller,
        funder,
        buyers,
        blocks: materialized.blocks.clone(),
        fundings,
        settlements,
        returns,
        ledgers,
    })
}

fn build_reciprocal(
    client: &Client,
    claim: &PlannedClaim,
    materialized: &MaterializedEvidence,
    period_start_block: u64,
    period_end_block: u64,
) -> Result<ReciprocalInput> {
    if claim.subjects.len() != 2 {
        bail!("reciprocal plan must have exactly two subjects");
    }
    let mut subjects = claim.subjects.clone();
    subjects.sort_unstable();
    if subjects[0] == subjects[1] {
        bail!("reciprocal plan subjects must be distinct");
    }
    let settlements = claim
        .selected_evidence
        .iter()
        .filter(|entry| entry.evidence_type == "RECIPROCAL_SETTLEMENT")
        .map(|entry| {
            log_ref(
                entry,
                required(entry.log_index, "reciprocal log index", entry)?,
                materialized,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let internal_deposits = claim
        .selected_evidence
        .iter()
        .filter(|entry| is_pair_deposit(entry, &subjects))
        .map(|entry| {
            Ok(PairDepositEvidence {
                member: entry.buyer.context("pair deposit member missing")?,
                transfer: log_ref(
                    entry,
                    required(entry.log_index, "pair deposit transfer log index", entry)?,
                    materialized,
                )?,
                deposited: log_ref(
                    entry,
                    required(entry.deposit_log_index, "pair Deposited log index", entry)?,
                    materialized,
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ReciprocalInput {
        chain_id: BASE_CHAIN_ID,
        period_start_block,
        period_end_block,
        source_claim_id: claim.claim_id.parse().context("invalid source claim ID")?,
        address_a: subjects[0],
        address_b: subjects[1],
        blocks: materialized.blocks.clone(),
        settlements,
        internal_deposits,
        ledger_a: buyer_ledger(client, materialized, subjects[0], period_end_block)?,
        ledger_b: buyer_ledger(client, materialized, subjects[1], period_end_block)?,
    })
}

fn funding_evidence(
    entry: &&PlannedEvidence,
    materialized: &MaterializedEvidence,
) -> Result<FundingEvidence> {
    let buyer = entry.buyer.context("funding buyer missing")?;
    let kind = if entry.evidence_type == "NATIVE_FUNDING" {
        FundingKind::Native {
            transaction: transaction_ref(entry, materialized)?,
            receipt: receipt_ref(entry, materialized)?,
        }
    } else if let Some(deposit_log_index) = entry.deposit_log_index {
        FundingKind::ProtocolDeposit {
            transfer: log_ref(
                entry,
                required(entry.log_index, "funding transfer log index", entry)?,
                materialized,
            )?,
            deposited: log_ref(entry, deposit_log_index, materialized)?,
        }
    } else {
        FundingKind::Usdc {
            transfer: log_ref(
                entry,
                required(entry.log_index, "funding transfer log index", entry)?,
                materialized,
            )?,
        }
    };
    Ok(FundingEvidence { buyer, kind })
}

fn build_return_paths(
    claim: &PlannedClaim,
    seller: Address,
    funder: Address,
    materialized: &MaterializedEvidence,
) -> Result<Vec<ReturnPath>> {
    if seller == funder {
        if claim.selected_evidence.iter().any(|entry| {
            matches!(
                entry.evidence_type.as_str(),
                "DIRECT_SELLER_FUNDER" | "DIRECT_SELLER_BUYER" | "RELAY_PATH"
            )
        }) {
            bail!("self-funded plan must not include return evidence");
        }
        return Ok(Vec::new());
    }
    if claim.closure_type.as_deref() == Some("DIRECT_SELLER_BUYER")
        || claim
            .selected_evidence
            .iter()
            .any(|entry| entry.evidence_type == "DIRECT_SELLER_BUYER")
    {
        bail!("DIRECT_SELLER_BUYER is not a seller-to-funder return path");
    }
    let mut returns = Vec::new();
    for entry in &claim.selected_evidence {
        if entry.evidence_type == "DIRECT_SELLER_FUNDER" {
            returns.push(ReturnPath {
                transfers: vec![log_ref(
                    entry,
                    required(entry.log_index, "return log index", entry)?,
                    materialized,
                )?],
            });
        } else if entry.evidence_type == "RELAY_PATH" {
            let hops = atomic_evidence(entry)
                .into_iter()
                .map(|hop| {
                    log_ref(
                        hop,
                        required(hop.log_index, "relay log index", hop)?,
                        materialized,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            returns.push(ReturnPath { transfers: hops });
        }
    }
    if returns.is_empty() {
        bail!("closed-loop plan has no seller-to-funder return evidence");
    }
    Ok(returns)
}

fn buyer_ledger(
    client: &Client,
    materialized: &MaterializedEvidence,
    buyer: Address,
    period_end_block: u64,
) -> Result<BuyerLedger> {
    let slot = loop_core::slot_offset(
        loop_core::mapping_slot_address(buyer, DEPOSITS_BUYERS_SLOT),
        BUYER_ACCOUNT_BALANCE_OFFSET,
    );
    Ok(BuyerLedger {
        end: state_read(
            client,
            materialized,
            period_end_block,
            DEPOSITS_ADDRESS,
            slot,
        )?
        .0,
    })
}

fn state_read(
    client: &Client,
    materialized: &MaterializedEvidence,
    block_number: u64,
    contract: Address,
    slot: B256,
) -> Result<(StateRead, alloy_primitives::U256)> {
    let block = *materialized
        .block_positions
        .get(&block_number)
        .with_context(|| format!("state block {block_number} missing"))?;
    let (proof, value) =
        client.storage_witness(&materialized.blocks[block].header, contract, slot)?;
    Ok((StateRead { block, proof }, value))
}

fn is_pair_deposit(entry: &PlannedEvidence, subjects: &[Address]) -> bool {
    entry.evidence_type == "USDC_FUNDING"
        && entry.deposit_log_index.is_some()
        && entry.buyer.is_some_and(|buyer| subjects.contains(&buyer))
        && entry
            .funder
            .is_some_and(|funder| subjects.contains(&funder))
}

fn requires_transaction_proof(entry: &PlannedEvidence) -> bool {
    matches!(
        entry.evidence_type.as_str(),
        "USDC_FUNDING" | "NATIVE_FUNDING"
    )
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
    Ok(LogRef {
        block: receipt.block,
        receipt: receipt.receipt,
        log: *materialized
            .log_positions
            .get(&(block_number, block_log_index))
            .context("materialized log missing")?,
    })
}

fn required<T: Copy>(value: Option<T>, label: &str, entry: &PlannedEvidence) -> Result<T> {
    value.with_context(|| format!("{} evidence missing {label}", entry.evidence_type))
}

fn rpc_endpoints() -> Result<Vec<String>> {
    let value = env::var("BASE_RPC_URLS")
        .or_else(|_| env::var("BASE_RPC_URL"))
        .context("BASE_RPC_URLS or BASE_RPC_URL is not configured")?;
    let endpoints = value
        .split(',')
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        bail!("Base RPC configuration contains no endpoints");
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

    fn address(value: u8) -> Address {
        Address::from([value; 20])
    }

    #[test]
    fn pair_deposits_must_be_internal_protocol_deposits() {
        let mut entry = PlannedEvidence {
            evidence_type: "USDC_FUNDING".into(),
            block_number: Some(1),
            transaction_index: Some(0),
            log_index: Some(1),
            deposit_log_index: Some(2),
            buyer: Some(address(1)),
            funder: Some(address(2)),
            seller_payment: None,
            relay_forward: None,
            funder_receipt: None,
        };
        assert!(is_pair_deposit(&entry, &[address(1), address(2)]));
        entry.deposit_log_index = None;
        assert!(!is_pair_deposit(&entry, &[address(1), address(2)]));
    }

    #[test]
    fn relay_paths_expand_in_order() {
        let hop = |value: &str| PlannedEvidence {
            evidence_type: value.into(),
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
            evidence_type: "RELAY_PATH".into(),
            block_number: None,
            transaction_index: None,
            log_index: None,
            deposit_log_index: None,
            buyer: None,
            funder: None,
            seller_payment: Some(Box::new(hop("first"))),
            relay_forward: Some(Box::new(hop("second"))),
            funder_receipt: Some(Box::new(hop("third"))),
        };
        let expanded = atomic_evidence(&relay);
        assert_eq!(
            expanded
                .iter()
                .map(|entry| entry.evidence_type.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second", "third"]
        );
    }
}
