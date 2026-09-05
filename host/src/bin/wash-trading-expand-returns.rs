#[path = "../rpc.rs"]
mod rpc;

use alloy_primitives::Address;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::BufWriter,
};
use wash_predicate::{
    resolver::ChainResolver,
    seller::{verify_seller, SellerEvidence, SellerProofInput},
    LogRef, ReturnPath,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Selection {
    target_return_bps: u64,
    fixed_volume_raw: String,
    paths: Vec<SelectedPath>,
}

#[derive(Deserialize)]
struct SelectedPath {
    hops: Vec<SelectedHop>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SelectedHop {
    from: Address,
    to: Address,
    amount_raw: String,
    timestamp: u64,
    block_number: u64,
    transaction_index: u64,
    receipt_log_index: usize,
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let original = args.first().context("original seller input required")?;
    let selection_file = args.get(1).context("selected paths required")?;
    let output = args.get(2).context("output directory required")?;
    let bytes = fs::read(original)?;
    let mut input: SellerProofInput = serde_json::from_slice(&bytes)?;
    drop(bytes);
    let selection: Selection = serde_json::from_slice(&fs::read(selection_file)?)?;
    if selection.target_return_bps == 0 || selection.target_return_bps > 10_000 {
        bail!("invalid target return basis points")
    }
    let baseline = verify_seller(&input).map_err(anyhow::Error::msg)?;
    let original_volume = baseline.journal.proven_wash_volume;
    let original_total = baseline.journal.total_seller_volume;
    if selection.fixed_volume_raw.parse::<u128>()? != original_volume {
        bail!("fixed V differs from baseline")
    }
    let SellerEvidence::ClosedLoop(evidence) = &mut input.evidence else {
        bail!("closed-loop input required")
    };
    let original_settlements = evidence.settlements.clone();
    let original_fundings = serde_json::to_vec(&evidence.fundings)?;
    let original_ledgers = serde_json::to_vec(&evidence.ledgers)?;
    let original_buyers = evidence.buyers.clone();
    let mut block_positions = evidence
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.header.number, index))
        .collect::<BTreeMap<_, _>>();
    let mut targets = BTreeMap::<u64, BTreeSet<u64>>::new();
    for path in &selection.paths {
        for hop in &path.hops {
            let present = block_positions
                .get(&hop.block_number)
                .is_some_and(|position| {
                    evidence.blocks[*position]
                        .receipts
                        .iter()
                        .any(|receipt| receipt.tx_index == hop.transaction_index)
                });
            if !present {
                targets
                    .entry(hop.block_number)
                    .or_default()
                    .insert(hop.transaction_index);
            }
        }
    }
    let targets = targets
        .into_iter()
        .map(|(number, receipts)| (number, receipts.into_iter().collect(), vec![]))
        .collect::<Vec<_>>();
    eprintln!(
        "fetching inclusion proofs for {} additional blocks",
        targets.len()
    );
    let client = rpc::Client::new(&[env::var("BASE_RPC_URL").context("BASE_RPC_URL required")?]);
    for (block, _) in client.block_evidence_many(&targets, 4)? {
        if let Some(position) = block_positions.get(&block.header.number) {
            let existing = &mut evidence.blocks[*position];
            if existing.header.hash_slow() != block.header.hash_slow() {
                bail!("conflicting block header")
            }
            for receipt in block.receipts {
                if !existing
                    .receipts
                    .iter()
                    .any(|item| item.tx_index == receipt.tx_index)
                {
                    existing.receipts.push(receipt);
                }
            }
        } else {
            block_positions.insert(block.header.number, evidence.blocks.len());
            evidence.blocks.push(block);
        }
    }
    let mut returns = Vec::new();
    for path in &selection.paths {
        let mut transfers = Vec::new();
        for hop in &path.hops {
            let block = *block_positions
                .get(&hop.block_number)
                .context("missing block")?;
            let receipt = evidence.blocks[block]
                .receipts
                .iter()
                .position(|receipt| receipt.tx_index == hop.transaction_index)
                .context("missing receipt")?;
            let reference = LogRef {
                block,
                receipt,
                log: hop.receipt_log_index,
            };
            let resolver = ChainResolver {
                blocks: &evidence.blocks,
            };
            let (from, to, amount, _) = resolver
                .usdc_transfer(reference)
                .map_err(anyhow::Error::msg)?;
            if from != hop.from
                || to != hop.to
                || amount != hop.amount_raw.parse::<u128>()?
                || resolver.timestamp(reference).map_err(anyhow::Error::msg)? != hop.timestamp
            {
                bail!("authenticated transfer differs from candidate")
            }
            transfers.push(reference);
        }
        returns.push(ReturnPath { transfers });
    }
    evidence.returns = returns;
    if evidence.settlements != original_settlements
        || serde_json::to_vec(&evidence.fundings)? != original_fundings
        || serde_json::to_vec(&evidence.ledgers)? != original_ledgers
        || evidence.buyers != original_buyers
    {
        bail!("original claim evidence changed")
    }
    let verified = verify_seller(&input).map_err(anyhow::Error::msg)?;
    if verified.journal.proven_wash_volume != original_volume
        || verified.journal.total_seller_volume != original_total
    {
        bail!("original V/T changed")
    }
    let SellerEvidence::ClosedLoop(evidence) = &input.evidence else {
        unreachable!()
    };
    let resolver = ChainResolver {
        blocks: &evidence.blocks,
    };
    let mut credit = 0u128;
    for path in &evidence.returns {
        let mut minimum = u128::MAX;
        for reference in &path.transfers {
            minimum = minimum.min(
                resolver
                    .usdc_transfer(*reference)
                    .map_err(anyhow::Error::msg)?
                    .2,
            );
        }
        credit = credit.checked_add(minimum).context("credit overflow")?;
    }
    let passes_target_return_floor = credit.checked_mul(10_000).context("ratio overflow")?
        >= verified
            .journal
            .proven_wash_volume
            .checked_mul(u128::from(selection.target_return_bps))
            .context("ratio overflow")?;
    if !passes_target_return_floor {
        bail!("expanded evidence below requested return floor")
    }
    fs::create_dir(output)?;
    serde_json::to_writer(
        BufWriter::new(fs::File::create(format!("{output}/expanded.witness.json"))?),
        evidence,
    )?;
    serde_json::to_writer(
        BufWriter::new(fs::File::create(format!(
            "{output}/total-volume-witness.json"
        ))?),
        &input.total_volume,
    )?;
    let report = json!({
        "seller": input.seller,
        "nativeVerified": true,
        "guestExecutionCompleted": false,
        "currentPredicateAlphaReturnBps": wash_predicate::ALPHA_RETURN_BPS,
        "targetReturnBps": selection.target_return_bps,
        "independentlyPassesTargetReturnFloor": passes_target_return_floor,
        "provenWashVolumeRaw": verified.journal.proven_wash_volume.to_string(),
        "totalSellerVolumeRaw": verified.journal.total_seller_volume.to_string(),
        "returnedCreditRaw": credit.to_string(),
        "settlementCount": evidence.settlements.len(),
        "buyerCount": evidence.buyers.len(),
        "returnPathCount": evidence.returns.len(),
        "settlementsFundingBuyersLedgersUnchanged": true,
        "additionalProofBlocks": targets.len(),
        "evidenceDigest": verified.journal.evidence_digest,
        "periodStartBlock": input.period_start_block,
        "periodEndBlock": input.period_end_block
    });
    fs::write(
        format!("{output}/native-verification.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
