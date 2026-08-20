//! Host: fetches seller-penalty evidence from Base RPC, builds the guest fixture,
//! and runs the executor/prover.
//!
//!   loop-host fetch --case case.json --out fixture.json --selection-out selection.json
//!   loop-host run fixture.json            # native check + zkVM execute/prove
//!
//! RISC0_DEV_MODE=1 gives instant fake proofs with real cycle counts;
//! unset it for a real STARK.

mod rpc;
mod selection;

use alloy_primitives::{Address, B256};
use anyhow::{bail, Context, Result};
use loop_core::{
    report_volume_summary, BuyerClaim, FundingClaim, HopClaim, LogRef, ReportSettlementClaim,
    ReportVolumeClaim, SellerPenaltyInput, SellerPenaltyJournal, MINIMUM_COHORT_VOLUME_RAW,
};
use rayon::prelude::*;
use selection::{
    checkpoint_block_number, SelectedCheckpointWindow, AGGREGATE_VERIFIER_START_BLOCK,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};

const RPCS: &[&str] = &[
    "https://base.gateway.tenderly.co",
    "https://base.drpc.org",
    "https://base-public.nodies.app",
];
const DEPLOY_BLOCK: u64 = 44_469_557;

/// Case description: the claim to fetch evidence for.
#[derive(Deserialize)]
struct Case {
    chain_id: u64,
    usdc: Address,
    channels_contract: Address,
    deposits_contract: Address,
    seller: Address,
    funder: Address,
    start_block: u64,
    end_block_exclusive: u64,
    /// Tx hashes of the forwarding chain, in order (seller → … → funder).
    hop_txs: Vec<B256>,
    /// Expected (from, to) per hop, same order.
    hop_edges: Vec<(Address, Address)>,
    buyers: Vec<BuyerCase>,
    report: ReportCase,
}

#[derive(Deserialize)]
struct BuyerCase {
    buyer: Address,
}

#[derive(Deserialize)]
struct ReportCase {
    report_id: B256,
    expected_total_volume_raw: u128,
    expected_suspected_volume_raw: u128,
    suspected_buyers: Vec<Address>,
}

#[derive(Serialize)]
struct SelectionManifest {
    version: u32,
    chain_id: u64,
    start_block: u64,
    end_block_exclusive: u64,
    aggregate_verifier_start_block: u64,
    minimum_volume_raw: u128,
    report_settlement_count: usize,
    report_total_volume_raw: u128,
    report_suspected_volume_raw: u128,
    report_suspected_buyer_count: usize,
    qualified_settlement_count: usize,
    qualified_volume_raw: u128,
    report_evidence_root: B256,
    buyer_count: usize,
    buyer_coverage: Vec<BuyerSelectionManifest>,
    selected_block_numbers: Vec<u64>,
    checkpoint_windows: Vec<SelectedCheckpointWindow>,
}

#[derive(Serialize)]
struct BuyerSelectionManifest {
    buyer: Address,
    candidate_settlement_count: usize,
    selected_settlement_count: usize,
    selected_volume_raw: u128,
}

#[derive(Deserialize, Serialize)]
struct CachedBlockEvidence {
    evidence: loop_core::BlockEvidence,
    report_log_positions: Vec<(u64, u64, usize)>,
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("fetch") => {
            let case_path = arg_value(&args, "--case").context("--case required")?;
            let out_path = arg_value(&args, "--out").context("--out required")?;
            let selection_out = arg_value(&args, "--selection-out")
                .unwrap_or_else(|| format!("{out_path}.selection.json"));
            fetch(&case_path, &out_path, &selection_out)
        }
        Some("run") => {
            let fixture = args.get(2).context("usage: loop-host run fixture.json")?;
            run(
                fixture,
                args.iter().any(|a| a == "--prove"),
                arg_value(&args, "--journal-out"),
            )
        }
        _ => bail!(
            "usage: loop-host fetch --case case.json --out fixture.json [--selection-out selection.json] | loop-host run fixture.json [--prove] [--journal-out journal.hex]"
        ),
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

// ─────────────────────────────── fetch ───────────────────────────────

fn fetch(case_path: &str, out_path: &str, selection_out: &str) -> Result<()> {
    let case: Case = serde_json::from_str(&std::fs::read_to_string(case_path)?)?;
    if case.start_block >= case.end_block_exclusive {
        bail!("case start_block must be before end_block_exclusive");
    }
    if case.end_block_exclusive <= AGGREGATE_VERIFIER_START_BLOCK + 1 {
        bail!("case period ends before AggregateVerifier coverage");
    }
    if case.hop_txs.len() != case.hop_edges.len() {
        bail!("hop_txs and hop_edges must have the same length");
    }
    if case.buyers.len() < 3 {
        bail!("case requires at least three linked buyers");
    }
    let suspected_buyers = case
        .report
        .suspected_buyers
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if suspected_buyers.len() != case.report.suspected_buyers.len() {
        bail!("report suspected buyer list contains duplicates");
    }

    let mut endpoints: Vec<String> = std::env::var("BASE_RPC_URL")
        .ok()
        .into_iter()
        .flat_map(|urls| {
            urls.split(',')
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    endpoints.extend(RPCS.iter().map(|endpoint| (*endpoint).to_owned()));
    let client = rpc::Client::new(endpoints);

    let mut hop_locs = Vec::new();
    for (index, transaction_hash) in case.hop_txs.iter().enumerate() {
        let (from, to) = case.hop_edges[index];
        let location = client
            .find_transfer_in_tx(*transaction_hash, case.usdc, from, to)
            .with_context(|| format!("hop {index}: transfer not found in tx"))?;
        validate_fixed_block(&case, location.0, "hop")?;
        println!(
            "hop {index}: {from} -> {to} @ block {} tx {} log {}",
            location.0, location.1, location.2
        );
        hop_locs.push(location);
    }

    let mut buyer_fundings = Vec::with_capacity(case.buyers.len());
    for buyer_case in &case.buyers {
        let funding = client
            .find_first_transfer(case.usdc, case.funder, buyer_case.buyer, DEPLOY_BLOCK)?
            .with_context(|| format!("no funder→{} transfer found", buyer_case.buyer))?;
        validate_fixed_block(&case, funding.0, "funding")?;
        println!(
            "buyer {} funding: block {} tx {} log {}",
            buyer_case.buyer, funding.0, funding.1, funding.2
        );
        buyer_fundings.push((buyer_case.buyer, funding));
    }

    let report_start = case.start_block.max(AGGREGATE_VERIFIER_START_BLOCK + 1);
    let report_candidates = client.find_seller_settlements(
        case.channels_contract,
        case.seller,
        report_start,
        case.end_block_exclusive,
    )?;
    if report_candidates.is_empty() {
        bail!("report period contains no seller settlements");
    }
    for candidate in &report_candidates {
        validate_evidence_block(
            case.start_block,
            case.end_block_exclusive,
            candidate.block_number,
            "report settlement",
        )?;
    }

    let report_total_volume_raw =
        report_candidates
            .iter()
            .try_fold(0_u128, |total, candidate| {
                total
                    .checked_add(candidate.amount_raw)
                    .ok_or_else(|| anyhow::anyhow!("report total volume overflow"))
            })?;
    let report_suspected_volume_raw = report_candidates
        .iter()
        .filter(|candidate| suspected_buyers.contains(&candidate.buyer))
        .try_fold(0_u128, |total, candidate| {
            total
                .checked_add(candidate.amount_raw)
                .ok_or_else(|| anyhow::anyhow!("report suspected volume overflow"))
        })?;
    if report_total_volume_raw != case.report.expected_total_volume_raw {
        bail!(
            "RPC report total {} does not match expected {}",
            report_total_volume_raw,
            case.report.expected_total_volume_raw
        );
    }
    if report_suspected_volume_raw != case.report.expected_suspected_volume_raw {
        bail!(
            "RPC report suspected volume {} does not match expected {}",
            report_suspected_volume_raw,
            case.report.expected_suspected_volume_raw
        );
    }
    let observed_suspected_buyers = report_candidates
        .iter()
        .filter(|candidate| suspected_buyers.contains(&candidate.buyer))
        .map(|candidate| candidate.buyer)
        .collect::<BTreeSet<_>>();
    if observed_suspected_buyers != suspected_buyers {
        bail!("not every configured suspected buyer has report settlements");
    }
    println!(
        "report: {} settlements, {:.6} total USDC, {:.6} suspected USDC, {} suspected buyers",
        report_candidates.len(),
        report_total_volume_raw as f64 / 1e6,
        report_suspected_volume_raw as f64 / 1e6,
        suspected_buyers.len()
    );

    let funding_by_buyer = buyer_fundings
        .iter()
        .map(|(buyer, location)| (*buyer, location.0))
        .collect::<BTreeMap<_, _>>();
    let mut qualified_candidate_indices = vec![Vec::new(); case.buyers.len()];
    let buyer_index = case
        .buyers
        .iter()
        .enumerate()
        .map(|(index, buyer)| (buyer.buyer, index))
        .collect::<BTreeMap<_, _>>();
    let mut qualified_volume_raw = 0_u128;
    for (candidate_index, candidate) in report_candidates.iter().enumerate() {
        let Some(index) = buyer_index.get(&candidate.buyer).copied() else {
            continue;
        };
        if candidate.block_number <= funding_by_buyer[&candidate.buyer] {
            continue;
        }
        qualified_candidate_indices[index].push(candidate_index);
        qualified_volume_raw = qualified_volume_raw
            .checked_add(candidate.amount_raw)
            .context("qualified volume overflow")?;
    }
    for (index, candidates) in qualified_candidate_indices.iter().enumerate() {
        if candidates.is_empty() {
            bail!(
                "linked buyer {} has no post-funding settlements",
                case.buyers[index].buyer
            );
        }
    }
    if qualified_volume_raw < MINIMUM_COHORT_VOLUME_RAW
        || qualified_volume_raw
            .checked_mul(2)
            .context("qualified ratio overflow")?
            < report_total_volume_raw
    {
        bail!("linked cohort does not reach the report penalty thresholds");
    }
    println!(
        "qualified common-funder volume: {:.6} USDC across {} buyers",
        qualified_volume_raw as f64 / 1e6,
        case.buyers.len()
    );

    let mut targets_by_block = BTreeMap::<u64, BTreeSet<u64>>::new();
    let mut report_logs_by_block = BTreeMap::<u64, BTreeSet<u64>>::new();
    for (block, transaction_index, _) in hop_locs
        .iter()
        .chain(buyer_fundings.iter().map(|(_, location)| location))
    {
        targets_by_block
            .entry(*block)
            .or_default()
            .insert(*transaction_index as u64);
    }
    for candidate in &report_candidates {
        targets_by_block
            .entry(candidate.block_number)
            .or_default()
            .insert(candidate.transaction_index as u64);
        report_logs_by_block
            .entry(candidate.block_number)
            .or_default()
            .insert(candidate.block_log_index);
    }

    let cache_directory = std::path::Path::new("cache/full-report-blocks");
    std::fs::create_dir_all(cache_directory)?;
    let work = targets_by_block
        .iter()
        .map(|(block_number, targets)| {
            (
                *block_number,
                targets.iter().copied().collect::<Vec<_>>(),
                report_logs_by_block
                    .get(block_number)
                    .map(|indices| indices.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    let completed = AtomicUsize::new(0);
    let fetched = work
        .par_iter()
        .map(|(block_number, target_indices, report_log_indices)| {
            let cache_path = cache_directory.join(format!("{block_number}.json"));
            let cached = if cache_path.exists() {
                let bytes = std::fs::read(&cache_path)
                    .with_context(|| format!("read {}", cache_path.display()))?;
                Some(
                    serde_json::from_slice::<CachedBlockEvidence>(&bytes)
                        .with_context(|| format!("decode {}", cache_path.display()))?,
                )
            } else {
                None
            };
            let cached = match cached {
                Some(cached) => cached,
                None => {
                    let (evidence, report_log_positions) =
                        client.block_evidence(*block_number, target_indices, report_log_indices)?;
                    let cached = CachedBlockEvidence {
                        evidence,
                        report_log_positions: report_log_positions
                            .into_iter()
                            .map(|((transaction_index, block_log_index), local_index)| {
                                (transaction_index, block_log_index, local_index)
                            })
                            .collect(),
                    };
                    let temporary_path = cache_path.with_extension("json.tmp");
                    std::fs::write(&temporary_path, serde_json::to_vec(&cached)?)?;
                    std::fs::rename(&temporary_path, &cache_path)?;
                    cached
                }
            };
            let count = completed.fetch_add(1, Ordering::Relaxed) + 1;
            if count % 100 == 0 || count == work.len() {
                println!("fetched block evidence {count}/{}", work.len());
            }
            Ok::<_, anyhow::Error>((*block_number, cached))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut blocks = Vec::with_capacity(targets_by_block.len());
    let mut block_index = BTreeMap::new();
    let mut receipt_position = BTreeMap::<(u64, u64), usize>::new();
    let mut report_local_log = BTreeMap::<(u64, u64, u64), usize>::new();
    for (index, (block_number, cached)) in fetched.into_iter().enumerate() {
        let evidence = cached.evidence;
        for (position, receipt) in evidence.receipts.iter().enumerate() {
            receipt_position.insert((block_number, receipt.tx_index), position);
        }
        for (transaction_index, block_log_index, local_index) in cached.report_log_positions {
            report_local_log.insert(
                (block_number, transaction_index, block_log_index),
                local_index,
            );
        }
        block_index.insert(block_number, index);
        blocks.push(evidence);
    }

    let fixed_ref = |location: &(u64, usize, usize)| LogRef {
        block: block_index[&location.0],
        receipt: receipt_position[&(location.0, location.1 as u64)],
        log: location.2,
    };
    let report_ref = |candidate: &rpc::SettlementCandidate| LogRef {
        block: block_index[&candidate.block_number],
        receipt: receipt_position[&(candidate.block_number, candidate.transaction_index as u64)],
        log: report_local_log[&(
            candidate.block_number,
            candidate.transaction_index as u64,
            candidate.block_log_index,
        )],
    };

    let mut input = SellerPenaltyInput {
        chain_id: case.chain_id,
        usdc: case.usdc,
        channels_contract: case.channels_contract,
        deposits_contract: case.deposits_contract,
        seller: case.seller,
        funder: case.funder,
        blocks,
        hops: hop_locs
            .iter()
            .zip(&case.hop_edges)
            .map(|(location, (from, to))| HopClaim {
                transfer: fixed_ref(location),
                from: *from,
                to: *to,
            })
            .collect(),
        buyers: buyer_fundings
            .iter()
            .enumerate()
            .map(|(index, (buyer, funding))| BuyerClaim {
                buyer: *buyer,
                funding: FundingClaim::DirectTransfer {
                    transfer: fixed_ref(funding),
                },
                settlements: qualified_candidate_indices[index]
                    .iter()
                    .map(|candidate_index| report_ref(&report_candidates[*candidate_index]))
                    .collect(),
            })
            .collect(),
        report: ReportVolumeClaim {
            report_id: case.report.report_id,
            evidence_root: B256::ZERO,
            start_block: case.start_block,
            end_block_exclusive: case.end_block_exclusive,
            expected_total_volume_raw: case.report.expected_total_volume_raw,
            expected_suspected_volume_raw: case.report.expected_suspected_volume_raw,
            expected_suspected_buyer_count: u32::try_from(suspected_buyers.len())
                .context("suspected buyer count overflow")?,
            settlements: report_candidates
                .iter()
                .map(|candidate| ReportSettlementClaim {
                    buyer: candidate.buyer,
                    settlement: report_ref(candidate),
                    suspected: suspected_buyers.contains(&candidate.buyer),
                })
                .collect(),
        },
    };
    input.report.evidence_root = report_volume_summary(&input)
        .map_err(|error| anyhow::anyhow!(error))?
        .evidence_root;

    let journal =
        loop_core::verify(&input).map_err(|error| anyhow::anyhow!("predicate: {error}"))?;
    if journal.qualified_volume_raw != qualified_volume_raw {
        bail!(
            "RPC qualified volume {} does not match authenticated volume {}",
            qualified_volume_raw,
            journal.qualified_volume_raw
        );
    }
    print_journal(&journal);

    let selected_block_numbers = targets_by_block.keys().copied().collect::<Vec<_>>();
    let mut target_blocks_by_checkpoint = BTreeMap::<u64, BTreeSet<u64>>::new();
    for block_number in &selected_block_numbers {
        target_blocks_by_checkpoint
            .entry(checkpoint_block_number(*block_number).map_err(anyhow::Error::msg)?)
            .or_default()
            .insert(*block_number);
    }
    let checkpoint_windows = target_blocks_by_checkpoint
        .into_iter()
        .map(
            |(checkpoint_block_number, target_blocks)| SelectedCheckpointWindow {
                checkpoint_block_number,
                target_blocks: target_blocks.into_iter().collect(),
            },
        )
        .collect::<Vec<_>>();
    let buyer_coverage = case
        .buyers
        .iter()
        .enumerate()
        .map(|(index, buyer)| BuyerSelectionManifest {
            buyer: buyer.buyer,
            candidate_settlement_count: report_candidates
                .iter()
                .filter(|candidate| candidate.buyer == buyer.buyer)
                .count(),
            selected_settlement_count: qualified_candidate_indices[index].len(),
            selected_volume_raw: qualified_candidate_indices[index]
                .iter()
                .map(|candidate_index| report_candidates[*candidate_index].amount_raw)
                .sum(),
        })
        .collect();
    let manifest = SelectionManifest {
        version: 2,
        chain_id: case.chain_id,
        start_block: case.start_block,
        end_block_exclusive: case.end_block_exclusive,
        aggregate_verifier_start_block: AGGREGATE_VERIFIER_START_BLOCK,
        minimum_volume_raw: MINIMUM_COHORT_VOLUME_RAW,
        report_settlement_count: report_candidates.len(),
        report_total_volume_raw,
        report_suspected_volume_raw,
        report_suspected_buyer_count: suspected_buyers.len(),
        qualified_settlement_count: qualified_candidate_indices.iter().map(Vec::len).sum(),
        qualified_volume_raw,
        report_evidence_root: input.report.evidence_root,
        buyer_count: case.buyers.len(),
        buyer_coverage,
        selected_block_numbers,
        checkpoint_windows,
    };

    std::fs::write(out_path, serde_json::to_vec(&input)?)?;
    std::fs::write(selection_out, serde_json::to_vec_pretty(&manifest)?)?;
    println!("fixture written to {out_path}");
    println!("selection manifest written to {selection_out}");
    Ok(())
}

#[cfg(any())]
fn fetch_legacy(case_path: &str, out_path: &str, selection_out: &str) -> Result<()> {
    let case: Case = serde_json::from_str(&std::fs::read_to_string(case_path)?)?;
    if case.start_block >= case.end_block_exclusive {
        bail!("case start_block must be before end_block_exclusive");
    }
    if case.end_block_exclusive <= AGGREGATE_VERIFIER_START_BLOCK + 1 {
        bail!("case period ends before AggregateVerifier coverage");
    }
    if case.hop_txs.len() != case.hop_edges.len() {
        bail!("hop_txs and hop_edges must have the same length");
    }
    let mut endpoints: Vec<String> = std::env::var("BASE_RPC_URL")
        .ok()
        .into_iter()
        .flat_map(|urls| {
            urls.split(',')
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    endpoints.extend(RPCS.iter().map(|endpoint| (*endpoint).to_owned()));
    let client = rpc::Client::new(endpoints);

    // 1. Locate the hop Transfer logs from their tx receipts.
    let mut hop_locs = Vec::new(); // (block_number, tx_index, log_index_in_receipt)
    for (i, tx) in case.hop_txs.iter().enumerate() {
        let (from, to) = case.hop_edges[i];
        let loc = client
            .find_transfer_in_tx(*tx, case.usdc, from, to)
            .with_context(|| format!("hop {i}: transfer not found in tx"))?;
        println!(
            "hop {i}: {from} -> {to} @ block {} tx {} log {}",
            loc.0, loc.1, loc.2
        );
        hop_locs.push(loc);
    }

    for (block_number, _, _) in &hop_locs {
        validate_fixed_block(&case, *block_number, "hop")?;
    }

    // 2. First funding and post-funding settlements for each claimed buyer.
    let mut buyer_fundings = Vec::new();
    let mut settlement_candidates = Vec::new();
    for (buyer_index, buyer_case) in case.buyers.iter().enumerate() {
        let funding = client
            .find_first_transfer(case.usdc, case.funder, buyer_case.buyer, DEPLOY_BLOCK)?
            .with_context(|| format!("no funder→{} transfer found", buyer_case.buyer))?;
        println!(
            "buyer {} funding: block {} tx {} log {}",
            buyer_case.buyer, funding.0, funding.1, funding.2
        );
        validate_fixed_block(&case, funding.0, "funding")?;
        buyer_fundings.push((buyer_case.buyer, funding));
        let settlement_start = (funding.0 + 1)
            .max(case.start_block)
            .max(AGGREGATE_VERIFIER_START_BLOCK + 1);
        let settlements = client.find_settlements(
            case.channels_contract,
            buyer_case.buyer,
            case.seller,
            settlement_start,
            case.end_block_exclusive,
        )?;
        for settlement in &settlements {
            validate_evidence_block(
                case.start_block,
                case.end_block_exclusive,
                settlement.block_number,
                "settlement",
            )?;
            if settlement.block_number <= funding.0 {
                bail!(
                    "settlement block {} is not after funding block {}",
                    settlement.block_number,
                    funding.0
                );
            }
        }
        if settlements.is_empty() {
            bail!(
                "no ChannelSettled({}, {}) events after funding block",
                buyer_case.buyer,
                case.seller
            );
        }
        println!(
            "buyer {}: {} bounded settlement candidates",
            buyer_case.buyer,
            settlements.len()
        );
        settlement_candidates.extend(settlements.into_iter().map(|settlement| {
            BuyerSettlementCandidate {
                buyer_index,
                settlement,
            }
        }));
    }

    let fixed_blocks = hop_locs
        .iter()
        .map(|location| location.0)
        .chain(buyer_fundings.iter().map(|(_, location)| location.0))
        .collect::<Vec<_>>();
    let selection = select_minimum_windows(
        &settlement_candidates,
        &fixed_blocks,
        case.buyers.len(),
        MINIMUM_COHORT_VOLUME_RAW,
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    println!(
        "selected {} of {} settlements across {} checkpoint windows",
        selection.selected_candidate_indices.len(),
        settlement_candidates.len(),
        selection.checkpoint_windows.len()
    );
    println!(
        "selected volume: {:.6} USDC",
        selection.selected_volume_raw as f64 / 1e6
    );

    let mut selected_by_buyer = vec![Vec::new(); case.buyers.len()];
    for candidate_index in &selection.selected_candidate_indices {
        let candidate = &settlement_candidates[*candidate_index];
        selected_by_buyer[candidate.buyer_index]
            .push(client.locate_settlement(&candidate.settlement)?);
    }
    for settlements in &mut selected_by_buyer {
        settlements.sort_unstable();
    }
    let buyer_locs = buyer_fundings
        .into_iter()
        .enumerate()
        .map(|(buyer_index, (buyer, funding))| {
            (
                buyer,
                funding,
                std::mem::take(&mut selected_by_buyer[buyer_index]),
            )
        })
        .collect::<Vec<_>>();

    // 3. Gather referenced blocks: header + inclusion proofs for exactly the
    // receipts the claim touches.
    let mut all_locs: Vec<&(u64, usize, usize)> = hop_locs.iter().collect();
    for (_, funding, settlements) in &buyer_locs {
        all_locs.push(funding);
        all_locs.extend(settlements.iter());
    }
    let mut targets_by_block: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (block, tx, _) in all_locs.iter().copied() {
        let t = targets_by_block.entry(*block).or_default();
        if !t.contains(&(*tx as u64)) {
            t.push(*tx as u64);
        }
    }

    let mut blocks = Vec::new();
    let mut block_index = BTreeMap::new();
    let mut receipt_pos: BTreeMap<(u64, u64), usize> = BTreeMap::new();
    for (idx, (num, targets)) in targets_by_block.iter().enumerate() {
        let evidence = client.block_evidence(*num, targets)?;
        println!(
            "block {num}: {} proven receipts, {} proof nodes, hash {}",
            evidence.receipts.len(),
            evidence
                .receipts
                .iter()
                .map(|r| r.proof.len())
                .sum::<usize>(),
            evidence.header.hash_slow()
        );
        for (pos, rp) in evidence.receipts.iter().enumerate() {
            receipt_pos.insert((*num, rp.tx_index), pos);
        }
        block_index.insert(*num, idx);
        blocks.push(evidence);
    }

    let to_ref = |loc: &(u64, usize, usize)| LogRef {
        block: block_index[&loc.0],
        receipt: receipt_pos[&(loc.0, loc.1 as u64)],
        log: loc.2,
    };

    let input = SellerPenaltyInput {
        chain_id: case.chain_id,
        usdc: case.usdc,
        channels_contract: case.channels_contract,
        deposits_contract: case.deposits_contract,
        seller: case.seller,
        funder: case.funder,
        blocks,
        hops: hop_locs
            .iter()
            .zip(&case.hop_edges)
            .map(|(loc, (from, to))| HopClaim {
                transfer: to_ref(loc),
                from: *from,
                to: *to,
            })
            .collect(),
        buyers: buyer_locs
            .iter()
            .map(|(buyer, funding, settlements)| BuyerClaim {
                buyer: *buyer,
                funding: FundingClaim::DirectTransfer {
                    transfer: to_ref(funding),
                },
                settlements: settlements.iter().map(&to_ref).collect(),
            })
            .collect(),
    };

    // 5. Native predicate check before writing the fixture.
    let journal = loop_core::verify(&input).map_err(|e| anyhow::anyhow!("predicate: {e}"))?;
    if journal.suspicious_volume_raw != selection.selected_volume_raw {
        bail!(
            "selected RPC volume {} does not match authenticated receipt volume {}",
            selection.selected_volume_raw,
            journal.suspicious_volume_raw
        );
    }
    print_journal(&journal);

    let selected_block_numbers = targets_by_block.keys().copied().collect::<Vec<_>>();
    let buyer_coverage = case
        .buyers
        .iter()
        .enumerate()
        .map(|(buyer_index, buyer_case)| {
            let candidate_settlement_count = settlement_candidates
                .iter()
                .filter(|candidate| candidate.buyer_index == buyer_index)
                .count();
            let selected_candidates = selection
                .selected_candidate_indices
                .iter()
                .map(|candidate_index| &settlement_candidates[*candidate_index])
                .filter(|candidate| candidate.buyer_index == buyer_index)
                .collect::<Vec<_>>();
            let selected_volume_raw = selected_candidates
                .iter()
                .map(|candidate| candidate.settlement.amount_raw)
                .sum();
            BuyerSelectionManifest {
                buyer: buyer_case.buyer,
                candidate_settlement_count,
                selected_settlement_count: selected_candidates.len(),
                selected_volume_raw,
            }
        })
        .collect();
    let manifest = SelectionManifest {
        version: 1,
        chain_id: case.chain_id,
        start_block: case.start_block,
        end_block_exclusive: case.end_block_exclusive,
        aggregate_verifier_start_block: AGGREGATE_VERIFIER_START_BLOCK,
        minimum_volume_raw: MINIMUM_COHORT_VOLUME_RAW,
        candidate_settlement_count: settlement_candidates.len(),
        selected_settlement_count: selection.selected_candidate_indices.len(),
        selected_volume_raw: selection.selected_volume_raw,
        buyer_count: case.buyers.len(),
        buyer_coverage,
        selected_block_numbers,
        checkpoint_windows: selection.checkpoint_windows,
    };

    std::fs::write(out_path, serde_json::to_vec(&input)?)?;
    std::fs::write(selection_out, serde_json::to_vec_pretty(&manifest)?)?;
    println!("fixture written to {out_path}");
    println!("selection manifest written to {selection_out}");
    Ok(())
}

fn validate_fixed_block(case_data: &Case, block_number: u64, label: &str) -> Result<()> {
    validate_evidence_block(
        case_data.start_block,
        case_data.end_block_exclusive,
        block_number,
        label,
    )
}

fn validate_evidence_block(
    start_block: u64,
    end_block_exclusive: u64,
    block_number: u64,
    label: &str,
) -> Result<()> {
    if block_number < start_block || block_number >= end_block_exclusive {
        bail!(
            "{label} block {block_number} is outside case period [{start_block}, {end_block_exclusive})"
        );
    }
    if block_number <= AGGREGATE_VERIFIER_START_BLOCK {
        bail!("{label} block {block_number} predates AggregateVerifier coverage");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_start_inclusive_end_exclusive_period() {
        let start = AGGREGATE_VERIFIER_START_BLOCK + 1;
        let end = start + 10;

        assert!(validate_evidence_block(start, end, start, "test").is_ok());
        assert!(validate_evidence_block(start, end, end - 1, "test").is_ok());
        assert!(validate_evidence_block(start, end, start - 1, "test").is_err());
        assert!(validate_evidence_block(start, end, end, "test").is_err());
    }

    #[test]
    fn rejects_blocks_before_aggregate_verifier_coverage() {
        assert!(validate_evidence_block(
            AGGREGATE_VERIFIER_START_BLOCK,
            AGGREGATE_VERIFIER_START_BLOCK + 2,
            AGGREGATE_VERIFIER_START_BLOCK,
            "test",
        )
        .is_err());
    }
}

// ─────────────────────────────── run ───────────────────────────────

fn run(fixture_path: &str, prove: bool, journal_out: Option<String>) -> Result<()> {
    let input: SellerPenaltyInput = serde_json::from_str(&std::fs::read_to_string(fixture_path)?)?;

    // Native check first — fail fast before spending prover time.
    let native = loop_core::verify(&input).map_err(|e| anyhow::anyhow!("predicate: {e}"))?;
    println!("native verify OK");
    print_journal(&native);

    let env = risc0_zkvm::ExecutorEnv::builder().write(&input)?.build()?;

    if prove {
        let prover = risc0_zkvm::default_prover();
        let start = std::time::Instant::now();
        let info = prover.prove(env, methods::LOOP_GUEST_ELF)?;
        let elapsed = start.elapsed();
        println!(
            "proved in {elapsed:?}  (dev mode: {})",
            std::env::var("RISC0_DEV_MODE").unwrap_or_default() == "1"
        );
        println!(
            "cycles: user={} total={} segments={}",
            info.stats.user_cycles, info.stats.total_cycles, info.stats.segments
        );
        info.receipt.verify(methods::LOOP_GUEST_ID)?;
        println!(
            "proof verified against image ID {:x?}",
            methods::LOOP_GUEST_ID
        );
        report_journal_bytes(&info.receipt.journal.bytes, journal_out.as_deref())?;
    } else {
        let exec = risc0_zkvm::default_executor();
        let session = exec.execute(env, methods::LOOP_GUEST_ELF)?;
        println!("executed OK (no proof)");
        report_journal_bytes(&session.journal.bytes, journal_out.as_deref())?;
    }
    Ok(())
}

/// Decode the guest's ABI journal and report the exact bytes the on-chain
/// registry will see (`sha256(journalData)` / calldata).
fn report_journal_bytes(bytes: &[u8], journal_out: Option<&str>) -> Result<()> {
    let journal = SellerPenaltyJournal::abi_decode(bytes).map_err(|e| anyhow::anyhow!(e))?;
    print_journal(&journal);
    use sha2::Digest;
    println!(
        "journal sha256: 0x{}",
        alloy_primitives::hex::encode(sha2::Sha256::digest(bytes))
    );
    println!("journal abi bytes: {}", bytes.len());
    let encoded = format!("0x{}", alloy_primitives::hex::encode(bytes));
    if let Some(path) = journal_out {
        std::fs::write(path, &encoded)?;
        println!("journal abi written to {path}");
    } else if bytes.len() <= 64 * 1024 {
        println!("journal abi hex: {encoded}");
    } else {
        println!("journal abi hex omitted; pass --journal-out to write it");
    }
    Ok(())
}

fn print_journal(j: &SellerPenaltyJournal) {
    println!("journal:");
    println!("  seller  {}", j.seller);
    println!("  funder  {} (hops: {})", j.funder, j.hop_count);
    println!("  linked buyers         {}", j.linked_buyer_count);
    println!("  future reward penalty {} BPS", j.penalty_bps);
    println!(
        "  seller outflow        ${:.2}",
        j.seller_outflow_raw as f64 / 1e6
    );
    println!(
        "  total funded          ${:.2} (first block {})",
        j.total_funded_raw as f64 / 1e6,
        j.earliest_funding_block
    );
    println!(
        "  qualified volume      ${:.6} ({:.2}% of report total)",
        j.qualified_volume_raw as f64 / 1e6,
        j.qualified_share_bps as f64 / 100.0,
    );
    println!(
        "  report volume         ${:.6} total / ${:.6} suspected ({} buyers)",
        j.report_total_volume_raw as f64 / 1e6,
        j.report_suspected_volume_raw as f64 / 1e6,
        j.report_suspected_buyer_count,
    );
    println!(
        "  report period         [{}..{})  id {}",
        j.report_start_block, j.report_end_block_exclusive, j.report_id,
    );
    println!(
        "  report evidence root  {}  (last settlement block {})",
        j.report_evidence_root, j.latest_settlement_block
    );
    println!("  blocks relied on      {}", j.block_refs.len());
}
