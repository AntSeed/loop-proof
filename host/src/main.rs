//! Host: fetches loop evidence from Base RPC, builds the guest fixture,
//! and runs the executor/prover.
//!
//!   loop-host fetch --case case.json --out fixture.json
//!   loop-host run fixture.json            # native check + zkVM execute/prove
//!
//! RISC0_DEV_MODE=1 gives instant fake proofs with real cycle counts;
//! unset it for a real STARK.

mod rpc;

use alloy_primitives::{Address, B256};
use anyhow::{bail, Context, Result};
use loop_core::{FundingClaim, HopClaim, LogRef, LoopInput, LoopJournal};
use serde::Deserialize;
use std::collections::BTreeMap;

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
    buyer: Address,
    funder: Address,
    /// Tx hashes of the forwarding chain, in order (seller → … → funder).
    hop_txs: Vec<B256>,
    /// Expected (from, to) per hop, same order.
    hop_edges: Vec<(Address, Address)>,
    /// Max settlements to include as evidence.
    #[serde(default = "default_max_settlements")]
    max_settlements: usize,
}
fn default_max_settlements() -> usize {
    3
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("fetch") => {
            let case_path = arg_value(&args, "--case").context("--case required")?;
            let out_path = arg_value(&args, "--out").context("--out required")?;
            fetch(&case_path, &out_path)
        }
        Some("run") => {
            let fixture = args.get(2).context("usage: loop-host run fixture.json")?;
            run(fixture, args.iter().any(|a| a == "--prove"))
        }
        _ => bail!("usage: loop-host fetch --case case.json --out fixture.json | loop-host run fixture.json [--prove]"),
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

// ─────────────────────────────── fetch ───────────────────────────────

fn fetch(case_path: &str, out_path: &str) -> Result<()> {
    let case: Case = serde_json::from_str(&std::fs::read_to_string(case_path)?)?;
    let client = rpc::Client::new(RPCS);

    // 1. Locate the hop Transfer logs from their tx receipts.
    let mut hop_locs = Vec::new(); // (block_number, tx_index, log_index_in_receipt)
    for (i, tx) in case.hop_txs.iter().enumerate() {
        let (from, to) = case.hop_edges[i];
        let loc = client
            .find_transfer_in_tx(*tx, case.usdc, from, to)
            .with_context(|| format!("hop {i}: transfer not found in tx"))?;
        println!("hop {i}: {from} -> {to} @ block {} tx {} log {}", loc.0, loc.1, loc.2);
        hop_locs.push(loc);
    }

    // 2. First funder→buyer USDC transfer (shape A funding evidence).
    let funding = client
        .find_first_transfer(case.usdc, case.funder, case.buyer, DEPLOY_BLOCK)?
        .context("no funder→buyer transfer found")?;
    println!("funding: block {} tx {} log {}", funding.0, funding.1, funding.2);

    // 3. Settlements buyer→seller strictly after the funding block.
    let settlements = client.find_settlements(
        case.channels_contract,
        case.buyer,
        case.seller,
        funding.0 + 1,
        case.max_settlements,
    )?;
    if settlements.is_empty() {
        bail!("no ChannelSettled(buyer, seller) events after funding block");
    }
    for s in &settlements {
        println!("settlement: block {} tx {} log {}", s.0, s.1, s.2);
    }

    // 4. Gather referenced blocks: header + inclusion proofs for exactly the
    // receipts the claim touches.
    let all_locs: Vec<&(u64, usize, usize)> = hop_locs
        .iter()
        .chain(std::iter::once(&funding))
        .chain(settlements.iter())
        .collect();
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
            evidence.receipts.iter().map(|r| r.proof.len()).sum::<usize>(),
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

    let input = LoopInput {
        chain_id: case.chain_id,
        usdc: case.usdc,
        channels_contract: case.channels_contract,
        deposits_contract: case.deposits_contract,
        seller: case.seller,
        buyer: case.buyer,
        funder: case.funder,
        blocks,
        hops: hop_locs
            .iter()
            .zip(&case.hop_edges)
            .map(|(loc, (from, to))| HopClaim { transfer: to_ref(loc), from: *from, to: *to })
            .collect(),
        funding: FundingClaim::DirectTransfer { transfer: to_ref(&funding) },
        settlements: settlements.iter().map(|l| to_ref(l)).collect(),
    };

    // 5. Native predicate check before writing the fixture.
    let journal = loop_core::verify(&input).map_err(|e| anyhow::anyhow!("predicate: {e}"))?;
    print_journal(&journal);

    std::fs::write(out_path, serde_json::to_vec(&input)?)?;
    println!("fixture written to {out_path}");
    Ok(())
}

// ─────────────────────────────── run ───────────────────────────────

fn run(fixture_path: &str, prove: bool) -> Result<()> {
    let input: LoopInput = serde_json::from_str(&std::fs::read_to_string(fixture_path)?)?;

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
        println!("proof verified against image ID {:x?}", methods::LOOP_GUEST_ID);
        report_journal_bytes(&info.receipt.journal.bytes)?;
    } else {
        let exec = risc0_zkvm::default_executor();
        let session = exec.execute(env, methods::LOOP_GUEST_ELF)?;
        println!("executed OK (no proof)");
        report_journal_bytes(&session.journal.bytes)?;
    }
    Ok(())
}

/// Decode the guest's ABI journal, print it, and print the digest + hex the
/// on-chain registry will see (`sha256(journalData)` / calldata).
fn report_journal_bytes(bytes: &[u8]) -> Result<()> {
    let journal = LoopJournal::abi_decode(bytes).map_err(|e| anyhow::anyhow!(e))?;
    print_journal(&journal);
    use sha2::Digest;
    println!("journal sha256: 0x{}", alloy_primitives::hex::encode(sha2::Sha256::digest(bytes)));
    println!("journal abi hex: 0x{}", alloy_primitives::hex::encode(bytes));
    Ok(())
}

fn print_journal(j: &LoopJournal) {
    println!("journal:");
    println!("  seller  {}", j.seller);
    println!("  buyer   {}", j.buyer);
    println!("  funder  {} (hops: {})", j.funder, j.hop_count);
    println!("  seller outflow        ${:.2}", j.seller_outflow_raw as f64 / 1e6);
    println!("  funded                ${:.2} @ block {}", j.funded_raw as f64 / 1e6, j.funding_block);
    println!("  settled after funding ${:.6}", j.settled_after_funding_raw as f64 / 1e6);
    println!("  blocks relied on      {}", j.block_refs.len());
}
