//! Host tooling: materializes conserved-loop evidence from Base RPC into a
//! guest fixture, runs the predicate natively, and (with the `sp1` feature)
//! executes/proves the SP1 guest and derives its verification key.
//!
//!   loop-host fetch --case case.json --out fixture.json [--expect-reject]
//!   loop-host run fixture.json [--prove --elf path/to/elf]
//!   loop-host vkey --elf path/to/elf
//!   loop-host verify-layout
//!
//! `verify-layout` is the live cross-check demanded by AIP-4: it proves a
//! known agent's `AgentStats.totalVolumeUsdc` storage slot at a recent block
//! and compares the proven value against `getAgentStats` via `eth_call`.

mod rpc;

use alloy_primitives::{Address, B256, U256};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use wash_predicate::{
    BuyerLedger, ClosedLoopInput, EvidenceBlock, FundingEvidence, FundingKind, LogRef, ReturnPath,
    SellerStatsWitness, StateRead, WashJournal, CHANNELS_ADDRESS, DEPOSITS_ADDRESS,
    PERIOD_END_BLOCK, PERIOD_LEDGER_START_BLOCK, STAKING_ADDRESS, USDC_ADDRESS,
};

const DEFAULT_RPCS: &[&str] = &[
    "https://base.gateway.tenderly.co",
    "https://base.drpc.org",
    "https://base-public.nodies.app",
    "https://mainnet.base.org",
];

fn endpoints() -> Vec<String> {
    match std::env::var("BASE_RPC_URLS") {
        Ok(v) if !v.trim().is_empty() => v.split(',').map(|s| s.trim().to_string()).collect(),
        _ => DEFAULT_RPCS.iter().map(|s| s.to_string()).collect(),
    }
}

// ─────────────────────────────── case format ───────────────────────────────

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CaseFunding {
    /// Direct USDC transfer funder → buyer inside `tx`.
    Usdc { buyer: Address, tx: B256 },
    /// `Deposits.deposit(buyer, …)` inside `tx`.
    Deposit { buyer: Address, tx: B256 },
}

#[derive(Deserialize)]
struct Case {
    seller: Address,
    funder: Address,
    buyers: Vec<Address>,
    fundings: Vec<CaseFunding>,
    /// Return paths: ordered tx hashes whose USDC transfers chain
    /// seller → … → funder.
    #[serde(default)]
    returns: Vec<Vec<B256>>,
    #[serde(default = "default_max_settlements")]
    max_settlements_per_buyer: usize,
}

fn default_max_settlements() -> usize {
    64
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("fetch") => fetch(
            &arg_value(&args, "--case").context("--case required")?,
            &arg_value(&args, "--out").context("--out required")?,
            args.iter().any(|a| a == "--expect-reject"),
            args.iter().any(|a| a == "--no-ledger"),
        ),
        Some("run") => run(
            args.get(2).context("usage: loop-host run fixture.json")?,
            args.iter().any(|a| a == "--prove"),
            arg_value(&args, "--elf"),
            args.iter().any(|a| a == "--reciprocal"),
        ),
        Some("vkey") => vkey(&arg_value(&args, "--elf").context("--elf required")?),
        Some("headers") => headers(
            arg_value(&args, "--start").context("--start required")?.parse()?,
            arg_value(&args, "--end").context("--end required")?.parse()?,
            &arg_value(&args, "--out").context("--out required")?,
        ),
        Some("verify-layout") => {
            let addresses: Vec<String> = args[2..].to_vec();
            verify_layout(&addresses)
        }
        _ => bail!(
            "usage: loop-host fetch --case case.json --out fixture.json [--expect-reject]\n       loop-host run fixture.json [--prove --elf path]\n       loop-host vkey --elf path\n       loop-host headers --start N --end M --out headers.json\n       loop-host verify-layout [seller_address ...]"
        ),
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

// ─────────────────────────────── fetch ───────────────────────────────

/// Accumulates the per-block receipt/transaction targets a claim touches,
/// then resolves them to indices inside the assembled fixture.
#[derive(Default)]
struct Targets {
    receipts: BTreeMap<u64, Vec<u64>>,
    transactions: BTreeMap<u64, Vec<u64>>,
}

impl Targets {
    fn receipt(&mut self, block: u64, tx_index: u64) {
        let t = self.receipts.entry(block).or_default();
        if !t.contains(&tx_index) {
            t.push(tx_index);
        }
    }
    fn transaction(&mut self, block: u64, tx_index: u64) {
        self.receipt(block, tx_index);
        let t = self.transactions.entry(block).or_default();
        if !t.contains(&tx_index) {
            t.push(tx_index);
        }
    }
}

fn fetch(case_path: &str, out_path: &str, expect_reject: bool, skip_ledger: bool) -> Result<()> {
    let case: Case = serde_json::from_str(&std::fs::read_to_string(case_path)?)?;
    let client = rpc::Client::new(&endpoints());
    let mut targets = Targets::default();

    // 1. Funding evidence locations (attribution needs the transactions too).
    let mut funding_locs = Vec::new(); // (buyer, kind, transfer loc, deposited loc?)
    for funding in &case.fundings {
        match funding {
            CaseFunding::Usdc { buyer, tx } => {
                let loc = client.find_log_in_tx(
                    *tx,
                    USDC_ADDRESS,
                    loop_core::TRANSFER_TOPIC,
                    Some(rpc::addr_topic(case.funder)),
                    Some(rpc::addr_topic(*buyer)),
                )?;
                targets.transaction(loc.0, loc.1 as u64);
                funding_locs.push((*buyer, "usdc", loc, None));
            }
            CaseFunding::Deposit { buyer, tx } => {
                let transfer = client.find_log_in_tx(
                    *tx,
                    USDC_ADDRESS,
                    loop_core::TRANSFER_TOPIC,
                    Some(rpc::addr_topic(case.funder)),
                    Some(rpc::addr_topic(DEPOSITS_ADDRESS)),
                )?;
                let deposited = client.find_log_in_tx(
                    *tx,
                    DEPOSITS_ADDRESS,
                    loop_core::DEPOSITED_TOPIC,
                    Some(rpc::addr_topic(*buyer)),
                    None,
                )?;
                targets.transaction(transfer.0, transfer.1 as u64);
                funding_locs.push((*buyer, "deposit", transfer, Some(deposited)));
            }
        }
    }

    // 2. Settlements per buyer, starting from each buyer's earliest funding
    //    block so we never hand the predicate a settlement that precedes the
    //    buyer's funding (which would trigger a hard reject).
    //    Uses the fast path: getLogs only, no per-settlement receipt fetch.
    //    Log positions are resolved during block evidence (step 4).
    let earliest_funding_block: BTreeMap<Address, u64> = {
        let mut m = BTreeMap::<Address, u64>::new();
        for (buyer, _, loc, _) in &funding_locs {
            m.entry(*buyer).and_modify(|b| *b = (*b).min(loc.0)).or_insert(loc.0);
        }
        m
    };
    let mut settlement_raw: Vec<(u64, usize, u64)> = Vec::new();
    for buyer in &case.buyers {
        let from = earliest_funding_block
            .get(buyer)
            .copied()
            .unwrap_or(wash_predicate::PERIOD_START_BLOCK);
        let found = client.find_settlement_logs(
            CHANNELS_ADDRESS,
            *buyer,
            case.seller,
            from,
            PERIOD_END_BLOCK,
            case.max_settlements_per_buyer,
        )?;
        println!("buyer {buyer}: {} settlements (from block {from})", found.len());
        for &(block, tx_index, _) in &found {
            targets.receipt(block, tx_index as u64);
        }
        settlement_raw.extend(found);
    }

    // 3. Return paths: chain USDC transfers starting at the seller.
    let mut return_locs = Vec::new();
    for path in &case.returns {
        let mut hops = Vec::new();
        let mut from = case.seller;
        for tx in path {
            let loc = client.find_log_in_tx(
                *tx,
                USDC_ADDRESS,
                loop_core::TRANSFER_TOPIC,
                Some(rpc::addr_topic(from)),
                None,
            )?;
            // Recover the hop's `to` for chaining: re-read the located log.
            let receipt =
                client.call("eth_getTransactionReceipt", serde_json::json!([format!("{tx}")]))?;
            let logs = receipt["logs"].as_array().context("logs")?;
            let topics = logs[loc.2]["topics"].as_array().context("topics")?;
            let word: B256 = topics.get(2).and_then(|t| t.as_str()).context("hop to")?.parse()?;
            let to = Address::from_slice(&word.as_slice()[12..]);
            targets.receipt(loc.0, loc.1 as u64);
            hops.push(loc);
            from = to;
        }
        return_locs.push(hops);
    }

    // 4. Fetch per-block evidence and resolve settlement log positions.
    let mut blocks: Vec<EvidenceBlock> = Vec::new();
    let mut block_index: BTreeMap<u64, usize> = BTreeMap::new();
    let mut receipt_pos: BTreeMap<(u64, u64), usize> = BTreeMap::new();
    let mut tx_pos: BTreeMap<(u64, u64), usize> = BTreeMap::new();
    let mut log_maps: BTreeMap<u64, BTreeMap<u64, usize>> = BTreeMap::new();
    let block_count = targets.receipts.len();
    for (idx, (number, receipt_targets)) in targets.receipts.iter().enumerate() {
        let tx_targets = targets.transactions.get(number).cloned().unwrap_or_default();
        let (evidence, log_map) =
            client.block_evidence(*number, receipt_targets, &tx_targets)?;
        if (idx + 1) % 100 == 0 || idx + 1 == block_count {
            println!(
                "block {}/{block_count}: {number} ({} receipts, {} transactions)",
                idx + 1,
                evidence.receipts.len(),
                evidence.transactions.len()
            );
        }
        for (pos, rp) in evidence.receipts.iter().enumerate() {
            receipt_pos.insert((*number, rp.tx_index), pos);
        }
        for (pos, tp) in evidence.transactions.iter().enumerate() {
            tx_pos.insert((*number, tp.tx_index), pos);
        }
        log_maps.insert(*number, log_map);
        block_index.insert(*number, blocks.len());
        blocks.push(evidence);
    }

    // Resolve settlement log positions from the block evidence maps.
    let settlement_locs: Vec<rpc::LogLoc> = settlement_raw
        .iter()
        .map(|(block, tx_index, block_log_index)| {
            let local = *log_maps
                .get(block)
                .and_then(|m| m.get(block_log_index))
                .with_context(|| {
                    format!("settlement log resolution failed: block {block} logIndex {block_log_index}")
                })?;
            Ok((*block, *tx_index, local))
        })
        .collect::<Result<_>>()?;

    // 5. Boundary state witnesses.
    let end_header = client.header(PERIOD_END_BLOCK)?;
    let end_block =
        EvidenceBlock { header: end_header.clone(), receipts: vec![], transactions: vec![] };

    let mut ledgers = Vec::new();
    if !skip_ledger {
        let start_header = client.header(PERIOD_LEDGER_START_BLOCK)?;
        let start_block = EvidenceBlock {
            header: start_header.clone(),
            receipts: vec![],
            transactions: vec![],
        };
        let start_index = blocks.len();
        let end_index = blocks.len() + 1;
        for buyer in &case.buyers {
            let slot = loop_core::slot_offset(
                loop_core::mapping_slot_address(*buyer, wash_predicate::DEPOSITS_BUYERS_SLOT),
                wash_predicate::BUYER_ACCOUNT_BALANCE_OFFSET,
            );
            let (start_proof, start_value) =
                client.storage_witness(&start_header, DEPOSITS_ADDRESS, slot)?;
            let (end_proof, end_value) =
                client.storage_witness(&end_header, DEPOSITS_ADDRESS, slot)?;
            println!("buyer {buyer}: balance {start_value} → {end_value}");
            ledgers.push(BuyerLedger {
                start: StateRead { block: start_index, proof: start_proof },
                end: StateRead { block: end_index, proof: end_proof },
            });
        }
        blocks.push(start_block);
    } else {
        println!("skipping LEDGER witnesses (--no-ledger)");
    }

    let end_index = blocks.len();
    let agent_slot = loop_core::mapping_slot_address(
        case.seller,
        wash_predicate::STAKING_SELLER_AGENT_ID_SLOT,
    );
    let (agent_proof, agent_id) = client.storage_witness(&end_header, STAKING_ADDRESS, agent_slot)?;
    println!("seller {}: agent id {agent_id}", case.seller);
    let stats_read = if agent_id.is_zero() {
        None
    } else {
        let volume_slot = loop_core::slot_offset(
            loop_core::mapping_slot_u256(agent_id, wash_predicate::CHANNELS_AGENT_STATS_SLOT),
            wash_predicate::AGENT_STATS_TOTAL_VOLUME_OFFSET,
        );
        let (proof, volume) = client.storage_witness(&end_header, CHANNELS_ADDRESS, volume_slot)?;
        println!("seller {}: period-end settled volume {volume}", case.seller);
        Some(StateRead { block: end_index, proof })
    };
    let seller_stats = SellerStatsWitness {
        agent_id_read: StateRead { block: end_index, proof: agent_proof },
        stats_read,
    };
    blocks.push(end_block);

    // 6. Assemble the input.
    let to_ref = |loc: &rpc::LogLoc| LogRef {
        block: block_index[&loc.0],
        receipt: receipt_pos[&(loc.0, loc.1 as u64)],
        log: loc.2,
    };
    let input = ClosedLoopInput {
        chain_id: wash_predicate::BASE_CHAIN_ID,
        seller: case.seller,
        funder: case.funder,
        buyers: case.buyers.clone(),
        blocks,
        fundings: funding_locs
            .iter()
            .map(|(buyer, kind, transfer, deposited)| FundingEvidence {
                buyer: *buyer,
                kind: match *kind {
                    "usdc" => FundingKind::Usdc { transfer: to_ref(transfer) },
                    _ => FundingKind::ProtocolDeposit {
                        transfer: to_ref(transfer),
                        deposited: to_ref(&deposited.unwrap()),
                    },
                },
            })
            .collect(),
        settlements: settlement_locs.iter().map(to_ref).collect(),
        returns: return_locs
            .iter()
            .map(|hops| ReturnPath { transfers: hops.iter().map(to_ref).collect() })
            .collect(),
        ledgers,
        seller_stats,
    };

    // 7. Native predicate check before writing the fixture.
    match wash_predicate::verify_closed_loop(&input) {
        Ok(journal) => {
            if expect_reject {
                bail!("predicate unexpectedly SATISFIED — this evidence proves a loop");
            }
            print_journal(&journal);
        }
        Err(e) => {
            if !expect_reject {
                bail!("predicate: {e}");
            }
            println!("predicate correctly rejects this evidence: {e}");
        }
    }

    std::fs::write(out_path, serde_json::to_vec(&input)?)?;
    println!("fixture written to {out_path}");
    Ok(())
}

// ─────────────────────────────── run / prove ───────────────────────────────

fn run(fixture_path: &str, prove: bool, elf: Option<String>, reciprocal: bool) -> Result<()> {
    let raw = std::fs::read_to_string(fixture_path)?;
    let (journal, input_bytes) = if reciprocal {
        let input: wash_predicate::ReciprocalInput = serde_json::from_str(&raw)?;
        let journal = wash_predicate::verify_reciprocal(&input)
            .map_err(|e| anyhow::anyhow!("predicate: {e}"))?;
        (journal, serde_json::to_vec(&input)?)
    } else {
        let input: ClosedLoopInput = serde_json::from_str(&raw)?;
        let journal = wash_predicate::verify_closed_loop(&input)
            .map_err(|e| anyhow::anyhow!("predicate: {e}"))?;
        (journal, serde_json::to_vec(&input)?)
    };
    println!("native verify OK");
    print_journal(&journal);
    report_journal_bytes(&journal.abi_encode());

    #[cfg(feature = "sp1")]
    if let Some(elf_path) = elf {
        return sp1_run(&input_bytes, &elf_path, &journal, prove);
    }
    let _ = input_bytes;
    #[cfg(not(feature = "sp1"))]
    if prove || elf.is_some() {
        bail!("rebuild with --features sp1 to execute or prove");
    }
    let _ = prove;
    Ok(())
}

#[cfg(feature = "sp1")]
fn sp1_run(input_bytes: &[u8], elf_path: &str, native: &WashJournal, prove: bool) -> Result<()> {
    use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
    use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Stdin};
    let elf = Elf::Dynamic(std::fs::read(elf_path)?.into());
    let client = ProverClient::from_env();
    let key = client.setup(elf.clone())?;
    let vkey = key.verifying_key().bytes32();
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_bytes.to_vec());
    if prove {
        let start = std::time::Instant::now();
        let proof = client.prove(&key, stdin).groth16().run()?;
        println!("proved in {:?}", start.elapsed());
        client.verify(&proof, key.verifying_key(), None)?;
        if proof.public_values.as_slice() != native.abi_encode() {
            bail!("guest journal differs from native journal");
        }
        println!("vkey: {vkey}");
        println!("proof bytes: 0x{}", alloy_primitives::hex::encode(proof.bytes()));
    } else {
        let (public_values, report) = client.execute(elf, stdin).run()?;
        println!("guest executed: {} instructions", report.total_instruction_count());
        if public_values.as_slice() != native.abi_encode() {
            bail!("guest journal differs from native journal");
        }
        println!("guest journal matches the native journal");
        println!("vkey: {vkey}");
    }
    Ok(())
}

fn vkey(elf_path: &str) -> Result<()> {
    #[cfg(feature = "sp1")]
    {
        use sp1_sdk::blocking::{Prover, ProverClient};
        use sp1_sdk::{Elf, HashableKey, ProvingKey};
        let elf = Elf::Dynamic(std::fs::read(elf_path)?.into());
        let client = ProverClient::builder().cpu().build();
        let key = client.setup(elf)?;
        println!("{}", key.verifying_key().bytes32());
        return Ok(());
    }
    #[cfg(not(feature = "sp1"))]
    {
        let _ = elf_path;
        bail!("rebuild with --features sp1 to derive vkeys");
    }
}

// ─────────────────────────────── header export ────────────────────────────

/// Export self-checked RLP block headers for the BlockhashStore backfill
/// walk (`backfill-blockhash-store.mjs` in the AntSeed monorepo). Every
/// header is re-encoded locally and its keccak checked against the RPC
/// hash, so a bad RPC cannot poison the walk.
fn headers(start: u64, end: u64, out_path: &str) -> Result<()> {
    let client = rpc::Client::new(&endpoints());
    let mut out = Vec::new();
    for number in start..=end {
        let header = client.header(number)?;
        let mut rlp = Vec::new();
        alloy_rlp::Encodable::encode(&header, &mut rlp);
        let hash = alloy_primitives::keccak256(&rlp);
        if hash != header.hash_slow() {
            bail!("block {number}: rlp re-encoding does not match the header hash");
        }
        out.push(serde_json::json!({
            "number": number.to_string(),
            "hash": format!("{hash}"),
            "rlp": format!("0x{}", alloy_primitives::hex::encode(&rlp)),
        }));
        if number % 500 == 0 {
            println!("… {number}");
        }
    }
    std::fs::write(out_path, serde_json::to_vec_pretty(&out)?)?;
    println!("{} headers written to {out_path}", end - start + 1);
    Ok(())
}

// ─────────────────────────────── layout cross-check ───────────────────────

/// Live verification of storage-layout constants the guest pins, against
/// Base mainnet. Pass one or more seller addresses to check.
///
///   loop-host verify-layout 0x0329…9b2c 0xb629…dab4
pub fn verify_layout(addresses: &[String]) -> Result<()> {
    if addresses.is_empty() {
        bail!("usage: loop-host verify-layout <seller_address> [seller_address ...]");
    }
    let sellers: Vec<Address> = addresses
        .iter()
        .map(|a| a.parse().with_context(|| format!("invalid address: {a}")))
        .collect::<Result<_>>()?;

    let client = rpc::Client::new(&endpoints());
    let latest = rpc::hex_u64(&client.call("eth_blockNumber", serde_json::json!([]))?)?;
    let number = latest.saturating_sub(8);
    let header = client.header(number)?;
    println!("checking layouts at block {number}");

    for seller in &sellers {
        verify_seller(&client, &header, number, seller)?;
    }

    println!("all storage-layout bindings verified");
    Ok(())
}

fn verify_seller(
    client: &rpc::Client,
    header: &alloy_consensus::Header,
    number: u64,
    seller: &Address,
) -> Result<()> {
    let agent_slot =
        loop_core::mapping_slot_address(*seller, wash_predicate::STAKING_SELLER_AGENT_ID_SLOT);
    let (_, agent_id) = client.storage_witness(header, STAKING_ADDRESS, agent_slot)?;
    let expected_id = eth_call_u256(
        client,
        STAKING_ADDRESS,
        &format!("0x042324b6{}", pad_address(*seller)),
        number,
    )?;
    ensure_equal(&format!("{seller} sellerAgentId"), agent_id, expected_id)?;

    if agent_id.is_zero() {
        println!("{seller}: no staked agent ✔");
        return Ok(());
    }
    let volume_slot = loop_core::slot_offset(
        loop_core::mapping_slot_u256(agent_id, wash_predicate::CHANNELS_AGENT_STATS_SLOT),
        wash_predicate::AGENT_STATS_TOTAL_VOLUME_OFFSET,
    );
    let (_, proven_volume) = client.storage_witness(header, CHANNELS_ADDRESS, volume_slot)?;
    let data = format!("0x68091633{:064x}", agent_id);
    let out = eth_call(client, CHANNELS_ADDRESS, &data, number)?;
    let expected_volume = U256::from_be_slice(&out[64..96]);
    ensure_equal(&format!("{seller} totalVolumeUsdc"), proven_volume, expected_volume)?;
    println!("{seller} agent {agent_id}: totalVolumeUsdc = {proven_volume} ✔");
    Ok(())
}

fn pad_address(a: Address) -> String {
    format!("{:0>64}", alloy_primitives::hex::encode(a.as_slice()))
}

fn eth_call(client: &rpc::Client, to: Address, data: &str, block: u64) -> Result<Vec<u8>> {
    let out = client.call(
        "eth_call",
        serde_json::json!([{ "to": format!("{to}"), "data": data }, format!("0x{block:x}")]),
    )?;
    Ok(alloy_primitives::hex::decode(out.as_str().context("call output")?)?)
}

fn eth_call_u256(client: &rpc::Client, to: Address, data: &str, block: u64) -> Result<U256> {
    let out = eth_call(client, to, data, block)?;
    Ok(U256::from_be_slice(&out[0..32]))
}

fn ensure_equal(label: &str, proven: U256, expected: U256) -> Result<()> {
    if proven != expected {
        bail!("{label}: proven storage value {proven} != contract view {expected} — layout drift");
    }
    Ok(())
}

// ─────────────────────────────── reporting ───────────────────────────────

fn print_journal(journal: &WashJournal) {
    println!("journal:");
    println!("  predicate {} period [{}, {}]", journal.predicate_id, journal.period_start_block, journal.period_end_block);
    println!("  claim id  {}", journal.claim_id);
    for subject in &journal.subjects {
        let ratio = if subject.settled_volume == 0 {
            1.0
        } else {
            (subject.wash_volume as f64 / subject.settled_volume as f64).min(1.0)
        };
        println!(
            "  subject {}  wash ${:.2}  settled ${:.2}  ratio {:.4}",
            subject.subject,
            subject.wash_volume as f64 / 1e6,
            subject.settled_volume as f64 / 1e6,
            ratio
        );
    }
    println!("  blocks relied on: {}", journal.block_refs.len());
}

fn report_journal_bytes(bytes: &[u8]) {
    use sha2::Digest;
    println!("journal sha256: 0x{}", alloy_primitives::hex::encode(sha2::Sha256::digest(bytes)));
    println!("journal abi hex: 0x{}", alloy_primitives::hex::encode(bytes));
}
