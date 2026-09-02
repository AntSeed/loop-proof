//! Host tooling: materializes conserved-loop evidence from Base RPC into a
//! guest fixture, runs the predicate natively, and (with the `sp1` feature)
//! executes/proves the SP1 guest and derives its verification key.
//!
//!   loop-host fetch --case case.json --out fixture.json [--expect-reject]
//!   loop-host run fixture.json [--prove --elf path/to/elf]
//!   loop-host vkey --elf path/to/elf

mod rpc;

use alloy_primitives::{Address, B256};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use wash_predicate::{
    BuyerLedger, ClosedLoopInput, EvidenceBlock, FundingEvidence, FundingKind, LogRef, ReturnPath,
    StateRead, WashJournal, CHANNELS_ADDRESS, DEPOSITS_ADDRESS, PERIOD_END_BLOCK, USDC_ADDRESS,
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
        ),
        Some("run") => run(
            args.get(2).context("usage: loop-host run fixture.json")?,
            args.iter().any(|a| a == "--prove"),
            arg_value(&args, "--elf"),
            args.iter().any(|a| a == "--reciprocal"),
            arg_value(&args, "--result"),
            arg_value(&args, "--source-claim-id"),
            args.iter().any(|a| a == "--production"),
        ),
        Some("vkey") => vkey(&arg_value(&args, "--elf").context("--elf required")?),
        Some("headers") => headers(
            arg_value(&args, "--start").context("--start required")?.parse()?,
            arg_value(&args, "--end").context("--end required")?.parse()?,
            &arg_value(&args, "--out").context("--out required")?,
        ),
        Some("batch-manifest") => batch_manifest(
            &arg_value(&args, "--results-dir").context("--results-dir required")?,
            &arg_value(&args, "--blockhash-store").context("--blockhash-store required")?,
            &arg_value(&args, "--closed-loop-vkey").context("--closed-loop-vkey required")?,
            &arg_value(&args, "--reciprocal-vkey").context("--reciprocal-vkey required")?,
            &arg_value(&args, "--out").context("--out required")?,
            args.iter().any(|a| a == "--development"),
        ),
        _ => bail!(
            "usage: loop-host fetch --case case.json --out fixture.json [--expect-reject]\n       loop-host run fixture.json [--elf path --result result.json --source-claim-id 0x...] [--prove --production]\n       loop-host vkey --elf path\n       loop-host headers --start N --end M --out headers.json\n       loop-host batch-manifest --results-dir DIR --blockhash-store 0x... --closed-loop-vkey 0x... --reciprocal-vkey 0x... --out proof-results.json [--development]"
        ),
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
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

fn fetch(case_path: &str, out_path: &str, expect_reject: bool) -> Result<()> {
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
            m.entry(*buyer)
                .and_modify(|b| *b = (*b).min(loc.0))
                .or_insert(loc.0);
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
        println!(
            "buyer {buyer}: {} settlements (from block {from})",
            found.len()
        );
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
            let receipt = client.call(
                "eth_getTransactionReceipt",
                serde_json::json!([format!("{tx}")]),
            )?;
            let logs = receipt["logs"].as_array().context("logs")?;
            let topics = logs[loc.2]["topics"].as_array().context("topics")?;
            let word: B256 = topics
                .get(2)
                .and_then(|t| t.as_str())
                .context("hop to")?
                .parse()?;
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
    let block_targets = targets
        .receipts
        .iter()
        .map(|(number, receipt_targets)| {
            (
                *number,
                receipt_targets.clone(),
                targets
                    .transactions
                    .get(number)
                    .cloned()
                    .unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    let block_count = block_targets.len();
    let concurrency = std::env::var("LOOP_RPC_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4);
    let block_evidence = client.block_evidence_many(&block_targets, concurrency)?;
    for (idx, ((number, _, _), (evidence, log_map))) in
        block_targets.into_iter().zip(block_evidence).enumerate()
    {
        if (idx + 1) % 100 == 0 || idx + 1 == block_count {
            println!(
                "block {}/{block_count}: {number} ({} receipts, {} transactions)",
                idx + 1,
                evidence.receipts.len(),
                evidence.transactions.len()
            );
        }
        for (pos, rp) in evidence.receipts.iter().enumerate() {
            receipt_pos.insert((number, rp.tx_index), pos);
        }
        for (pos, tp) in evidence.transactions.iter().enumerate() {
            tx_pos.insert((number, tp.tx_index), pos);
        }
        log_maps.insert(number, log_map);
        block_index.insert(number, blocks.len());
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
    let end_index = blocks.len();
    let end_block = EvidenceBlock {
        header: end_header.clone(),
        receipts: vec![],
        transactions: vec![],
    };

    let mut ledgers = Vec::new();
    for buyer in &case.buyers {
        let slot = loop_core::slot_offset(
            loop_core::mapping_slot_address(*buyer, wash_predicate::DEPOSITS_BUYERS_SLOT),
            wash_predicate::BUYER_ACCOUNT_BALANCE_OFFSET,
        );
        let (end_proof, end_value) = client.storage_witness(&end_header, DEPOSITS_ADDRESS, slot)?;
        println!("buyer {buyer}: period-end balance {end_value}");
        ledgers.push(BuyerLedger {
            end: StateRead {
                block: end_index,
                proof: end_proof,
            },
        });
    }

    blocks.push(end_block);

    // 6. Assemble the input.
    let to_ref = |loc: &rpc::LogLoc| LogRef {
        block: block_index[&loc.0],
        receipt: receipt_pos[&(loc.0, loc.1 as u64)],
        log: loc.2,
    };
    let settlement_refs = settlement_locs.iter().map(to_ref).collect::<Vec<_>>();
    let input = ClosedLoopInput {
        chain_id: wash_predicate::BASE_CHAIN_ID,
        period_start_block: wash_predicate::PERIOD_START_BLOCK,
        period_end_block: PERIOD_END_BLOCK,
        source_claim_id: alloy_primitives::keccak256(std::fs::read(case_path)?),
        seller: case.seller,
        funder: case.funder,
        buyers: case.buyers.clone(),
        blocks,
        fundings: funding_locs
            .iter()
            .map(|(buyer, kind, transfer, deposited)| FundingEvidence {
                buyer: *buyer,
                kind: match *kind {
                    "usdc" => FundingKind::Usdc {
                        transfer: to_ref(transfer),
                    },
                    _ => FundingKind::ProtocolDeposit {
                        transfer: to_ref(transfer),
                        deposited: to_ref(&deposited.unwrap()),
                    },
                },
            })
            .collect(),
        settlements: settlement_refs,
        returns: return_locs
            .iter()
            .map(|hops| ReturnPath {
                transfers: hops.iter().map(to_ref).collect(),
            })
            .collect(),
        ledgers,
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

fn run(
    fixture_path: &str,
    prove: bool,
    elf: Option<String>,
    reciprocal: bool,
    result_path: Option<String>,
    source_claim_id: Option<String>,
    production: bool,
) -> Result<()> {
    if result_path.is_some() && elf.is_none() {
        bail!("--result requires --elf");
    }
    if production && !prove {
        bail!("--production requires --prove");
    }
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
        return sp1_run(
            &input_bytes,
            &elf_path,
            &journal,
            prove,
            reciprocal,
            result_path.as_deref(),
            source_claim_id.as_deref(),
            production,
        );
    }
    let _ = input_bytes;
    #[cfg(not(feature = "sp1"))]
    if prove || elf.is_some() {
        bail!("rebuild with --features sp1 to execute or prove");
    }
    let _ = prove;
    let _ = result_path;
    let _ = source_claim_id;
    let _ = production;
    Ok(())
}

#[cfg(feature = "sp1")]
fn sp1_run(
    input_bytes: &[u8],
    elf_path: &str,
    native: &WashJournal,
    prove: bool,
    reciprocal: bool,
    result_path: Option<&str>,
    source_claim_id: Option<&str>,
    production: bool,
) -> Result<()> {
    use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
    use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Stdin};
    let elf = Elf::Dynamic(std::fs::read(elf_path)?.into());
    let client = ProverClient::from_env();
    let key = client.setup(elf.clone())?;
    let vkey = key.verifying_key().bytes32();
    let mut execution_stdin = SP1Stdin::new();
    execution_stdin.write(&input_bytes.to_vec());
    let (public_values, report) = client.execute(elf.clone(), execution_stdin).run()?;
    let instruction_count = report.total_instruction_count();
    println!("guest executed: {instruction_count} instructions");
    if public_values.as_slice() != native.abi_encode() {
        bail!("guest journal differs from native journal");
    }
    println!("guest journal matches the native journal");
    println!("vkey: {vkey}");
    if prove {
        let mut proving_stdin = SP1Stdin::new();
        proving_stdin.write(&input_bytes.to_vec());
        let start = std::time::Instant::now();
        let proof = client.prove(&key, proving_stdin).groth16().run()?;
        println!("proved in {:?}", start.elapsed());
        client.verify(&proof, key.verifying_key(), None)?;
        if proof.public_values.as_slice() != native.abi_encode() {
            bail!("guest journal differs from native journal");
        }
        let proof_bytes = format!("0x{}", alloy_primitives::hex::encode(proof.bytes()));
        println!("proof bytes: {proof_bytes}");
        if let Some(path) = result_path {
            write_proof_result(
                path,
                native,
                reciprocal,
                source_claim_id,
                &vkey,
                &proof_bytes,
                instruction_count,
                production,
            )?;
        }
    } else if let Some(path) = result_path {
        write_proof_result(
            path,
            native,
            reciprocal,
            source_claim_id,
            &vkey,
            "0x01",
            instruction_count,
            false,
        )?;
    }
    Ok(())
}

#[cfg(feature = "sp1")]
fn write_proof_result(
    path: &str,
    journal: &WashJournal,
    reciprocal: bool,
    source_claim_id: Option<&str>,
    program_vkey: &str,
    proof_bytes: &str,
    instruction_count: u64,
    production: bool,
) -> Result<()> {
    use sha2::Digest;
    let journal_bytes = journal.abi_encode();
    let journal_digest = format!(
        "0x{}",
        alloy_primitives::hex::encode(sha2::Sha256::digest(&journal_bytes))
    );
    let block_references: Vec<_> = journal
        .block_refs
        .iter()
        .map(|(number, block_hash)| {
            serde_json::json!({
                "number": number.to_string(),
                "blockHash": format!("{block_hash}"),
            })
        })
        .collect();
    let subjects: Vec<_> = journal
        .subjects
        .iter()
        .map(|subject| format!("{}", subject.subject))
        .collect();
    let metrics = if reciprocal {
        serde_json::json!({
            "volumeAToBRaw": journal.subjects[1].wash_volume.to_string(),
            "volumeBToARaw": journal.subjects[0].wash_volume.to_string(),
            "journalVolumeAToBRaw": journal.subjects[1].wash_volume.to_string(),
            "journalVolumeBToARaw": journal.subjects[0].wash_volume.to_string(),
            "authenticatedReceiptVolumeAToBRaw": journal.subjects[1].wash_volume.to_string(),
            "authenticatedReceiptVolumeBToARaw": journal.subjects[0].wash_volume.to_string(),
        })
    } else {
        serde_json::json!({
            "qualifiedVolumeRaw": journal.subjects[0].wash_volume.to_string(),
            "journalWashVolumeRaw": journal.subjects[0].wash_volume.to_string(),
            "authenticatedReceiptVolumeRaw": journal.subjects[0].wash_volume.to_string(),
        })
    };
    let result = serde_json::json!({
        "version": 2,
        "kind": "antseed-wash-trading-proof-result",
        "chainId": journal.chain_id,
        "securityMode": if production { "production" } else { "development" },
        "entry": {
            "claimId": format!("{}", journal.claim_id),
            "sourceClaimId": source_claim_id,
            "claimType": if reciprocal { "P0_RECIPROCAL" } else { "P0_CLOSED_LOOP" },
            "subjects": subjects,
            "metrics": metrics,
            "programVKey": program_vkey,
            "journalBytes": format!("0x{}", alloy_primitives::hex::encode(journal_bytes)),
            "journalDigest": journal_digest,
            "proofBytes": proof_bytes,
            "blockReferences": block_references,
            "instructionCount": instruction_count,
        },
    });
    std::fs::write(path, serde_json::to_vec_pretty(&result)?)?;
    println!("proof result written to {path}");
    Ok(())
}

// ─────────────────────────────── batch manifest ──────────────────────────

fn batch_manifest(
    results_dir: &str,
    blockhash_store: &str,
    closed_loop_vkey: &str,
    reciprocal_vkey: &str,
    out_path: &str,
    development: bool,
) -> Result<()> {
    use alloy_primitives::{keccak256, Address, B256};
    use sha2::Digest;

    let store: Address = blockhash_store
        .parse()
        .context("invalid BlockhashStore address")?;
    let closed_vkey: B256 = closed_loop_vkey
        .parse()
        .context("invalid closed-loop vkey")?;
    let reciprocal_vkey: B256 = reciprocal_vkey.parse().context("invalid reciprocal vkey")?;
    let security_mode = if development {
        "development"
    } else {
        "production"
    };
    let mut entries = Vec::<serde_json::Value>::new();
    for item in std::fs::read_dir(results_dir)? {
        let path = item?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        if value.get("kind").and_then(|item| item.as_str())
            != Some("antseed-wash-trading-proof-result")
        {
            continue;
        }
        if value.get("version").and_then(|item| item.as_u64()) != Some(2)
            || value.get("chainId").and_then(|item| item.as_u64()) != Some(8_453)
            || value.get("securityMode").and_then(|item| item.as_str()) != Some(security_mode)
        {
            bail!("{}: invalid {security_mode} proof result", path.display());
        }
        entries.push(
            value
                .get("entry")
                .cloned()
                .context("proof result entry missing")?,
        );
    }
    if entries.is_empty() {
        bail!("no {security_mode} proof result files found");
    }
    entries.sort_by(|left, right| {
        left.get("claimId")
            .and_then(|value| value.as_str())
            .cmp(&right.get("claimId").and_then(|value| value.as_str()))
    });

    let mut commitments = Vec::new();
    let mut previous = B256::ZERO;
    for entry in &entries {
        let claim: B256 = entry
            .get("claimId")
            .and_then(|value| value.as_str())
            .context("claimId missing")?
            .parse()
            .context("invalid claimId")?;
        if claim <= previous {
            bail!("proof claim IDs must be unique and strictly ordered");
        }
        previous = claim;
        let journal_hex = entry
            .get("journalBytes")
            .and_then(|value| value.as_str())
            .context("journalBytes missing")?
            .strip_prefix("0x")
            .context("journalBytes must be hex")?;
        let journal_bytes = alloy_primitives::hex::decode(journal_hex)?;
        let journal = WashJournal::abi_decode(&journal_bytes).map_err(anyhow::Error::msg)?;
        if journal.claim_id != claim {
            bail!("{claim}: journal claim ID mismatch");
        }
        let journal_digest = B256::from_slice(&sha2::Sha256::digest(&journal_bytes));
        let declared_digest: B256 = entry
            .get("journalDigest")
            .and_then(|value| value.as_str())
            .context("journalDigest missing")?
            .parse()
            .context("invalid journalDigest")?;
        if journal_digest != declared_digest {
            bail!("{claim}: journal digest mismatch");
        }
        let claim_type = entry.get("claimType").and_then(|value| value.as_str());
        let program_vkey: B256 = entry
            .get("programVKey")
            .and_then(|value| value.as_str())
            .context("programVKey missing")?
            .parse()
            .context("invalid programVKey")?;
        match claim_type {
            Some("P0_CLOSED_LOOP") if program_vkey == closed_vkey => {}
            Some("P0_RECIPROCAL") if program_vkey == reciprocal_vkey => {}
            _ => bail!("{claim}: predicate type and vkey mismatch"),
        }
        commitments.push((claim, journal_digest));
    }

    let domain = keccak256("ANTSEED_AIP4_BACKFILL_V1");
    let digest = compute_batch_digest(store, closed_vkey, reciprocal_vkey, &commitments);
    let commitment_values: Vec<_> = commitments
        .iter()
        .map(|(claim, journal_digest)| {
            serde_json::json!({
                "claimId": format!("{claim}"),
                "journalDigest": format!("{journal_digest}"),
            })
        })
        .collect();
    let manifest = serde_json::json!({
        "version": 2,
        "kind": "antseed-wash-trading-proof-results",
        "chainId": 8_453,
        "securityMode": security_mode,
        "batch": {
            "domain": format!("{domain}"),
            "blockhashStore": format!("{store}"),
            "closedLoopVKey": format!("{closed_vkey}"),
            "reciprocalVKey": format!("{reciprocal_vkey}"),
            "expectedBatchCount": entries.len(),
            "expectedBatchDigest": format!("{digest}"),
            "commitments": commitment_values,
        },
        "entries": entries,
    });
    std::fs::write(out_path, serde_json::to_vec_pretty(&manifest)?)?;
    println!("batch manifest written to {out_path}");
    println!("expectedBatchCount {}", commitments.len());
    println!("expectedBatchDigest {digest}");
    Ok(())
}

fn compute_batch_digest(
    blockhash_store: alloy_primitives::Address,
    closed_loop_vkey: alloy_primitives::B256,
    reciprocal_vkey: alloy_primitives::B256,
    commitments: &[(alloy_primitives::B256, alloy_primitives::B256)],
) -> alloy_primitives::B256 {
    use alloy_primitives::{keccak256, U256};
    use alloy_sol_types::SolValue;
    let domain = keccak256("ANTSEED_AIP4_BACKFILL_V1");
    let mut digest = keccak256(
        (
            domain,
            8_453u64,
            closed_loop_vkey,
            reciprocal_vkey,
            blockhash_store,
            U256::from(commitments.len()),
        )
            .abi_encode(),
    );
    for (claim, journal_digest) in commitments {
        digest = keccak256((digest, *claim, *journal_digest).abi_encode());
    }
    digest
}

#[cfg(test)]
mod batch_tests {
    use super::compute_batch_digest;
    use alloy_primitives::{Address, B256};

    #[test]
    fn batch_digest_matches_solidity_and_ethers() {
        let store: Address = "0x78b69899C8cD252126cBB1A50171ec37286C3877"
            .parse()
            .unwrap();
        let closed: B256 = format!("0x{}", "55".repeat(32)).parse().unwrap();
        let reciprocal: B256 = format!("0x{}", "66".repeat(32)).parse().unwrap();
        let claim: B256 = format!("0x{}", "11".repeat(32)).parse().unwrap();
        let journal: B256 = "0xa5b524c49d791184e67724513c459f42e290127c33496dd59e933e329f3c815e"
            .parse()
            .unwrap();
        assert_eq!(
            compute_batch_digest(store, closed, reciprocal, &[(claim, journal)]),
            "0xbdbd8ffe503030c82e83e23a9496b7bd106dd934b19e1ec976ddf48c50ec3175"
                .parse::<B256>()
                .unwrap()
        );
    }
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

// ─────────────────────────────── reporting ───────────────────────────────

fn print_journal(journal: &WashJournal) {
    println!("journal:");
    println!(
        "  predicate {} period [{}, {}]",
        journal.predicate_id, journal.period_start_block, journal.period_end_block
    );
    println!("  claim id  {}", journal.claim_id);
    for subject in &journal.subjects {
        println!(
            "  subject {}  proven wash ${:.2}",
            subject.subject,
            subject.wash_volume as f64 / 1e6,
        );
    }
    println!("  blocks relied on: {}", journal.block_refs.len());
}

fn report_journal_bytes(bytes: &[u8]) {
    use sha2::Digest;
    println!(
        "journal sha256: 0x{}",
        alloy_primitives::hex::encode(sha2::Sha256::digest(bytes))
    );
    println!(
        "journal abi hex: 0x{}",
        alloy_primitives::hex::encode(bytes)
    );
}
