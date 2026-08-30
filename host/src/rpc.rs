//! Minimal JSON-RPC client with endpoint fallback, plus the re-encoding
//! needed to rebuild the exact trie values the guest verifies: receipts,
//! transactions (for signer attribution), and account/storage proofs (for
//! the LEDGER and AgentStats witnesses).

use alloy_eips::eip2718::Encodable2718;
use alloy_network::AnyRpcTransaction;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};
use anyhow::{anyhow, bail, Context, Result};
use loop_core::{rlp_bytes, rlp_list, rlp_uint};
use op_alloy_consensus::OpTxEnvelope;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};
use wash_predicate::EvidenceBlock;

const BLOCK_EVIDENCE_CACHE_VERSION: u32 = 1;
const DEFAULT_BLOCK_EVIDENCE_CACHE_DIR: &str = "cache/block-evidence-v1";
static CACHE_TEMP_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub struct Client {
    endpoints: Vec<String>,
}

/// (block_number, tx_index, log_index_within_receipt)
pub type LogLoc = (u64, usize, usize);

#[derive(Deserialize, Serialize)]
struct CachedBlockEvidence {
    version: u32,
    block_number: u64,
    receipt_targets: Vec<u64>,
    transaction_targets: Vec<u64>,
    evidence: EvidenceBlock,
    log_position_map: BTreeMap<u64, usize>,
}

impl Client {
    pub fn new(endpoints: &[String]) -> Self {
        Self {
            endpoints: endpoints.to_vec(),
        }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut last_err = None;
        let attempts = std::env::var("LOOP_RPC_ATTEMPTS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(6u32);
        for attempt in 0..attempts {
            for url in &self.endpoints {
                let res = ureq::post(url)
                    .timeout(std::time::Duration::from_secs(90))
                    .send_json(
                        json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
                    );
                match res {
                    Ok(r) => {
                        let body: Value = r.into_json()?;
                        if let Some(err) = body.get("error").filter(|e| !e.is_null()) {
                            last_err = Some(anyhow!("{method}: {err}"));
                            continue;
                        }
                        return Ok(body["result"].clone());
                    }
                    Err(e) => last_err = Some(anyhow!("{method} via {url}: {e}")),
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(
                500 * 2u64.pow(attempt.min(5)),
            ));
        }
        Err(last_err.unwrap_or_else(|| anyhow!("{method}: all endpoints failed")))
    }

    // ── log discovery ──────────────────────────────────────────────────

    /// Locate a log in `tx` matching `topics[0..]` on `address`.
    pub fn find_log_in_tx(
        &self,
        tx: B256,
        address: Address,
        topic0: B256,
        topic1: Option<B256>,
        topic2: Option<B256>,
    ) -> Result<LogLoc> {
        let rec = self.call("eth_getTransactionReceipt", json!([format!("{tx}")]))?;
        if rec.is_null() {
            bail!("receipt not found for {tx}");
        }
        let logs = rec["logs"].as_array().context("no logs")?;
        for (i, l) in logs.iter().enumerate() {
            if parse_addr(&l["address"])? == address
                && topic(l, 0)? == Some(topic0)
                && (topic1.is_none() || topic(l, 1)? == topic1)
                && (topic2.is_none() || topic(l, 2)? == topic2)
            {
                return Ok((
                    hex_u64(&rec["blockNumber"])?,
                    hex_u64(&rec["transactionIndex"])? as usize,
                    i,
                ));
            }
        }
        bail!("no matching log in {tx}")
    }

    /// Fast settlement scan — returns `(block, tx_index, block_log_index)`
    /// without fetching individual receipts. The receipt-local log index is
    /// resolved later during `block_evidence`, which already fetches full
    /// block receipts.
    pub fn find_settlement_logs(
        &self,
        channels: Address,
        buyer: Address,
        seller: Address,
        from_block: u64,
        to_block: u64,
        max: usize,
    ) -> Result<Vec<(u64, usize, u64)>> {
        let topics = json!([
            format!("{}", loop_core::CHANNEL_SETTLED_TOPIC),
            Value::Null,
            format!("{}", addr_topic(buyer)),
            format!("{}", addr_topic(seller))
        ]);
        let mut out = Vec::new();
        let mut b = from_block;
        while b <= to_block && out.len() < max {
            let end = (b + 99_999).min(to_block);
            let logs = self.call(
                "eth_getLogs",
                json!([{ "address": format!("{channels}"), "topics": topics,
                         "fromBlock": format!("0x{b:x}"), "toBlock": format!("0x{end:x}") }]),
            )?;
            for l in logs.as_array().into_iter().flatten() {
                if out.len() >= max {
                    break;
                }
                let block = hex_u64(&l["blockNumber"])?;
                let tx_index = hex_u64(&l["transactionIndex"])? as usize;
                let block_log_index = hex_u64(&l["logIndex"])?;
                out.push((block, tx_index, block_log_index));
            }
            b = end + 1;
        }
        Ok(out)
    }

    // ── block evidence ─────────────────────────────────────────────────

    pub fn header(&self, number: u64) -> Result<alloy_consensus::Header> {
        let block = self.call(
            "eth_getBlockByNumber",
            json!([format!("0x{number:x}"), false]),
        )?;
        let rpc_hash: B256 = parse_b256(&block["hash"])?;
        let header: alloy_consensus::Header = serde_json::from_value(block.clone())
            .context("header deserialization — RPC schema mismatch")?;
        if header.hash_slow() != rpc_hash {
            bail!(
                "block {number}: recomputed header hash {} != RPC hash {rpc_hash}",
                header.hash_slow()
            );
        }
        Ok(header)
    }

    /// Fetch one block's header plus inclusion proofs for the requested
    /// receipt and transaction indices. Everything is rebuilt and
    /// self-checked locally before it can reach the guest.
    ///
    /// Also returns a map from block-level logIndex → receipt-local log
    /// index, so callers that used `find_settlement_logs` can resolve log
    /// positions without an extra receipt fetch.
    pub fn block_evidence(
        &self,
        number: u64,
        receipt_targets: &[u64],
        transaction_targets: &[u64],
    ) -> Result<(EvidenceBlock, BTreeMap<u64, usize>)> {
        let header = self.header(number)?;

        let mut receipts_out = Vec::new();
        let mut log_position_map = BTreeMap::new();
        if !receipt_targets.is_empty() {
            let raw_receipts =
                self.call("eth_getBlockReceipts", json!([format!("0x{number:x}")]))?;
            let raw_receipts = raw_receipts
                .as_array()
                .context("eth_getBlockReceipts unsupported")?;
            for receipt in raw_receipts {
                if let Some(logs) = receipt["logs"].as_array() {
                    for (local_idx, log) in logs.iter().enumerate() {
                        if let Ok(block_log_idx) = hex_u64(&log["logIndex"]) {
                            log_position_map.insert(block_log_idx, local_idx);
                        }
                    }
                }
            }
            let encoded: Vec<Bytes> = raw_receipts
                .iter()
                .map(encode_receipt)
                .collect::<Result<_>>()
                .with_context(|| format!("block {number}: receipt encoding"))?;
            receipts_out = prove_index_trie(
                &encoded,
                receipt_targets,
                header.receipts_root,
                &format!("block {number} receipts"),
            )?
            .into_iter()
            .map(|(tx_index, value, proof)| loop_core::ReceiptProof {
                tx_index,
                value,
                proof,
            })
            .collect();
        }

        let mut transactions_out = Vec::new();
        if !transaction_targets.is_empty() {
            let block = self.call(
                "eth_getBlockByNumber",
                json!([format!("0x{number:x}"), true]),
            )?;
            let transactions = block["transactions"]
                .as_array()
                .context("full block transactions missing")?;
            let mut encoded = Vec::with_capacity(transactions.len());
            for transaction in transactions {
                let expected = parse_b256(&transaction["hash"])?;
                let bytes = encode_rpc_transaction(transaction.clone()).with_context(|| {
                    format!("block {number}: reconstruct transaction {expected}")
                })?;
                if alloy_primitives::keccak256(&bytes) != expected {
                    bail!("block {number}: reconstructed transaction hash mismatch for {expected}");
                }
                encoded.push(bytes);
            }
            transactions_out = prove_index_trie(
                &encoded,
                transaction_targets,
                header.transactions_root,
                &format!("block {number} transactions"),
            )?
            .into_iter()
            .map(|(tx_index, value, proof)| loop_core::TransactionProof {
                tx_index,
                value,
                proof,
            })
            .collect();
        }

        Ok((
            EvidenceBlock {
                header,
                receipts: receipts_out,
                transactions: transactions_out,
            },
            log_position_map,
        ))
    }

    pub fn block_evidence_many(
        &self,
        targets: &[(u64, Vec<u64>, Vec<u64>)],
        concurrency: usize,
    ) -> Result<Vec<(EvidenceBlock, BTreeMap<u64, usize>)>> {
        let cache_dir = std::env::var_os("LOOP_EVIDENCE_CACHE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_BLOCK_EVIDENCE_CACHE_DIR));
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("create evidence cache {}", cache_dir.display()))?;
        let cache_index = index_cached_blocks(&cache_dir)?;
        eprintln!("block evidence cache: {}", cache_dir.display());
        let next = AtomicUsize::new(0);
        let completed = AtomicUsize::new(0);
        let cache_hits = AtomicUsize::new(0);
        let rpc_fetches = AtomicUsize::new(0);
        let results = Mutex::new(
            (0..targets.len())
                .map(|_| None)
                .collect::<Vec<Option<Result<(EvidenceBlock, BTreeMap<u64, usize>)>>>>(),
        );
        std::thread::scope(|scope| {
            for _ in 0..concurrency.max(1).min(targets.len().max(1)) {
                scope.spawn(|| loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some((number, receipt_targets, transaction_targets)) = targets.get(index)
                    else {
                        break;
                    };
                    let receipt_targets = canonical_targets(receipt_targets);
                    let transaction_targets = canonical_targets(transaction_targets);
                    let result = self
                        .cached_block_evidence(
                            &cache_dir,
                            cache_index.get(number).map(Vec::as_slice).unwrap_or(&[]),
                            *number,
                            &receipt_targets,
                            &transaction_targets,
                        )
                        .map(|(evidence, log_position_map, cached)| {
                            if cached {
                                cache_hits.fetch_add(1, Ordering::Relaxed);
                            } else {
                                rpc_fetches.fetch_add(1, Ordering::Relaxed);
                            }
                            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                            if done % 100 == 0 || done == targets.len() {
                                eprintln!(
                                    "block evidence {done}/{} ({} cached, {} fetched)",
                                    targets.len(),
                                    cache_hits.load(Ordering::Relaxed),
                                    rpc_fetches.load(Ordering::Relaxed),
                                );
                            }
                            (evidence, log_position_map)
                        });
                    results.lock().expect("block evidence results lock")[index] = Some(result);
                });
            }
        });
        results
            .into_inner()
            .expect("block evidence results lock")
            .into_iter()
            .map(|result| result.context("block evidence worker did not return")?)
            .collect()
    }

    fn cached_block_evidence(
        &self,
        cache_dir: &Path,
        cached_paths: &[PathBuf],
        number: u64,
        receipt_targets: &[u64],
        transaction_targets: &[u64],
    ) -> Result<(EvidenceBlock, BTreeMap<u64, usize>, bool)> {
        let cache_path =
            block_evidence_cache_path(cache_dir, number, receipt_targets, transaction_targets)?;
        if let Some(cached) =
            load_cached_block_evidence(&cache_path, number, receipt_targets, transaction_targets)?
        {
            return Ok((cached.evidence, cached.log_position_map, true));
        }
        if let Some(cached) =
            merge_cached_block_evidence(cached_paths, number, receipt_targets, transaction_targets)?
        {
            write_cached_block_evidence(&cache_path, &cached)?;
            return Ok((cached.evidence, cached.log_position_map, true));
        }
        let (evidence, log_position_map) =
            self.block_evidence(number, receipt_targets, transaction_targets)?;
        let cached = CachedBlockEvidence {
            version: BLOCK_EVIDENCE_CACHE_VERSION,
            block_number: number,
            receipt_targets: receipt_targets.to_vec(),
            transaction_targets: transaction_targets.to_vec(),
            evidence,
            log_position_map,
        };
        write_cached_block_evidence(&cache_path, &cached)?;
        Ok((cached.evidence, cached.log_position_map, false))
    }

    // ── state witnesses ────────────────────────────────────────────────

    /// `eth_getProof` for one slot, self-checked against the block's state
    /// root through the exact verifier the guest runs.
    pub fn storage_witness(
        &self,
        header: &alloy_consensus::Header,
        contract: Address,
        slot: B256,
    ) -> Result<(loop_core::StorageProof, U256)> {
        let number = header.number;
        let res = self.call(
            "eth_getProof",
            json!([
                format!("{contract}"),
                [format!("{slot}")],
                format!("0x{number:x}")
            ]),
        )?;
        let account_proof: Vec<Bytes> = res["accountProof"]
            .as_array()
            .context("accountProof missing (archive node required)")?
            .iter()
            .map(parse_hex_bytes_b)
            .collect::<Result<_>>()?;
        let entry = res["storageProof"]
            .as_array()
            .and_then(|a| a.first())
            .context("storageProof missing")?;
        let value: U256 = parse_u256(&entry["value"])?;
        let mut storage_proof: Vec<Bytes> = entry["proof"]
            .as_array()
            .context("storage proof nodes missing")?
            .iter()
            .map(parse_hex_bytes_b)
            .collect::<Result<_>>()?;
        // An account with an empty storage trie proves every slot zero with
        // no nodes; normalize the RPC's representation.
        if value.is_zero() && storage_proof.len() == 1 && storage_proof[0].as_ref() == [0x80] {
            storage_proof.clear();
        }
        let witness = loop_core::StorageProof {
            account_proof,
            storage_proof,
        };
        let checked = loop_core::verify_storage_value(header.state_root, contract, slot, &witness)
            .map_err(|e| anyhow!("block {number} {contract} slot {slot}: self-check: {e}"))?;
        if checked != value {
            bail!("block {number} {contract} slot {slot}: proof value {checked} != RPC {value}");
        }
        Ok((witness, value))
    }
}

fn index_cached_blocks(cache_dir: &Path) -> Result<BTreeMap<u64, Vec<PathBuf>>> {
    let mut index = BTreeMap::<u64, Vec<PathBuf>>::new();
    for entry in fs::read_dir(cache_dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((number, _)) = name.split_once('-') else {
            continue;
        };
        let Ok(number) = number.parse::<u64>() else {
            continue;
        };
        index.entry(number).or_default().push(entry.path());
    }
    Ok(index)
}

fn merge_cached_block_evidence(
    paths: &[PathBuf],
    number: u64,
    receipt_targets: &[u64],
    transaction_targets: &[u64],
) -> Result<Option<CachedBlockEvidence>> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut header = None;
    let mut receipts = BTreeMap::new();
    let mut transactions = BTreeMap::new();
    let mut log_position_map = BTreeMap::new();
    for path in paths {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let Ok(cached) = serde_json::from_slice::<CachedBlockEvidence>(&bytes) else {
            continue;
        };
        if cached.version != BLOCK_EVIDENCE_CACHE_VERSION
            || cached.block_number != number
            || cached.evidence.header.number != number
        {
            continue;
        }
        let block_hash = cached.evidence.header.hash_slow();
        if header
            .as_ref()
            .is_some_and(|existing: &alloy_consensus::Header| existing.hash_slow() != block_hash)
        {
            continue;
        }
        header.get_or_insert(cached.evidence.header);
        for proof in cached.evidence.receipts {
            if receipt_targets.binary_search(&proof.tx_index).is_ok() {
                receipts.entry(proof.tx_index).or_insert(proof);
            }
        }
        for proof in cached.evidence.transactions {
            if transaction_targets.binary_search(&proof.tx_index).is_ok() {
                transactions.entry(proof.tx_index).or_insert(proof);
            }
        }
        log_position_map.extend(cached.log_position_map);
        if receipts.len() == receipt_targets.len()
            && transactions.len() == transaction_targets.len()
        {
            let evidence = EvidenceBlock {
                header: header.context("cached block header missing")?,
                receipts: receipts.into_values().collect(),
                transactions: transactions.into_values().collect(),
            };
            return Ok(Some(CachedBlockEvidence {
                version: BLOCK_EVIDENCE_CACHE_VERSION,
                block_number: number,
                receipt_targets: receipt_targets.to_vec(),
                transaction_targets: transaction_targets.to_vec(),
                evidence,
                log_position_map,
            }));
        }
    }
    Ok(None)
}

fn canonical_targets(targets: &[u64]) -> Vec<u64> {
    let mut targets = targets.to_vec();
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn block_evidence_cache_path(
    cache_dir: &Path,
    number: u64,
    receipt_targets: &[u64],
    transaction_targets: &[u64],
) -> Result<PathBuf> {
    let key = serde_json::to_vec(&(
        BLOCK_EVIDENCE_CACHE_VERSION,
        number,
        receipt_targets,
        transaction_targets,
    ))?;
    let digest = Sha256::digest(key)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(cache_dir.join(format!("{number}-{digest}.json")))
}

fn load_cached_block_evidence(
    cache_path: &Path,
    number: u64,
    receipt_targets: &[u64],
    transaction_targets: &[u64],
) -> Result<Option<CachedBlockEvidence>> {
    let bytes = match fs::read(cache_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read evidence cache {}", cache_path.display()))
        }
    };
    let cached: CachedBlockEvidence = match serde_json::from_slice(&bytes) {
        Ok(cached) => cached,
        Err(error) => {
            eprintln!(
                "ignoring invalid evidence cache {}: {error}",
                cache_path.display()
            );
            return Ok(None);
        }
    };
    let receipt_indices = canonical_targets(
        &cached
            .evidence
            .receipts
            .iter()
            .map(|proof| proof.tx_index)
            .collect::<Vec<_>>(),
    );
    let transaction_indices = canonical_targets(
        &cached
            .evidence
            .transactions
            .iter()
            .map(|proof| proof.tx_index)
            .collect::<Vec<_>>(),
    );
    if cached.version != BLOCK_EVIDENCE_CACHE_VERSION
        || cached.block_number != number
        || cached.evidence.header.number != number
        || cached.receipt_targets != receipt_targets
        || cached.transaction_targets != transaction_targets
        || receipt_indices != receipt_targets
        || transaction_indices != transaction_targets
    {
        eprintln!(
            "ignoring mismatched evidence cache {}",
            cache_path.display()
        );
        return Ok(None);
    }
    Ok(Some(cached))
}

fn write_cached_block_evidence(cache_path: &Path, cached: &CachedBlockEvidence) -> Result<()> {
    let parent = cache_path
        .parent()
        .context("evidence cache path has no parent")?;
    let counter = CACHE_TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = cache_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("evidence cache path has invalid file name")?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        counter
    ));
    let result = (|| -> Result<()> {
        let mut file = File::create(&temporary)
            .with_context(|| format!("create evidence checkpoint {}", temporary.display()))?;
        serde_json::to_writer(&mut file, cached)
            .with_context(|| format!("serialize evidence checkpoint {}", temporary.display()))?;
        file.flush()?;
        file.sync_all()?;
        fs::rename(&temporary, cache_path).with_context(|| {
            format!(
                "publish evidence checkpoint {} -> {}",
                temporary.display(),
                cache_path.display()
            )
        })?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_evidence_cache_round_trips_and_keys_targets() {
        let directory = std::env::temp_dir().join(format!(
            "loop-proof-block-cache-{}-{}",
            std::process::id(),
            CACHE_TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        let mut header = alloy_consensus::Header::default();
        header.number = 42;
        let cached = CachedBlockEvidence {
            version: BLOCK_EVIDENCE_CACHE_VERSION,
            block_number: 42,
            receipt_targets: vec![],
            transaction_targets: vec![],
            evidence: EvidenceBlock {
                header,
                receipts: vec![],
                transactions: vec![],
            },
            log_position_map: BTreeMap::from([(7, 3)]),
        };
        let path = block_evidence_cache_path(&directory, 42, &[], &[]).unwrap();
        let other_path = block_evidence_cache_path(&directory, 42, &[1], &[]).unwrap();
        assert_ne!(path, other_path);
        write_cached_block_evidence(&path, &cached).unwrap();
        let loaded = load_cached_block_evidence(&path, 42, &[], &[])
            .unwrap()
            .unwrap();
        assert_eq!(loaded.block_number, 42);
        assert_eq!(loaded.evidence.header.number, 42);
        assert_eq!(loaded.log_position_map, BTreeMap::from([(7, 3)]));
        assert!(load_cached_block_evidence(&path, 42, &[1], &[])
            .unwrap()
            .is_none());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn block_evidence_cache_merges_target_subsets() {
        let directory = std::env::temp_dir().join(format!(
            "loop-proof-block-cache-merge-{}-{}",
            std::process::id(),
            CACHE_TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        let mut header = alloy_consensus::Header::default();
        header.number = 42;
        for target in [1, 2] {
            let cached = CachedBlockEvidence {
                version: BLOCK_EVIDENCE_CACHE_VERSION,
                block_number: 42,
                receipt_targets: vec![target],
                transaction_targets: vec![],
                evidence: EvidenceBlock {
                    header: header.clone(),
                    receipts: vec![loop_core::ReceiptProof {
                        tx_index: target,
                        value: Bytes::new(),
                        proof: vec![],
                    }],
                    transactions: vec![],
                },
                log_position_map: BTreeMap::from([(target, 0)]),
            };
            let path = block_evidence_cache_path(&directory, 42, &[target], &[]).unwrap();
            write_cached_block_evidence(&path, &cached).unwrap();
        }
        let paths = index_cached_blocks(&directory)
            .unwrap()
            .remove(&42)
            .unwrap();
        let merged = merge_cached_block_evidence(&paths, 42, &[1, 2], &[])
            .unwrap()
            .unwrap();
        assert_eq!(merged.receipt_targets, vec![1, 2]);
        assert_eq!(merged.evidence.receipts.len(), 2);
        fs::remove_dir_all(directory).unwrap();
    }
}

fn prove_index_trie(
    encoded: &[Bytes],
    targets: &[u64],
    expected_root: B256,
    label: &str,
) -> Result<Vec<(u64, Bytes, Vec<Bytes>)>> {
    let target_keys: Vec<Nibbles> = targets
        .iter()
        .map(|i| Nibbles::unpack(loop_core::trie_index_key(*i)))
        .collect();
    let mut leaves: Vec<(Nibbles, &Bytes)> = encoded
        .iter()
        .enumerate()
        .map(|(i, v)| (Nibbles::unpack(loop_core::trie_index_key(i as u64)), v))
        .collect();
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hb =
        HashBuilder::default().with_proof_retainer(ProofRetainer::new(target_keys.clone()));
    for (key, value) in &leaves {
        hb.add_leaf(key.clone(), value.as_ref());
    }
    let root = hb.root();
    if root != expected_root {
        bail!("{label}: local root {root} != header {expected_root}");
    }
    let proof_nodes = hb.take_proof_nodes();
    let mut out = Vec::new();
    for (i, key) in targets.iter().zip(&target_keys) {
        let proof: Vec<Bytes> = proof_nodes
            .matching_nodes_sorted(key)
            .into_iter()
            .map(|(_, node)| node)
            .collect();
        let value = encoded
            .get(*i as usize)
            .with_context(|| format!("{label}: index {i} out of range"))?
            .clone();
        alloy_trie::proof::verify_proof(root, key.clone(), Some(value.to_vec()), proof.iter())
            .map_err(|e| anyhow!("{label}: index {i} proof self-check: {e}"))?;
        out.push((*i, value, proof));
    }
    Ok(out)
}

fn encode_rpc_transaction(value: Value) -> Result<Bytes> {
    let transaction: AnyRpcTransaction = serde_json::from_value(value)?;
    let envelope = OpTxEnvelope::try_from(transaction)
        .map_err(|error| anyhow!("unsupported Base transaction: {error}"))?;
    Ok(envelope.encoded_2718().into())
}

// ── receipt trie-value encoding ────────────────────────────────────────

/// `[type]? ++ rlp([status, cumulativeGas, bloom, logs, (depositNonce, depositReceiptVersion)?])`
fn encode_receipt(r: &Value) -> Result<Bytes> {
    let ty = r.get("type").map(hex_u64).transpose()?.unwrap_or(0);
    let status = hex_u64(&r["status"])?;
    let cum_gas = hex_u64(&r["cumulativeGasUsed"])?;
    let bloom = parse_hex_bytes(&r["logsBloom"])?;

    let mut log_items = Vec::new();
    for l in r["logs"].as_array().context("logs")? {
        let addr = parse_addr(&l["address"])?;
        let topics: Vec<Vec<u8>> = l["topics"]
            .as_array()
            .context("topics")?
            .iter()
            .map(|t| Ok(parse_b256(t)?.to_vec()))
            .collect::<Result<_>>()?;
        let data = parse_hex_bytes(&l["data"])?;
        log_items.push(rlp_list(&[
            rlp_bytes(addr.as_slice()),
            rlp_list(&topics.iter().map(|t| rlp_bytes(t)).collect::<Vec<_>>()),
            rlp_bytes(&data),
        ]));
    }

    let mut fields = vec![
        rlp_uint(status as u128),
        rlp_uint(cum_gas as u128),
        rlp_bytes(&bloom),
        rlp_list(&log_items),
    ];
    // OP-stack deposit receipts (post-Canyon) hash two extra fields.
    if ty == 0x7e {
        if let Some(v) = r.get("depositReceiptVersion").filter(|v| !v.is_null()) {
            let nonce = r.get("depositNonce").context("depositNonce")?;
            fields.push(rlp_uint(hex_u64(nonce)? as u128));
            fields.push(rlp_uint(hex_u64(v)? as u128));
        }
    }
    let inner = rlp_list(&fields);
    Ok(if ty == 0 {
        inner.into()
    } else {
        [vec![ty as u8], inner].concat().into()
    })
}

// ── hex parsing helpers ────────────────────────────────────────────────

pub fn hex_u64(v: &Value) -> Result<u64> {
    let s = v.as_str().context("expected hex string")?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

fn parse_hex_bytes(v: &Value) -> Result<Vec<u8>> {
    let s = v.as_str().context("expected hex string")?;
    Ok(alloy_primitives::hex::decode(s)?)
}

fn parse_hex_bytes_b(v: &Value) -> Result<Bytes> {
    Ok(Bytes::from(parse_hex_bytes(v)?))
}

fn parse_addr(v: &Value) -> Result<Address> {
    Ok(v.as_str().context("expected address")?.parse()?)
}

fn parse_b256(v: &Value) -> Result<B256> {
    Ok(v.as_str().context("expected b256")?.parse()?)
}

pub fn parse_u256(v: &Value) -> Result<U256> {
    let s = v.as_str().context("expected u256")?;
    Ok(U256::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

pub fn addr_topic(a: Address) -> B256 {
    let mut t = [0u8; 32];
    t[12..].copy_from_slice(a.as_slice());
    B256::from(t)
}

fn topic(log: &Value, i: usize) -> Result<Option<B256>> {
    match log["topics"].as_array().and_then(|t| t.get(i)) {
        Some(v) => Ok(Some(parse_b256(v)?)),
        None => Ok(None),
    }
}
