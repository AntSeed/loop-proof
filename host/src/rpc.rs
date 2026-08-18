//! Minimal JSON-RPC client with endpoint fallback, plus the receipt
//! re-encoding needed to rebuild the exact trie values the guest verifies.

use alloy_primitives::{Address, Bytes, B256};
use anyhow::{anyhow, bail, Context, Result};
use loop_core::{BlockEvidence, TRANSFER_TOPIC};
use serde_json::{json, Value};

pub struct Client {
    endpoints: Vec<String>,
}

/// (block_number, tx_index, log_index_within_receipt)
pub type LogLoc = (u64, usize, usize);

impl Client {
    pub fn new(endpoints: &[&str]) -> Self {
        Self { endpoints: endpoints.iter().map(|s| s.to_string()).collect() }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut last_err = None;
        for attempt in 0..3 {
            for url in &self.endpoints {
                let res = ureq::post(url)
                    .timeout(std::time::Duration::from_secs(30))
                    .send_json(json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}));
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
            std::thread::sleep(std::time::Duration::from_millis(500 * (attempt + 1)));
        }
        Err(last_err.unwrap_or_else(|| anyhow!("{method}: all endpoints failed")))
    }

    // ── log discovery ──────────────────────────────────────────────────

    pub fn find_transfer_in_tx(
        &self,
        tx: B256,
        usdc: Address,
        from: Address,
        to: Address,
    ) -> Result<LogLoc> {
        let rec = self.call("eth_getTransactionReceipt", json!([format!("{tx}")]))?;
        if rec.is_null() {
            bail!("receipt not found for {tx}");
        }
        let logs = rec["logs"].as_array().context("no logs")?;
        for (i, l) in logs.iter().enumerate() {
            if parse_addr(&l["address"])? == usdc
                && topic(l, 0)? == Some(TRANSFER_TOPIC)
                && topic(l, 1)? == Some(addr_topic(from))
                && topic(l, 2)? == Some(addr_topic(to))
            {
                return Ok((hex_u64(&rec["blockNumber"])?, hex_u64(&rec["transactionIndex"])? as usize, i));
            }
        }
        bail!("no matching USDC transfer in {tx}")
    }

    pub fn find_first_transfer(
        &self,
        usdc: Address,
        from: Address,
        to: Address,
        from_block: u64,
    ) -> Result<Option<LogLoc>> {
        let latest = hex_u64(&self.call("eth_blockNumber", json!([]))?)?;
        let filter_topics = json!([format!("{TRANSFER_TOPIC}"), format!("{}", addr_topic(from)), format!("{}", addr_topic(to))]);
        let mut b = from_block;
        while b <= latest {
            let end = (b + 499_999).min(latest);
            let logs = self.call(
                "eth_getLogs",
                json!([{ "address": format!("{usdc}"), "topics": filter_topics,
                         "fromBlock": format!("0x{b:x}"), "toBlock": format!("0x{end:x}") }]),
            )?;
            if let Some(l) = logs.as_array().and_then(|a| a.first()) {
                return Ok(Some(self.locate(l)?));
            }
            b = end + 1;
        }
        Ok(None)
    }

    pub fn find_settlements(
        &self,
        channels: Address,
        buyer: Address,
        seller: Address,
        from_block: u64,
        max: usize,
    ) -> Result<Vec<LogLoc>> {
        let latest = hex_u64(&self.call("eth_blockNumber", json!([]))?)?;
        let topics = json!([format!("{}", loop_core::CHANNEL_SETTLED_TOPIC), Value::Null,
                            format!("{}", addr_topic(buyer)), format!("{}", addr_topic(seller))]);
        let mut out = Vec::new();
        let mut b = from_block;
        while b <= latest && out.len() < max {
            let end = (b + 99_999).min(latest);
            let logs = self.call(
                "eth_getLogs",
                json!([{ "address": format!("{channels}"), "topics": topics,
                         "fromBlock": format!("0x{b:x}"), "toBlock": format!("0x{end:x}") }]),
            )?;
            for l in logs.as_array().into_iter().flatten() {
                if out.len() >= max {
                    break;
                }
                out.push(self.locate(l)?);
            }
            b = end + 1;
        }
        Ok(out)
    }

    /// Convert a getLogs entry to (block, tx_index, log_index_within_receipt).
    fn locate(&self, log: &Value) -> Result<LogLoc> {
        let block = hex_u64(&log["blockNumber"])?;
        let tx_index = hex_u64(&log["transactionIndex"])? as usize;
        let block_log_index = hex_u64(&log["logIndex"])?;
        let rec = self.call("eth_getTransactionReceipt", json!([log["transactionHash"]]))?;
        let logs = rec["logs"].as_array().context("no logs")?;
        let local = logs
            .iter()
            .position(|l| hex_u64(&l["logIndex"]).ok() == Some(block_log_index))
            .context("log not found in its own receipt")?;
        Ok((block, tx_index, local))
    }

    // ── block evidence ─────────────────────────────────────────────────

    /// Fetch a block's header and inclusion proofs for the `targets` receipt
    /// (transaction) indices. Builds the full receipts trie locally, retains
    /// the proof paths for the targets, and self-checks everything before it
    /// can reach the guest.
    pub fn block_evidence(&self, number: u64, targets: &[u64]) -> Result<BlockEvidence> {
        use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};

        let block = self.call("eth_getBlockByNumber", json!([format!("0x{number:x}"), false]))?;
        let rpc_hash: B256 = parse_b256(&block["hash"])?;
        let header: alloy_consensus::Header = serde_json::from_value(block.clone())
            .context("header deserialization — RPC schema mismatch")?;
        if header.hash_slow() != rpc_hash {
            bail!("block {number}: recomputed header hash {} != RPC hash {rpc_hash}", header.hash_slow());
        }

        let receipts = self.call("eth_getBlockReceipts", json!([format!("0x{number:x}")]))?;
        let receipts = receipts.as_array().context("eth_getBlockReceipts unsupported")?;
        let encoded: Vec<Bytes> = receipts
            .iter()
            .map(encode_receipt)
            .collect::<Result<_>>()
            .with_context(|| format!("block {number}: receipt encoding"))?;

        // Build the receipts trie, retaining proofs for the target keys.
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
        let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(target_keys.clone()));
        for (key, value) in &leaves {
            hb.add_leaf(key.clone(), value.as_ref());
        }
        let root = hb.root();
        if root != header.receipts_root {
            bail!("block {number}: local receipts-root {root} != header {}", header.receipts_root);
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
                .with_context(|| format!("block {number}: tx index {i} out of range"))?
                .clone();
            // self-check the exact proof the guest will verify
            alloy_trie::proof::verify_proof(root, key.clone(), Some(value.to_vec()), proof.iter())
                .map_err(|e| anyhow!("block {number}: receipt {i} proof self-check: {e}"))?;
            out.push(loop_core::ReceiptProof { tx_index: *i, value, proof });
        }
        Ok(BlockEvidence { header, receipts: out })
    }
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
    Ok(if ty == 0 { inner.into() } else { [vec![ty as u8], inner].concat().into() })
}

// ── tiny RLP encoder ───────────────────────────────────────────────────

fn rlp_len_prefix(base: u8, len: usize) -> Vec<u8> {
    if len <= 55 {
        vec![base + len as u8]
    } else {
        let be = (len as u64).to_be_bytes();
        let sig = be.iter().skip_while(|b| **b == 0).cloned().collect::<Vec<_>>();
        let mut out = vec![base + 55 + sig.len() as u8];
        out.extend(sig);
        out
    }
}

fn rlp_bytes(payload: &[u8]) -> Vec<u8> {
    if payload.len() == 1 && payload[0] < 0x80 {
        payload.to_vec()
    } else {
        let mut out = rlp_len_prefix(0x80, payload.len());
        out.extend_from_slice(payload);
        out
    }
}

fn rlp_uint(v: u128) -> Vec<u8> {
    let be = v.to_be_bytes();
    let sig: Vec<u8> = be.iter().skip_while(|b| **b == 0).cloned().collect();
    rlp_bytes(&sig)
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = rlp_len_prefix(0xc0, payload.len());
    out.extend(payload);
    out
}

// ── hex parsing helpers ────────────────────────────────────────────────

fn hex_u64(v: &Value) -> Result<u64> {
    let s = v.as_str().context("expected hex string")?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

fn parse_hex_bytes(v: &Value) -> Result<Vec<u8>> {
    let s = v.as_str().context("expected hex string")?;
    Ok(alloy_primitives::hex::decode(s)?)
}

fn parse_addr(v: &Value) -> Result<Address> {
    Ok(v.as_str().context("expected address")?.parse()?)
}

fn parse_b256(v: &Value) -> Result<B256> {
    Ok(v.as_str().context("expected b256")?.parse()?)
}

fn addr_topic(a: Address) -> B256 {
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
