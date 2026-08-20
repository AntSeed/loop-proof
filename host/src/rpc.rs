//! Minimal JSON-RPC client with endpoint fallback, plus the receipt
//! re-encoding needed to rebuild the exact trie values the guest verifies.

use alloy_eips::eip2718::Encodable2718;
use alloy_network::AnyRpcTransaction;
use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::{anyhow, bail, Context, Result};
use loop_core::{BlockEvidence, TRANSFER_TOPIC};
use op_alloy_consensus::OpTxEnvelope;
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct Client {
    endpoints: Vec<String>,
}

/// (block_number, tx_index, log_index_within_receipt)
pub type LogLoc = (u64, usize, usize);
pub type ReportLogPositions = BTreeMap<(u64, u64), usize>;

#[derive(Clone, Debug)]
pub struct SettlementCandidate {
    pub buyer: Address,
    pub block_number: u64,
    pub transaction_hash: B256,
    pub transaction_index: usize,
    pub block_log_index: u64,
    pub amount_raw: u128,
}

impl SettlementCandidate {
    pub fn canonical_key(&self) -> (u64, usize, u64) {
        (
            self.block_number,
            self.transaction_index,
            self.block_log_index,
        )
    }
}

impl Client {
    pub fn new<I, S>(endpoints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            endpoints: endpoints
                .into_iter()
                .map(|endpoint| endpoint.as_ref().to_owned())
                .collect(),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut last_err = None;
        for attempt in 0..8 {
            for url in &self.endpoints {
                let res = ureq::post(url)
                    .timeout(std::time::Duration::from_secs(30))
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
            std::thread::sleep(std::time::Duration::from_millis(750 * (attempt + 1)));
        }
        Err(last_err.unwrap_or_else(|| anyhow!("{method}: all endpoints failed")))
    }

    /// Fetch and authenticate a consensus header used by proof evidence.
    pub fn header(&self, number: u64) -> Result<alloy_consensus::Header> {
        let block = self.call(
            "eth_getBlockByNumber",
            json!([format!("0x{number:x}"), false]),
        )?;
        let rpc_hash = parse_b256(&block["hash"])?;
        let header: alloy_consensus::Header = serde_json::from_value(block)
            .context("header deserialization — RPC schema mismatch")?;
        if header.hash_slow() != rpc_hash {
            bail!("block {number}: recomputed header hash differs from RPC hash");
        }
        Ok(header)
    }

    /// Locate a transaction by its successful or reverted receipt.
    pub fn transaction_location(&self, transaction_hash: B256) -> Result<(u64, u64)> {
        let receipt = self.call(
            "eth_getTransactionReceipt",
            json!([format!("{transaction_hash}")]),
        )?;
        if receipt.is_null() {
            bail!("receipt not found for {transaction_hash}");
        }
        Ok((
            hex_u64(&receipt["blockNumber"])?,
            hex_u64(&receipt["transactionIndex"])?,
        ))
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
                return Ok((
                    hex_u64(&rec["blockNumber"])?,
                    hex_u64(&rec["transactionIndex"])? as usize,
                    i,
                ));
            }
        }
        bail!("no matching USDC transfer in {tx}")
    }

    pub fn find_protocol_deposit_in_tx(
        &self,
        transaction_hash: B256,
        funder: Address,
        buyer: Address,
        amount: u128,
    ) -> Result<(u64, u64, usize, usize)> {
        let receipt = self.call(
            "eth_getTransactionReceipt",
            json!([format!("{transaction_hash}")]),
        )?;
        if receipt.is_null() {
            bail!("receipt not found for {transaction_hash}");
        }
        let logs = receipt["logs"].as_array().context("receipt logs missing")?;
        let transfer = logs.iter().position(|log| {
            parse_addr(&log["address"]).ok() == Some(enforcement_core::USDC_ADDRESS)
                && topic(log, 0).ok().flatten() == Some(loop_core::TRANSFER_TOPIC)
                && topic(log, 1).ok().flatten() == Some(addr_topic(funder))
                && topic(log, 2).ok().flatten()
                    == Some(addr_topic(enforcement_core::DEPOSITS_ADDRESS))
                && parse_u256(&log["data"]).ok() == Some(U256::from(amount))
        });
        let deposited = logs.iter().position(|log| {
            parse_addr(&log["address"]).ok() == Some(enforcement_core::DEPOSITS_ADDRESS)
                && topic(log, 0).ok().flatten() == Some(enforcement_core::DEPOSITED_TOPIC)
                && topic(log, 1).ok().flatten() == Some(addr_topic(buyer))
                && parse_u256(&log["data"]).ok() == Some(U256::from(amount))
        });
        let transfer = transfer.context("matching protocol-deposit USDC transfer missing")?;
        let deposited = deposited.context("matching Antseed Deposited event missing")?;
        if transfer >= deposited {
            bail!("protocol-deposit Transfer must precede Deposited");
        }
        Ok((
            hex_u64(&receipt["blockNumber"])?,
            hex_u64(&receipt["transactionIndex"])?,
            transfer,
            deposited,
        ))
    }

    pub fn find_first_transfer(
        &self,
        usdc: Address,
        from: Address,
        to: Address,
        from_block: u64,
    ) -> Result<Option<LogLoc>> {
        let latest = hex_u64(&self.call("eth_blockNumber", json!([]))?)?;
        let filter_topics = json!([
            format!("{TRANSFER_TOPIC}"),
            format!("{}", addr_topic(from)),
            format!("{}", addr_topic(to))
        ]);
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
        end_block_exclusive: u64,
    ) -> Result<Vec<SettlementCandidate>> {
        if from_block >= end_block_exclusive {
            return Ok(Vec::new());
        }
        let topics = json!([
            format!("{}", loop_core::CHANNEL_SETTLED_TOPIC),
            Value::Null,
            format!("{}", addr_topic(buyer)),
            format!("{}", addr_topic(seller))
        ]);
        let mut out = Vec::new();
        let mut b = from_block;
        let last_block = end_block_exclusive - 1;
        while b <= last_block {
            let end = (b + 99_999).min(last_block);
            let logs = self.call(
                "eth_getLogs",
                json!([{ "address": format!("{channels}"), "topics": topics,
                         "fromBlock": format!("0x{b:x}"), "toBlock": format!("0x{end:x}") }]),
            )?;
            for l in logs.as_array().into_iter().flatten() {
                let data = parse_hex_bytes(&l["data"])?;
                if data.len() < 64 || data[32..48].iter().any(|byte| *byte != 0) {
                    bail!("ChannelSettled volume does not fit u128");
                }
                let amount_raw = u128::from_be_bytes(data[48..64].try_into().unwrap());
                out.push(SettlementCandidate {
                    buyer,
                    block_number: hex_u64(&l["blockNumber"])?,
                    transaction_hash: parse_b256(&l["transactionHash"])?,
                    transaction_index: hex_u64(&l["transactionIndex"])? as usize,
                    block_log_index: hex_u64(&l["logIndex"])?,
                    amount_raw,
                });
            }
            b = end + 1;
        }
        Ok(out)
    }

    pub fn find_seller_settlements(
        &self,
        channels: Address,
        seller: Address,
        from_block: u64,
        end_block_exclusive: u64,
    ) -> Result<Vec<SettlementCandidate>> {
        if from_block >= end_block_exclusive {
            return Ok(Vec::new());
        }
        let topics = json!([
            format!("{}", loop_core::CHANNEL_SETTLED_TOPIC),
            Value::Null,
            Value::Null,
            format!("{}", addr_topic(seller))
        ]);
        let mut out = Vec::new();
        let mut block = from_block;
        let last_block = end_block_exclusive - 1;
        while block <= last_block {
            let end = (block + 99_999).min(last_block);
            let logs = self.call(
                "eth_getLogs",
                json!([{ "address": format!("{channels}"), "topics": topics,
                         "fromBlock": format!("0x{block:x}"), "toBlock": format!("0x{end:x}") }]),
            )?;
            for log in logs.as_array().into_iter().flatten() {
                let data = parse_hex_bytes(&log["data"])?;
                if data.len() < 64 || data[32..48].iter().any(|byte| *byte != 0) {
                    bail!("ChannelSettled volume does not fit u128");
                }
                let buyer_topic = topic(log, 2)?.context("ChannelSettled missing buyer topic")?;
                out.push(SettlementCandidate {
                    buyer: Address::from_slice(&buyer_topic.as_slice()[12..]),
                    block_number: hex_u64(&log["blockNumber"])?,
                    transaction_hash: parse_b256(&log["transactionHash"])?,
                    transaction_index: hex_u64(&log["transactionIndex"])? as usize,
                    block_log_index: hex_u64(&log["logIndex"])?,
                    amount_raw: u128::from_be_bytes(data[48..64].try_into().unwrap()),
                });
            }
            block = end + 1;
        }
        out.sort_by_key(SettlementCandidate::canonical_key);
        Ok(out)
    }

    pub fn locate_settlement(&self, candidate: &SettlementCandidate) -> Result<LogLoc> {
        let rec = self.call(
            "eth_getTransactionReceipt",
            json!([format!("{}", candidate.transaction_hash)]),
        )?;
        if hex_u64(&rec["blockNumber"])? != candidate.block_number
            || hex_u64(&rec["transactionIndex"])? as usize != candidate.transaction_index
        {
            bail!("settlement receipt location changed");
        }
        let logs = rec["logs"].as_array().context("no logs")?;
        let local = logs
            .iter()
            .position(|log| hex_u64(&log["logIndex"]).ok() == Some(candidate.block_log_index))
            .context("settlement log not found in its receipt")?;
        Ok((candidate.block_number, candidate.transaction_index, local))
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
    pub fn block_evidence(
        &self,
        number: u64,
        targets: &[u64],
        report_block_log_indices: &[u64],
    ) -> Result<(BlockEvidence, ReportLogPositions)> {
        use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};

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

        let receipts = self.call("eth_getBlockReceipts", json!([format!("0x{number:x}")]))?;
        let receipts = receipts
            .as_array()
            .context("eth_getBlockReceipts unsupported")?;
        let requested_logs = report_block_log_indices
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let mut report_log_positions = BTreeMap::new();
        for target in targets {
            let receipt = receipts
                .get(*target as usize)
                .with_context(|| format!("block {number}: tx index {target} out of range"))?;
            for (local_index, log) in receipt["logs"].as_array().into_iter().flatten().enumerate() {
                let block_log_index = hex_u64(&log["logIndex"])?;
                if requested_logs.contains(&block_log_index) {
                    report_log_positions.insert((*target, block_log_index), local_index);
                }
            }
        }
        if report_log_positions.len() != requested_logs.len() {
            bail!(
                "block {number}: located {} of {} requested report logs",
                report_log_positions.len(),
                requested_logs.len()
            );
        }
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
        let mut hb =
            HashBuilder::default().with_proof_retainer(ProofRetainer::new(target_keys.clone()));
        add_ordered_trie_leaves(&mut hb, &encoded);
        let root = hb.root();
        if root != header.receipts_root {
            bail!(
                "block {number}: local receipts-root {root} != header {}",
                header.receipts_root
            );
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
            alloy_trie::proof::verify_proof(root, *key, Some(value.to_vec()), proof.iter())
                .map_err(|e| anyhow!("block {number}: receipt {i} proof self-check: {e}"))?;
            out.push(loop_core::ReceiptProof {
                tx_index: *i,
                value,
                proof,
            });
        }
        Ok((
            BlockEvidence {
                header,
                receipts: out,
            },
            report_log_positions,
        ))
    }

    pub fn enforcement_block_evidence(
        &self,
        number: u64,
        receipt_targets: &[u64],
        transaction_targets: &[u64],
        block_log_indices: &[u64],
    ) -> Result<(enforcement_core::EnforcementBlock, ReportLogPositions)> {
        use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};

        let (receipt_evidence, log_positions) =
            self.block_evidence(number, receipt_targets, block_log_indices)?;
        if transaction_targets.is_empty() {
            return Ok((
                enforcement_core::EnforcementBlock {
                    header: receipt_evidence.header,
                    receipts: receipt_evidence.receipts,
                    transactions: Vec::new(),
                },
                log_positions,
            ));
        }

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
            let bytes = encode_rpc_transaction(transaction.clone())
                .with_context(|| format!("block {number}: reconstruct transaction {expected}"))?;
            if alloy_primitives::keccak256(&bytes) != expected {
                bail!("block {number}: reconstructed transaction hash mismatch for {expected}");
            }
            encoded.push(bytes);
        }
        let target_keys = transaction_targets
            .iter()
            .map(|index| Nibbles::unpack(loop_core::trie_index_key(*index)))
            .collect::<Vec<_>>();
        let mut builder =
            HashBuilder::default().with_proof_retainer(ProofRetainer::new(target_keys.clone()));
        add_ordered_trie_leaves(&mut builder, &encoded);
        let root = builder.root();
        if root != receipt_evidence.header.transactions_root {
            bail!(
                "block {number}: local transactions root {root} != header {}",
                receipt_evidence.header.transactions_root
            );
        }
        let proof_nodes = builder.take_proof_nodes();
        let mut transactions = Vec::new();
        for (index, key) in transaction_targets.iter().zip(target_keys) {
            let value = encoded
                .get(*index as usize)
                .with_context(|| format!("block {number}: tx index {index} out of range"))?
                .clone();
            let proof = proof_nodes
                .matching_nodes_sorted(&key)
                .into_iter()
                .map(|(_, node)| node)
                .collect::<Vec<_>>();
            alloy_trie::proof::verify_proof(root, key, Some(value.to_vec()), proof.iter())
                .map_err(|error| anyhow!("block {number}: transaction {index} proof: {error}"))?;
            transactions.push(enforcement_core::TransactionProof {
                tx_index: *index,
                value,
                proof,
            });
        }
        Ok((
            enforcement_core::EnforcementBlock {
                header: receipt_evidence.header,
                receipts: receipt_evidence.receipts,
                transactions,
            },
            log_positions,
        ))
    }
}

fn encode_rpc_transaction(value: Value) -> Result<Bytes> {
    let transaction: AnyRpcTransaction = serde_json::from_value(value)?;
    let envelope = OpTxEnvelope::try_from(transaction)
        .map_err(|error| anyhow!("unsupported Base transaction: {error}"))?;
    Ok(envelope.encoded_2718().into())
}

fn add_ordered_trie_leaves<K>(builder: &mut alloy_trie::HashBuilder<K>, encoded: &[Bytes])
where
    K: AsRef<alloy_trie::proof::AddedRemovedKeys>,
{
    let mut leaves = encoded
        .iter()
        .enumerate()
        .map(|(index, value)| {
            (
                alloy_trie::Nibbles::unpack(loop_core::trie_index_key(index as u64)),
                value,
            )
        })
        .collect::<Vec<_>>();
    leaves.sort_by(|left, right| left.0.cmp(&right.0));
    for (key, value) in leaves {
        builder.add_leaf(key, value.as_ref());
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
    Ok(if ty == 0 {
        inner.into()
    } else {
        [vec![ty as u8], inner].concat().into()
    })
}

// ── tiny RLP encoder ───────────────────────────────────────────────────

fn rlp_len_prefix(base: u8, len: usize) -> Vec<u8> {
    if len <= 55 {
        vec![base + len as u8]
    } else {
        let be = (len as u64).to_be_bytes();
        let sig = be
            .iter()
            .skip_while(|b| **b == 0)
            .cloned()
            .collect::<Vec<_>>();
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

fn parse_u256(value: &Value) -> Result<U256> {
    let text = value.as_str().context("expected hex quantity")?;
    U256::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16)
        .map_err(|error| anyhow!("invalid U256 quantity: {error}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_base_deposit_transaction() {
        let transaction = serde_json::json!({
            "type": "0x7e",
            "sourceHash": "0xaa943be17c137fece0613f1590c9ce4f4060e4773cbd6cdd8872797a2929574c",
            "from": "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001",
            "to": "0x4200000000000000000000000000000000000015",
            "mint": "0x0",
            "value": "0x0",
            "gas": "0xf4240",
            "input": "0x3db6be2b000008dd00101c1200000000000000000000000069fe0aef00000000017e413a0000000000000000000000000000000000000000000000000000000035d3993f0000000000000000000000000000000000000000000000000000000003313bde9769893c3700063346fb55688ff06a43e5a3915877d033e706853182b822acef0000000000000000000000005050f69a9786f081509234f1a7f4684b5e5b76c90000000000000000000000000094",
            "hash": "0xbfd4ecde1bca0d8417de482af8db2121881b574b6250b4e7cb7deea2e78d5086",
            "r": "0x0",
            "s": "0x0",
            "yParity": "0x0",
            "v": "0x0",
            "blockHash": "0x2274101a3826ce4ef456a76a0b6ab6819e3a952f882ef9a05564d616b92cc3e5",
            "blockNumber": "0x2b9d75e",
            "transactionIndex": "0x0",
            "blockTimestamp": "0x69fe0b9f",
            "depositReceiptVersion": "0x1",
            "gasPrice": "0x0",
            "nonce": "0x2b9d761"
        });
        let encoded = encode_rpc_transaction(transaction).unwrap();

        assert_eq!(encoded.first(), Some(&0x7e));
        assert_eq!(
            alloy_primitives::keccak256(encoded),
            "0xbfd4ecde1bca0d8417de482af8db2121881b574b6250b4e7cb7deea2e78d5086"
                .parse::<B256>()
                .unwrap()
        );
    }

    #[test]
    fn transaction_trie_leaves_follow_rlp_key_order() {
        let encoded = vec![Bytes::from(vec![0xc0]), Bytes::from(vec![0xc1, 0x01])];
        let mut builder = alloy_trie::HashBuilder::default();
        add_ordered_trie_leaves(&mut builder, &encoded);

        assert_eq!(
            builder.root(),
            alloy_trie::root::ordered_trie_root_encoded(&encoded)
        );
    }
}
