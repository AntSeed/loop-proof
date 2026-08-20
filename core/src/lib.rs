//! Shared Base receipt primitives for the current enforcement guests.
//!
//! Predicate rules, thresholds, witness types, and journals live in
//! `enforcement-core`. This crate only contains receipt parsing and
//! Merkle-Patricia inclusion helpers reused by the host and all three guests.

use alloy_consensus::Header;
use alloy_primitives::{Address, Bytes, B256};
use serde::{Deserialize, Serialize};

pub const TRANSFER_TOPIC: B256 =
    alloy_primitives::b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
pub const CHANNEL_SETTLED_TOPIC: B256 =
    alloy_primitives::b256!("0b287f37d8bd14ef37f2966734ab387c243cc1a1663616a25a4cc259877736b1");

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptProof {
    pub tx_index: u64,
    pub value: Bytes,
    pub proof: Vec<Bytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockEvidence {
    pub header: Header,
    pub receipts: Vec<ReceiptProof>,
}

#[derive(Clone, Debug)]
pub struct ParsedLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

fn next_item<'a>(buf: &mut &'a [u8]) -> Result<(bool, &'a [u8]), String> {
    let header = alloy_rlp::Header::decode(buf).map_err(|error| format!("rlp: {error}"))?;
    if buf.len() < header.payload_length {
        return Err("rlp: short payload".into());
    }
    let payload = &buf[..header.payload_length];
    *buf = &buf[header.payload_length..];
    Ok((header.list, payload))
}

/// Extract one log from a receipt's trie-value encoding.
pub fn receipt_log(receipt: &[u8], log_index: usize) -> Result<ParsedLog, String> {
    let mut encoded = receipt;
    if !encoded.is_empty() && encoded[0] < 0xc0 {
        encoded = &encoded[1..];
    }
    let (is_list, mut body) = next_item(&mut encoded)?;
    if !is_list {
        return Err("receipt: not a list".into());
    }
    for _ in 0..3 {
        next_item(&mut body)?;
    }
    let (is_list, mut logs) = next_item(&mut body)?;
    if !is_list {
        return Err("receipt: logs not a list".into());
    }
    let mut index = 0usize;
    while !logs.is_empty() {
        let (is_list, mut log) = next_item(&mut logs)?;
        if !is_list {
            return Err("receipt: log not a list".into());
        }
        if index == log_index {
            let (_, address) = next_item(&mut log)?;
            if address.len() != 20 {
                return Err("log: bad address".into());
            }
            let (is_list, mut topics_buf) = next_item(&mut log)?;
            if !is_list {
                return Err("log: topics not a list".into());
            }
            let mut topics = Vec::new();
            while !topics_buf.is_empty() {
                let (_, topic) = next_item(&mut topics_buf)?;
                if topic.len() != 32 {
                    return Err("log: bad topic".into());
                }
                topics.push(B256::from_slice(topic));
            }
            let (_, data) = next_item(&mut log)?;
            return Ok(ParsedLog {
                address: Address::from_slice(address),
                topics,
                data: data.to_vec(),
            });
        }
        index += 1;
    }
    Err(format!("receipt: log index {log_index} out of range"))
}

/// Return whether an authenticated post-Byzantium receipt succeeded.
pub fn receipt_success(receipt: &[u8]) -> Result<bool, String> {
    let mut encoded = receipt;
    if !encoded.is_empty() && encoded[0] < 0xc0 {
        encoded = &encoded[1..];
    }
    let (is_list, mut body) = next_item(&mut encoded)?;
    if !is_list {
        return Err("receipt: not a list".into());
    }
    let (is_list, status) = next_item(&mut body)?;
    if is_list {
        return Err("receipt: status is a list".into());
    }
    match status {
        [] | [0] => Ok(false),
        [1] => Ok(true),
        _ => Err("receipt: invalid status".into()),
    }
}

/// Return the RLP-encoded transaction index used as a receipt-trie key.
pub fn trie_index_key(index: u64) -> Vec<u8> {
    if index == 0 {
        return vec![0x80];
    }
    let bytes = index.to_be_bytes();
    let significant = bytes
        .iter()
        .skip_while(|byte| **byte == 0)
        .copied()
        .collect::<Vec<_>>();
    if significant.len() == 1 && significant[0] < 0x80 {
        significant
    } else {
        let mut encoded = vec![0x80 + significant.len() as u8];
        encoded.extend(significant);
        encoded
    }
}

pub fn verify_receipt_inclusion(header: &Header, receipt: &ReceiptProof) -> Result<(), String> {
    let key = alloy_trie::Nibbles::unpack(trie_index_key(receipt.tx_index));
    alloy_trie::proof::verify_proof(
        header.receipts_root,
        key,
        Some(receipt.value.to_vec()),
        receipt.proof.iter(),
    )
    .map_err(|error| {
        format!(
            "block {}: receipt {} inclusion: {error}",
            header.number, receipt.tx_index
        )
    })
}
