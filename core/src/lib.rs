//! Evidence-authentication primitives shared by the wash-trading predicates:
//! receipt/transaction Merkle-Patricia inclusion proofs, receipt log parsing,
//! and account/storage state proofs (the `LEDGER` witness of AIP-4).
//!
//! Everything in this crate runs identically natively (for tests) and inside
//! the zkVM guest (for proofs). No predicate logic lives here.

use alloy_consensus::Header;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::{proof::verify_proof, Nibbles};
use serde::{Deserialize, Serialize};

pub const TRANSFER_TOPIC: B256 =
    alloy_primitives::b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
pub const CHANNEL_SETTLED_TOPIC: B256 =
    alloy_primitives::b256!("0b287f37d8bd14ef37f2966734ab387c243cc1a1663616a25a4cc259877736b1");
pub const DEPOSITED_TOPIC: B256 =
    alloy_primitives::b256!("2da466a7b24304f47e87fa2e1e5a81b9831ce54fec19055ce277ca2f39ba42c4");

/// keccak256(rlp("")) — the root of an empty Merkle-Patricia trie.
pub const EMPTY_TRIE_ROOT: B256 =
    alloy_primitives::b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

// ─────────────────────────────── proof types ───────────────────────────────

/// One receipt plus its Merkle-Patricia inclusion proof against the block's
/// receipts root. Only the receipts the claim references are carried — the
/// proof path authenticates each one individually, so whole-block receipt
/// sets are unnecessary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptProof {
    /// Transaction index within the block (the trie key is rlp(tx_index)).
    pub tx_index: u64,
    /// The receipt's trie-value encoding.
    pub value: Bytes,
    /// MPT nodes from root to leaf.
    pub proof: Vec<Bytes>,
}

/// One transaction plus its inclusion proof against the block's
/// transactions root. Carried wherever an action must be attributed to an
/// address: attribution comes from recovering the transaction signer, never
/// from log topics alone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionProof {
    pub tx_index: u64,
    /// The transaction's trie-value encoding (EIP-2718 envelope).
    pub value: Bytes,
    pub proof: Vec<Bytes>,
}

/// Account + storage proof for one storage slot at one block, against that
/// block's `stateRoot`. The *guest* derives the address and slot from pinned
/// constants — they are deliberately not part of the witness, so a prover
/// cannot point the proof at a different contract or slot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageProof {
    /// MPT nodes proving the account under keccak256(address) in the state
    /// trie (or its absence).
    pub account_proof: Vec<Bytes>,
    /// MPT nodes proving the slot value under keccak256(slot) in the
    /// account's storage trie (or its absence). Empty when the account does
    /// not exist or has an empty storage trie.
    pub storage_proof: Vec<Bytes>,
}

// ─────────────────────────── receipt log parsing ───────────────────────────

#[derive(Clone, Debug)]
pub struct ParsedLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

fn next_item<'a>(buf: &mut &'a [u8]) -> Result<(bool, &'a [u8]), String> {
    let h = alloy_rlp::Header::decode(buf).map_err(|e| format!("rlp: {e}"))?;
    if buf.len() < h.payload_length {
        return Err("rlp: short payload".into());
    }
    let payload = &buf[..h.payload_length];
    *buf = &buf[h.payload_length..];
    Ok((h.list, payload))
}

/// Strip an optional EIP-2718 type byte and return the receipt body fields.
fn receipt_body<'a>(receipt: &'a [u8]) -> Result<&'a [u8], String> {
    let mut buf = receipt;
    if !buf.is_empty() && buf[0] < 0xc0 {
        // typed receipt envelope: first byte is the tx type
        buf = &buf[1..];
    }
    let (is_list, body) = next_item(&mut buf)?;
    if !is_list {
        return Err("receipt: not a list".into());
    }
    Ok(body)
}

/// Whether the receipt's status field is 1 (success). Evidence from reverted
/// receipts is never accepted.
pub fn receipt_success(receipt: &[u8]) -> Result<bool, String> {
    let mut body = receipt_body(receipt)?;
    let (_, status) = next_item(&mut body)?;
    Ok(status == [1u8])
}

/// Extract log `log_index` from a receipt's trie-value encoding.
///
/// Layout (legacy and every typed receipt, incl. OP-stack 0x7e deposits):
/// `[type]? ++ rlp([status, cumulativeGas, logsBloom, logs, ...extra])`
/// We only interpret the log list; extra trailing fields are ignored.
pub fn receipt_log(receipt: &[u8], log_index: usize) -> Result<ParsedLog, String> {
    let mut body = receipt_body(receipt)?;
    // skip status, cumulativeGasUsed, logsBloom
    for _ in 0..3 {
        next_item(&mut body)?;
    }
    let (is_list, mut logs) = next_item(&mut body)?;
    if !is_list {
        return Err("receipt: logs not a list".into());
    }
    let mut i = 0usize;
    while !logs.is_empty() {
        let (is_list, mut log) = next_item(&mut logs)?;
        if !is_list {
            return Err("receipt: log not a list".into());
        }
        if i == log_index {
            let (_, addr) = next_item(&mut log)?;
            if addr.len() != 20 {
                return Err("log: bad address".into());
            }
            let (is_list, mut topics_buf) = next_item(&mut log)?;
            if !is_list {
                return Err("log: topics not a list".into());
            }
            let mut topics = Vec::new();
            while !topics_buf.is_empty() {
                let (_, t) = next_item(&mut topics_buf)?;
                if t.len() != 32 {
                    return Err("log: bad topic".into());
                }
                topics.push(B256::from_slice(t));
            }
            let (_, data) = next_item(&mut log)?;
            return Ok(ParsedLog {
                address: Address::from_slice(addr),
                topics,
                data: data.to_vec(),
            });
        }
        i += 1;
    }
    Err(format!("receipt: log index {log_index} out of range"))
}

// ─────────────────────────── inclusion proofs ───────────────────────────

/// The receipts and transactions tries are keyed by rlp(tx_index) (NOT
/// hashed keys).
pub fn trie_index_key(i: u64) -> Vec<u8> {
    if i == 0 {
        return vec![0x80];
    }
    let be = i.to_be_bytes();
    let sig: Vec<u8> = be.iter().skip_while(|b| **b == 0).cloned().collect();
    if sig.len() == 1 && sig[0] < 0x80 {
        sig
    } else {
        let mut out = vec![0x80 + sig.len() as u8];
        out.extend(sig);
        out
    }
}

pub fn verify_receipt_inclusion(header: &Header, rp: &ReceiptProof) -> Result<(), String> {
    let key = Nibbles::unpack(trie_index_key(rp.tx_index));
    verify_proof(
        header.receipts_root,
        key,
        Some(rp.value.to_vec()),
        rp.proof.iter(),
    )
    .map_err(|e| {
        format!(
            "block {}: receipt {} inclusion: {e}",
            header.number, rp.tx_index
        )
    })
}

pub fn verify_transaction_inclusion(header: &Header, tp: &TransactionProof) -> Result<(), String> {
    let key = Nibbles::unpack(trie_index_key(tp.tx_index));
    verify_proof(
        header.transactions_root,
        key,
        Some(tp.value.to_vec()),
        tp.proof.iter(),
    )
    .map_err(|e| {
        format!(
            "block {}: transaction {} inclusion: {e}",
            header.number, tp.tx_index
        )
    })
}

// ─────────────────────────── state proofs ───────────────────────────

/// Verify `proof` for `slot` of account `address` against `state_root` and
/// return the slot's value. Zero-valued (absent) slots and absent accounts
/// verify as exclusion proofs and return zero — a predicate must be able to
/// prove that a counter *is* zero, not merely fail to prove it non-zero.
pub fn verify_storage_value(
    state_root: B256,
    address: Address,
    slot: B256,
    proof: &StorageProof,
) -> Result<U256, String> {
    let account_key = Nibbles::unpack(keccak256(address));
    let account_rlp = mpt_get(state_root, account_key, &proof.account_proof)
        .map_err(|e| format!("account {address}: {e}"))?;
    let storage_root = match account_rlp {
        None => {
            // Account does not exist — every slot is zero.
            if !proof.storage_proof.is_empty() {
                return Err(format!(
                    "account {address}: storage proof for absent account"
                ));
            }
            return Ok(U256::ZERO);
        }
        Some(rlp) => {
            decode_account_storage_root(&rlp).map_err(|e| format!("account {address}: {e}"))?
        }
    };
    if storage_root == EMPTY_TRIE_ROOT {
        if !proof.storage_proof.is_empty() {
            return Err(format!("account {address}: storage proof for empty trie"));
        }
        return Ok(U256::ZERO);
    }
    let slot_key = Nibbles::unpack(keccak256(slot));
    match mpt_get(storage_root, slot_key, &proof.storage_proof)
        .map_err(|e| format!("account {address} slot {slot}: {e}"))?
    {
        None => Ok(U256::ZERO),
        Some(value_rlp) => {
            let mut buf = value_rlp.as_slice();
            let (is_list, payload) = next_item(&mut buf)?;
            if is_list || !buf.is_empty() || payload.len() > 32 {
                return Err(format!("account {address} slot {slot}: bad value encoding"));
            }
            Ok(U256::from_be_slice(payload))
        }
    }
}

/// Inclusion-or-exclusion MPT lookup: `Ok(Some(value))` when the key is
/// present, `Ok(None)` when the proof shows it absent, `Err` when the proof
/// is inconsistent with the root.
fn mpt_get(root: B256, key: Nibbles, proof: &[Bytes]) -> Result<Option<Vec<u8>>, String> {
    // Try exclusion first: a valid exclusion proof means the key is absent.
    if verify_proof(root, key.clone(), None, proof.iter()).is_ok() {
        return Ok(None);
    }
    // Otherwise the proof must be a valid inclusion proof; recover the leaf
    // value by walking the last node.
    let value = leaf_value(proof)?;
    verify_proof(root, key, Some(value.clone()), proof.iter())
        .map_err(|e| format!("inclusion: {e}"))?;
    Ok(Some(value))
}

/// Extract the value carried by the final (leaf) node of an MPT proof; the
/// subsequent inclusion verification binds it to the key.
fn leaf_value(proof: &[Bytes]) -> Result<Vec<u8>, String> {
    let last = proof.last().ok_or("empty proof")?;
    let mut buf = last.as_ref();
    let (is_list, mut node) = next_item(&mut buf)?;
    if !is_list {
        return Err("proof node: not a list".into());
    }
    let mut items: Vec<&[u8]> = Vec::new();
    while !node.is_empty() {
        let (_, payload) = next_item(&mut node)?;
        items.push(payload);
    }
    match items.len() {
        2 => {
            // leaf or extension; for an inclusion proof of this key the last
            // node must be the leaf carrying the value.
            let path = items[0];
            if path.is_empty() {
                return Err("proof node: empty path".into());
            }
            let flag = path[0] >> 4;
            if flag != 2 && flag != 3 {
                return Err("proof node: last node is not a leaf".into());
            }
            Ok(items[1].to_vec())
        }
        17 => {
            // branch node: value sits in the 17th item only when the key
            // terminates here (never the case for fixed-length keys we use).
            Err("proof node: key terminates in a branch".into())
        }
        n => Err(format!("proof node: {n} items")),
    }
}

/// Decode `rlp([nonce, balance, storageRoot, codeHash])` → storageRoot.
fn decode_account_storage_root(account_rlp: &[u8]) -> Result<B256, String> {
    let mut buf = account_rlp;
    let (is_list, mut body) = next_item(&mut buf)?;
    if !is_list {
        return Err("account: not a list".into());
    }
    next_item(&mut body)?; // nonce
    next_item(&mut body)?; // balance
    let (_, storage_root) = next_item(&mut body)?;
    if storage_root.len() != 32 {
        return Err("account: bad storage root".into());
    }
    Ok(B256::from_slice(storage_root))
}

// ─────────────────────────── slot derivation ───────────────────────────

/// Storage slot of `mapping(uint256 => V)` entry: keccak256(key ‖ base).
pub fn mapping_slot_u256(key: U256, base: u64) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&key.to_be_bytes::<32>());
    buf[32..64].copy_from_slice(&U256::from(base).to_be_bytes::<32>());
    keccak256(buf)
}

/// Storage slot of `mapping(address => V)` entry: keccak256(pad32(key) ‖ base).
pub fn mapping_slot_address(key: Address, base: u64) -> B256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(key.as_slice());
    buf[32..64].copy_from_slice(&U256::from(base).to_be_bytes::<32>());
    keccak256(buf)
}

/// `slot + offset` for struct fields behind a mapping value.
pub fn slot_offset(slot: B256, offset: u64) -> B256 {
    let v = U256::from_be_bytes(slot.0) + U256::from(offset);
    B256::from(v.to_be_bytes::<32>())
}

// ─────────────────────────── tiny RLP encoder ───────────────────────────

fn rlp_len_prefix(base: u8, len: usize) -> Vec<u8> {
    if len <= 55 {
        vec![base + len as u8]
    } else {
        let be = (len as u64).to_be_bytes();
        let sig: Vec<u8> = be.iter().skip_while(|b| **b == 0).cloned().collect();
        let mut out = vec![base + 55 + sig.len() as u8];
        out.extend(sig);
        out
    }
}

pub fn rlp_bytes(payload: &[u8]) -> Vec<u8> {
    if payload.len() == 1 && payload[0] < 0x80 {
        payload.to_vec()
    } else {
        let mut out = rlp_len_prefix(0x80, payload.len());
        out.extend_from_slice(payload);
        out
    }
}

pub fn rlp_uint(v: u128) -> Vec<u8> {
    let be = v.to_be_bytes();
    let sig: Vec<u8> = be.iter().skip_while(|b| **b == 0).cloned().collect();
    rlp_bytes(&sig)
}

pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = rlp_len_prefix(0xc0, payload.len());
    out.extend(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256, hex, U256};
    use alloy_trie::{proof::ProofRetainer, HashBuilder};

    #[test]
    fn event_topics_match_signatures() {
        assert_eq!(
            keccak256("Transfer(address,address,uint256)"),
            TRANSFER_TOPIC
        );
        assert_eq!(keccak256("Deposited(address,uint256)"), DEPOSITED_TOPIC);
        assert_eq!(
            keccak256(
                "ChannelSettled(bytes32,address,address,uint128,uint128,uint128,uint256,bytes)"
            ),
            CHANNEL_SETTLED_TOPIC
        );
    }

    #[test]
    fn mapping_slots_match_solidity_layout() {
        // cast keccak $(cast abi-encode "f(uint256,uint256)" 53008 11)
        assert_eq!(
            mapping_slot_u256(U256::from(53008u64), 11),
            b256!("1244a5b59bdc1bb02e7545618c6786acbe94a376aac8fbeb8f429267f2df438b")
        );
        // cast keccak $(cast abi-encode "f(address,uint256)" 0x0329c5d3920e301740f78d6e17b8d1a11cca9b2c 4)
        let a = address!("0329c5d3920e301740f78d6e17b8d1a11cca9b2c");
        assert_eq!(
            mapping_slot_address(a, 4),
            b256!("013add9faeed6aa4207ae7398064c1f23724f4a190e7ef6ff1f1f9c9d3edea72")
        );
        assert_ne!(mapping_slot_address(a, 4), mapping_slot_address(a, 9));
        assert_eq!(
            slot_offset(mapping_slot_u256(U256::from(7u64), 11), 0),
            mapping_slot_u256(U256::from(7u64), 11)
        );
        assert_eq!(
            U256::from_be_bytes(slot_offset(mapping_slot_u256(U256::from(7u64), 11), 1).0),
            U256::from_be_bytes(mapping_slot_u256(U256::from(7u64), 11).0) + U256::from(1u64)
        );
    }

    fn storage_trie(entries: &[(B256, U256)]) -> (B256, Vec<(B256, Vec<Bytes>)>) {
        let mut leaves: Vec<(Nibbles, Vec<u8>)> = entries
            .iter()
            .map(|(slot, value)| {
                let be = value.to_be_bytes::<32>();
                let sig: Vec<u8> = be.iter().skip_while(|b| **b == 0).cloned().collect();
                (Nibbles::unpack(keccak256(slot)), rlp_bytes(&sig))
            })
            .collect();
        leaves.sort_by(|a, b| a.0.cmp(&b.0));
        let keys: Vec<Nibbles> = leaves.iter().map(|(k, _)| k.clone()).collect();
        let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(keys));
        for (k, v) in &leaves {
            hb.add_leaf(k.clone(), v);
        }
        let root = hb.root();
        let nodes = hb.take_proof_nodes();
        let proofs = entries
            .iter()
            .map(|(slot, _)| {
                let key = Nibbles::unpack(keccak256(slot));
                (
                    *slot,
                    nodes
                        .matching_nodes_sorted(&key)
                        .into_iter()
                        .map(|(_, n)| n)
                        .collect::<Vec<Bytes>>(),
                )
            })
            .collect();
        (root, proofs)
    }

    #[test]
    fn storage_value_roundtrip_through_account_and_storage_tries() {
        let contract = address!("ba66d3b4fbcf472f6f11d6f9f96aace96516f09d");
        let slot = mapping_slot_u256(U256::from(53008u64), 11);
        let value = U256::from(47_390_485_481u64);
        let (storage_root, mut storage_proofs) = storage_trie(&[(slot, value)]);

        // account leaf: rlp([nonce, balance, storageRoot, codeHash])
        let account_rlp = rlp_list(&[
            rlp_uint(1),
            rlp_uint(0),
            rlp_bytes(storage_root.as_slice()),
            rlp_bytes(&[0u8; 32]),
        ]);

        let account_key = Nibbles::unpack(keccak256(contract));
        let mut hb = HashBuilder::default()
            .with_proof_retainer(ProofRetainer::new(vec![account_key.clone()]));
        hb.add_leaf(account_key.clone(), &account_rlp);
        let state_root = hb.root();
        let account_proof: Vec<Bytes> = hb
            .take_proof_nodes()
            .matching_nodes_sorted(&account_key)
            .into_iter()
            .map(|(_, n)| n)
            .collect();

        let proof = StorageProof {
            account_proof: account_proof.clone(),
            storage_proof: storage_proofs.remove(0).1,
        };
        assert_eq!(
            verify_storage_value(state_root, contract, slot, &proof).unwrap(),
            value
        );

        // Wrong slot → exclusion → zero.
        let other = mapping_slot_u256(U256::from(1u64), 11);
        let excl = StorageProof {
            account_proof,
            storage_proof: proof.storage_proof.clone(),
        };
        // The inclusion nodes for `slot` also prove `other`'s absence when the
        // paths diverge at the root; if they do not, verification must fail —
        // either way, the value can never be attributed to the wrong slot.
        match verify_storage_value(state_root, contract, other, &excl) {
            Ok(v) => assert_eq!(v, U256::ZERO),
            Err(_) => {}
        }

        // Tampered state root → error, never zero.
        assert!(verify_storage_value(B256::ZERO, contract, slot, &proof).is_err());
    }

    #[test]
    fn absent_account_reads_zero_only_with_consistent_proof() {
        // Single-account trie; a different address is provably absent.
        let present = address!("0000000000000000000000000000000000000001");
        let absent = address!("00000000000000000000000000000000000000aa");
        let account_rlp = rlp_list(&[
            rlp_uint(1),
            rlp_uint(0),
            rlp_bytes(EMPTY_TRIE_ROOT.as_slice()),
            rlp_bytes(&[0u8; 32]),
        ]);
        let key = Nibbles::unpack(keccak256(present));
        let mut hb =
            HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![key.clone()]));
        hb.add_leaf(key.clone(), &account_rlp);
        let state_root = hb.root();
        let nodes: Vec<Bytes> = hb
            .take_proof_nodes()
            .matching_nodes_sorted(&key)
            .into_iter()
            .map(|(_, n)| n)
            .collect();

        // Present account with empty storage: every slot is zero, no storage proof.
        let proof = StorageProof {
            account_proof: nodes.clone(),
            storage_proof: vec![],
        };
        assert_eq!(
            verify_storage_value(state_root, present, B256::ZERO, &proof).unwrap(),
            U256::ZERO
        );
        // The same nodes prove the absent account excluded (single-leaf trie).
        assert_eq!(
            verify_storage_value(state_root, absent, B256::ZERO, &proof).unwrap(),
            U256::ZERO
        );
        // Absent account may not carry a storage proof.
        let bad = StorageProof {
            account_proof: nodes,
            storage_proof: vec![Bytes::from(hex!("c0"))],
        };
        assert!(verify_storage_value(state_root, absent, B256::ZERO, &bad).is_err());
    }

    fn typed_receipt(status: u128) -> Vec<u8> {
        // 0x02 ++ rlp([status, cumulativeGas, bloom, []])
        let body = rlp_list(&[
            rlp_uint(status),
            rlp_uint(1),
            rlp_bytes(&[0u8; 256]),
            rlp_list(&[]),
        ]);
        [vec![0x02], body].concat()
    }

    #[test]
    fn receipt_success_reads_the_status_field() {
        assert!(receipt_success(&typed_receipt(1)).unwrap());
        assert!(!receipt_success(&typed_receipt(0)).unwrap());
    }
}
