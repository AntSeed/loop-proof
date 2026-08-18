//! Loop predicate: prove that a seller funded a buyer (directly or through a
//! chain of forwarding hops) and that the buyer subsequently settled volume
//! with that same seller on AntSeed.
//!
//! Everything in this crate runs identically natively (for tests) and inside
//! the RISC Zero guest (for proofs). The zkVM boundary lives in methods/guest.

use alloy_consensus::Header;
use alloy_primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};

// ── Pinned rule parameters. Changing any of these changes the guest image ID. ──
pub const PREDICATE_VERSION: u32 = 1;
/// Each hop must forward at least this share (bps) of the previous hop amount.
pub const MIN_FORWARD_BPS: u128 = 9_800;
/// Consecutive hops must land within this many blocks (~1 day on Base).
pub const MAX_HOP_GAP_BLOCKS: u64 = 43_200;
/// Minimum funding amount considered material (1 USDC, 6 decimals).
pub const MIN_FUNDING_RAW: u128 = 1_000_000;

pub const TRANSFER_TOPIC: B256 =
    alloy_primitives::b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
pub const CHANNEL_SETTLED_TOPIC: B256 =
    alloy_primitives::b256!("0b287f37d8bd14ef37f2966734ab387c243cc1a1663616a25a4cc259877736b1");
pub const DEPOSITED_TOPIC: B256 =
    alloy_primitives::b256!("2da466a7b24304f47e87fa2e1e5a81b9831ce54fec19055ce277ca2f39ba42c4");

// ─────────────────────────────── input types ───────────────────────────────

/// One receipt plus its Merkle-Patricia inclusion proof against the block's
/// receipts root. Only the receipts the claim references are carried — the
/// proof path authenticates each one individually, so whole-block receipt
/// sets are unnecessary.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReceiptProof {
    /// Transaction index within the block (the trie key is rlp(tx_index)).
    pub tx_index: u64,
    /// The receipt's trie-value encoding.
    pub value: Bytes,
    /// MPT nodes from root to leaf.
    pub proof: Vec<Bytes>,
}

/// One referenced block: consensus header + inclusion-proven receipts.
#[derive(Clone, Serialize, Deserialize)]
pub struct BlockEvidence {
    pub header: Header,
    pub receipts: Vec<ReceiptProof>,
}

/// Reference to one log: block (by index into `LoopInput::blocks`), receipt
/// (by position in that block's `receipts` list), log (index within receipt).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct LogRef {
    pub block: usize,
    pub receipt: usize,
    pub log: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HopClaim {
    pub transfer: LogRef,
    pub from: Address,
    pub to: Address,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum FundingClaim {
    /// Shape A: USDC Transfer(funder → buyer).
    DirectTransfer { transfer: LogRef },
    /// Shape B: USDC Transfer(funder → Deposits) paired with
    /// Deposited(buyer, amount) in the same receipt.
    DirectDeposit { transfer: LogRef, deposited: LogRef },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoopInput {
    pub chain_id: u64,
    pub usdc: Address,
    pub channels_contract: Address,
    pub deposits_contract: Address,

    pub seller: Address,
    pub buyer: Address,
    /// The wallet that funds the buyer. Equal to `seller` when hops is empty.
    pub funder: Address,

    pub blocks: Vec<BlockEvidence>,
    /// Forwarding chain seller → … → funder. Empty for a direct loop.
    pub hops: Vec<HopClaim>,
    pub funding: FundingClaim,
    /// ChannelSettled(buyer, seller) events, all strictly after the funding block.
    pub settlements: Vec<LogRef>,
}

// ─────────────────────────────── journal ───────────────────────────────

/// Public outputs. On-chain, the registry checks `block_refs` against
/// canonical Base block hashes (checkpointer) and pins the image ID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoopJournal {
    pub predicate_version: u32,
    pub chain_id: u64,
    pub usdc: Address,
    pub channels_contract: Address,
    pub deposits_contract: Address,

    pub seller: Address,
    pub buyer: Address,
    pub funder: Address,
    pub hop_count: u32,
    /// Amount the seller demonstrably routed toward the funder (raw USDC).
    pub seller_outflow_raw: u128,
    /// Amount the funder put into the buyer (raw USDC).
    pub funded_raw: u128,
    /// Buyer→seller settled volume proven AFTER the funding block (raw USDC).
    pub settled_after_funding_raw: u128,
    pub funding_block: u64,

    /// Every block this proof relied on: (number, hash). All must be canonical.
    pub block_refs: Vec<(u64, B256)>,
}

// Solidity mirror of the journal. The guest commits `abi_encode()` of this,
// so `sha256(journalData)` in AntseedWashTradingRegistry equals the receipt's
// journal digest and `abi.decode(journalData, (LoopJournal))` recovers it.
alloy_sol_types::sol! {
    struct SolBlockRef {
        uint64 number;
        bytes32 blockHash;
    }

    struct SolLoopJournal {
        uint32 predicateVersion;
        uint64 chainId;
        address usdc;
        address channels;
        address deposits;
        address seller;
        address buyer;
        address funder;
        uint32 hopCount;
        uint128 sellerOutflowRaw;
        uint128 fundedRaw;
        uint128 settledAfterFundingRaw;
        uint64 fundingBlock;
        SolBlockRef[] blockRefs;
    }
}

impl LoopJournal {
    /// ABI encoding matching Solidity `abi.encode(LoopJournal)`.
    pub fn abi_encode(&self) -> Vec<u8> {
        use alloy_sol_types::SolValue;
        SolLoopJournal {
            predicateVersion: self.predicate_version,
            chainId: self.chain_id,
            usdc: self.usdc,
            channels: self.channels_contract,
            deposits: self.deposits_contract,
            seller: self.seller,
            buyer: self.buyer,
            funder: self.funder,
            hopCount: self.hop_count,
            sellerOutflowRaw: self.seller_outflow_raw,
            fundedRaw: self.funded_raw,
            settledAfterFundingRaw: self.settled_after_funding_raw,
            fundingBlock: self.funding_block,
            blockRefs: self
                .block_refs
                .iter()
                .map(|(number, hash)| SolBlockRef { number: *number, blockHash: *hash })
                .collect(),
        }
        .abi_encode()
    }

    /// Decode the ABI journal bytes back into the native struct.
    pub fn abi_decode(data: &[u8]) -> Result<Self, String> {
        use alloy_sol_types::SolValue;
        let j = SolLoopJournal::abi_decode(data).map_err(|e| format!("journal abi: {e}"))?;
        Ok(LoopJournal {
            predicate_version: j.predicateVersion,
            chain_id: j.chainId,
            usdc: j.usdc,
            channels_contract: j.channels,
            deposits_contract: j.deposits,
            seller: j.seller,
            buyer: j.buyer,
            funder: j.funder,
            hop_count: j.hopCount,
            seller_outflow_raw: j.sellerOutflowRaw,
            funded_raw: j.fundedRaw,
            settled_after_funding_raw: j.settledAfterFundingRaw,
            funding_block: j.fundingBlock,
            block_refs: j.blockRefs.iter().map(|r| (r.number, r.blockHash)).collect(),
        })
    }
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

/// Extract log `log_index` from a receipt's trie-value encoding.
///
/// Layout (legacy and every typed receipt, incl. OP-stack 0x7e deposits):
/// `[type]? ++ rlp([status, cumulativeGas, logsBloom, logs, ...extra])`
/// We only interpret the log list; extra trailing fields are ignored.
pub fn receipt_log(receipt: &[u8], log_index: usize) -> Result<ParsedLog, String> {
    let mut buf = receipt;
    if !buf.is_empty() && buf[0] < 0xc0 {
        // typed receipt envelope: first byte is the tx type
        buf = &buf[1..];
    }
    let (is_list, mut body) = next_item(&mut buf)?;
    if !is_list {
        return Err("receipt: not a list".into());
    }
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

// ─────────────────────────── block authentication ───────────────────────────

/// The receipts trie is keyed by rlp(tx_index) (NOT hashed keys).
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

fn verify_receipt_inclusion(header: &Header, rp: &ReceiptProof) -> Result<(), String> {
    let key = alloy_trie::Nibbles::unpack(trie_index_key(rp.tx_index));
    alloy_trie::proof::verify_proof(
        header.receipts_root,
        key,
        Some(rp.value.to_vec()),
        rp.proof.iter(),
    )
    .map_err(|e| format!("block {}: receipt {} inclusion: {e}", header.number, rp.tx_index))
}

// ─────────────────────────────── the predicate ───────────────────────────────

fn topic_addr(t: &B256) -> Address {
    Address::from_slice(&t.as_slice()[12..])
}

fn word_u128(word: &[u8]) -> Result<u128, String> {
    if word.len() != 32 || !word[..16].iter().all(|b| *b == 0) {
        return Err("abi: u128 overflow".into());
    }
    Ok(u128::from_be_bytes(word[16..32].try_into().unwrap()))
}

struct Resolver<'a> {
    input: &'a LoopInput,
}

impl<'a> Resolver<'a> {
    fn log(&self, r: LogRef) -> Result<(ParsedLog, u64), String> {
        let block = self
            .input
            .blocks
            .get(r.block)
            .ok_or_else(|| format!("block index {} out of range", r.block))?;
        let receipt = block
            .receipts
            .get(r.receipt)
            .ok_or_else(|| format!("receipt position {} out of range", r.receipt))?;
        Ok((receipt_log(&receipt.value, r.log)?, block.header.number))
    }

    /// USDC Transfer log → (from, to, value, block_number)
    fn usdc_transfer(&self, r: LogRef) -> Result<(Address, Address, u128, u64), String> {
        let (log, block) = self.log(r)?;
        if log.address != self.input.usdc {
            return Err("transfer: not the USDC contract".into());
        }
        if log.topics.len() != 3 || log.topics[0] != TRANSFER_TOPIC {
            return Err("transfer: wrong event".into());
        }
        let value = U256::from_be_slice(&log.data);
        let value = u128::try_from(value).map_err(|_| "transfer: value overflow")?;
        Ok((topic_addr(&log.topics[1]), topic_addr(&log.topics[2]), value, block))
    }
}

/// Verify the loop claim. Returns the journal on success; any inconsistency
/// is an error (in the guest, an error aborts and no proof exists).
pub fn verify(input: &LoopInput) -> Result<LoopJournal, String> {
    // 1. Authenticate every block: header hash + per-receipt inclusion proofs.
    let mut block_refs = Vec::with_capacity(input.blocks.len());
    for b in &input.blocks {
        for rp in &b.receipts {
            verify_receipt_inclusion(&b.header, rp)?;
        }
        block_refs.push((b.header.number, b.header.hash_slow()));
    }

    let r = Resolver { input };

    // 2. Forwarding chain: seller → hop₁ → … → funder.
    let mut seller_outflow_raw: u128 = 0;
    if input.hops.is_empty() {
        if input.funder != input.seller {
            return Err("no hops but funder != seller".into());
        }
    } else {
        let mut expected_from = input.seller;
        let mut prev_amount: Option<u128> = None;
        let mut prev_block: Option<u64> = None;
        for (i, hop) in input.hops.iter().enumerate() {
            let (from, to, value, block) = r.usdc_transfer(hop.transfer)?;
            if from != expected_from || from != hop.from || to != hop.to {
                return Err(format!("hop {i}: address chain broken"));
            }
            if let Some(prev) = prev_amount {
                // forwarded share ≥ MIN_FORWARD_BPS of what arrived
                if (value as u128) * 10_000 < prev * MIN_FORWARD_BPS {
                    return Err(format!("hop {i}: forwarded share below threshold"));
                }
            }
            if let Some(pb) = prev_block {
                if block < pb || block - pb > MAX_HOP_GAP_BLOCKS {
                    return Err(format!("hop {i}: outside hop window"));
                }
            }
            if i == 0 {
                seller_outflow_raw = value;
            }
            prev_amount = Some(value);
            prev_block = Some(block);
            expected_from = to;
        }
        if expected_from != input.funder {
            return Err("hop chain does not terminate at funder".into());
        }
    }

    // 3. Funding: funder → buyer (directly, or via a deposit on their behalf).
    let (funded_raw, funding_block) = match &input.funding {
        FundingClaim::DirectTransfer { transfer } => {
            let (from, to, value, block) = r.usdc_transfer(*transfer)?;
            if from != input.funder || to != input.buyer {
                return Err("funding: wrong transfer parties".into());
            }
            (value, block)
        }
        FundingClaim::DirectDeposit { transfer, deposited } => {
            let (from, to, value, block) = r.usdc_transfer(*transfer)?;
            if from != input.funder || to != input.deposits_contract {
                return Err("funding: wrong deposit transfer parties".into());
            }
            if transfer.block != deposited.block || transfer.receipt != deposited.receipt {
                return Err("funding: Deposited not in the same receipt".into());
            }
            let (dep, _) = r.log(*deposited)?;
            if dep.address != input.deposits_contract
                || dep.topics.len() != 2
                || dep.topics[0] != DEPOSITED_TOPIC
                || topic_addr(&dep.topics[1]) != input.buyer
            {
                return Err("funding: Deposited event mismatch".into());
            }
            if word_u128(&dep.data[..32.min(dep.data.len())])? != value {
                return Err("funding: deposit amount != transfer amount".into());
            }
            (value, block)
        }
    };
    if funded_raw < MIN_FUNDING_RAW {
        return Err("funding: below materiality threshold".into());
    }

    // 4. Settlements: ChannelSettled(buyer, seller), strictly after funding.
    let mut settled_after_funding_raw: u128 = 0;
    for (i, sref) in input.settlements.iter().enumerate() {
        let (log, block) = r.log(*sref)?;
        if log.address != input.channels_contract {
            return Err(format!("settlement {i}: not the Channels contract"));
        }
        if log.topics.len() != 4 || log.topics[0] != CHANNEL_SETTLED_TOPIC {
            return Err(format!("settlement {i}: wrong event"));
        }
        if topic_addr(&log.topics[2]) != input.buyer || topic_addr(&log.topics[3]) != input.seller {
            return Err(format!("settlement {i}: wrong buyer/seller"));
        }
        if block <= funding_block {
            return Err(format!("settlement {i}: not after funding"));
        }
        // data: (cumulativeAmount, delta, totalSettled, platformFee, bytes metadata)
        if log.data.len() < 64 {
            return Err(format!("settlement {i}: short data"));
        }
        settled_after_funding_raw = settled_after_funding_raw
            .checked_add(word_u128(&log.data[32..64])?)
            .ok_or("settlement: volume overflow")?;
    }

    Ok(LoopJournal {
        predicate_version: PREDICATE_VERSION,
        chain_id: input.chain_id,
        usdc: input.usdc,
        channels_contract: input.channels_contract,
        deposits_contract: input.deposits_contract,
        seller: input.seller,
        buyer: input.buyer,
        funder: input.funder,
        hop_count: input.hops.len() as u32,
        seller_outflow_raw,
        funded_raw,
        settled_after_funding_raw,
        funding_block,
        block_refs,
    })
}
