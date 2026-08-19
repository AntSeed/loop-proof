//! Seller-penalty predicate: prove that a seller is linked to a funder, that
//! the funder funded a cohort of distinct buyers, and that those buyers later
//! settled material volume with the same seller on AntSeed.
//!
//! Everything in this crate runs identically natively (for tests) and inside
//! the RISC Zero guest (for proofs). The zkVM boundary lives in methods/guest.

use alloy_consensus::Header;
use alloy_primitives::{address, Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

// ── Pinned rule parameters. Changing any of these changes the guest image ID. ──
pub const PREDICATE_VERSION: u32 = 2;
pub const BASE_CHAIN_ID: u64 = 8_453;
pub const USDC_ADDRESS: Address = address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
pub const CHANNELS_ADDRESS: Address = address!("BA66d3b4fbCf472F6F11D6F9F96aaCE96516F09d");
pub const DEPOSITS_ADDRESS: Address = address!("0F7a3a8f4Da01637d1202bb5443fcF7F88F99fD2");
pub const PENALTY_BPS: u16 = 9_000;
pub const MINIMUM_COHORT_BUYERS: usize = 3;
/// Minimum authenticated post-funding settlement volume (1,000 USDC).
pub const MINIMUM_COHORT_VOLUME_RAW: u128 = 1_000_000_000;
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptProof {
    /// Transaction index within the block (the trie key is rlp(tx_index)).
    pub tx_index: u64,
    /// The receipt's trie-value encoding.
    pub value: Bytes,
    /// MPT nodes from root to leaf.
    pub proof: Vec<Bytes>,
}

/// One referenced block: consensus header + inclusion-proven receipts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockEvidence {
    pub header: Header,
    pub receipts: Vec<ReceiptProof>,
}

/// Reference to one log: block (by index into `SellerPenaltyInput::blocks`), receipt
/// (by position in that block's `receipts` list), log (index within receipt).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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
pub struct BuyerClaim {
    pub buyer: Address,
    pub funding: FundingClaim,
    /// ChannelSettled(buyer, seller) events, all strictly after funding.
    pub settlements: Vec<LogRef>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SellerPenaltyInput {
    pub chain_id: u64,
    pub usdc: Address,
    pub channels_contract: Address,
    pub deposits_contract: Address,

    pub seller: Address,
    /// The wallet that funds the buyer. Equal to `seller` when hops is empty.
    pub funder: Address,

    pub blocks: Vec<BlockEvidence>,
    /// Forwarding chain seller → … → funder. Empty for a direct loop.
    pub hops: Vec<HopClaim>,
    pub buyers: Vec<BuyerClaim>,
}

// ─────────────────────────────── journal ───────────────────────────────

/// Public outputs. On-chain, the registry checks `block_refs` against
/// canonical finalized Base block hashes and pins the image ID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SellerPenaltyJournal {
    pub predicate_version: u32,
    pub chain_id: u64,
    pub usdc: Address,
    pub channels_contract: Address,
    pub deposits_contract: Address,

    pub seller: Address,
    pub funder: Address,
    pub linked_buyer_count: u32,
    pub hop_count: u32,
    pub penalty_bps: u16,
    /// Amount the seller demonstrably routed toward the funder (raw USDC).
    pub seller_outflow_raw: u128,
    /// Total amount the funder put into the proven buyers (raw USDC).
    pub total_funded_raw: u128,
    /// Proven buyer→seller volume strictly after each buyer's funding (raw USDC).
    pub suspicious_volume_raw: u128,
    pub earliest_funding_block: u64,
    pub latest_settlement_block: u64,

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

    struct SolSellerPenaltyJournal {
        uint32 predicateVersion;
        uint64 chainId;
        address usdc;
        address channels;
        address deposits;
        address seller;
        address funder;
        uint32 linkedBuyerCount;
        uint32 hopCount;
        uint16 penaltyBps;
        uint128 sellerOutflowRaw;
        uint128 totalFundedRaw;
        uint128 suspiciousVolumeRaw;
        uint64 earliestFundingBlock;
        uint64 latestSettlementBlock;
        SolBlockRef[] blockRefs;
    }
}

impl SellerPenaltyJournal {
    /// ABI encoding matching Solidity `abi.encode(SellerPenaltyJournal)`.
    pub fn abi_encode(&self) -> Vec<u8> {
        use alloy_sol_types::SolValue;
        SolSellerPenaltyJournal {
            predicateVersion: self.predicate_version,
            chainId: self.chain_id,
            usdc: self.usdc,
            channels: self.channels_contract,
            deposits: self.deposits_contract,
            seller: self.seller,
            funder: self.funder,
            linkedBuyerCount: self.linked_buyer_count,
            hopCount: self.hop_count,
            penaltyBps: self.penalty_bps,
            sellerOutflowRaw: self.seller_outflow_raw,
            totalFundedRaw: self.total_funded_raw,
            suspiciousVolumeRaw: self.suspicious_volume_raw,
            earliestFundingBlock: self.earliest_funding_block,
            latestSettlementBlock: self.latest_settlement_block,
            blockRefs: self
                .block_refs
                .iter()
                .map(|(number, hash)| SolBlockRef {
                    number: *number,
                    blockHash: *hash,
                })
                .collect(),
        }
        .abi_encode()
    }

    /// Decode the ABI journal bytes back into the native struct.
    pub fn abi_decode(data: &[u8]) -> Result<Self, String> {
        use alloy_sol_types::SolValue;
        let j =
            SolSellerPenaltyJournal::abi_decode(data).map_err(|e| format!("journal abi: {e}"))?;
        Ok(SellerPenaltyJournal {
            predicate_version: j.predicateVersion,
            chain_id: j.chainId,
            usdc: j.usdc,
            channels_contract: j.channels,
            deposits_contract: j.deposits,
            seller: j.seller,
            funder: j.funder,
            linked_buyer_count: j.linkedBuyerCount,
            hop_count: j.hopCount,
            penalty_bps: j.penaltyBps,
            seller_outflow_raw: j.sellerOutflowRaw,
            total_funded_raw: j.totalFundedRaw,
            suspicious_volume_raw: j.suspiciousVolumeRaw,
            earliest_funding_block: j.earliestFundingBlock,
            latest_settlement_block: j.latestSettlementBlock,
            block_refs: j
                .blockRefs
                .iter()
                .map(|r| (r.number, r.blockHash))
                .collect(),
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

pub fn verify_receipt_inclusion(header: &Header, rp: &ReceiptProof) -> Result<(), String> {
    let key = alloy_trie::Nibbles::unpack(trie_index_key(rp.tx_index));
    alloy_trie::proof::verify_proof(
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
    input: &'a SellerPenaltyInput,
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
        Ok((
            topic_addr(&log.topics[1]),
            topic_addr(&log.topics[2]),
            value,
            block,
        ))
    }
}

/// Verify the seller-penalty claim. Returns the journal on success; any inconsistency
/// is an error (in the guest, an error aborts and no proof exists).
pub fn verify(input: &SellerPenaltyInput) -> Result<SellerPenaltyJournal, String> {
    if input.chain_id != BASE_CHAIN_ID
        || input.usdc != USDC_ADDRESS
        || input.channels_contract != CHANNELS_ADDRESS
        || input.deposits_contract != DEPOSITS_ADDRESS
    {
        return Err("unrecognized chain or contract configuration".into());
    }
    if input.buyers.len() < MINIMUM_COHORT_BUYERS {
        return Err("cohort: fewer than three buyers".into());
    }

    // 1. Authenticate every block: header hash + per-receipt inclusion proofs.
    let mut block_refs = Vec::with_capacity(input.blocks.len());
    let mut block_numbers = BTreeSet::new();
    for b in &input.blocks {
        if !block_numbers.insert(b.header.number) {
            return Err(format!("duplicate block evidence: {}", b.header.number));
        }
        for rp in &b.receipts {
            verify_receipt_inclusion(&b.header, rp)?;
        }
        block_refs.push((b.header.number, b.header.hash_slow()));
    }
    block_refs.sort_unstable_by_key(|(number, _)| *number);

    let r = Resolver { input };

    // 2. Forwarding chain: seller → hop₁ → … → funder.
    let mut seller_outflow_raw: u128 = 0;
    let mut latest_hop_block = None;
    let mut used_logs = BTreeSet::new();
    if input.hops.is_empty() {
        if input.funder != input.seller {
            return Err("no hops but funder != seller".into());
        }
    } else {
        let mut expected_from = input.seller;
        let mut prev_amount: Option<u128> = None;
        let mut prev_block: Option<u64> = None;
        for (i, hop) in input.hops.iter().enumerate() {
            claim_log_once(input, hop.transfer, &mut used_logs)?;
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
            latest_hop_block = Some(block);
            expected_from = to;
        }
        if expected_from != input.funder {
            return Err("hop chain does not terminate at funder".into());
        }
    }

    // 3. Authenticate each distinct buyer's funding and post-funding settlements.
    let mut distinct_buyers = BTreeSet::new();
    let mut total_funded_raw = 0u128;
    let mut suspicious_volume_raw = 0u128;
    let mut earliest_funding_block = u64::MAX;
    let mut latest_settlement_block = 0u64;

    for (buyer_index, claim) in input.buyers.iter().enumerate() {
        if !distinct_buyers.insert(claim.buyer) {
            return Err(format!("buyer {buyer_index}: duplicate buyer"));
        }
        if claim.settlements.is_empty() {
            return Err(format!("buyer {buyer_index}: no settlements"));
        }

        let (funded_raw, funding_block) = match &claim.funding {
            FundingClaim::DirectTransfer { transfer } => {
                claim_log_once(input, *transfer, &mut used_logs)?;
                let (from, to, value, block) = r.usdc_transfer(*transfer)?;
                if from != input.funder || to != claim.buyer {
                    return Err(format!("buyer {buyer_index}: wrong funding parties"));
                }
                (value, block)
            }
            FundingClaim::DirectDeposit {
                transfer,
                deposited,
            } => {
                claim_log_once(input, *transfer, &mut used_logs)?;
                claim_log_once(input, *deposited, &mut used_logs)?;
                let (from, to, value, block) = r.usdc_transfer(*transfer)?;
                if from != input.funder || to != input.deposits_contract {
                    return Err(format!(
                        "buyer {buyer_index}: wrong deposit transfer parties"
                    ));
                }
                if transfer.block != deposited.block || transfer.receipt != deposited.receipt {
                    return Err(format!(
                        "buyer {buyer_index}: Deposited not in funding receipt"
                    ));
                }
                let (deposited_log, _) = r.log(*deposited)?;
                if deposited_log.address != input.deposits_contract
                    || deposited_log.topics.len() != 2
                    || deposited_log.topics[0] != DEPOSITED_TOPIC
                    || topic_addr(&deposited_log.topics[1]) != claim.buyer
                {
                    return Err(format!("buyer {buyer_index}: Deposited event mismatch"));
                }
                if word_u128(&deposited_log.data[..32.min(deposited_log.data.len())])? != value {
                    return Err(format!("buyer {buyer_index}: deposit amount mismatch"));
                }
                (value, block)
            }
        };
        if funded_raw < MIN_FUNDING_RAW {
            return Err(format!("buyer {buyer_index}: funding below threshold"));
        }
        if latest_hop_block.is_some_and(|hop_block| funding_block < hop_block) {
            return Err(format!(
                "buyer {buyer_index}: funding predates seller-funder path"
            ));
        }
        total_funded_raw = total_funded_raw
            .checked_add(funded_raw)
            .ok_or("funding: total overflow")?;
        earliest_funding_block = earliest_funding_block.min(funding_block);

        for (settlement_index, settlement_ref) in claim.settlements.iter().enumerate() {
            claim_log_once(input, *settlement_ref, &mut used_logs)?;
            let (log, block) = r.log(*settlement_ref)?;
            if log.address != input.channels_contract {
                return Err(format!(
                    "buyer {buyer_index} settlement {settlement_index}: wrong contract"
                ));
            }
            if log.topics.len() != 4 || log.topics[0] != CHANNEL_SETTLED_TOPIC {
                return Err(format!(
                    "buyer {buyer_index} settlement {settlement_index}: wrong event"
                ));
            }
            if topic_addr(&log.topics[2]) != claim.buyer
                || topic_addr(&log.topics[3]) != input.seller
            {
                return Err(format!(
                    "buyer {buyer_index} settlement {settlement_index}: wrong parties"
                ));
            }
            if block <= funding_block {
                return Err(format!(
                    "buyer {buyer_index} settlement {settlement_index}: not after funding"
                ));
            }
            if log.data.len() < 64 {
                return Err(format!(
                    "buyer {buyer_index} settlement {settlement_index}: short data"
                ));
            }
            suspicious_volume_raw = suspicious_volume_raw
                .checked_add(word_u128(&log.data[32..64])?)
                .ok_or("settlement: volume overflow")?;
            latest_settlement_block = latest_settlement_block.max(block);
        }
    }
    if suspicious_volume_raw < MINIMUM_COHORT_VOLUME_RAW {
        return Err("cohort: suspicious volume below 1,000 USDC".into());
    }
    let linked_buyer_count =
        u32::try_from(distinct_buyers.len()).map_err(|_| "cohort: buyer count overflow")?;
    let hop_count = u32::try_from(input.hops.len()).map_err(|_| "hop count overflow")?;

    Ok(SellerPenaltyJournal {
        predicate_version: PREDICATE_VERSION,
        chain_id: input.chain_id,
        usdc: input.usdc,
        channels_contract: input.channels_contract,
        deposits_contract: input.deposits_contract,
        seller: input.seller,
        funder: input.funder,
        linked_buyer_count,
        hop_count,
        penalty_bps: PENALTY_BPS,
        seller_outflow_raw,
        total_funded_raw,
        suspicious_volume_raw,
        earliest_funding_block,
        latest_settlement_block,
        block_refs,
    })
}

fn claim_log_once(
    input: &SellerPenaltyInput,
    log_ref: LogRef,
    used_logs: &mut BTreeSet<(u64, u64, usize)>,
) -> Result<(), String> {
    let block = input
        .blocks
        .get(log_ref.block)
        .ok_or_else(|| format!("block index {} out of range", log_ref.block))?;
    let receipt = block
        .receipts
        .get(log_ref.receipt)
        .ok_or_else(|| format!("receipt position {} out of range", log_ref.receipt))?;
    if !used_logs.insert((block.header.number, receipt.tx_index, log_ref.log)) {
        return Err("duplicate log reference".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};

    const SELLER: Address = address!("0000000000000000000000000000000000000051");
    const BUYER_1: Address = address!("00000000000000000000000000000000000000B1");
    const BUYER_2: Address = address!("00000000000000000000000000000000000000B2");
    const BUYER_3: Address = address!("00000000000000000000000000000000000000B3");

    #[test]
    fn three_buyers_and_exact_volume_pass() {
        let journal = verify(&valid_input()).unwrap();
        assert_eq!(journal.linked_buyer_count, 3);
        assert_eq!(journal.suspicious_volume_raw, MINIMUM_COHORT_VOLUME_RAW);
        assert_eq!(journal.penalty_bps, PENALTY_BPS);
    }

    #[test]
    fn two_buyers_fail() {
        let mut input = valid_input();
        input.buyers.pop();
        assert!(verify(&input).unwrap_err().contains("fewer than three"));
    }

    #[test]
    fn duplicate_buyer_fails() {
        let mut input = valid_input();
        input.buyers[2].buyer = input.buyers[1].buyer;
        assert!(verify(&input).unwrap_err().contains("duplicate buyer"));
    }

    #[test]
    fn volume_one_unit_below_threshold_fails() {
        let mut input = valid_input();
        input.blocks[5] = settlement_block(31, BUYER_3, 299_999_999);
        assert!(verify(&input).unwrap_err().contains("below 1,000"));
    }

    #[test]
    fn settlement_before_funding_fails() {
        let mut input = valid_input();
        input.blocks[1].header.number = 9;
        assert!(verify(&input).unwrap_err().contains("not after funding"));
    }

    #[test]
    fn duplicate_log_reference_fails() {
        let mut input = valid_input();
        input.buyers[1].funding = input.buyers[0].funding.clone();
        assert!(verify(&input).unwrap_err().contains("duplicate log"));
    }

    #[test]
    fn wrong_pinned_contract_fails() {
        let mut input = valid_input();
        input.usdc = Address::ZERO;
        assert!(verify(&input).unwrap_err().contains("unrecognized"));
    }

    #[test]
    fn journal_abi_round_trip() {
        let journal = verify(&valid_input()).unwrap();
        let decoded = SellerPenaltyJournal::abi_decode(&journal.abi_encode()).unwrap();
        assert_eq!(decoded.suspicious_volume_raw, journal.suspicious_volume_raw);
        assert_eq!(decoded.block_refs, journal.block_refs);
    }

    fn valid_input() -> SellerPenaltyInput {
        SellerPenaltyInput {
            chain_id: BASE_CHAIN_ID,
            usdc: USDC_ADDRESS,
            channels_contract: CHANNELS_ADDRESS,
            deposits_contract: DEPOSITS_ADDRESS,
            seller: SELLER,
            funder: SELLER,
            blocks: vec![
                funding_block(10, BUYER_1),
                settlement_block(11, BUYER_1, 400_000_000),
                funding_block(20, BUYER_2),
                settlement_block(21, BUYER_2, 300_000_000),
                funding_block(30, BUYER_3),
                settlement_block(31, BUYER_3, 300_000_000),
            ],
            hops: vec![],
            buyers: vec![
                buyer_claim(BUYER_1, 0, 1),
                buyer_claim(BUYER_2, 2, 3),
                buyer_claim(BUYER_3, 4, 5),
            ],
        }
    }

    fn buyer_claim(buyer: Address, funding_block: usize, settlement_block: usize) -> BuyerClaim {
        BuyerClaim {
            buyer,
            funding: FundingClaim::DirectTransfer {
                transfer: LogRef {
                    block: funding_block,
                    receipt: 0,
                    log: 0,
                },
            },
            settlements: vec![LogRef {
                block: settlement_block,
                receipt: 0,
                log: 0,
            }],
        }
    }

    fn funding_block(number: u64, buyer: Address) -> BlockEvidence {
        let mut value = [0u8; 32];
        value[16..].copy_from_slice(&MIN_FUNDING_RAW.to_be_bytes());
        block_with_log(
            number,
            USDC_ADDRESS,
            vec![TRANSFER_TOPIC, address_topic(SELLER), address_topic(buyer)],
            &value,
        )
    }

    fn settlement_block(number: u64, buyer: Address, delta: u128) -> BlockEvidence {
        let mut data = [0u8; 64];
        data[48..].copy_from_slice(&delta.to_be_bytes());
        block_with_log(
            number,
            CHANNELS_ADDRESS,
            vec![
                CHANNEL_SETTLED_TOPIC,
                B256::ZERO,
                address_topic(buyer),
                address_topic(SELLER),
            ],
            &data,
        )
    }

    fn block_with_log(
        number: u64,
        log_address: Address,
        topics: Vec<B256>,
        data: &[u8],
    ) -> BlockEvidence {
        let log = rlp_list(&[
            rlp_bytes(log_address.as_slice()),
            rlp_list(
                &topics
                    .iter()
                    .map(|topic| rlp_bytes(topic.as_slice()))
                    .collect::<Vec<_>>(),
            ),
            rlp_bytes(data),
        ]);
        let receipt = Bytes::from(rlp_list(&[
            rlp_uint(1),
            rlp_uint(1),
            rlp_bytes(&[0u8; 256]),
            rlp_list(&[log]),
        ]));
        let key = Nibbles::unpack(trie_index_key(0));
        let mut builder =
            HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![key.clone()]));
        builder.add_leaf(key.clone(), receipt.as_ref());
        let receipts_root = builder.root();
        let proof = builder
            .take_proof_nodes()
            .matching_nodes_sorted(&key)
            .into_iter()
            .map(|(_, node)| node)
            .collect();
        BlockEvidence {
            header: Header {
                number,
                receipts_root,
                ..Default::default()
            },
            receipts: vec![ReceiptProof {
                tx_index: 0,
                value: receipt,
                proof,
            }],
        }
    }

    fn address_topic(address: Address) -> B256 {
        let mut topic = [0u8; 32];
        topic[12..].copy_from_slice(address.as_slice());
        B256::from(topic)
    }

    fn rlp_len_prefix(base: u8, len: usize) -> Vec<u8> {
        if len <= 55 {
            vec![base + len as u8]
        } else {
            let bytes = (len as u64).to_be_bytes();
            let significant = bytes
                .iter()
                .skip_while(|byte| **byte == 0)
                .copied()
                .collect::<Vec<_>>();
            let mut prefix = vec![base + 55 + significant.len() as u8];
            prefix.extend(significant);
            prefix
        }
    }

    fn rlp_bytes(payload: &[u8]) -> Vec<u8> {
        if payload.len() == 1 && payload[0] < 0x80 {
            payload.to_vec()
        } else {
            let mut encoded = rlp_len_prefix(0x80, payload.len());
            encoded.extend_from_slice(payload);
            encoded
        }
    }

    fn rlp_uint(value: u128) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let significant = bytes
            .iter()
            .skip_while(|byte| **byte == 0)
            .copied()
            .collect::<Vec<_>>();
        rlp_bytes(&significant)
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload = items.concat();
        let mut encoded = rlp_len_prefix(0xc0, payload.len());
        encoded.extend(payload);
        encoded
    }
}
