//! Seller-penalty predicate: prove that a seller is linked to a funder, that
//! the funder funded a cohort of distinct buyers, and that those buyers later
//! settled material volume with the same seller on AntSeed.
//!
//! Everything in this crate runs identically natively (for tests) and inside
//! the RISC Zero guest (for proofs). The zkVM boundary lives in methods/guest.

use alloy_consensus::Header;
use alloy_primitives::{address, keccak256, Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ── Pinned rule parameters. Changing any of these changes the guest image ID. ──
pub const PREDICATE_VERSION: u32 = 3;
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

/// One settlement row reproduced from the published analytics report.
/// `suspected` identifies rows included in the report's suspected-volume
/// numerator; every row contributes to the report's seller-volume denominator.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReportSettlementClaim {
    pub buyer: Address,
    pub settlement: LogRef,
    pub suspected: bool,
}

/// Exact report snapshot whose computation is reproduced over authenticated
/// settlement receipts. The evidence root commits to the ordered settlement
/// set, including each row's suspected/non-suspected classification.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReportVolumeClaim {
    pub report_id: B256,
    pub evidence_root: B256,
    pub start_block: u64,
    pub end_block_exclusive: u64,
    pub expected_total_volume_raw: u128,
    pub expected_suspected_volume_raw: u128,
    pub expected_suspected_buyer_count: u32,
    pub settlements: Vec<ReportSettlementClaim>,
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
    pub report: ReportVolumeClaim,
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
    /// Proven common-funder buyer→seller volume strictly after funding.
    pub qualified_volume_raw: u128,
    /// Exact total seller volume reproduced from the report settlement set.
    pub report_total_volume_raw: u128,
    /// Exact suspected volume reproduced from the report settlement set.
    pub report_suspected_volume_raw: u128,
    pub report_suspected_buyer_count: u32,
    pub qualified_share_bps: u16,
    pub report_id: B256,
    pub report_evidence_root: B256,
    pub report_start_block: u64,
    pub report_end_block_exclusive: u64,
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
        uint128 qualifiedVolumeRaw;
        uint128 reportTotalVolumeRaw;
        uint128 reportSuspectedVolumeRaw;
        uint32 reportSuspectedBuyerCount;
        uint16 qualifiedShareBps;
        bytes32 reportId;
        bytes32 reportEvidenceRoot;
        uint64 reportStartBlock;
        uint64 reportEndBlockExclusive;
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
            qualifiedVolumeRaw: self.qualified_volume_raw,
            reportTotalVolumeRaw: self.report_total_volume_raw,
            reportSuspectedVolumeRaw: self.report_suspected_volume_raw,
            reportSuspectedBuyerCount: self.report_suspected_buyer_count,
            qualifiedShareBps: self.qualified_share_bps,
            reportId: self.report_id,
            reportEvidenceRoot: self.report_evidence_root,
            reportStartBlock: self.report_start_block,
            reportEndBlockExclusive: self.report_end_block_exclusive,
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
            qualified_volume_raw: j.qualifiedVolumeRaw,
            report_total_volume_raw: j.reportTotalVolumeRaw,
            report_suspected_volume_raw: j.reportSuspectedVolumeRaw,
            report_suspected_buyer_count: j.reportSuspectedBuyerCount,
            qualified_share_bps: j.qualifiedShareBps,
            report_id: j.reportId,
            report_evidence_root: j.reportEvidenceRoot,
            report_start_block: j.reportStartBlock,
            report_end_block_exclusive: j.reportEndBlockExclusive,
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

#[derive(Clone, Debug)]
pub struct ReportVolumeSummary {
    pub evidence_root: B256,
    pub total_volume_raw: u128,
    pub suspected_volume_raw: u128,
    pub suspected_buyer_count: u32,
    log_ids: BTreeSet<(u64, u64, usize)>,
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

/// Return whether an authenticated receipt completed successfully.
///
/// Post-Byzantium receipts encode the first payload item as status `0` or `1`.
/// Base blocks covered by the wash-trading predicates are post-Byzantium, so a
/// 32-byte pre-Byzantium state root is intentionally rejected.
pub fn receipt_success(receipt: &[u8]) -> Result<bool, String> {
    let mut buf = receipt;
    if !buf.is_empty() && buf[0] < 0xc0 {
        buf = &buf[1..];
    }
    let (is_list, mut body) = next_item(&mut buf)?;
    if !is_list {
        return Err("receipt: not a list".into());
    }
    let (is_list, status) = next_item(&mut body)?;
    if is_list {
        return Err("receipt: status is a list".into());
    }
    match status {
        [] => Ok(false),
        [1] => Ok(true),
        [0] => Ok(false),
        _ => Err("receipt: invalid status".into()),
    }
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
                if value * 10_000 < prev * MIN_FORWARD_BPS {
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
    let mut qualified_volume_raw = 0u128;
    let mut qualified_settlement_logs = BTreeSet::new();
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
            qualified_settlement_logs.insert(log_identity(input, *settlement_ref)?);
            qualified_volume_raw = qualified_volume_raw
                .checked_add(word_u128(&log.data[32..64])?)
                .ok_or("settlement: volume overflow")?;
            latest_settlement_block = latest_settlement_block.max(block);
        }
    }
    if qualified_volume_raw < MINIMUM_COHORT_VOLUME_RAW {
        return Err("cohort: suspicious volume below 1,000 USDC".into());
    }

    let report_summary = report_volume_summary(input)?;
    if report_summary.evidence_root != input.report.evidence_root {
        return Err("report: evidence root mismatch".into());
    }
    if report_summary.total_volume_raw != input.report.expected_total_volume_raw {
        return Err("report: total seller volume mismatch".into());
    }
    if report_summary.suspected_volume_raw != input.report.expected_suspected_volume_raw {
        return Err("report: suspected volume mismatch".into());
    }
    if report_summary.suspected_buyer_count != input.report.expected_suspected_buyer_count {
        return Err("report: suspected buyer count mismatch".into());
    }
    if !qualified_settlement_logs.is_subset(&report_summary.log_ids) {
        return Err("cohort: qualified settlement missing from report evidence".into());
    }
    let doubled_qualified = qualified_volume_raw
        .checked_mul(2)
        .ok_or("cohort: qualified volume ratio overflow")?;
    if doubled_qualified < report_summary.total_volume_raw {
        return Err("cohort: qualified volume below 50% of report seller volume".into());
    }
    let qualified_share_bps = qualified_volume_raw
        .checked_mul(10_000)
        .ok_or("cohort: qualified share overflow")?
        / report_summary.total_volume_raw;
    let qualified_share_bps =
        u16::try_from(qualified_share_bps).map_err(|_| "cohort: qualified share overflow")?;
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
        qualified_volume_raw,
        report_total_volume_raw: report_summary.total_volume_raw,
        report_suspected_volume_raw: report_summary.suspected_volume_raw,
        report_suspected_buyer_count: report_summary.suspected_buyer_count,
        qualified_share_bps,
        report_id: input.report.report_id,
        report_evidence_root: report_summary.evidence_root,
        report_start_block: input.report.start_block,
        report_end_block_exclusive: input.report.end_block_exclusive,
        earliest_funding_block,
        latest_settlement_block,
        block_refs,
    })
}

/// Reproduce the report's total and suspected volume over authenticated
/// ChannelSettled log references and derive a deterministic evidence root.
/// The caller remains responsible for verifying receipt inclusion first.
pub fn report_volume_summary(input: &SellerPenaltyInput) -> Result<ReportVolumeSummary, String> {
    if input.report.report_id == B256::ZERO {
        return Err("report: zero report id".into());
    }
    if input.report.start_block >= input.report.end_block_exclusive {
        return Err("report: invalid period".into());
    }
    if input.report.settlements.is_empty() {
        return Err("report: no settlements".into());
    }

    let resolver = Resolver { input };
    let mut total_volume_raw = 0_u128;
    let mut suspected_volume_raw = 0_u128;
    let mut buyer_classification = BTreeMap::<Address, bool>::new();
    let mut log_ids = BTreeSet::new();
    let mut previous_key = None;

    let mut root_preimage = Vec::with_capacity(32 + 32 + 8 + 8 + 20);
    root_preimage.extend_from_slice(b"ANTSEED_REPORT_VOLUME_V1");
    root_preimage.extend_from_slice(input.report.report_id.as_slice());
    root_preimage.extend_from_slice(&input.report.start_block.to_be_bytes());
    root_preimage.extend_from_slice(&input.report.end_block_exclusive.to_be_bytes());
    root_preimage.extend_from_slice(input.seller.as_slice());
    let mut evidence_root = keccak256(root_preimage);

    for (index, claim) in input.report.settlements.iter().enumerate() {
        let log_id = log_identity(input, claim.settlement)?;
        if !log_ids.insert(log_id) {
            return Err(format!("report settlement {index}: duplicate log"));
        }
        if previous_key.is_some_and(|previous| log_id <= previous) {
            return Err(format!(
                "report settlement {index}: not canonically ordered"
            ));
        }
        previous_key = Some(log_id);

        let (log, block_number) = resolver.log(claim.settlement)?;
        if block_number < input.report.start_block
            || block_number >= input.report.end_block_exclusive
        {
            return Err(format!("report settlement {index}: outside report period"));
        }
        if log.address != input.channels_contract
            || log.topics.len() != 4
            || log.topics[0] != CHANNEL_SETTLED_TOPIC
            || topic_addr(&log.topics[2]) != claim.buyer
            || topic_addr(&log.topics[3]) != input.seller
        {
            return Err(format!("report settlement {index}: event mismatch"));
        }
        if log.data.len() < 64 {
            return Err(format!("report settlement {index}: short data"));
        }
        let delta_raw = word_u128(&log.data[32..64])?;
        total_volume_raw = total_volume_raw
            .checked_add(delta_raw)
            .ok_or("report: total volume overflow")?;
        if claim.suspected {
            suspected_volume_raw = suspected_volume_raw
                .checked_add(delta_raw)
                .ok_or("report: suspected volume overflow")?;
        }
        match buyer_classification.insert(claim.buyer, claim.suspected) {
            Some(previous) if previous != claim.suspected => {
                return Err(format!(
                    "report settlement {index}: buyer classification changed"
                ));
            }
            _ => {}
        }

        let block = input
            .blocks
            .get(claim.settlement.block)
            .ok_or_else(|| format!("block index {} out of range", claim.settlement.block))?;
        let receipt = block
            .receipts
            .get(claim.settlement.receipt)
            .ok_or_else(|| format!("receipt position {} out of range", claim.settlement.receipt))?;
        let mut item = Vec::with_capacity(32 + 32 + 8 + 8 + 8 + 20 + 16 + 1);
        item.extend_from_slice(evidence_root.as_slice());
        item.extend_from_slice(block.header.hash_slow().as_slice());
        item.extend_from_slice(&block.header.number.to_be_bytes());
        item.extend_from_slice(&receipt.tx_index.to_be_bytes());
        item.extend_from_slice(&(claim.settlement.log as u64).to_be_bytes());
        item.extend_from_slice(claim.buyer.as_slice());
        item.extend_from_slice(&delta_raw.to_be_bytes());
        item.push(u8::from(claim.suspected));
        evidence_root = keccak256(item);
    }

    let suspected_buyer_count = buyer_classification
        .values()
        .filter(|suspected| **suspected)
        .count();
    let suspected_buyer_count = u32::try_from(suspected_buyer_count)
        .map_err(|_| "report: suspected buyer count overflow")?;

    Ok(ReportVolumeSummary {
        evidence_root,
        total_volume_raw,
        suspected_volume_raw,
        suspected_buyer_count,
        log_ids,
    })
}

fn log_identity(input: &SellerPenaltyInput, log_ref: LogRef) -> Result<(u64, u64, usize), String> {
    let block = input
        .blocks
        .get(log_ref.block)
        .ok_or_else(|| format!("block index {} out of range", log_ref.block))?;
    let receipt = block
        .receipts
        .get(log_ref.receipt)
        .ok_or_else(|| format!("receipt position {} out of range", log_ref.receipt))?;
    Ok((block.header.number, receipt.tx_index, log_ref.log))
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
        assert_eq!(journal.qualified_volume_raw, MINIMUM_COHORT_VOLUME_RAW);
        assert_eq!(
            journal.report_suspected_volume_raw,
            MINIMUM_COHORT_VOLUME_RAW
        );
        assert_eq!(journal.qualified_share_bps, 10_000);
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
    fn report_volume_mismatch_fails() {
        let mut input = valid_input();
        input.report.expected_suspected_volume_raw -= 1;
        assert!(verify(&input)
            .unwrap_err()
            .contains("suspected volume mismatch"));
    }

    #[test]
    fn report_evidence_root_mismatch_fails() {
        let mut input = valid_input();
        input.report.evidence_root = B256::with_last_byte(99);
        assert!(verify(&input)
            .unwrap_err()
            .contains("evidence root mismatch"));
    }

    #[test]
    fn report_buyer_count_mismatch_fails() {
        let mut input = valid_input();
        input.report.expected_suspected_buyer_count = 2;
        assert!(verify(&input).unwrap_err().contains("buyer count mismatch"));
    }

    #[test]
    fn journal_abi_round_trip() {
        let journal = verify(&valid_input()).unwrap();
        let decoded = SellerPenaltyJournal::abi_decode(&journal.abi_encode()).unwrap();
        assert_eq!(decoded.qualified_volume_raw, journal.qualified_volume_raw);
        assert_eq!(
            decoded.report_suspected_volume_raw,
            journal.report_suspected_volume_raw
        );
        assert_eq!(decoded.report_evidence_root, journal.report_evidence_root);
        assert_eq!(decoded.block_refs, journal.block_refs);
    }

    fn valid_input() -> SellerPenaltyInput {
        let mut input = SellerPenaltyInput {
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
            report: ReportVolumeClaim {
                report_id: B256::with_last_byte(1),
                evidence_root: B256::ZERO,
                start_block: 1,
                end_block_exclusive: 40,
                expected_total_volume_raw: MINIMUM_COHORT_VOLUME_RAW,
                expected_suspected_volume_raw: MINIMUM_COHORT_VOLUME_RAW,
                expected_suspected_buyer_count: 3,
                settlements: vec![
                    report_settlement(BUYER_1, 1),
                    report_settlement(BUYER_2, 3),
                    report_settlement(BUYER_3, 5),
                ],
            },
        };
        input.report.evidence_root = report_volume_summary(&input).unwrap().evidence_root;
        input
    }

    fn report_settlement(buyer: Address, settlement_block: usize) -> ReportSettlementClaim {
        ReportSettlementClaim {
            buyer,
            settlement: LogRef {
                block: settlement_block,
                receipt: 0,
                log: 0,
            },
            suspected: true,
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
